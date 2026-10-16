"""인증 · 권한(RBAC).

- 비밀번호: PBKDF2-HMAC-SHA256 (600,000회, 사용자별 salt) — OWASP 권고치
- 세션 토큰: 무작위 32바이트, DB 에는 SHA-256 해시만 저장, 만료 시간 있음
- SSE 스트림: EventSource 가 헤더를 못 보내므로 1회용·60초짜리 티켓을 따로 발급 (세션 토큰을 URL 에 싣지 않음)
- 수집 API 키: 환경 변수 RKMSIEM_INGEST_KEYS (쉼표 구분). 소스 코드/설정 파일에 두지 않음
- 권한 표는 config/rbac.yaml — 백엔드의 모든 API 에서 검사
- 첫 관리자(admin/admin)·관리자가 재설정한 임시 비밀번호·12자 미만 비밀번호 → 로그인 직후 비밀번호 변경 전까지 다른 API 거부
- 2단계 인증(TOTP): 켠 계정은 비밀번호 다음에 OTP 코드까지 맞아야 세션 발급. 비밀 값은 vault 로 암호화해 DB 에 저장
"""
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

from . import totp

ITER = 600_000
MIN_PASSWORD = 12


class AuthError(PermissionError):
    pass


def hash_password(pw, iterations=ITER):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(pw, stored):
    try:
        algo, it, salt, h = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode(), base64.b64decode(salt), int(it))
        return algo == "pbkdf2_sha256" and hmac.compare_digest(dk, base64.b64decode(h))
    except Exception:            # noqa: BLE001
        return False


_DUMMY = None


def _sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


class RateLimiter:
    def __init__(self, per_min):
        self.per_min, self.hits, self.lock = per_min, {}, threading.Lock()

    def allow(self, key):
        now = time.time()
        with self.lock:
            q = [t for t in self.hits.get(key, []) if t > now - 60]
            if len(q) >= self.per_min:
                self.hits[key] = q
                return False
            q.append(now)
            self.hits[key] = q
            return True


class AuthService:
    def __init__(self, db, config, audit, settings, vault=None):
        self.db, self.config, self.audit, self.settings, self.vault = db, config, audit, settings, vault
        self.limiter = RateLimiter(settings.get("api.login_rate_per_min", 10))
        self._mfa, self._mfa_lock = {}, threading.Lock()          # 비밀번호는 맞고 OTP 를 기다리는 로그인 (5분 · 5번까지)
        keys = (settings.secret("RKMSIEM_INGEST_KEYS") or "").split(",")
        self._ingest = {_sha(k.strip()) for k in keys if k.strip()}

    # ---------- 사용자 ----------
    def roles(self):
        return (self.config.get("rbac") or {}).get("roles", {})

    def permissions(self, role):
        return set((self.roles().get(role) or {}).get("permissions", []))

    def create_user(self, username, password, role, actor, allow_short=False, must_change=False):
        if not username or not username.replace("_", "").replace("-", "").replace(".", "").isalnum() or len(username) > 64:
            raise ValueError("사용자 이름은 영문/숫자/._- 64자 이하")
        if role not in self.roles():
            raise ValueError(f"알 수 없는 역할 {role}")
        if not password or (len(password) < MIN_PASSWORD and not allow_short):
            raise ValueError(f"비밀번호는 {MIN_PASSWORD}자 이상")
        with self.db.tx() as c:
            cur = c.execute("INSERT INTO users (username, pw_hash, role, active, created_at, must_change_pw) VALUES (?,?,?,1,?,?)",
                            (username, hash_password(password), role, time.time(), int(must_change)))
            self.audit.record(actor, "user.create", "user", username, None, {"role": role}, conn=c)
        return cur.lastrowid

    def set_active(self, username, active, actor):
        with self.db.tx() as c:
            c.execute("UPDATE users SET active=? WHERE username=?", (int(active), username))
            if not active:
                c.execute("DELETE FROM tokens WHERE user_id = (SELECT id FROM users WHERE username=?)", (username,))
            self.audit.record(actor, "user.active", "user", username, None, {"active": bool(active)}, conn=c)

    def change_password(self, username, current, new, actor, require_current=True):
        u = self.db.one("SELECT * FROM users WHERE username=?", (username,))
        if not u:
            raise KeyError(username)
        if require_current and not verify_password(current or "", u["pw_hash"]):
            self.audit.record(actor, "user.password_failed", "user", username)
            raise AuthError("invalid_credentials")
        if len(new or "") < MIN_PASSWORD:
            raise ValueError(f"비밀번호는 {MIN_PASSWORD}자 이상")
        if require_current and verify_password(new, u["pw_hash"]):
            raise ValueError("지금 비밀번호와 다른 비밀번호를 쓰세요")
        with self.db.tx() as c:
            # 본인이 바꾸면 변경 요구 해제, 관리자가 재설정한 임시 비밀번호면 다음 로그인 때 본인이 바꾸게
            c.execute("UPDATE users SET pw_hash=?, must_change_pw=? WHERE id=?", (hash_password(new), int(not require_current), u["id"]))
            c.execute("DELETE FROM tokens WHERE user_id=?", (u["id"],))       # 다른 세션 모두 로그아웃
            self.audit.record(actor, "user.password_change", "user", username, conn=c)

    def list_users(self):
        """로그인 계정만 (이름·팀·연락처는 담당자 관리 앱의 명단에 있음)."""
        return self.db.all("SELECT id, username, role, active, created_at, totp_enabled AS mfa, must_change_pw AS must_change FROM users ORDER BY id")

    def _admins(self, c, exclude=None):
        """users:write 권한을 가진 활성 사용자 수 (마지막 관리자를 잃지 않게)."""
        admin_roles = [r for r in self.roles() if "users:write" in self.permissions(r)]
        q = f"SELECT COUNT(*) FROM users WHERE active=1 AND role IN ({','.join('?' * len(admin_roles)) or 'NULL'})"
        params = list(admin_roles)
        if exclude:
            q += " AND username <> ?"
            params.append(exclude)
        return c.execute(q, params).fetchone()[0]

    def update_user(self, username, fields, actor):
        """역할 변경. 마지막 관리자의 권한은 내릴 수 없음."""
        fields = {k: v for k, v in fields.items() if k == "role"}
        if "role" in fields and fields["role"] not in self.roles():
            raise ValueError(f"알 수 없는 역할 {fields['role']}")
        with self.db.tx() as c:
            u = c.execute("SELECT username, role FROM users WHERE username=?", (username,)).fetchone()
            if not u:
                raise KeyError(username)
            if "role" in fields and "users:write" not in self.permissions(fields["role"]) and "users:write" in self.permissions(u["role"]) \
                    and self._admins(c, exclude=username) == 0:
                raise ValueError("마지막 관리자의 권한은 내릴 수 없습니다")
            if fields:
                c.execute("UPDATE users SET role=?, updated_at=? WHERE username=?", (fields["role"], time.time(), username))
            if "role" in fields and fields["role"] != u["role"]:
                c.execute("DELETE FROM tokens WHERE user_id = (SELECT id FROM users WHERE username=?)", (username,))   # 권한이 바뀌면 다시 로그인
            self.audit.record(actor, "user.update", "user", username, None, fields, conn=c)

    def guard_deactivate(self, username):
        with self.db.tx() as c:
            u = c.execute("SELECT role, active FROM users WHERE username=?", (username,)).fetchone()
            if not u:
                raise KeyError(username)
            if u["active"] and "users:write" in self.permissions(u["role"]) and self._admins(c, exclude=username) == 0:
                raise ValueError("마지막 관리자는 비활성화할 수 없습니다")

    def bootstrap_admin(self):
        """사용자가 하나도 없고 RKMSIEM_ADMIN_PASSWORD 가 있으면 관리자 1명 생성.
        첫 관리자만 짧은 비밀번호(기본 admin)를 허용 — 이후 바꾸는 비밀번호는 12자 이상."""
        if self.db.scalar("SELECT COUNT(*) FROM users"):
            return None
        pw = self.settings.secret("RKMSIEM_ADMIN_PASSWORD")
        if not pw:
            return None
        name = self.settings.secret("RKMSIEM_ADMIN_USER", "admin")
        self.create_user(name, pw, "admin", "bootstrap", allow_short=True, must_change=True)
        return name

    # ---------- 세션 ----------
    def login(self, username, password, client):
        """비밀번호 확인. 2단계 인증을 켠 계정이면 세션 대신 OTP 대기표를 돌려준다 → login_mfa."""
        if not self.limiter.allow(client):
            self.audit.record(username or "?", "auth.rate_limited", "user", username, None, {"client": client})
            raise AuthError("rate_limited")
        u = self.db.one("SELECT * FROM users WHERE username=?", (username or "",))
        ok = verify_password(password or "", u["pw_hash"]) if u else verify_password(password or "", _dummy_hash())
        if not u or not ok or not u["active"]:
            self.audit.record(username or "?", "auth.login_failed", "user", username, None, {"client": client})
            raise AuthError("invalid_credentials")
        if len(password) < MIN_PASSWORD and not u["must_change_pw"]:      # 예전 설치의 admin/admin 등 → 바꾸게
            self.db.execute("UPDATE users SET must_change_pw=1 WHERE id=?", (u["id"],))
        if u["totp_enabled"]:
            ticket = secrets.token_urlsafe(24)
            with self._mfa_lock:
                now = time.time()
                self._mfa = {k: v for k, v in self._mfa.items() if v["exp"] > now}
                self._mfa[_sha(ticket)] = {"uid": u["id"], "exp": now + 300, "tries": 0}
            self.audit.record(username, "auth.password_ok", "user", username, None, {"client": client, "mfa": "pending"})
            return None, {"mfa_required": True, "mfa_ticket": ticket}
        return self._issue(u, client, mfa=False)

    def login_mfa(self, ticket, code, client):
        if not self.limiter.allow("mfa:" + client):
            raise AuthError("rate_limited")
        with self._mfa_lock:
            t = self._mfa.get(_sha(ticket or ""))
            if not t or t["exp"] < time.time() or t["tries"] >= 5:
                self._mfa.pop(_sha(ticket or ""), None)
                raise AuthError("mfa_expired")
            t["tries"] += 1
        u = self.db.one("SELECT * FROM users WHERE id=?", (t["uid"],))
        step = self._check_code(u, code) if u and u["active"] and u["totp_enabled"] else None
        if step is None:
            self.audit.record(u["username"] if u else "?", "auth.mfa_failed", "user", u["username"] if u else None, None, {"client": client})
            raise AuthError("invalid_code")
        with self._mfa_lock:
            self._mfa.pop(_sha(ticket), None)
        self.db.execute("UPDATE users SET totp_last_step=? WHERE id=?", (step, u["id"]))
        return self._issue(u, client, mfa=True)

    def _issue(self, u, client, mfa):
        token = secrets.token_urlsafe(32)
        ttl = self.settings.get("api.token_ttl_sec", 28800)
        self.db.execute("INSERT INTO tokens (token_hash, user_id, kind, expires_at, created_at) VALUES (?,?,?,?,?)",
                        (_sha(token), u["id"], "session", time.time() + ttl, time.time()))
        self.db.execute("DELETE FROM tokens WHERE expires_at < ?", (time.time(),))
        self.audit.record(u["username"], "auth.login", "user", u["username"], None, {"client": client, "mfa": mfa})
        must = bool(self.db.scalar("SELECT must_change_pw FROM users WHERE id=?", (u["id"],)))
        return token, {"username": u["username"], "role": u["role"], "permissions": sorted(self.permissions(u["role"])), "expires_in": ttl,
                       "must_change_password": must}

    # ---------- 2단계 인증 (TOTP) ----------
    def _check_code(self, u, code):
        try:
            secret = self.vault.decrypt(u["totp_secret"])
        except Exception:     # noqa: BLE001 — 암호화 키가 바뀐 경우 등
            return None
        return totp.verify(secret, code, u["totp_last_step"])

    def totp_status(self, user):
        r = self.db.one("SELECT totp_enabled, totp_secret FROM users WHERE id=?", (user["id"],))
        return {"enabled": bool(r["totp_enabled"]), "pending": bool(r["totp_secret"]) and not r["totp_enabled"]}

    def totp_begin(self, user):
        """새 비밀 값을 만들어 '대기' 로 저장 → 앱에 등록 후 totp_enable 로 코드 확인해야 켜짐."""
        if not self.vault or not self.vault.ready:
            raise ValueError("암호화 키(RKMSIEM_SECRET_KEY)가 없어 2단계 인증을 쓸 수 없습니다")
        if self.totp_status(user)["enabled"]:
            raise ValueError("이미 켜져 있습니다 — 다시 등록하려면 먼저 끄세요")
        secret = totp.new_secret()
        self.db.execute("UPDATE users SET totp_secret=?, totp_last_step=NULL WHERE id=?", (self.vault.encrypt(secret), user["id"]))
        return {"secret": secret, "uri": totp.uri(secret, user["username"])}

    def totp_enable(self, user, code):
        u = self.db.one("SELECT * FROM users WHERE id=?", (user["id"],))
        if u["totp_enabled"] or not u["totp_secret"]:
            raise ValueError("먼저 등록(setup)을 시작하세요")
        step = self._check_code(u, code)
        if step is None:
            raise AuthError("invalid_code")
        with self.db.tx() as c:
            c.execute("UPDATE users SET totp_enabled=1, totp_last_step=? WHERE id=?", (step, u["id"]))
            self.audit.record(u["username"], "user.mfa_enable", "user", u["username"], conn=c)

    def totp_disable(self, user, password, code):
        u = self.db.one("SELECT * FROM users WHERE id=?", (user["id"],))
        if not u["totp_enabled"]:
            raise ValueError("2단계 인증이 꺼져 있습니다")
        if not verify_password(password or "", u["pw_hash"]) or self._check_code(u, code) is None:
            self.audit.record(u["username"], "user.mfa_disable_failed", "user", u["username"])
            raise AuthError("invalid_credentials")
        with self.db.tx() as c:
            c.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL, totp_last_step=NULL WHERE id=?", (u["id"],))
            self.audit.record(u["username"], "user.mfa_disable", "user", u["username"], conn=c)

    def totp_reset(self, username, actor):
        """휴대폰을 잃어버린 경우: 관리자(또는 서버 CLI)가 끔. 그 사용자의 세션도 모두 끊음."""
        with self.db.tx() as c:
            u = c.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
            if not u:
                raise KeyError(username)
            c.execute("UPDATE users SET totp_enabled=0, totp_secret=NULL, totp_last_step=NULL WHERE id=?", (u["id"],))
            c.execute("DELETE FROM tokens WHERE user_id=?", (u["id"],))
            self.audit.record(actor, "user.mfa_reset", "user", username, conn=c)

    # ---------- 장기 API 토큰 (rkm_…) ----------
    TOKEN_SCOPES = ["metrics:read", "alerts:read", "incidents:read", "events:read", "collectors:read"]

    def create_api_token(self, name, scopes, actor, expires_days=None):
        name = (name or "").strip()
        if not name or len(name) > 64 or not all(c.isalnum() or c in "-_. " for c in name):
            raise ValueError("이름: 64자 이하 (영문·숫자·한글·-_. )")
        scopes = sorted(set(scopes or []))
        bad = [s for s in scopes if s not in self.TOKEN_SCOPES]
        if not scopes or bad:
            raise ValueError(f"권한은 {', '.join(self.TOKEN_SCOPES)} 중에서 (읽기 전용)")
        tok = "rkm_" + secrets.token_urlsafe(32)
        exp = time.time() + int(expires_days) * 86400 if expires_days else None
        import json as _json
        with self.db.tx() as c:
            if c.execute("SELECT 1 FROM api_tokens WHERE name=?", (name,)).fetchone():
                raise ValueError("같은 이름의 토큰이 있습니다")
            cur = c.execute("INSERT INTO api_tokens (name, token_hash, prefix, scopes, created_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                            (name, _sha(tok), tok[:10], _json.dumps(scopes), actor, time.time(), exp))
            self.audit.record(actor, "api_token.create", "api_token", name, None, {"scopes": scopes, "expires_days": expires_days}, conn=c)
        return {"id": cur.lastrowid, "name": name, "token": tok, "scopes": scopes, "expires_at": exp}

    def list_api_tokens(self):
        import json as _json
        return [dict(r, scopes=_json.loads(r["scopes"])) for r in self.db.all(
            "SELECT id, name, prefix, scopes, created_by, created_at, expires_at, last_used_at, last_used_ip, revoked_at FROM api_tokens ORDER BY id DESC")]

    def revoke_api_token(self, tid, actor):
        r = self.db.one("SELECT name FROM api_tokens WHERE id=? AND revoked_at IS NULL", (tid,))
        if not r:
            raise KeyError(tid)
        self.db.execute("UPDATE api_tokens SET revoked_at=? WHERE id=?", (time.time(), tid))
        self.audit.record(actor, "api_token.revoke", "api_token", r["name"])

    def _resolve_api_token(self, token, client=None):
        import json as _json
        r = self.db.one("SELECT * FROM api_tokens WHERE token_hash=?", (_sha(token),))
        now = time.time()
        if not r or r["revoked_at"] or (r["expires_at"] and r["expires_at"] < now):
            return None
        if not r["last_used_at"] or now - r["last_used_at"] > 60:        # 매 요청마다 쓰지 않게 (1분 단위)
            self.db.execute("UPDATE api_tokens SET last_used_at=?, last_used_ip=? WHERE id=?", (now, client, r["id"]))
        return {"id": None, "username": f"token:{r['name']}", "role": "api", "permissions": set(_json.loads(r["scopes"])),
                "must_change": False, "mfa": False}

    def resolve(self, token, kind="session", client=None):
        if not token:
            return None
        if kind == "session" and token.startswith("rkm_"):
            return self._resolve_api_token(token, client)
        r = self.db.one("SELECT u.id, u.username, u.role, u.active, u.must_change_pw, u.totp_enabled, t.expires_at FROM tokens t JOIN users u ON u.id = t.user_id "
                        "WHERE t.token_hash=? AND t.kind=?", (_sha(token), kind))
        if not r or not r["active"] or r["expires_at"] < time.time():
            return None
        if kind == "stream":                                 # 1회용
            self.db.execute("DELETE FROM tokens WHERE token_hash=?", (_sha(token),))
        return {"id": r["id"], "username": r["username"], "role": r["role"], "permissions": self.permissions(r["role"]),
                "must_change": bool(r["must_change_pw"]), "mfa": bool(r["totp_enabled"])}

    def logout(self, token):
        r = self.db.one("SELECT user_id FROM tokens WHERE token_hash=? AND kind='session'", (_sha(token),))
        self.db.execute("DELETE FROM tokens WHERE token_hash=?", (_sha(token),))
        if r:                                                # 임베드 Grafana 출입증도 같이 무효화
            self.db.execute("DELETE FROM tokens WHERE user_id=? AND kind='grafana'", (r["user_id"],))

    def grafana_ticket(self, user):
        """/grafana/ 전용 쿠키 값 — 세션 토큰과 별개라 Grafana 쪽에 새어도 RKMSIEM API 에는 못 씀."""
        t = secrets.token_urlsafe(32)
        ttl = int(self.settings.get("grafana.ticket_ttl_sec", 28800) or 28800)
        self.db.execute("DELETE FROM tokens WHERE user_id=? AND kind='grafana' AND expires_at < ?", (user["id"], time.time()))
        self.db.execute("INSERT INTO tokens (token_hash, user_id, kind, expires_at, created_at) VALUES (?,?,?,?,?)",
                        (_sha(t), user["id"], "grafana", time.time() + ttl, time.time()))
        return t, ttl

    def drop_grafana_ticket(self, ticket):
        if ticket:
            self.db.execute("DELETE FROM tokens WHERE token_hash=? AND kind='grafana'", (_sha(ticket),))

    def stream_ticket(self, user):
        t = secrets.token_urlsafe(24)
        self.db.execute("INSERT INTO tokens (token_hash, user_id, kind, expires_at, created_at) VALUES (?,?,?,?,?)",
                        (_sha(t), user["id"], "stream", time.time() + self.settings.get("api.stream_ticket_ttl_sec", 60), time.time()))
        return t

    def local_user(self, key, addr):
        """root 전용 점검 키 (rkmsiem.env 의 RKMSIEM_LOCAL_TOKEN, root 0600): 이 서버 안(127.0.0.1)에서 온 요청만.
        설치 자가 점검·smoketest 가 첫 비밀번호 변경·2단계 인증과 상관없이 돌 수 있게. 감사 로그 행위자는 root@local."""
        want = self.settings.secret("RKMSIEM_LOCAL_TOKEN") or ""
        if len(want) < 32 or not key or addr not in ("127.0.0.1", "::1") or not hmac.compare_digest(key.encode(), want.encode()):
            return None
        role = "admin" if "admin" in self.roles() else next((r for r in self.roles() if "users:write" in self.permissions(r)), None)
        if not role:
            return None
        return {"id": None, "username": "root@local", "role": role, "permissions": self.permissions(role), "must_change": False, "mfa": True}

    def check_ingest_key(self, key):
        return bool(key) and any(hmac.compare_digest(_sha(key), k) for k in self._ingest)


def _dummy_hash():
    """존재하지 않는 사용자도 같은 시간이 걸리게(사용자 존재 여부 노출 방지)."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_hex(8))
    return _DUMMY
