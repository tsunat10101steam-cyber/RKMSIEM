"""인증 · 권한(RBAC).

- 비밀번호: PBKDF2-HMAC-SHA256 (600,000회, 사용자별 salt) — OWASP 권고치
- 세션 토큰: 무작위 32바이트, DB 에는 SHA-256 해시만 저장, 만료 시간 있음
- SSE 스트림: EventSource 가 헤더를 못 보내므로 1회용·60초짜리 티켓을 따로 발급 (세션 토큰을 URL 에 싣지 않음)
- 수집 API 키: 환경 변수 RKMSIEM_INGEST_KEYS (쉼표 구분). 소스 코드/설정 파일에 두지 않음
- 권한 표는 config/rbac.yaml — 백엔드의 모든 API 에서 검사
"""
import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

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
    def __init__(self, db, config, audit, settings):
        self.db, self.config, self.audit, self.settings = db, config, audit, settings
        self.limiter = RateLimiter(settings.get("api.login_rate_per_min", 10))
        keys = (settings.secret("RKMSIEM_INGEST_KEYS") or "").split(",")
        self._ingest = {_sha(k.strip()) for k in keys if k.strip()}

    # ---------- 사용자 ----------
    def roles(self):
        return (self.config.get("rbac") or {}).get("roles", {})

    def permissions(self, role):
        return set((self.roles().get(role) or {}).get("permissions", []))

    def create_user(self, username, password, role, actor, allow_short=False):
        if not username or not username.replace("_", "").replace("-", "").replace(".", "").isalnum() or len(username) > 64:
            raise ValueError("사용자 이름은 영문/숫자/._- 64자 이하")
        if role not in self.roles():
            raise ValueError(f"알 수 없는 역할 {role}")
        if not password or (len(password) < MIN_PASSWORD and not allow_short):
            raise ValueError(f"비밀번호는 {MIN_PASSWORD}자 이상")
        with self.db.tx() as c:
            cur = c.execute("INSERT INTO users (username, pw_hash, role, active, created_at) VALUES (?,?,?,1,?)",
                            (username, hash_password(password), role, time.time()))
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
        with self.db.tx() as c:
            c.execute("UPDATE users SET pw_hash=? WHERE id=?", (hash_password(new), u["id"]))
            c.execute("DELETE FROM tokens WHERE user_id=?", (u["id"],))       # 다른 세션 모두 로그아웃
            self.audit.record(actor, "user.password_change", "user", username, conn=c)

    def list_users(self):
        """로그인 계정만 (이름·팀·연락처는 담당자 관리 앱의 명단에 있음)."""
        return self.db.all("SELECT id, username, role, active, created_at FROM users ORDER BY id")

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
        self.create_user(name, pw, "admin", "bootstrap", allow_short=True)
        return name

    # ---------- 세션 ----------
    def login(self, username, password, client):
        if not self.limiter.allow(client):
            self.audit.record(username or "?", "auth.rate_limited", "user", username, None, {"client": client})
            raise AuthError("rate_limited")
        u = self.db.one("SELECT * FROM users WHERE username=?", (username or "",))
        ok = verify_password(password or "", u["pw_hash"]) if u else verify_password(password or "", _dummy_hash())
        if not u or not ok or not u["active"]:
            self.audit.record(username or "?", "auth.login_failed", "user", username, None, {"client": client})
            raise AuthError("invalid_credentials")
        token = secrets.token_urlsafe(32)
        ttl = self.settings.get("api.token_ttl_sec", 28800)
        self.db.execute("INSERT INTO tokens (token_hash, user_id, kind, expires_at, created_at) VALUES (?,?,?,?,?)",
                        (_sha(token), u["id"], "session", time.time() + ttl, time.time()))
        self.db.execute("DELETE FROM tokens WHERE expires_at < ?", (time.time(),))
        self.audit.record(username, "auth.login", "user", username, None, {"client": client})
        return token, {"username": u["username"], "role": u["role"], "permissions": sorted(self.permissions(u["role"])), "expires_in": ttl}

    def resolve(self, token, kind="session"):
        if not token:
            return None
        r = self.db.one("SELECT u.id, u.username, u.role, u.active, t.expires_at FROM tokens t JOIN users u ON u.id = t.user_id "
                        "WHERE t.token_hash=? AND t.kind=?", (_sha(token), kind))
        if not r or not r["active"] or r["expires_at"] < time.time():
            return None
        if kind == "stream":                                 # 1회용
            self.db.execute("DELETE FROM tokens WHERE token_hash=?", (_sha(token),))
        return {"id": r["id"], "username": r["username"], "role": r["role"], "permissions": self.permissions(r["role"])}

    def logout(self, token):
        self.db.execute("DELETE FROM tokens WHERE token_hash=?", (_sha(token),))

    def stream_ticket(self, user):
        t = secrets.token_urlsafe(24)
        self.db.execute("INSERT INTO tokens (token_hash, user_id, kind, expires_at, created_at) VALUES (?,?,?,?,?)",
                        (_sha(t), user["id"], "stream", time.time() + self.settings.get("api.stream_ticket_ttl_sec", 60), time.time()))
        return t

    def check_ingest_key(self, key):
        return bool(key) and any(hmac.compare_digest(_sha(key), k) for k in self._ingest)


def _dummy_hash():
    """존재하지 않는 사용자도 같은 시간이 걸리게(사용자 존재 여부 노출 방지)."""
    global _DUMMY
    if _DUMMY is None:
        _DUMMY = hash_password(secrets.token_hex(8))
    return _DUMMY
