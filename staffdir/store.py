"""담당자 앱 저장소: SQLite(WAL) — 담당자 · 앱 관리자 · 세션 · 변경 기록 · 연동 기록.

- 관리자 비밀번호: PBKDF2-HMAC-SHA256 (600,000회), 세션 토큰·연동 키는 SHA-256 해시만 다룬다.
- 변경 기록에는 메일·전화 값을 남기지 않는다 ('(변경)' 으로만 표시).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time

ITER = 600_000
MIN_PASSWORD = 12
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^[0-9+()\- ]{4,32}$")
FIELDS = ("display_name", "team", "email", "phone", "notify_assign")
PRIVATE = ("email", "phone")

SCHEMA = """
CREATE TABLE IF NOT EXISTS people (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT, team TEXT, email TEXT, phone TEXT,
  notify_assign INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE, pw_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
  expires_at REAL NOT NULL, created_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS changes (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS sync_log (
  client TEXT PRIMARY KEY, last_at REAL NOT NULL, count INTEGER NOT NULL DEFAULT 0);
"""


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


def sha(t):
    return hashlib.sha256(t.encode()).hexdigest()


class StaffError(ValueError):
    pass


class Store:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self.lock = threading.RLock()
        with self.lock:
            self.conn().executescript(SCHEMA)
        self._dummy = hash_password(secrets.token_hex(8))

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, check_same_thread=False, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.conn = c
        return c

    def all(self, sql, params=()):
        return [dict(r) for r in self.conn().execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        r = self.conn().execute(sql, params).fetchone()
        return dict(r) if r else None

    def tx(self):
        store = self

        class _Tx:
            def __enter__(self):
                store.lock.acquire()
                self.c = store.conn()
                self.c.execute("BEGIN IMMEDIATE")
                return self.c

            def __exit__(self, et, *_):
                try:
                    self.c.execute("ROLLBACK" if et else "COMMIT")
                finally:
                    store.lock.release()
        return _Tx()

    def _log(self, c, actor, action, target=None, detail=None):
        c.execute("INSERT INTO changes (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                  (time.time(), actor, action, target, json.dumps(detail, ensure_ascii=False) if detail is not None else None))

    # ------------------------------------------------------------ 담당자
    @staticmethod
    def _clean(fields):
        out = {}
        for k, v in fields.items():
            if k not in FIELDS:
                continue
            if k == "notify_assign":
                out[k] = int(bool(v))
                continue
            v = (v or "").strip() if isinstance(v, str) or v is None else str(v)
            if len(v) > (254 if k == "email" else 64):
                raise StaffError(f"{k} 값이 너무 깁니다")
            if v and k == "email" and not EMAIL_RE.match(v):
                raise StaffError("메일 주소 형식이 올바르지 않습니다")
            if v and k == "phone" and not PHONE_RE.match(v):
                raise StaffError("전화번호 형식이 올바르지 않습니다")
            out[k] = v or None
        return out

    @staticmethod
    def _shown(fields):
        return {k: ("(변경)" if k in PRIVATE and v else v) for k, v in fields.items()}

    def people(self, include_inactive=True):
        q = "SELECT * FROM people" + ("" if include_inactive else " WHERE active=1") + " ORDER BY active DESC, team IS NULL, team, display_name, username"
        return self.all(q)

    def get(self, username):
        p = self.one("SELECT * FROM people WHERE username=?", (username,))
        if not p:
            raise KeyError(username)
        return p

    def add(self, username, fields, actor):
        username = (username or "").strip()
        if not USERNAME_RE.match(username):
            raise StaffError("아이디는 영문·숫자·._- 64자 이하")
        f = self._clean(fields)
        now = time.time()
        with self.tx() as c:
            if c.execute("SELECT 1 FROM people WHERE username=?", (username,)).fetchone():
                raise StaffError("이미 있는 아이디입니다")
            cols = ["username", "created_at", "updated_at"] + list(f)
            c.execute(f"INSERT INTO people ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})", [username, now, now] + list(f.values()))
            self._log(c, actor, "person.add", username, self._shown(f))
        return self.get(username)

    def update(self, username, fields, actor):
        f = self._clean(fields)
        with self.tx() as c:
            if not c.execute("SELECT 1 FROM people WHERE username=?", (username,)).fetchone():
                raise KeyError(username)
            if f:
                c.execute(f"UPDATE people SET {', '.join(f'{k}=?' for k in f)}, updated_at=? WHERE username=?",
                          list(f.values()) + [time.time(), username])
                self._log(c, actor, "person.update", username, self._shown(f))
        return self.get(username)

    def set_active(self, username, active, actor):
        with self.tx() as c:
            if not c.execute("UPDATE people SET active=?, updated_at=? WHERE username=?", (int(bool(active)), time.time(), username)).rowcount:
                raise KeyError(username)
            self._log(c, actor, "person.active", username, {"active": bool(active)})

    def delete(self, username, actor):
        with self.tx() as c:
            if not c.execute("DELETE FROM people WHERE username=?", (username,)).rowcount:
                raise KeyError(username)
            self._log(c, actor, "person.delete", username)

    def import_rows(self, rows, actor):
        """다른 곳(예: 예전 RKMSIEM 사용자 정보)에서 가져오기 — 이미 있는 아이디는 건너뜀."""
        added = []
        for r in rows:
            try:
                self.add(r["username"], {k: r.get(k) for k in FIELDS if r.get(k) is not None}, actor)
                if not r.get("active", 1):
                    self.set_active(r["username"], False, actor)
                added.append(r["username"])
            except StaffError:
                continue
        return added

    def roster(self):
        """연동용 명단 (비활성 포함) + 내용 해시(바뀐 게 없으면 받는 쪽이 저장을 건너뛰게)."""
        items = [{k: p[k] for k in ("username", "display_name", "team", "email", "phone", "notify_assign", "active", "updated_at")}
                 for p in self.all("SELECT * FROM people ORDER BY username")]
        body = json.dumps(items, ensure_ascii=False, sort_keys=True)
        return {"items": items, "version": hashlib.sha256(body.encode()).hexdigest()[:16], "generated_at": time.time()}

    def note_sync(self, client, count):
        with self.lock:
            self.conn().execute("INSERT INTO sync_log (client, last_at, count) VALUES (?,?,?) "
                                "ON CONFLICT(client) DO UPDATE SET last_at=excluded.last_at, count=excluded.count", (client, time.time(), count))

    def sync_clients(self):
        return self.all("SELECT * FROM sync_log ORDER BY last_at DESC")

    def changes(self, limit=50):
        rows = self.all("SELECT * FROM changes ORDER BY id DESC LIMIT ?", (limit,))
        for r in rows:
            r["detail"] = json.loads(r["detail"]) if r["detail"] else None
        return rows

    # ------------------------------------------------------------ 앱 관리자
    def admin_count(self):
        return self.one("SELECT COUNT(*) n FROM admins WHERE active=1")["n"]

    def add_admin(self, username, password, actor="cli"):
        if not USERNAME_RE.match(username or ""):
            raise StaffError("아이디는 영문·숫자·._- 64자 이하")
        if len(password or "") < MIN_PASSWORD:
            raise StaffError(f"비밀번호는 {MIN_PASSWORD}자 이상")
        with self.tx() as c:
            if c.execute("SELECT 1 FROM admins WHERE username=?", (username,)).fetchone():
                raise StaffError("이미 있는 관리자입니다")
            c.execute("INSERT INTO admins (username, pw_hash, created_at) VALUES (?,?,?)", (username, hash_password(password), time.time()))
            self._log(c, actor, "admin.add", username)

    def set_admin_password(self, username, password, actor="cli"):
        if len(password or "") < MIN_PASSWORD:
            raise StaffError(f"비밀번호는 {MIN_PASSWORD}자 이상")
        with self.tx() as c:
            a = c.execute("SELECT id FROM admins WHERE username=?", (username,)).fetchone()
            if not a:
                raise KeyError(username)
            c.execute("UPDATE admins SET pw_hash=? WHERE id=?", (hash_password(password), a["id"]))
            c.execute("DELETE FROM sessions WHERE admin_id=?", (a["id"],))
            self._log(c, actor, "admin.password", username)

    def login(self, username, password, ttl):
        a = self.one("SELECT * FROM admins WHERE username=?", (username or "",))
        ok = verify_password(password or "", a["pw_hash"] if a else self._dummy)
        if not (a and ok and a["active"]):
            with self.tx() as c:
                self._log(c, username or "?", "auth.login_failed")
            return None
        token = secrets.token_urlsafe(32)
        with self.tx() as c:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (time.time(),))
            c.execute("INSERT INTO sessions VALUES (?,?,?,?)", (sha(token), a["id"], time.time() + ttl, time.time()))
            self._log(c, a["username"], "auth.login")
        return token

    def resolve(self, token):
        if not token:
            return None
        r = self.one("SELECT a.username, a.active, s.expires_at FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=?", (sha(token),))
        if not r or not r["active"] or r["expires_at"] < time.time():
            return None
        return r["username"]

    def logout(self, token):
        with self.lock:
            self.conn().execute("DELETE FROM sessions WHERE token_hash=?", (sha(token or ""),))
