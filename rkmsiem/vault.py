"""비밀 값 보관소: 웹에서 입력한 SMTP 비밀번호 · API 키를 암호화(Fernet: AES-128-CBC + HMAC-SHA256)해 DB 에 저장.

- 암호화 키: 환경 변수 RKMSIEM_SECRET_KEY (운영: /etc/rkmsiem/rkmsiem.env, install.sh 가 생성)
  없으면 DB 옆 secret.key 파일(0600)을 만들어 씀 — 개발용. 키가 DB 와 다른 곳에 있어야 DB 만 유출돼도 값이 안전
- 값은 API 로 다시 읽을 수 없음 (설정됨 여부와 끝 2자리만 표시). 설정·삭제는 감사 로그에 남김(값 제외)
- 웹에 값이 없으면 기존 환경 변수(RKMSIEM_SMTP_PASSWORD 등)를 그대로 사용
"""
import base64
import logging
import os
import time

log = logging.getLogger("rkmsiem.vault")
KEY_ENV = "RKMSIEM_SECRET_KEY"
NAMES = {"smtp_password": ("RKMSIEM_SMTP_PASSWORD", "SMTP 비밀번호"), "abuseipdb_key": ("RKMSIEM_ABUSEIPDB_KEY", "AbuseIPDB API 키")}


class VaultError(Exception):
    pass


class Vault:
    def __init__(self, db, audit=None, environ=None):
        self.db, self.audit = db, audit
        self.env = os.environ if environ is None else environ
        self.key_source, self._f = None, None
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            self.error = "cryptography 패키지 없음 — pip install cryptography"
            return
        key = (self.env.get(KEY_ENV) or "").strip()
        if key:
            self.key_source = "env"
        else:
            key, self.key_source = self._file_key(), "file"
        try:
            self._f = Fernet(key.encode() if isinstance(key, str) else key)
            self.error = None
        except (ValueError, TypeError):
            self.error = f"{KEY_ENV} 형식 오류 (base64 32바이트)"

    def _file_key(self):
        if self.db.path == ":memory:":
            return base64.urlsafe_b64encode(os.urandom(32)).decode()
        path = os.path.join(os.path.dirname(os.path.abspath(self.db.path)), "secret.key")
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(base64.urlsafe_b64encode(os.urandom(32)).decode())
            log.warning("%s 가 없어 %s 에 암호화 키를 만들었습니다 (운영에서는 환경 변수 권장)", KEY_ENV, path)
        with open(path) as fh:
            return fh.read().strip()

    @property
    def ready(self):
        return self._f is not None

    def get(self, name):
        """웹에서 넣은 값 → 없으면 환경 변수."""
        r = self.db.one("SELECT ciphertext FROM secrets WHERE name=?", (name,))
        if r and self._f:
            try:
                return self._f.decrypt(r["ciphertext"].encode()).decode()
            except Exception:     # noqa: BLE001 — 키가 바뀐 경우 등
                log.error("secret %s 복호화 실패 — 암호화 키가 바뀌었으면 웹에서 다시 입력하세요", name)
        env_name = NAMES.get(name, (None,))[0]
        return self.env.get(env_name) if env_name else None

    def set(self, name, value, actor):
        if name not in NAMES:
            raise VaultError(f"알 수 없는 항목: {name}")
        if not self._f:
            raise VaultError(self.error or "암호화를 쓸 수 없습니다")
        value = (value or "").strip()
        if not value or len(value) > 4096:
            raise VaultError("값이 비었거나 너무 깁니다")
        self.db.execute("INSERT INTO secrets (name, ciphertext, hint, updated_at, updated_by) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(name) DO UPDATE SET ciphertext=excluded.ciphertext, hint=excluded.hint, "
                        "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                        (name, self._f.encrypt(value.encode()).decode(), "…" + value[-4:] if name == "abuseipdb_key" and len(value) >= 16 else "", time.time(), actor))
        if self.audit:
            self.audit.record(actor, "secret.set", "secret", name, None, {"length": len(value)})

    def clear(self, name, actor):
        if name not in NAMES:
            raise VaultError(f"알 수 없는 항목: {name}")
        n = self.db.execute("DELETE FROM secrets WHERE name=?", (name,)).rowcount
        if self.audit and n:
            self.audit.record(actor, "secret.clear", "secret", name, None, {})
        return bool(n)

    def status(self):
        rows = {r["name"]: r for r in self.db.all("SELECT name, hint, updated_at, updated_by FROM secrets")}
        out = []
        for name, (env_name, label) in NAMES.items():
            r = rows.get(name)
            src = "web" if r else ("env" if self.env.get(env_name) else None)
            out.append({"name": name, "label": label, "set": bool(src), "source": src, "env_name": env_name,
                        "hint": r["hint"] if r else None, "updated_at": r["updated_at"] if r else None, "updated_by": r["updated_by"] if r else None})
        return {"items": out, "ready": self.ready, "key_source": self.key_source, "error": self.error}
