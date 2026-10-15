"""P11: 웹 설정 — settings.yaml 값 가져오기 · 검증 · 바로 반영 · 비밀 값 암호화 저장(다시 읽기 불가) · 저장 전 메일 시험 · 권한."""
import pytest

from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings
from rkmsiem.vault import Vault, VaultError

PW = "correct-horse-battery-9"


class FakeSMTP:
    def __init__(self):
        self.box, self.logins = [], []

    def __call__(self, host, port, security, timeout):
        self.host = host
        return self

    def login(self, u, p):
        self.logins.append((u, p))

    def send_message(self, m):
        self.box.append(m)

    def quit(self):
        pass


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.delenv("RKMSIEM_SECRET_KEY", raising=False)
    monkeypatch.delenv("RKMSIEM_SMTP_PASSWORD", raising=False)
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "w.db"),
                                             "mail": {"host": "smtp.old.test", "from": "soc@corp.test", "alerts": {"to": ["soc@corp.test"]}}})
    p = Platform(s)
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("adm", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("adm", "ana")}
    yield p, c, (lambda u: {"Authorization": f"Bearer {tok[u]}"}), tmp_path
    p.stop()


def test_seeded_from_settings_and_live_update(ctx):
    p, c, H, _ = ctx
    m = c.get("/api/config/mail", headers=H("adm")).get_json()
    assert m["content"]["host"] == "smtp.old.test" and m["content"]["enabled"] is False and m["content"]["port"] == 587   # 파일 값 + 기본값
    new = dict(m["content"], enabled=True, host="smtp.gmail.com", username="soc@corp.test", allowed_recipients=["@corp.test"])
    assert c.put("/api/config/mail", headers=H("ana"), json=new).status_code == 403
    assert c.put("/api/config/mail?comment=웹", headers=H("adm"), json=new).status_code == 200
    assert p.mailer.configured and p.mailer.cfg["host"] == "smtp.gmail.com"                     # 재시작 없이 반영
    bad = dict(new, allowed_recipients=["*"], port=99999)
    r = c.put("/api/config/mail", headers=H("adm"), json=bad)
    assert r.status_code == 400 and p.mailer.cfg["port"] == 587                                   # 거부 · 기존 유지
    assert c.put("/api/config/mail", headers=H("adm"), json=dict(new, allowed_recipients=["*"])).status_code == 400
    r = c.put("/api/config/reports", headers=H("adm"), json={"schedule": [{"name": "daily", "every": "day", "at": "25:00"}]})
    assert r.status_code == 400
    r = c.put("/api/config/reputation", headers=H("adm"), json={"abuseipdb": {"malicious_score": 30, "suspicious_score": 40}})
    assert r.status_code == 400
    assert c.put("/api/config/reputation", headers=H("adm"), json={"abuseipdb": {"malicious_score": 90, "suspicious_score": 40}}).status_code == 200
    assert p.response.abuseipdb.mal == 90                                                         # 평판 기준도 바로 반영
    lists = c.get("/api/config/lists", headers=H("adm")).get_json()["content"]
    lists["never_block"]["values"].append("not-an-ip")
    assert c.put("/api/config/lists", headers=H("adm"), json=lists).status_code == 400


def test_secrets_encrypted_write_only_and_used(ctx):
    p, c, H, tmp = ctx
    assert c.put("/api/secrets/smtp_password", headers=H("ana"), json={"value": "x" * 16}).status_code == 403
    st = c.put("/api/secrets/smtp_password", headers=H("adm"), json={"value": "app-pass-1234 5678"}).get_json()
    item = next(i for i in st["items"] if i["name"] == "smtp_password")
    assert item["set"] and item["source"] == "web" and item["hint"] == "" and st["key_source"] == "file"
    raw = p.db.one("SELECT ciphertext FROM secrets WHERE name='smtp_password'")["ciphertext"]
    assert "app-pass" not in raw and p.vault.get("smtp_password") == "app-pass-1234 5678"          # 암호화 저장 · 복호화
    assert "app-pass" not in str(c.get("/api/secrets", headers=H("adm")).get_json())                # API 로 다시 읽을 수 없음
    assert all("app-pass" not in str(a["detail"]) for a in p.audit.list(50))                       # 감사 로그에도 값 없음
    assert (tmp / "secret.key").exists()
    # 다른 키로는 복호화 불가 → 환경 변수로 대체
    other = Vault(p.db, environ={"RKMSIEM_SECRET_KEY": "A" * 43 + "=", "RKMSIEM_SMTP_PASSWORD": "from-env"})
    assert other.get("smtp_password") == "from-env"
    with pytest.raises(VaultError):
        p.vault.set("root_password", "x", "adm")
    c.put("/api/secrets/abuseipdb_key", headers=H("adm"), json={"value": "k" * 40})
    assert p.response.abuseipdb.enabled and p.response.abuseipdb.key == "k" * 40                   # 키 넣으면 바로 사용
    c.delete("/api/secrets/abuseipdb_key", headers=H("adm"))
    assert not p.response.abuseipdb.enabled


def test_mail_test_with_unsaved_settings(ctx):
    p, c, H, _ = ctx
    smtp = FakeSMTP()
    p.mailer.smtp_factory = smtp
    draft = dict(p.mailer.cfg, host="smtp.draft.test", username="soc@corp.test", allowed_recipients=["boss@corp.test"], retries=0)
    r = c.post("/api/mail/test", headers=H("adm"), json={"to": "boss@corp.test", "mail": draft, "password": "draft-pw"}).get_json()
    assert r["status"] == "sent" and smtp.host == "smtp.draft.test" and smtp.logins == [("soc@corp.test", "draft-pw")]
    assert p.mailer.configured is False and p.mailer.cfg["host"] == "smtp.old.test"                 # 저장은 안 됨
    r = c.post("/api/mail/test", headers=H("adm"), json={"to": "boss@corp.test", "mail": dict(draft, port="x")})
    assert r.status_code == 400
