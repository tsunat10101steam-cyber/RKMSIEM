"""P18: 첫 로그인 비밀번호 변경 강제 · 2단계 인증(TOTP) · 웹 터미널은 2단계 인증 계정만."""
import time

import pytest

from rkmsiem import totp
from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_ADMIN_PASSWORD", "admin")
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.bootstrap_admin()                                    # admin / admin
    auth.create_user("boss", PW, "admin", "t")
    c = app.test_client()
    yield p, c, auth
    p.terminal.stop()


def login(c, u, pw):
    return c.post("/api/auth/login", json={"username": u, "password": pw})


def H(t):
    return {"Authorization": f"Bearer {t}"}


def test_first_login_must_change_password(ctx):
    p, c, auth = ctx
    r = login(c, "admin", "admin").get_json()
    assert r["must_change_password"] is True
    t = r["token"]
    blocked = c.get("/api/alerts", headers=H(t))
    assert blocked.status_code == 403 and blocked.get_json()["error"] == "password_change_required"
    me = c.get("/api/me", headers=H(t)).get_json()
    assert me["must_change_password"] is True
    assert c.post("/api/me/password", headers=H(t), json={"current": "admin", "new": "short"}).status_code == 400
    assert c.post("/api/me/password", headers=H(t), json={"current": "admin", "new": "a-much-better-pass-42"}).status_code == 200
    t2 = login(c, "admin", "a-much-better-pass-42").get_json()
    assert t2["must_change_password"] is False
    assert c.get("/api/alerts", headers=H(t2["token"])).status_code == 200


def test_admin_reset_password_is_temporary(ctx):
    p, c, auth = ctx
    boss = login(c, "boss", PW).get_json()["token"]
    auth.create_user("ana", PW, "analyst", "t")
    assert c.post("/api/users/ana/password", headers=H(boss), json={"password": "temporary-pass-123"}).status_code == 200
    r = login(c, "ana", "temporary-pass-123").get_json()
    assert r["must_change_password"] is True
    # 같은 비밀번호로 '변경' 은 안 됨
    assert c.post("/api/me/password", headers=H(r["token"]), json={"current": "temporary-pass-123", "new": "temporary-pass-123"}).status_code == 400


def test_old_short_password_gets_flagged(ctx):
    p, c, auth = ctx
    auth.create_user("old", "abc", "viewer", "t", allow_short=True)            # 예전 설치에서 만든 짧은 비밀번호
    t = login(c, "old", "abc").get_json()
    assert t["must_change_password"] is True


def test_totp_enroll_login_replay_and_reset(ctx):
    p, c, auth = ctx
    boss = login(c, "boss", PW).get_json()["token"]
    assert c.get("/api/me/mfa", headers=H(boss)).get_json()["enabled"] is False
    setup = c.post("/api/me/mfa/setup", headers=H(boss)).get_json()
    assert setup["uri"].startswith("otpauth://totp/RKMSIEM:boss?secret=")
    sec = setup["secret"]
    assert "boss" not in (p.db.scalar("SELECT totp_secret FROM users WHERE username='boss'") or "") and sec not in p.db.scalar(
        "SELECT totp_secret FROM users WHERE username='boss'")                    # DB 에는 암호문만
    assert c.post("/api/me/mfa/enable", headers=H(boss), json={"code": "000000"}).status_code == 400
    now_step = int(time.time() // 30)
    assert c.post("/api/me/mfa/enable", headers=H(boss), json={"code": totp.code_at(sec, now_step)}).status_code == 200
    # 비밀번호만으로는 세션이 안 나옴
    r = login(c, "boss", PW).get_json()
    assert r.get("mfa_required") and "token" not in r
    assert c.post("/api/auth/mfa", json={"ticket": r["mfa_ticket"], "code": "123456"}).status_code == 401
    # 등록 때 쓴 코드(같은 30초 칸)는 재사용 불가 → 다음 칸 코드로
    assert c.post("/api/auth/mfa", json={"ticket": r["mfa_ticket"], "code": totp.code_at(sec, now_step)}).status_code == 401
    ok = c.post("/api/auth/mfa", json={"ticket": r["mfa_ticket"], "code": totp.code_at(sec, now_step + 1)})
    assert ok.status_code == 200 and ok.get_json()["token"]
    # 대기표는 한 번만
    assert c.post("/api/auth/mfa", json={"ticket": r["mfa_ticket"], "code": totp.code_at(sec, now_step + 1)}).status_code == 401
    # 5번 틀리면 대기표 폐기
    r2 = login(c, "boss", PW).get_json()
    for _ in range(5):
        c.post("/api/auth/mfa", json={"ticket": r2["mfa_ticket"], "code": "000000"})
    assert c.post("/api/auth/mfa", json={"ticket": r2["mfa_ticket"], "code": totp.code_at(sec, now_step + 1)}).get_json()["error"] == "mfa_expired"
    # 관리자 재설정 → 다시 비밀번호만으로 로그인
    auth.totp_reset("boss", "cli")
    assert login(c, "boss", PW).get_json().get("token")
    acts = {a["action"] for a in p.audit.list(100)}
    assert {"user.mfa_enable", "auth.mfa_failed", "user.mfa_reset"} <= acts


def test_terminal_requires_mfa(ctx):
    p, c, auth = ctx
    boss = login(c, "boss", PW).get_json()["token"]
    layout = {"nodes": [{"id": "s", "type": "siem", "x": 0, "y": 0}, {"id": "w", "type": "server", "ip": "10.0.0.20", "x": 1, "y": 1}],
              "links": [{"id": "l", "from": "s", "to": "w"}]}
    c.put("/api/config/topology", headers=H(boss), json=layout)
    r = c.post("/api/terminal", headers=H(boss), json={"ip": "10.0.0.20", "login": "ops"})
    assert r.status_code == 403 and "2단계" in r.get_json()["details"]
    sec = c.post("/api/me/mfa/setup", headers=H(boss)).get_json()["secret"]
    step = int(time.time() // 30)
    c.post("/api/me/mfa/enable", headers=H(boss), json={"code": totp.code_at(sec, step)})
    p.terminal.argv = lambda ip, login, port, legacy=False: ["/bin/sh", "-c", "sleep 5"]
    assert c.post("/api/terminal", headers=H(boss), json={"ip": "10.0.0.20", "login": "ops"}).status_code == 201


def test_totp_rfc6238_vector():
    # RFC 6238 부록 B (SHA1, 비밀 "12345678901234567890", T=59 → 94287082 의 끝 6자리)
    import base64
    sec = base64.b32encode(b"12345678901234567890").decode()
    assert totp.code_at(sec, 59 // 30) == "287082"
    assert totp.verify(sec, "287082", now=59) == 1 and totp.verify(sec, "287082", last_step=1, now=59) is None


def test_local_maintenance_key(tmp_path, config_dir, monkeypatch):
    key = "k" * 40
    monkeypatch.setenv("RKMSIEM_LOCAL_TOKEN", key)
    monkeypatch.setenv("RKMSIEM_ADMIN_PASSWORD", "admin")
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")}))
    app = create_app(p)
    app.extensions["rkmsiem_auth"].bootstrap_admin()            # 관리자는 아직 admin/admin (변경 대기)
    c = app.test_client()
    local = {"X-RKMSIEM-Local": key}
    assert c.get("/api/system/doctor", headers=local).status_code == 200            # 비밀번호 변경 대기와 무관
    assert c.get("/api/system/doctor", headers={"X-RKMSIEM-Local": "x" * 40}).status_code == 401
    assert c.get("/api/system/doctor", headers=local, environ_base={"REMOTE_ADDR": "10.0.0.9"}).status_code == 401   # 밖에서는 안 됨
    assert c.post("/api/me/mfa/setup", headers=local).status_code == 403
    checks = {x["check"]: x for x in c.get("/api/system/doctor", headers=local).get_json()["checks"]}
    assert checks["first_password"]["status"] == "warn" and "admin" in checks["first_password"]["detail"]
    assert checks["mfa"]["status"] == "warn" and checks["https"]["status"] == "ok"
    p.terminal.stop()


def test_doctor_flags_plain_http_exposure(tmp_path, config_dir):
    from rkmsiem.doctor import security_checks
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db"), "api.host": "0.0.0.0"})
    p = Platform(s)
    assert {x["check"]: x for x in security_checks(s, p)}["https"]["status"] == "fail"
    s2 = load_settings(config_dir, overrides={"database.path": str(tmp_path / "t2.db"), "api.host": "127.0.0.1", "api.trusted_proxies": 1})
    assert "nginx" in {x["check"]: x for x in security_checks(s2, Platform(s2))}["https"]["detail"]


def test_doctor_access_path_detects_nat(tmp_path, config_dir, monkeypatch):
    from rkmsiem import topology
    from rkmsiem.doctor import security_checks
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")})
    p = Platform(s)
    monkeypatch.setattr(topology, "local_view", lambda: ({}, {"10.0.0.2"}, {}))
    for _ in range(3):
        p.audit.record("boss", "auth.login", "user", "boss", None, {"client": "10.0.0.2"})
    assert {x["check"]: x for x in security_checks(s, p)}["access_path"]["status"] == "warn"
    p.audit.record("boss", "auth.login", "user", "boss", None, {"client": "192.168.0.7"})
    assert {x["check"]: x for x in security_checks(s, p)}["access_path"]["status"] == "ok"
