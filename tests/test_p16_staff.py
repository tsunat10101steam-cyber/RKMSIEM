"""P16: 별도 담당자 관리 앱(staffdir) · RKMSIEM 명단 연동(가져오기·알림·장애 시 마지막 명단) · 배정·배정 메일 · 로그인 계정 분리."""
import os
import sqlite3

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings
from rkmsiem.staffsync import StaffSyncError
from staffdir import __main__ as staff_cli
from staffdir.app import create_app as create_staff_app
from staffdir.store import Store

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"
SYNC = "test-staff-sync-key-0987654321"


class FakeSMTP:
    def __init__(self):
        self.box = []

    def __call__(self, *a):
        return self

    def send_message(self, m):
        self.box.append(m)

    def quit(self):
        pass


@pytest.fixture
def staff(tmp_path):
    cfg = {"db": str(tmp_path / "staff.db"), "host": "127.0.0.1", "port": 0, "sync_keys": [SYNC], "notify_url": "",
           "console_url": "", "token_ttl": 3600, "login_per_min": 50}
    app = create_staff_app(cfg)
    st = app.extensions["staff_store"]
    st.add_admin("hr", PW)
    c = app.test_client()
    tok = c.post("/api/login", json={"username": "hr", "password": PW}).get_json()["token"]
    return st, c, {"Authorization": f"Bearer {tok}"}


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch, staff):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    monkeypatch.setenv("RKMSIEM_STAFF_SYNC_KEY", SYNC)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db"), "soar.worker_poll_ms": 50,
                                                      "staff": {"url": "http://staff.test"},
                                                      "mail": {"enabled": True, "host": "smtp.test", "from": "soc@corp.test", "retry_backoff_sec": 0}}))
    st, sc, sh = staff
    down = {"v": False}

    def fetch():                                        # 실제 HTTP 대신 담당자 앱 테스트 클라이언트로
        if down["v"]:
            raise StaffSyncError("담당자 앱에 연결할 수 없습니다")
        r = sc.get("/api/sync/people", headers={"X-Sync-Key": SYNC})
        assert r.status_code == 200
        return r.get_json()
    p.staff.fetch = fetch
    smtp = FakeSMTP()
    p.mailer.smtp_factory = smtp
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("boss", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    login = lambda u, pw=PW: c.post("/api/auth/login", json={"username": u, "password": pw}).get_json().get("token")   # noqa: E731
    yield p, c, login, smtp, (st, sc, sh), down
    p.pipeline.stop()


def H(t):
    return {"Authorization": f"Bearer {t}"}


def _incident(p, c, tok):
    evs = [{"id": f"a{i}", "timestamp": f"2026-10-12T06:00:{i:02d}Z", "src_ip": "45.33.32.9", "user": "root", "outcome": "failure",
            "category": "authentication"} for i in range(11)]
    c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs)
    return c.get("/api/incidents", headers=H(tok)).get_json()["items"][0]["id"]


# ---------------------------------------------------------------- 담당자 앱 단독
def test_staff_app_people_and_sync_api(staff):
    st, c, h = staff
    assert c.get("/api/people").status_code == 401
    assert c.post("/api/login", json={"username": "hr", "password": "wrong-password-x"}).status_code == 401
    r = c.post("/api/people", headers=h, json={"username": "kim", "display_name": "김관제", "team": "관제 1팀",
                                               "email": "kim@corp.test", "phone": "010-1234-5678"})
    assert r.status_code == 201 and r.get_json()["notify_assign"] == 1
    assert c.post("/api/people", headers=h, json={"username": "kim"}).status_code == 400                # 같은 아이디
    assert c.post("/api/people", headers=h, json={"username": "lee", "email": "nope"}).status_code == 400
    assert c.post("/api/people", headers=h, json={"username": "bad name"}).status_code == 400
    assert c.patch("/api/people/kim", headers=h, json={"phone": "010-9999-0000"}).status_code == 200
    assert c.patch("/api/people/ghost", headers=h, json={"team": "x"}).status_code == 404
    ch = c.get("/api/changes", headers=h).get_json()["items"]
    assert any(x["action"] == "person.update" for x in ch) and all("010-" not in str(x["detail"]) and "@corp" not in str(x["detail"]) for x in ch)
    # 연동 API: 키 없으면 거부, 내용이 그대로면 버전도 그대로
    assert c.get("/api/sync/people").status_code == 401
    assert c.get("/api/sync/people", headers={"X-Sync-Key": "wrong"}).status_code == 401
    a = c.get("/api/sync/people", headers={"X-Sync-Key": SYNC}).get_json()
    b = c.get("/api/sync/people", headers={"X-Sync-Key": SYNC}).get_json()
    assert a["version"] == b["version"] and a["items"][0]["email"] == "kim@corp.test"
    assert c.get("/api/me", headers=h).get_json()["sync_clients"][0]["count"] == 1                       # 마지막으로 가져간 기록
    c.post("/api/people/kim/active", headers=h, json={"active": False})
    assert c.get("/api/sync/people", headers={"X-Sync-Key": SYNC}).get_json()["version"] != a["version"]
    assert c.delete("/api/people/kim", headers=h).status_code == 200 and not st.people()
    assert c.post("/api/logout", headers=h).status_code == 200 and c.get("/api/people", headers=h).status_code == 401


def test_staff_import_from_rkmsiem_db(tmp_path, staff):
    st, _, _ = staff
    path = str(tmp_path / "old.db")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, active INTEGER, display_name TEXT, team TEXT, email TEXT, "
                "phone TEXT, notify_assign INTEGER)")
    con.executemany("INSERT INTO users (username, active, display_name, team, email, phone, notify_assign) VALUES (?,?,?,?,?,?,?)",
                    [("adm", 1, "관리자", None, None, None, 1), ("kim", 1, "김관제", "1팀", "kim@corp.test", None, 0), ("old", 0, None, None, None, None, 1)])
    con.commit()
    con.close()
    rows = staff_cli.read_rkmsiem_users(path)
    assert st.import_rows(rows, "import") == ["adm", "kim", "old"]
    kim = st.get("kim")
    assert kim["email"] == "kim@corp.test" and kim["notify_assign"] == 0 and st.get("old")["active"] == 0
    assert st.import_rows(rows, "import") == []                                                         # 두 번째는 건너뜀


# ---------------------------------------------------------------- RKMSIEM 연동
def test_roster_sync_assignment_and_mail(ctx):
    p, c, login, smtp, (st, sc, sh), _ = ctx
    boss, ana = login("boss"), login("ana")
    sc.post("/api/people", headers=sh, json={"username": "kim", "display_name": "김관제", "team": "관제 1팀", "email": "kim@corp.test"})
    sc.post("/api/people", headers=sh, json={"username": "ana", "display_name": "안분석"})
    assert c.post("/api/staff/sync", headers=H(ana)).status_code == 403
    r = c.post("/api/staff/sync", headers=H(boss)).get_json()
    assert r["added"] == ["ana", "kim"] and r["status"]["last_ok"] and r["status"]["directory"] == 2
    items = {x["username"]: x for x in c.get("/api/assignees", headers=H(ana)).get_json()["items"]}
    assert set(items) == {"ana", "kim"}                                                                 # boss 는 계정만 있고 명단에 없음
    assert items["kim"]["display_name"] == "김관제" and not items["kim"]["has_account"] and items["kim"]["has_email"]
    assert items["ana"]["has_account"] and items["ana"]["role"] == "analyst" and all("email" not in x for x in items.values())
    users = {u["username"]: u for u in c.get("/api/users", headers=H(boss)).get_json()["items"]}
    assert users["ana"]["in_roster"] and not users["boss"]["in_roster"] and "email" not in users["ana"]
    # 배정: 명단에 있으면 로그인 계정이 없어도 가능, 계정만 있고 명단에 없으면 거부
    iid = _incident(p, c, boss)
    assert c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": "boss"}).status_code == 400
    assert c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": "kim"}).status_code == 200
    assert next(x for x in c.get("/api/assignees", headers=H(boss)).get_json()["items"] if x["username"] == "kim")["open_incidents"] == 1
    p.mailer._deliver(p.mailer.q.get(timeout=2))                                                        # 명단의 메일로 배정 알림
    assert smtp.box and smtp.box[-1]["To"] == "kim@corp.test" and f"#{iid}" in smtp.box[-1]["Subject"]
    # 담당자 앱에서 알림을 끄면 다음 동기화부터 안 보냄
    sc.patch("/api/people/kim", headers=sh, json={"notify_assign": False})
    assert p.staff.sync()["updated"] == ["kim"]
    c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": None})
    c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": "kim"})
    assert p.mailer.q.empty()
    # 변경이 없으면 다시 쓰지 않음 · 감사 로그엔 아이디만
    assert p.staff.sync()["changed"] is False
    syncs = [x for x in p.audit.list(50) if x["action"] == "staff.sync"]
    assert syncs and all("kim@corp" not in str(x["detail"]) for x in syncs)
    # 비활성화 → 배정 목록에서 빠지고 새 배정 불가, 지난 담당 기록은 그대로
    sc.post("/api/people/kim/active", headers=sh, json={"active": False})
    p.staff.sync()
    assert all(x["username"] != "kim" for x in c.get("/api/assignees", headers=H(boss)).get_json()["items"])
    assert c.get(f"/api/incidents/{iid}", headers=H(boss)).get_json()["assignee"] == "kim"
    c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": None})
    assert c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": "kim"}).status_code == 400
    # 삭제 → 명단에서도 빠짐
    sc.delete("/api/people/kim", headers=sh)
    assert p.staff.sync()["removed"] == ["kim"]


def test_staff_outage_keeps_last_roster_and_hook(ctx):
    p, c, login, _, (st, sc, sh), down = ctx
    boss = login("boss")
    sc.post("/api/people", headers=sh, json={"username": "kim"})
    p.staff.sync()
    down["v"] = True
    assert c.post("/api/staff/sync", headers=H(boss)).status_code == 502
    s = c.get("/api/staff/status", headers=H(boss)).get_json()
    assert s["last_error"] and s["directory"] == 1 and s["configured"]
    iid = _incident(p, c, boss)
    assert c.post(f"/api/incidents/{iid}/assign", headers=H(boss), json={"assignee": "kim"}).status_code == 200   # 마지막 명단으로 계속
    doc = {x["check"]: x for x in c.get("/api/system/doctor", headers=H(boss)).get_json()["checks"]}
    assert doc["staff_sync"]["status"] == "fail"
    # 변경 알림: 키가 맞을 때만 받아서 바로 다시 가져가게 함
    assert c.post("/api/staff/hook").status_code == 401
    assert c.post("/api/staff/hook", headers={"X-Sync-Key": "wrong"}).status_code == 401
    assert not p.staff._kick.is_set()
    assert c.post("/api/staff/hook", headers={"X-Sync-Key": SYNC}).status_code == 202 and p.staff._kick.is_set()


def test_unconfigured_staff_uses_existing_directory(tmp_path, config_dir, monkeypatch):
    monkeypatch.delenv("RKMSIEM_STAFF_SYNC_KEY", raising=False)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "u.db")}))
    assert not p.staff.configured
    with pytest.raises(StaffSyncError):
        p.staff.sync()
    p.staff.loop()                                                                                       # 설정이 없으면 바로 끝남
    # 0008 은 예전 사용자 정보(0007)로 명단을 채운다
    p.db.execute("INSERT INTO users (username, pw_hash, role, active, created_at, display_name, email) VALUES ('old','x','analyst',1,0,'예전','o@corp.test')")
    p.db.execute("DELETE FROM staff_directory")
    sql = open(os.path.join(os.path.dirname(__file__), "..", "rkmsiem", "migrations", "0008_staff_directory.sql"), encoding="utf-8").read()
    p.db.conn().executescript(sql)
    assert p.staff.person("old")["email"] == "o@corp.test"


def test_login_accounts_without_profile(ctx):
    p, c, login, _, _, _ = ctx
    boss, ana = login("boss"), login("ana")
    assert c.post("/api/users", headers=H(ana), json={"username": "x", "password": PW, "role": "viewer"}).status_code == 403
    assert c.post("/api/users", headers=H(boss), json={"username": "kim", "password": PW, "role": "responder"}).status_code == 201
    assert c.post("/api/users", headers=H(boss), json={"username": "kim", "password": PW, "role": "viewer"}).status_code == 409
    assert c.post("/api/users", headers=H(boss), json={"username": "lee", "password": PW, "role": "viewer", "email": "a@b.co"}).status_code == 400
    kim = login("kim")
    assert c.patch("/api/users/kim", headers=H(boss), json={"role": "analyst"}).status_code == 200
    assert c.get("/api/me", headers=H(kim)).status_code == 401                                          # 역할 변경 → 다시 로그인
    assert c.patch("/api/users/kim", headers=H(boss), json={"team": "x"}).status_code == 400
    assert c.patch("/api/users/boss", headers=H(boss), json={"role": "viewer"}).status_code == 400       # 마지막 관리자
    assert c.post("/api/users/boss/active", headers=H(boss), json={"active": False}).status_code == 400
    assert c.post("/api/users/kim/password", headers=H(boss), json={"password": "temporary-pass-1234"}).status_code == 200
    assert login("kim", "temporary-pass-1234") and not login("kim")


def test_staff_store_admin_rules(tmp_path):
    st = Store(str(tmp_path / "s.db"))
    with pytest.raises(ValueError):
        st.add_admin("a", "short")
    st.add_admin("a", PW)
    t = st.login("a", PW, 60)
    assert st.resolve(t) == "a"
    st.set_admin_password("a", PW + "x")
    assert st.resolve(t) is None and st.login("a", PW, 60) is None
