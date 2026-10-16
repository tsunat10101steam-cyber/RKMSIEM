"""P23: 확장 지점 — 추가 기능용 쓰기 권한 토큰 · 이벤트 피드 · addon-token CLI · deploy/addon.sh."""
import os
import subprocess
import threading
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    monkeypatch.setenv("RKMSIEM_LOCAL_TOKEN", "L" * 40)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "x.db"), "soar.mode": "live"}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("adm", PW, "admin", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    adm = c.post("/api/auth/login", json={"username": "adm", "password": PW}).get_json()["token"]
    yield p, c, auth, {"Authorization": f"Bearer {adm}"}
    p.pipeline.stop()
    p.terminal.stop()


def attack(c):
    evs = [{"id": f"x-{i}", "timestamp": f"2026-10-12T02:10:{i:02d}Z", "src_ip": "103.75.190.8", "user": "backup", "outcome": "failure",
            "category": "authentication"} for i in range(11)]
    assert c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs).get_json()["stored"] == 11


def T(t):
    return {"Authorization": f"Bearer {t}"}


def test_feed_follows_events_in_order(ctx):
    p, c, auth, A = ctx
    tok = auth.create_api_token("hsoar-test", ["feed:read", "incidents:read"], "adm")["token"]
    assert c.get("/api/feed", headers=A).status_code == 403                                 # 사람 관리자도 feed:read 없음 (추가 기능용)
    start = c.get("/api/feed", headers=T(tok)).get_json()
    assert start["items"] == [] and isinstance(start["last_seq"], int)
    attack(c)
    r = c.get(f"/api/feed?after={start['last_seq']}", headers=T(tok)).get_json()
    types = [x["type"] for x in r["items"]]
    assert "alert" in types and "incident" in types and r["last_seq"] == r["items"][-1]["seq"]
    assert [x["seq"] for x in r["items"]] == sorted(x["seq"] for x in r["items"])
    only = c.get(f"/api/feed?after={start['last_seq']}&types=incident", headers=T(tok)).get_json()["items"]
    assert only and {x["type"] for x in only} == {"incident"}
    # 롱 폴링: 기다리는 동안 생긴 이벤트를 바로 받음
    last = r["last_seq"]
    threading.Timer(0.5, lambda: p.bus.publish("config", {"kind": "blocklist", "name": "1.2.3.4"})).start()
    t0 = time.time()
    r2 = c.get(f"/api/feed?after={last}&wait=10", headers=T(tok)).get_json()
    assert r2["items"][0]["type"] == "blocklist" and time.time() - t0 < 5
    p.db.execute("UPDATE event_feed SET ts=ts-8*86400")
    assert p.feed.prune() > 0 and not c.get("/api/feed?after=0", headers=T(tok)).get_json()["items"]


def test_addon_token_can_act_and_is_audited(ctx):
    p, c, auth, A = ctx
    attack(c)
    iid = c.get("/api/incidents", headers=A).get_json()["items"][0]["id"]
    ro = auth.create_api_token("ro", ["incidents:read"], "adm")["token"]
    rw = auth.create_api_token("addon-hsoar", ["incidents:read", "incidents:write", "runs:approve", "runs:cancel", "playbooks:run"], "adm")["token"]
    body = {"action": "block_ip", "target": "103.75.190.8", "reason": "자동 등급: 평판 90 이상", "duration_sec": 3600}
    assert c.post(f"/api/incidents/{iid}/actions", headers=T(ro), json=body).status_code == 403
    r = c.post(f"/api/incidents/{iid}/actions", headers=T(rw), json=body)
    assert r.status_code == 200 and r.get_json()["output"]["blocked"]
    assert p.db.one("SELECT added_by FROM blocklist WHERE ip='103.75.190.8'")["added_by"] == "token:addon-hsoar"
    tl = [t for t in c.get(f"/api/incidents/{iid}", headers=A).get_json()["timeline"] if t["kind"] == "manual_action"]
    assert tl[-1]["actor"] == "token:addon-hsoar"
    loc = {"X-RKMSIEM-Local": "L" * 40}                                                     # 점검 키는 조치 불가
    assert c.post(f"/api/incidents/{iid}/actions", headers=loc, json=body).status_code == 403
    assert c.post("/api/tokens", headers=T(rw), json={"name": "x", "scopes": ["metrics:read"]}).status_code == 403   # 토큰으로 토큰 못 만듦
    assert c.put("/api/config/lists", headers=T(rw), json={}).status_code == 403                                     # 설정 변경 불가
    rid = c.post("/api/playbooks/runbook_cryptojacking/run", headers=T(rw), json={"incident_id": iid}).get_json()["run_id"]
    p.soar.run_pending()
    r = c.post(f"/api/runs/{rid}/steps/identify/task", headers=T(rw), json={"outcome": "skipped", "note": "HSOAR: 자동 확인"})
    assert r.status_code == 200


def test_addon_token_cli_rotates(ctx, tmp_path, config_dir):
    p, *_ = ctx
    env = dict(os.environ, RKMSIEM_CONFIG_DIR=str(config_dir), RKMSIEM_DATABASE__PATH=str(tmp_path / "x.db"), PYTHONPATH=ROOT)
    run = lambda *a: subprocess.run(["python3", "-m", "rkmsiem", "addon-token", *a], env=env, capture_output=True, text=True, timeout=60, cwd=ROOT)
    r1 = run("create", "hsoar", "feed:read", "incidents:read")
    assert r1.returncode == 0, r1.stderr
    t1 = r1.stdout.strip().splitlines()[-1]
    assert t1.startswith("rkm_")
    t2 = run("create", "hsoar", "feed:read").stdout.strip().splitlines()[-1]
    from rkmsiem.auth import AuthService
    auth = AuthService(p.db, p.config, p.audit, p.settings, vault=p.vault)
    assert auth.resolve(t1) is None and auth.resolve(t2)["username"] == "token:addon-hsoar"            # 다시 만들면 예전 것은 폐기
    assert run("create", "Bad!", "feed:read").returncode == 2
    assert run("create", "x", "config:write").returncode == 2                                            # 없는 권한
    assert run("revoke", "hsoar").returncode == 0 and auth.resolve(t2) is None


def test_addon_sh_lists_hsoar():
    out = subprocess.run(["bash", os.path.join(ROOT, "deploy", "addon.sh"), "list"], capture_output=True, text=True).stdout
    row = [l.split("\t") for l in out.splitlines() if l.startswith("hsoar\t")][0]
    assert row[2] == "HSOAR" and row[1] in ("설치 안 됨", "설치됨")
    d = os.path.join(ROOT, "deploy", "addons", "hsoar")
    for f in ("install.sh", "uninstall.sh", "configure.sh", "status.sh"):
        assert os.access(os.path.join(d, f), os.X_OK), f
    conf = open(os.path.join(d, "addon.conf"), encoding="utf-8").read()
    assert "AVAILABLE=1" in conf and "config:write" not in conf and "users:write" not in conf          # 전용 토큰은 정해진 권한만
    tui = open(os.path.join(ROOT, "deploy", "setup-tui.sh"), encoding="utf-8").read()
    assert "do_addons" in tui and '6 "추가 기능 (HSOAR 등)"' in tui and 'addon.sh" configure' in tui
