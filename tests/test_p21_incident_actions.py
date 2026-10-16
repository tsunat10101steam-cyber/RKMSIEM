"""P21: 사건 화면의 즉시 조치 — 사건에서 나온 IP·계정, 권한·사유·보호 목록, 타임라인·감사 기록, simulate/live."""
import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"


def build(tmp_path, config_dir, monkeypatch, mode):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / f"{mode}.db"), "soar.mode": mode, "soar.worker_poll_ms": 50}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    for u, r in (("adm", "admin"), ("ana", "analyst"), ("resp", "responder"), ("view", "viewer")):
        auth.create_user(u, PW, r, "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("adm", "ana", "resp", "view")}
    return p, c, (lambda u: {"Authorization": f"Bearer {tok[u]}"})


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    p, c, H = build(tmp_path, config_dir, monkeypatch, "simulate")
    yield p, c, H
    p.pipeline.stop()
    p.terminal.stop()


def attack(c, ip, user):
    evs = [{"id": f"{ip}-{i}", "timestamp": f"2026-10-12T02:10:{i:02d}Z", "src_ip": ip, "user": user, "outcome": "failure",
            "category": "authentication", "host": "web-01"} for i in range(11)]
    assert c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs).get_json()["stored"] == 11


def first_incident(c, H):
    items = c.get("/api/incidents", headers=H("adm")).get_json()["items"]
    assert items
    return items[0]["id"]


def test_targets_from_incident(ctx):
    p, c, H = ctx
    attack(c, "103.75.190.8", "backup")
    iid = first_incident(c, H)
    t = c.get(f"/api/incidents/{iid}/targets", headers=H("view")).get_json()
    assert [x["value"] for x in t["ips"]] == ["103.75.190.8"] and t["ips"][0]["events"] == 11 and not t["ips"][0]["blocked"]
    assert [x["value"] for x in t["accounts"]] == ["backup"]
    assert t["mode"] == "simulate" and t["actions"]["block_ip"] is False and t["playbooks"] == []        # 읽기 전용은 조치 없음
    t = c.get(f"/api/incidents/{iid}/targets", headers=H("adm")).get_json()
    assert all(t["actions"].values()) and any(pb["id"] == "manual_enrichment" for pb in t["playbooks"])


def test_actions_permissions_reason_and_timeline(ctx):
    p, c, H = ctx
    attack(c, "103.75.190.8", "backup")
    iid = first_incident(c, H)
    act = lambda u, **b: c.post(f"/api/incidents/{iid}/actions", headers=H(u), json=b)
    assert act("view", action="ip_reputation", target="103.75.190.8").status_code == 403
    assert act("ana", action="block_ip", target="103.75.190.8", reason="x").status_code == 403             # 분석가는 차단 권한 없음
    assert act("adm", action="block_ip", target="103.75.190.8").status_code == 400                         # 사유 필수
    assert act("adm", action="rm_rf", target="x", reason="x").status_code == 400

    r = act("ana", action="asset_lookup", target="backup")
    assert r.status_code == 200 and r.get_json()["output"]["account"] == "backup"

    r = act("adm", action="block_ip", target="103.75.190.8", reason="반복 대입", duration_sec=3600)
    assert r.status_code == 200 and r.get_json()["output"]["simulated"] is True                            # simulate: 기록만
    r = act("resp", action="disable_account", target="backup", reason="탈취 의심")
    assert r.status_code == 200 and r.get_json()["output"]["simulated"] is True

    tl = c.get(f"/api/incidents/{iid}", headers=H("adm")).get_json()["timeline"]
    acts = [t for t in tl if t["kind"] == "manual_action"]
    assert [a["detail"]["action"] for a in acts] == ["asset_lookup", "block_ip", "disable_account"]
    assert acts[1]["actor"] == "adm" and acts[1]["detail"]["reason"] == "반복 대입" and acts[1]["detail"]["mode"] == "simulate"
    audit = [a for a in p.audit.list(200) if a["action"] == "manual.block_ip"]
    assert audit and audit[0]["target_type"] == "incident" and audit[0]["target_id"] == str(iid)


def test_guards_refuse(ctx):
    p, c, H = ctx
    attack(c, "10.1.2.3", "root")                                                    # 사내망 · 보호 계정
    iid = first_incident(c, H)
    t = c.get(f"/api/incidents/{iid}/targets", headers=H("adm")).get_json()
    assert t["ips"][0]["guard"] and t["accounts"][0]["guard"] == "보호 계정"
    r = c.post(f"/api/incidents/{iid}/actions", headers=H("adm"), json={"action": "block_ip", "target": "10.1.2.3", "reason": "x"})
    assert r.status_code == 409 and "차단할 수 없습니다" in r.get_json()["details"]
    r = c.post(f"/api/incidents/{iid}/actions", headers=H("adm"), json={"action": "disable_account", "target": "root", "reason": "x"})
    assert r.status_code == 409 and "보호 계정" in r.get_json()["details"]
    fails = [t for t in c.get(f"/api/incidents/{iid}", headers=H("adm")).get_json()["timeline"] if t["kind"] == "manual_action"]
    assert len(fails) == 2 and all(f["detail"]["ok"] is False for f in fails)                 # 거부도 남김


def test_live_block_and_unblock_shows_state(tmp_path, config_dir, monkeypatch):
    p, c, H = build(tmp_path, config_dir, monkeypatch, "live")
    try:
        attack(c, "103.75.190.8", "backup")
        iid = first_incident(c, H)
        r = c.post(f"/api/incidents/{iid}/actions", headers=H("adm"), json={"action": "block_ip", "target": "103.75.190.8", "reason": "차단", "duration_sec": 3600})
        assert r.status_code == 200 and r.get_json()["output"]["blocked"] is True
        ip = c.get(f"/api/incidents/{iid}/targets", headers=H("adm")).get_json()["ips"][0]
        assert ip["blocked"] and ip["expires_at"]
        assert p.db.one("SELECT reason FROM blocklist WHERE ip='103.75.190.8'")["reason"].startswith(f"사건 #{iid}")
        r = c.post(f"/api/incidents/{iid}/actions", headers=H("adm"), json={"action": "unblock_ip", "target": "103.75.190.8", "reason": "오탐"})
        assert r.status_code == 200 and not c.get(f"/api/incidents/{iid}/targets", headers=H("adm")).get_json()["ips"][0]["blocked"]
    finally:
        p.pipeline.stop()
        p.terminal.stop()
