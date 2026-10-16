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


# ---------------------------------------------------------------- ③ 차단 관리
def test_blocklist_manage_extend_bulk_history_expiry(tmp_path, config_dir, monkeypatch):
    import time
    p, c, H = build(tmp_path, config_dir, monkeypatch, "live")
    try:
        attack(c, "103.75.190.8", "backup")
        iid = first_incident(c, H)
        c.post(f"/api/incidents/{iid}/actions", headers=H("adm"), json={"action": "block_ip", "target": "103.75.190.8", "reason": "사건", "duration_sec": 3600})
        for ip in ("198.51.100.1", "198.51.100.2"):
            assert c.post("/api/blocklist", headers=H("adm"), json={"ip": ip, "reason": "수동 테스트"}).status_code == 201       # 무기한
        bl = c.get("/api/blocklist", headers=H("view")).get_json()
        assert bl["stats"]["total"] == 3 and bl["stats"]["soon"] == 1 and bl["stats"]["forever"] == 2 and bl["stats"]["incident"] == 1
        row = next(x for x in bl["items"] if x["ip"] == "103.75.190.8")
        assert row["source"] == "incident" and row["incident_id"] == iid and row["added_by"] == "adm" and 0 < row["remaining_sec"] <= 3600
        assert [x["ip"] for x in c.get("/api/blocklist?view=forever", headers=H("adm")).get_json()["items"]] == ["198.51.100.2", "198.51.100.1"]
        assert [x["ip"] for x in c.get("/api/blocklist?q=사건", headers=H("adm")).get_json()["items"]] == ["103.75.190.8"]

        ext = lambda u, ip, **b: c.post(f"/api/blocklist/{ip}/extend", headers=H(u), json=b)
        assert ext("ana", "103.75.190.8", reason="x", duration_sec=86400).status_code == 403
        assert ext("adm", "103.75.190.8", duration_sec=86400).status_code == 400                     # 사유 필수
        assert ext("adm", "203.0.113.9", reason="x", duration_sec=86400).status_code == 409           # 목록에 없음
        r = ext("adm", "103.75.190.8", reason="재범", duration_sec=86400)
        assert r.status_code == 200 and r.get_json()["expires_at"] > time.time() + 80000
        assert ext("adm", "198.51.100.1", reason="한시적으로", duration_sec=3600).status_code == 200    # 무기한 → 1시간

        r = c.post("/api/blocklist/unblock", headers=H("adm"), json={"ips": ["198.51.100.2", "198.51.100.1"], "reason": "오탐 일괄"})
        assert r.get_json()["ok"] == 2
        assert c.post("/api/blocklist/unblock", headers=H("ana"), json={"ips": ["103.75.190.8"], "reason": "x"}).status_code == 403
        assert c.post("/api/blocklist/unblock", headers=H("adm"), json={"ips": ["103.75.190.8"]}).status_code == 400

        p.db.execute("UPDATE blocklist SET expires_at=? WHERE ip='103.75.190.8'", (time.time() - 1,))
        assert c.get("/api/blocklist", headers=H("adm")).get_json()["stats"]["total"] == 0               # 만료는 바로 목록에서 빠짐
        assert p.sweep_blocks() == ["103.75.190.8"] and not p.db.one("SELECT 1 FROM blocklist")
        h = c.get("/api/blocklist/history?ip=103.75.190.8", headers=H("view")).get_json()["items"]
        assert [x["action"] for x in h] == ["expire", "extend", "block"] and h[2]["incident_id"] == iid and h[1]["reason"] == "재범"
        allh = c.get("/api/blocklist/history", headers=H("adm")).get_json()["items"]
        assert sum(1 for x in allh if x["action"] == "unblock") == 2
    finally:
        p.pipeline.stop()
        p.terminal.stop()


def test_simulate_block_goes_to_history_only(ctx):
    p, c, H = ctx
    assert c.post("/api/blocklist", headers=H("adm"), json={"ip": "198.51.100.7", "reason": "시험"}).get_json()["simulated"] is True
    assert c.get("/api/blocklist", headers=H("adm")).get_json()["stats"]["total"] == 0
    h = c.get("/api/blocklist/history", headers=H("adm")).get_json()["items"]
    assert h[0]["ip"] == "198.51.100.7" and h[0]["action"] == "block" and h[0]["simulated"] == 1 and h[0]["actor"] == "adm"
