"""P5: API — 인증 · RBAC · 입력 검증 · 인젝션 방어 · 마스킹 · SSE · 보안 헤더 · API 로 끝까지 흐름."""
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "api.db"), "api.login_rate_per_min": 8,
                                             "api.max_body_kb": 64, "soar.worker_poll_ms": 50})
    p = Platform(s)
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    for u, r in (("admin1", "admin"), ("ana", "analyst"), ("resp", "responder"), ("view", "viewer")):
        auth.create_user(u, PW, r, "test")
    src = p.sources()["http-json"]
    p.collectors["http-json"] = HttpCollector(src, p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    p.soar.start()
    c = app.test_client()
    tokens = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("admin1", "ana", "resp", "view")}
    yield {"p": p, "c": c, "t": tokens}
    p.soar.stop()
    p.pipeline.stop()


def H(tok):
    return {"Authorization": f"Bearer {tok}"}


def ingest(c, events, wait=True):
    return c.post("/api/ingest/http-json" + ("?wait=1" if wait else ""), headers={"X-API-Key": KEY}, json=events)


def ev(i, ip, user, outcome="failure", ts="2026-10-12T01:00:00Z", **kw):
    return dict({"id": f"e{i}-{ip}-{user}-{outcome}", "timestamp": ts, "src_ip": ip, "user": user, "outcome": outcome,
                 "category": "authentication"}, **kw)


def test_auth_required_and_public_health(ctx):
    c = ctx["c"]
    assert c.get("/healthz").status_code == 200
    for path in ("/api/overview", "/api/alerts", "/api/incidents", "/api/audit", "/metrics", "/api/rules"):
        assert c.get(path).status_code == 401
    assert c.get("/api/alerts", headers=H("forged-token")).status_code == 401


def test_login_failures_rate_limit_and_audit(ctx):
    c, p = ctx["c"], ctx["p"]
    assert c.post("/api/auth/login", json={"username": "ana", "password": "wrong"}).status_code == 401
    assert c.post("/api/auth/login", json={"username": "nobody", "password": "x"}).status_code == 401
    codes = [c.post("/api/auth/login", json={"username": "ana", "password": "wrong"}).status_code for _ in range(6)]
    assert 429 in codes                                                       # 분당 8회 제한 (픽스처 로그인 4회 포함)
    acts = [a["action"] for a in p.audit.list(200)]
    assert "auth.login_failed" in acts and "auth.rate_limited" in acts
    assert c.post("/api/auth/login", json={"username": "ana", "password": PW, "extra": 1}).status_code in (400, 429)   # 알 수 없는 필드 거부


def test_rbac_enforced_on_backend(ctx):
    c, t, p = ctx["c"], ctx["t"], ctx["p"]
    rule = c.get("/api/rules/auth_bruteforce", headers=H(t["view"])).get_json()["rule"]
    assert c.put("/api/rules/auth_bruteforce", headers=H(t["view"]), json=rule).status_code == 403
    assert c.put("/api/rules/auth_bruteforce", headers=H(t["ana"]), json=rule).status_code == 403
    assert c.get("/api/audit", headers=H(t["view"])).status_code == 403
    assert c.get("/api/audit", headers=H(t["ana"])).status_code == 403
    assert c.get("/api/audit", headers=H(t["admin1"])).status_code == 200
    assert c.post("/api/users", headers=H(t["resp"]), json={"username": "x", "password": PW, "role": "admin"}).status_code == 403
    assert c.post("/api/runs/1/steps/x/decision", headers=H(t["ana"]), json={"approve": True, "reason": "r"}).status_code == 403
    assert any(a["action"] == "auth.forbidden" and a["actor"] == "view" for a in p.audit.list(200))


def test_ingest_auth_validation_and_search(ctx):
    c, t = ctx["c"], ctx["t"]
    assert c.post("/api/ingest/http-json", json=[ev(1, "1.1.1.1", "a")]).status_code == 401
    assert c.post("/api/ingest/nope", headers={"X-API-Key": KEY}, json=[ev(1, "1.1.1.1", "a")]).status_code == 404
    r = ingest(c, [ev(1, "198.51.100.20", "alice"), ev(1, "198.51.100.20", "alice"), {"bad": "event"}, ev(2, "not-an-ip", "bob")])
    j = r.get_json()
    assert r.status_code == 200 and j["stored"] == 2 and j["duplicates"] == 1 and j["failed"] == 1
    res = c.get("/api/events?ip=198.51.100.20", headers=H(t["view"])).get_json()
    assert res["total"] == 1 and res["items"][0]["user_name"] == "alice"
    # 인젝션 시도: 값은 바인딩되어 결과 0건, 정렬 필드는 허용 목록 밖이면 400
    assert c.get("/api/events?ip=' OR 1=1 --", headers=H(t["view"])).get_json()["total"] == 0
    assert c.get("/api/events?sort=ts;DROP TABLE events", headers=H(t["view"])).status_code == 400
    assert c.get("/api/events?q=%25", headers=H(t["view"])).get_json()["total"] == 0         # LIKE 와일드카드 이스케이프
    assert c.get("/api/collectors", headers=H(t["view"])).get_json()["pipeline"]["dlq_pending"] == 1


def test_payload_limit_and_security_headers(ctx):
    c = ctx["c"]
    r = c.post("/api/ingest/http-json", headers={"X-API-Key": KEY}, data="x" * (70 * 1024), content_type="application/json")
    assert r.status_code == 413
    h = c.get("/healthz").headers
    assert h["X-Content-Type-Options"] == "nosniff" and "frame-ancestors 'none'" in h["Content-Security-Policy"]


def test_sensitive_data_masked(ctx):
    c, t = ctx["c"], ctx["t"]
    ingest(c, [ev(9, "198.51.100.21", "x", message="login failed password=Sup3rS3cret token=abc123")])
    eid = c.get("/api/events?ip=198.51.100.21", headers=H(t["view"])).get_json()["items"][0]["id"]
    raw = c.get(f"/api/events/{eid}", headers=H(t["view"])).get_json()["raw"]
    assert "Sup3rS3cret" not in raw and "abc123" not in raw


def test_rule_validation_and_simulation_via_api(ctx):
    c, t, p = ctx["c"], ctx["t"], ctx["p"]
    ingest(c, [ev(i, "198.51.100.30", "bob", ts=f"2026-10-12T01:00:{i:02d}Z") for i in range(4)])
    bad = {"id": "auth_bruteforce", "name": "x", "type": "threshold", "where": [], "group_by": [], "levels": []}
    assert c.put("/api/rules/auth_bruteforce", headers=H(t["admin1"]), json=bad).status_code == 400
    assert p.config.get("rule", "auth_bruteforce")["levels"][0]["min"] == 5             # 기존 버전 유지
    cand = p.config.get("rule", "auth_bruteforce")
    cand["levels"][0]["min"] = 3
    r = c.post("/api/rules/simulate", headers=H(t["ana"]), json={"rule": cand}).get_json()
    assert [a["group_key"] for a in r["diff"]["added"]] == ["source.ip=198.51.100.30|user.name=bob"]
    assert p.config.get("rule", "auth_bruteforce")["levels"][0]["min"] == 5             # 시뮬레이션은 저장 안 함
    y = "id: x_rule\nname: t\ntype: match\nwhere: [{field: user.name, op: eq, value: z}]\ngroup_by: [user.name]\nlevels: [{id: Z, min: 1, severity: low, title: z}]\n"
    assert c.put("/api/rules/x_rule", headers=H(t["admin1"]), data=y, content_type="text/yaml").status_code == 200


def test_sse_stream_ticket_single_use(ctx):
    c, t, p = ctx["c"], ctx["t"], ctx["p"]
    tk = c.post("/api/stream/ticket", headers=H(t["view"])).get_json()["ticket"]
    resp = c.get(f"/api/stream?ticket={tk}")
    it = iter(resp.response)
    assert b"retry" in next(it) and b"hello" in next(it)
    p.bus.publish("alert", {"id": 1, "title": "t"})
    assert b"event: alert" in next(it)
    resp.close()
    assert c.get(f"/api/stream?ticket={tk}").status_code == 401                       # 재사용 불가


def test_end_to_end_via_api(ctx):
    """이벤트 입력 → 수집·정규화 → 탐지 → 경보·사건 → 플레이북 → 승인 → 감사 (모두 API 로)."""
    c, t = ctx["c"], ctx["t"]
    evs = [ev(i, "103.75.190.8", "backup", ts=f"2026-10-12T01:12:{i:02d}Z") for i in range(6)]
    evs.append(ev(99, "103.75.190.8", "backup", outcome="success", ts="2026-10-12T01:12:30Z"))
    assert ingest(c, evs).get_json()["stored"] == 7
    inc = c.get("/api/incidents", headers=H(t["view"])).get_json()["items"]
    assert len(inc) == 1 and inc[0]["severity"] == "critical"
    iid = inc[0]["id"]
    end = time.time() + 10
    while time.time() < end:
        runs = c.get(f"/api/runs?incident_id={iid}&playbook_id=compromise_response", headers=H(t["view"])).get_json()["items"]
        if runs and runs[0]["state"] == "waiting_approval":
            break
        time.sleep(.1)
    rid = runs[0]["id"]
    for step in ("block_ip", "disable_account"):
        r = c.post(f"/api/runs/{rid}/steps/{step}/decision", headers=H(t["resp"]), json={"approve": True, "reason": "확인"})
        assert r.status_code == 200
        end = time.time() + 10
        while time.time() < end and c.get(f"/api/runs/{rid}", headers=H(t["view"])).get_json()["state"] == "queued":
            time.sleep(.1)
        time.sleep(.3)
    end = time.time() + 10
    while time.time() < end and c.get(f"/api/runs/{rid}", headers=H(t["view"])).get_json()["state"] != "succeeded":
        time.sleep(.1)
    d = c.get(f"/api/incidents/{iid}", headers=H(t["admin1"])).get_json()
    assert d["runs"][0]["state"] == "succeeded"
    kinds = {x["kind"] for x in d["timeline"]}
    assert {"created", "approval_requested", "approval_approved", "playbook_result", "playbook_finished"} <= kinds
    assert any(a["action"] == "approval.approved" and a["actor"] == "resp" for a in d["audit"])
    ov = c.get("/api/overview", headers=H(t["view"])).get_json()
    assert ov["threat"]["current"]["id"] == "severe" and ov["totals"]["events"] == 7
    assert c.get("/api/audit/verify", headers=H(t["admin1"])).get_json()["ok"] is True
    lat = c.get("/api/metrics", headers=H(t["view"])).get_json()["latency"]["e2e_event_to_alert_ms"]
    assert lat["all"]["count"] >= 1


def test_playbook_builder_endpoints(ctx):
    """자동화 편집기: 검증·미리보기(저장 안 함) → 저장 → 조회·이력 → 비활성화 → 롤백, 권한 검사."""
    c, t = ctx["c"], ctx["t"]
    ingest(c, [ev(i, "103.75.190.9", "backup", ts=f"2026-10-12T02:00:{i:02d}Z") for i in range(11)])
    pb = {"id": "ui_built", "name": "편집기에서 만든 플레이북", "enabled": True,
          "trigger": {"on": "alert", "where": [{"field": "alert.level_id", "op": "in", "value": ["BRUTEFORCE_HIGH"]}]},
          "steps": [{"id": "rep", "action": "ip_reputation", "input": {"ip": "{{alert.group.source.ip}}"}},
                    {"id": "say", "action": "notify", "input": {"message": "{{alert.group.source.ip}} 판정 {{steps.rep.output.verdict}}"}}]}
    bad = dict(pb, steps=[{"id": "x", "action": "no_such_action"}])
    r = c.post("/api/playbooks/validate", headers=H(t["view"]), json={"playbook": bad}).get_json()
    assert r["ok"] is False and any("no_such_action" in e for e in r["errors"])
    r = c.post("/api/playbooks/validate", headers=H(t["view"]), json={"playbook": pb}).get_json()
    assert r["ok"] and r["preview"]["matched"] >= 1 and "ui_built" in r["yaml"]
    assert r["preview"]["samples"][0]["inputs"]["rep"] == {"ip": "103.75.190.9"}
    assert c.get("/api/playbooks/ui_built", headers=H(t["view"])).status_code == 404       # 검증은 저장하지 않음
    assert c.put("/api/playbooks/ui_built", headers=H(t["ana"]), json=pb).status_code == 403
    assert c.put("/api/playbooks/ui_built?comment=first", headers=H(t["admin1"]), json=pb).get_json()["version"] == 1
    assert c.post("/api/playbooks/ui_built/enabled", headers=H(t["admin1"]), json={"enabled": False}).get_json()["version"] == 2
    d = c.get("/api/playbooks/ui_built", headers=H(t["view"])).get_json()
    assert d["playbook"]["enabled"] is False and [v["version"] for v in d["versions"]] == [2, 1]
    assert c.post("/api/playbooks/ui_built/rollback", headers=H(t["admin1"]), json={"version": 1}).get_json()["version"] == 3
    assert c.get("/api/playbooks/ui_built", headers=H(t["view"])).get_json()["playbook"]["enabled"] is True
