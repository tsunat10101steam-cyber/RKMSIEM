"""P20: Grafana 연결 — API 토큰(읽기 전용) · /metrics 보안 지표 · Grafana 임베드 출입증(/grafana/ 쿠키 · nginx auth_request)."""
import json
import os
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def make(tmp_path, config_dir, **over):
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db"), **over}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("boss", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    return p, app.test_client(), auth


@pytest.fixture
def ctx(tmp_path, config_dir):
    p, c, auth = make(tmp_path, config_dir, **{"grafana.enabled": True})
    yield p, c, auth
    p.terminal.stop()


def H(t):
    return {"Authorization": f"Bearer {t}"}


def login(c, u):
    return c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"]


def test_api_token_scopes_metrics_and_revoke(ctx):
    p, c, auth = ctx
    boss, ana = login(c, "boss"), login(c, "ana")
    assert c.post("/api/tokens", headers=H(ana), json={"name": "x", "scopes": ["metrics:read"]}).status_code == 403
    assert c.post("/api/tokens", headers=H(boss), json={"name": "x", "scopes": ["config:write"]}).status_code == 400   # 쓰기 권한은 못 줌
    r = c.post("/api/tokens", headers=H(boss), json={"name": "prometheus-lab", "scopes": ["metrics:read"], "expires_days": 30})
    assert r.status_code == 201
    tok = r.get_json()["token"]
    assert tok.startswith("rkm_")
    assert c.post("/api/tokens", headers=H(boss), json={"name": "prometheus-lab", "scopes": ["metrics:read"]}).status_code == 400   # 같은 이름

    m = c.get("/metrics", headers=H(tok))
    assert m.status_code == 200
    body = m.get_data(as_text=True)
    for name in ("rkmsiem_threat_level", "rkmsiem_alerts_open", "rkmsiem_blocked_ips", "rkmsiem_runs_waiting_approval", "rkmsiem_info"):
        assert name in body
    assert c.get("/api/alerts", headers=H(tok)).status_code == 403              # 권한 밖
    assert c.get("/api/config/settings", headers=H(tok)).status_code == 403
    assert c.post("/api/tokens", headers=H(tok), json={"name": "y", "scopes": ["metrics:read"]}).status_code == 403
    assert c.get("/api/me/mfa", headers=H(tok)).status_code in (403, 404)

    items = c.get("/api/tokens", headers=H(boss)).get_json()["items"]
    row = next(i for i in items if i["name"] == "prometheus-lab")
    assert "token" not in row and "token_hash" not in row and row["last_used_at"]
    assert c.delete(f"/api/tokens/{row['id']}", headers=H(boss)).status_code == 200
    assert c.get("/metrics", headers=H(tok)).status_code == 401
    assert c.delete("/api/tokens/9999", headers=H(boss)).status_code == 404
    acts = [r["action"] for r in p.db.all("SELECT action FROM audit_log")]
    assert "api_token.create" in acts and "api_token.revoke" in acts


def test_expired_token_rejected(ctx):
    p, c, auth = ctx
    t = auth.create_api_token("short", ["metrics:read"], "t", expires_days=1)
    assert c.get("/metrics", headers=H(t["token"])).status_code == 200
    p.db.execute("UPDATE api_tokens SET expires_at=? WHERE id=?", (time.time() - 1, t["id"]))
    assert c.get("/metrics", headers=H(t["token"])).status_code == 401


def test_prometheus_label_escaping():
    from rkmsiem.metrics import Metrics
    m = Metrics()
    m.inc("x", source='a"b\\c\nd')
    out = m.prometheus()
    assert 'source="a\\"b\\\\c\\nd"' in out


def test_grafana_ticket_cookie_and_auth(ctx):
    p, c, auth = ctx
    boss, ana = login(c, "boss"), login(c, "ana")
    assert c.get("/api/grafana/auth").status_code == 401                          # 쿠키 없음
    cfg = c.get("/api/grafana", headers=H(ana)).get_json()
    assert cfg["enabled"] and cfg["path"] == "/grafana/" and cfg["dashboards"][0]["uid"] == "rkmsiem-overview"

    r = c.post("/api/grafana/session", headers={**H(boss), "X-Forwarded-Proto": "https"})
    ck = r.headers["Set-Cookie"]
    assert "rk_gf=" in ck and "Path=/grafana/" in ck and "HttpOnly" in ck and "SameSite=Strict" in ck
    ticket = ck.split("rk_gf=")[1].split(";")[0]
    assert ticket != boss and auth.resolve(ticket) is None                       # 출입증으로는 RKMSIEM API 를 못 씀
    assert c.get("/api/alerts", headers=H(ticket)).status_code == 401

    c.set_cookie("rk_gf", ticket, path="/")                                      # nginx auth_request 가 원래 요청 쿠키를 넘김
    a = c.get("/api/grafana/auth")
    assert a.status_code == 200 and a.headers["X-RK-User"] == "rk-boss" and a.headers["X-RK-Role"] == "Admin"

    r2 = c.post("/api/grafana/session", headers=H(ana))
    t2 = r2.headers["Set-Cookie"].split("rk_gf=")[1].split(";")[0]
    c.set_cookie("rk_gf", t2, path="/")
    a2 = c.get("/api/grafana/auth")
    assert a2.headers["X-RK-User"] == "rk-ana" and a2.headers["X-RK-Role"] == "Viewer"

    c.post("/api/auth/logout", headers=H(ana))                                   # 로그아웃 → Grafana 도 바로 막힘
    assert c.get("/api/grafana/auth").status_code == 401
    c.set_cookie("rk_gf", ticket, path="/")
    assert c.get("/api/grafana/auth").status_code == 200                         # 다른 사람 출입증은 그대로

    p.db.execute("UPDATE users SET active=0 WHERE username='boss'")              # 비활성 계정
    assert c.get("/api/grafana/auth").status_code == 401


def test_grafana_disabled_and_api_token_cannot_get_ticket(tmp_path, config_dir):
    p, c, auth = make(tmp_path, config_dir)
    try:
        boss = login(c, "boss")
        assert c.get("/api/grafana", headers=H(boss)).get_json()["enabled"] is False
        assert c.post("/api/grafana/session", headers=H(boss)).status_code == 409
    finally:
        p.terminal.stop()
    p2, c2, auth2 = make(tmp_path / "b", config_dir, **{"grafana.enabled": True})
    try:
        t = auth2.create_api_token("m", ["metrics:read"], "t")["token"]
        assert c2.post("/api/grafana/session", headers=H(t)).status_code == 403
    finally:
        p2.terminal.stop()


def test_csp_allows_same_origin_frames_only(ctx):
    p, c, auth = ctx
    csp = c.get("/").headers["Content-Security-Policy"]
    assert "frame-src 'self'" in csp and "frame-ancestors 'none'" in csp


def test_dashboard_json_uses_known_metrics():
    d = json.load(open(os.path.join(ROOT, "web", "grafana", "rkmsiem-overview.json"), encoding="utf-8"))
    assert d["uid"] == "rkmsiem-overview"
    src = open(os.path.join(ROOT, "rkmsiem", "promsec.py"), encoding="utf-8").read()
    import re
    used = {m for pn in d["panels"] for t in pn["targets"] for m in re.findall(r"rkmsiem_[a-z0-9_]+", t["expr"])}
    assert used and all(f'"{u[len("rkmsiem_"):]}"' in src for u in used), used


def test_grafana_embed_script_and_tls_include():
    tls = open(os.path.join(ROOT, "deploy", "tls.sh"), encoding="utf-8").read()
    assert "include $ETC/nginx/*.conf;" in tls and "$rk_conn_upgrade" in tls
    g = open(os.path.join(ROOT, "deploy", "grafana-embed.sh"), encoding="utf-8").read()
    for k in ("auth_request /_rk_grafana_auth", "internal;", "X-WEBAUTH-USER \\$rk_user", "GF_AUTH_PROXY_WHITELIST", "GF_SECURITY_ALLOW_EMBEDDING=true"):
        assert k in g, k


def test_grafana_panel_slots_config(ctx):
    p, c, auth = ctx
    boss, ana = login(c, "boss"), login(c, "ana")
    put = lambda body: c.put("/api/config/grafana_panels", headers=H(boss), json=body)
    ok = {"slots": [{"slot": "hourly", "mode": "replace", "uid": "rkmsiem-overview", "panel_id": 7, "title": "열린 경보", "height": 300},
                    {"slot": "collectors", "mode": "after", "uid": "node-exp", "panel_id": 5, "span": 12}]}
    assert put(ok).status_code == 200
    assert put({"slots": [{"slot": "hourly", "uid": "a", "panel_id": 1}, {"slot": "hourly", "mode": "replace", "uid": "b", "panel_id": 2}]}).status_code == 400   # 같은 칸 두 번 바꾸기
    assert put({"slots": [{"slot": "settings", "uid": "a", "panel_id": 1}]}).status_code == 400          # 대시보드 칸이 아님
    assert put({"slots": [{"slot": "hourly", "uid": "../api/admin", "panel_id": 1}]}).status_code == 400  # uid 는 경로로 못 씀
    assert put({"slots": [{"slot": "hourly", "uid": "a", "panel_id": 0}]}).status_code == 400
    assert c.put("/api/config/grafana_panels", headers=H(ana), json=ok).status_code == 403               # 분석가는 못 바꿈
    g = c.get("/api/grafana", headers=H(ana)).get_json()                                                   # 보는 것은 metrics:read 로
    assert [s["slot"] for s in g["slots"]] == ["hourly", "collectors"] and g["slots"][1]["mode"] == "after"
    assert c.get("/api/config/grafana_panels", headers=H(boss)).get_json()["version"] >= 2
