"""P20: 연동 — API 토큰(읽기 전용) · /metrics 보안 지표 · 연동 화면(connect: 당겨오기 소스의 view, 8445 출처 · /connect/ 프록시)."""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

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
    p, c, auth = make(tmp_path, config_dir)
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


class Up(BaseHTTPRequestHandler):
    """연동 제품 흉내 — 받은 경로·헤더를 그대로 돌려줌."""
    def log_message(self, *a):
        pass

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else b""
        if self.path.startswith("/connect/gf/login"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/connect/gf/home")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        out = json.dumps({"path": self.path, "method": self.command, "body": body.decode(), "user": self.headers.get("X-WEBAUTH-USER"),
                          "role": self.headers.get("X-WEBAUTH-ROLE"), "cookie": self.headers.get("Cookie"), "auth": self.headers.get("Authorization"),
                          "fwd": self.headers.get("X-Forwarded-Prefix")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Frame-Options", "deny")
        self.send_header("Set-Cookie", "grafana_session=abc; Path=/connect/gf/")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)
    do_GET = do_POST = _go


@pytest.fixture
def upstream():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Up)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def add_source(p, src):
    cur = p.config.get("sources")
    return p.config.put("sources", "default", dict(cur, sources=[x for x in cur["sources"] if x["id"] != src["id"]] + [src]), "t", "test")


def gf_source(url):
    return {"id": "gf", "type": "http_pull", "parser": "json", "enabled": False, "options": {"url": url + "/api/alerts", "items_path": "data.alerts"},
            "view": {"url": url, "home": "/d/x/?kiosk&from={from}", "kind": "grafana", "title": "Grafana",
                     "dashboards": [{"name": "alerts", "path": "/alerting/list"}],
                     "sso": {"user_header": "X-WEBAUTH-USER", "role_header": "X-WEBAUTH-ROLE", "prefix": "rk-", "roles": {"admin": "Admin", "default": "Viewer"}}}}


def test_view_validation(ctx, upstream):
    p, c, auth = ctx
    from rkmsiem.schemas import SchemaError
    ok = gf_source(upstream)
    add_source(p, ok)
    bad = [{"url": "ftp://x"}, {"url": "http://u:p@h"}, {"url": "http://h", "home": "/../admin"}, {"url": "http://h", "home": "x"},
           {"url": "http://h", "sso": {"user_header": "Cookie"}}, {"url": "http://h", "sso": {"user_header": "X-Forwarded-For"}},
           {"url": "http://h", "dashboards": [{"name": "A B", "path": "/"}]}, {"url": "http://h", "nope": 1}]
    for v in bad:
        with pytest.raises(SchemaError):
            add_source(p, dict(ok, view=v))


def test_connect_list_session_and_proxy(ctx, upstream):
    p, c, auth = ctx
    add_source(p, gf_source(upstream))
    boss, ana = login(c, "boss"), login(c, "ana")
    lst = c.get("/api/connect", headers={**H(ana), "Host": "10.0.0.53:8443"}).get_json()
    assert lst["origin"] == "https://10.0.0.53:8445"
    gf = next(x for x in lst["items"] if x["id"] == "gf")
    assert gf["view"]["home"].startswith("/d/x/") and "url" not in json.dumps(gf["view"])            # 내부 주소는 안 보여 줌
    csp = c.get("/", headers={"Host": "10.0.0.53:8443"}).headers["Content-Security-Policy"]
    assert "frame-src 'self' https://10.0.0.53:8445" in csp and "frame-ancestors 'none'" in csp

    r = c.post("/api/connect/session", headers={**H(boss), "X-Forwarded-Proto": "https"})
    ck = r.headers["Set-Cookie"]
    assert "rk_cx=" in ck and "Path=/connect/" in ck and "HttpOnly" in ck and "SameSite=Strict" in ck and "Secure" in ck
    ticket = ck.split("rk_cx=")[1].split(";")[0]
    assert auth.resolve(ticket) is None and c.get("/api/alerts", headers=H(ticket)).status_code == 401   # 출입증으로 API 불가

    VIA = {"X-RKMSIEM-Connect": "1", "Host": "10.0.0.53:8445"}
    b = c.application.test_client(use_cookies=False)                                    # 브라우저처럼 Cookie 헤더를 직접
    assert b.get("/connect/gf/d/x/").status_code == 404                                  # 8445(nginx)를 안 거침 → 콘솔 출처에서 열기 금지
    assert b.get("/connect/gf/d/x/", headers=VIA).status_code == 401                      # 쿠키 없음
    VIA = dict(VIA, Cookie=f"rk_cx={ticket}; other=1")
    r = b.get("/connect/gf/d/x/?kiosk=1", headers={**VIA, "X-WEBAUTH-USER": "admin", "X-Forwarded-For": "6.6.6.6", "Authorization": "Bearer zz"})
    assert r.status_code == 200
    j = r.get_json()
    assert j["path"] == "/connect/gf/d/x/?kiosk=1" and j["user"] == "rk-boss" and j["role"] == "Admin"   # 위조 헤더는 덮어씀
    assert "rk_cx" not in (j["cookie"] or "") and "other=1" in j["cookie"] and j["fwd"] == "/connect/gf"
    assert "X-Frame-Options" not in r.headers and "frame-ancestors https://10.0.0.53:*" in r.headers["Content-Security-Policy"]
    assert "grafana_session=abc" in r.headers.get("Set-Cookie", "")
    j = b.post("/connect/gf/api/ds/query", headers=VIA, data=b'{"q":1}', content_type="application/json").get_json()
    assert j["method"] == "POST" and j["body"] == '{"q":1}'
    r = b.get("/connect/gf/login", headers=VIA)                                           # 제품 내부 주소 리다이렉트 → 연동 화면 주소
    assert r.status_code == 302 and r.headers["Location"] == "https://10.0.0.53:8445/connect/gf/home"
    assert b.get("/connect/nope/", headers=VIA).status_code == 404

    t2 = c.post("/api/connect/session", headers=H(ana)).headers["Set-Cookie"].split("rk_cx=")[1].split(";")[0]
    VIA2 = dict(VIA, Cookie=f"rk_cx={t2}")
    assert b.get("/connect/gf/", headers=VIA2).get_json()["role"] == "Viewer"
    c.post("/api/auth/logout", headers=H(ana))                                            # 로그아웃 → 바로 막힘
    assert b.get("/connect/gf/", headers=VIA2).status_code == 401
    assert b.get("/connect/gf/", headers=VIA).status_code == 200

    f = c.get("/api/connect/gf/fetch?path=/api/search%3Ftype%3Ddash-db", headers=H(boss)).get_json()["data"]    # 설정 도우미 (서버가 대신 읽음)
    assert f["path"] == "/connect/gf/api/search?type=dash-db" and f["user"] == "rk-boss"
    assert c.get("/api/connect/gf/fetch?path=/api/search", headers=H(login(c, "ana"))).status_code == 403
    assert c.get("/api/connect/gf/fetch?path=/../x", headers=H(boss)).status_code == 400

    tok = auth.create_api_token("m", ["metrics:read"], "t")["token"]
    assert c.post("/api/connect/session", headers=H(tok)).status_code == 403             # API 토큰은 화면 출입증 불가


def test_strip_prefix_mode(ctx, upstream):
    p, c, auth = ctx
    add_source(p, dict(gf_source(upstream), view={"url": upstream + "/sub", "keep_prefix": False}))
    boss = login(c, "boss")
    t = c.post("/api/connect/session", headers=H(boss)).headers["Set-Cookie"].split("rk_cx=")[1].split(";")[0]
    b = c.application.test_client(use_cookies=False)
    j = b.get("/connect/gf/graph?x=1", headers={"X-RKMSIEM-Connect": "1", "Cookie": f"rk_cx={t}"}).get_json()
    assert j["path"] == "/sub/graph?x=1" and j["user"] is None                            # sso 없으면 헤더도 없음


def test_embeds_config(ctx, upstream):
    p, c, auth = ctx
    add_source(p, gf_source(upstream))
    boss, ana = login(c, "boss"), login(c, "ana")
    put = lambda body: c.put("/api/config/embeds", headers=H(boss), json=body)
    ok = {"slots": [{"slot": "hourly", "mode": "replace", "source": "gf", "path": "/d-solo/x/?panelId=7&from={from}&to={to}", "title": "경보", "height": 300},
                    {"slot": "collectors", "mode": "after", "source": "gf", "path": "/d-solo/x/?panelId=8", "span": 12}]}
    assert put(ok).status_code == 200
    assert put({"slots": [{"slot": "hourly", "source": "gf", "path": "/a"}, {"slot": "hourly", "source": "gf", "path": "/b"}]}).status_code == 400
    assert put({"slots": [{"slot": "hourly", "source": "nope", "path": "/a"}]}).status_code == 400          # 화면 없는 연동
    assert put({"slots": [{"slot": "settings", "source": "gf", "path": "/a"}]}).status_code == 400
    assert put({"slots": [{"slot": "hourly", "source": "gf", "path": "/../api"}]}).status_code == 400
    assert c.put("/api/config/embeds", headers=H(ana), json=ok).status_code == 403
    assert [x["slot"] for x in c.get("/api/connect", headers=H(ana)).get_json()["slots"]] == ["hourly", "collectors"]


def test_dashboard_json_uses_known_metrics():
    d = json.load(open(os.path.join(ROOT, "web", "grafana", "rkmsiem-overview.json"), encoding="utf-8"))
    assert d["uid"] == "rkmsiem-overview"
    src = open(os.path.join(ROOT, "rkmsiem", "promsec.py"), encoding="utf-8").read()
    import re
    used = {m for pn in d["panels"] for t in pn["targets"] for m in re.findall(r"rkmsiem_[a-z0-9_]+", t["expr"])}
    assert used and all(f'"{u[len("rkmsiem_"):]}"' in src for u in used), used


def test_tls_has_separate_connect_origin():
    tls = open(os.path.join(ROOT, "deploy", "tls.sh"), encoding="utf-8").read()
    assert "CONNECT=8445" in tls and "location /connect/ { return 404; }" in tls        # 콘솔(8443)에서는 막힘
    assert 'proxy_set_header X-RKMSIEM-Connect "";' in tls and "proxy_set_header X-RKMSIEM-Connect 1;" in tls
    tui = open(os.path.join(ROOT, "deploy", "setup-tui.sh"), encoding="utf-8").read()
    assert "8445" in tui
    assert not os.path.exists(os.path.join(ROOT, "deploy", "grafana-embed.sh"))


def test_console_files_revalidate_after_update(ctx):
    p, c, auth = ctx
    for path in ("/", "/static/app.js", "/static/settings.js"):
        assert c.get(path).headers.get("Cache-Control") == "no-cache", path
    js = c.get("/static/app.js").get_data(as_text=True)
    assert '"grafana"' not in js and 'panel("connect"' in js
