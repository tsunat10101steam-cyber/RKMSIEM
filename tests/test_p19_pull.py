"""P19: 당겨오기(HTTP pull) 수집기 — 가짜 API 서버를 실제로 조회해 저장·중복 제거·커서·인증·탐지까지."""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http_pull import HttpPullCollector, PullError, pull_once
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
TOKEN = "s3cr3t-token"
ALERTS = {"status": "success", "data": {"alerts": [
    {"labels": {"alertname": "HighCPU", "instance": "web-01", "severity": "critical"}, "annotations": {"summary": "CPU 98% (채굴 의심)"},
     "state": "firing", "activeAt": "2026-10-16T01:00:00Z", "value": "98"},
    {"labels": {"alertname": "DiskFull", "instance": "db-01", "severity": "warning"}, "annotations": {"summary": "disk 92%"},
     "state": "firing", "activeAt": "2026-10-16T01:05:00Z", "value": "92"}]}}
GRAFANA_ALERTS = {"status": "success", "data": {"alerts": [
    {"labels": {"__alert_rule_uid__": "cpu1", "alertname": "노드 CPU 과다", "grafana_folder": "infra", "instance": "web-01", "severity": "critical"},
     "annotations": {"summary": "web-01 CPU 97% 10분 지속"}, "state": "Alerting", "activeAt": "2026-10-16T02:00:00Z", "value": "97"},
    {"labels": {"__alert_rule_uid__": "disk1", "alertname": "디스크", "grafana_folder": "infra", "instance": "db-01"},
     "annotations": {"summary": "곧 울림"}, "state": "Pending", "activeAt": "2026-10-16T02:01:00Z", "value": "80"}]}}
EVENTS = [{"id": i, "ts": 1760000000 + i * 10, "msg": f"event {i}", "type": "Warning" if i % 2 else "Normal"} for i in range(1, 8)]


class Api(BaseHTTPRequestHandler):
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        Api.seen.append((self.path, self.headers.get("Authorization")))
        u = urlsplit(self.path)
        q = parse_qs(u.query)
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            return self._send(401, {"error": "unauthorized"})
        if u.path == "/api/v1/alerts":
            return self._send(200, ALERTS)
        if u.path == "/api/prometheus/grafana/api/v1/alerts":     # Grafana-managed 경보 (Prometheus 호환 응답)
            return self._send(200, GRAFANA_ALERTS)
        if u.path == "/events":                       # since 커서 + continue 쪽 나누기 (3개씩)
            since = int(q.get("since", ["0"])[0])
            rows = [e for e in EVENTS if e["ts"] > since]
            start = int(q.get("continue", ["0"])[0])
            page = rows[start:start + 3]
            return self._send(200, {"items": page, "next": str(start + 3) if start + 3 < len(rows) else None})
        if u.path == "/redirect":
            self.send_response(302); self.send_header("Location", "http://evil.example/"); self.end_headers(); return
        self._send(404, {})

    def _send(self, code, obj):
        data = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)


@pytest.fixture
def api_server():
    srv = HTTPServer(("127.0.0.1", 0), Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    Api.seen = []
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


@pytest.fixture
def plat(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_PULL_TEST_TOKEN", TOKEN)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")}))
    p.pipeline.start()
    yield p
    p.pipeline.stop()
    p.terminal.stop()


PROM = {"id": "prom", "type": "http_pull", "parser": "json", "dataset": "pull.prometheus", "options": {
    "items_path": "data.alerts", "interval_sec": 30, "auth": {"type": "bearer", "token_env": "RKMSIEM_PULL_TEST_TOKEN"},
    "id_fields": ["labels.alertname", "labels.instance", "activeAt"],
    "field_map": {"@timestamp": "activeAt", "rule.name": "labels.alertname", "host.name": "labels.instance",
                  "labels.severity": "labels.severity", "message": "annotations.summary"},
    "static": {"event.action": "external_alert", "event.category": "metric", "observer.product": "prometheus"}}}


def _collector(p, src):
    c = HttpPullCollector(src, p.pipeline, p.db, p.metrics)
    c.vault = p.vault
    return c


def test_pull_prometheus_alerts_store_dedupe_and_detect(plat, api_server):
    p = plat
    src = json.loads(json.dumps(PROM)); src["options"]["url"] = api_server + "/api/v1/alerts"
    cur = p.config.get("sources"); p.config.put("sources", "default", dict(cur, sources=cur["sources"] + [src]), "t", "pull")
    c = _collector(p, src)
    c.poll()
    rows = p.db.all("SELECT * FROM events WHERE source_id='prom' ORDER BY id")
    assert len(rows) == 2 and rows[0]["host_name"] == "web-01" and "채굴" in rows[0]["message"]
    doc = json.loads(rows[0]["doc"])
    assert doc["event"]["action"] == "external_alert" and doc["observer"]["product"] == "prometheus"
    c.poll()                                                         # 같은 경보 다시 → 중복 제거
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_id='prom'") == 2
    alerts = p.db.all("SELECT title, severity FROM alerts WHERE rule_id='external_alert'")
    assert alerts and {a["severity"] for a in alerts} >= {"high"}              # critical → 한 단계 위
    assert c.status()["last_count"] == 2 and "127.0.0.1" in c.status()["listen"]


def test_pull_cursor_pages_and_auth(plat, api_server):
    p = plat
    src = {"id": "ev", "type": "http_pull", "parser": "json", "options": {
        "url": api_server + "/events", "items_path": "items", "next_path": "next", "next_param": "continue",
        "auth": {"token_env": "RKMSIEM_PULL_TEST_TOKEN"}, "id_fields": ["id"], "only_if": {"type": ["Warning"]},
        "cursor": {"field": "ts", "param": "since", "start": "beginning"},
        "field_map": {"@timestamp": "ts", "message": "msg"}}}
    cur = p.config.get("sources"); p.config.put("sources", "default", dict(cur, sources=cur["sources"] + [src]), "t", "pull")
    c = _collector(p, src)
    c.poll()
    msgs = [r["message"] for r in p.db.all("SELECT message FROM events WHERE source_id='ev' ORDER BY ts")]
    assert msgs == ["event 1", "event 3", "event 5", "event 7"]                 # 쪽 3개 모두 · Warning 만
    assert json.loads(p.db.scalar("SELECT value FROM collector_state WHERE source_id='ev'")) == EVENTS[-1]["ts"]   # 저장 후 커서 이동
    Api.seen = []
    c.poll()
    assert any("since=1760000070" in path for path, _ in Api.seen)               # 다음엔 커서 이후만
    assert all(auth == f"Bearer {TOKEN}" for _, auth in Api.seen)


def test_pull_errors_are_clear(api_server, monkeypatch):
    with pytest.raises(PullError, match="인증 실패"):
        pull_once({"url": api_server + "/api/v1/alerts"}, None)
    with pytest.raises(PullError, match="옮겨졌습니다"):
        pull_once({"url": api_server + "/redirect"}, TOKEN)
    from rkmsiem.collectors.http_pull import secret_for
    monkeypatch.setenv("RKMSIEM_SECRET_KEY", "x")
    with pytest.raises(PullError, match="RKMSIEM_PULL_"):
        secret_for({"auth": {"token_env": "RKMSIEM_SECRET_KEY"}}, "x", None)       # 다른 비밀 값은 못 읽음


def test_pull_validation_and_api(plat, api_server, tmp_path):
    p = plat
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("boss", PW, "admin", "t")
    c = app.test_client()
    H = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"username": "boss", "password": PW}).get_json()["token"]}
    cur = p.config.get("sources")
    bad = [{"id": "x1", "type": "http_pull", "parser": "json", "options": {"url": "ftp://a"}},
           {"id": "x2", "type": "http_pull", "parser": "json", "options": {"url": "https://a", "auth": {"token_env": "RKMSIEM_SECRET_KEY"}}},
           {"id": "x3", "type": "http_pull", "parser": "json", "options": {"url": "http://a", "auth": {"type": "bearer"}}},
           {"id": "x4", "type": "http_pull", "parser": "json", "options": {"url": "https://a", "headers": {"Authorization": "Bearer x"}}}]
    for b in bad:
        r = c.put("/api/config/sources", headers=H, json=dict(cur, sources=cur["sources"] + [b]))
        assert r.status_code == 400, b["id"]
    # 저장 전 시험 조회: 비밀 값을 함께 보내면 그걸로
    src = json.loads(json.dumps(PROM)); src["options"]["url"] = api_server + "/api/v1/alerts"; src["options"]["auth"] = {"type": "bearer"}
    t = c.post("/api/pull/test", headers=H, json={"source": src, "secret": TOKEN}).get_json()
    assert t["ok"] and t["count"] == 2 and t["parsed"][0]["doc"]["host"]["name"] == "web-01"
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_id='prom'") == 0               # 시험은 저장 안 함
    assert c.post("/api/pull/test", headers=H, json={"source": src}).get_json()["error"].startswith("인증 실패")
    # 토큰을 웹에서 암호화 저장 → 수집기가 사용
    assert c.post("/api/pull/prom/secret", headers=H, json={"value": TOKEN}).status_code == 200
    assert TOKEN not in (p.db.scalar("SELECT ciphertext FROM secrets WHERE name='pull:prom'") or "")
    assert c.put("/api/config/sources", headers=H, json=dict(cur, sources=cur["sources"] + [src])).status_code == 200
    col = _collector(p, src); col.poll()
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_id='prom'") == 2
    lst = c.get("/api/pull", headers=H).get_json()["items"]
    assert lst[0]["source"]["id"] == "prom" and lst[0]["secret_set"] is True


GRAFANA = {"id": "grafana", "type": "http_pull", "parser": "json", "dataset": "pull.grafana", "options": {   # web/settings.js PULL_PRESETS.grafana 과 같게
    "interval_sec": 60, "auth": {"type": "bearer", "token_env": "RKMSIEM_PULL_TEST_TOKEN"},
    "items_path": "data.alerts", "only_if": {"state": ["Alerting", "alerting", "firing"]},
    "id_fields": ["labels.__alert_rule_uid__", "labels.alertname", "labels.instance", "activeAt"],
    "field_map": {"@timestamp": "activeAt", "rule.name": "labels.alertname", "host.name": "labels.instance", "labels.severity": "labels.severity",
                  "message": "annotations.summary", "labels.folder": "labels.grafana_folder"},
    "static": {"event.action": "external_alert", "event.category": "metric", "observer.product": "grafana"}}}


def test_pull_grafana_alerts_preset(plat, api_server):
    p = plat
    src = json.loads(json.dumps(GRAFANA)); src["options"]["url"] = api_server + "/api/prometheus/grafana/api/v1/alerts"
    cur = p.config.get("sources"); p.config.put("sources", "default", dict(cur, sources=cur["sources"] + [src]), "t", "pull")
    c = _collector(p, src)
    c.poll(); c.poll()
    rows = p.db.all("SELECT * FROM events WHERE source_id='grafana'")
    assert len(rows) == 1 and rows[0]["host_name"] == "web-01" and "CPU 97%" in rows[0]["message"]    # Pending 은 거름 · 중복 제거
    doc = json.loads(rows[0]["doc"])
    assert doc["observer"]["product"] == "grafana" and doc["labels"]["folder"] == "infra"
    assert p.db.all("SELECT 1 FROM alerts WHERE rule_id='external_alert'")
    preset = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "settings.js"), encoding="utf-8").read()
    assert "/api/prometheus/grafana/api/v1/alerts" in preset and '"labels.__alert_rule_uid__"' in preset
