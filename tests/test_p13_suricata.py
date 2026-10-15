"""P13: Suricata IDS 연동 — EVE 파서 · IDS 규칙 · IDS→로그인 상관 규칙 · 전송기(이어 보내기·재시도·로그 회전)."""
import http.server
import json
import os
import subprocess
import sys
import threading
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.parsers import Skip
from rkmsiem.plugins import PARSERS, load_builtin

load_builtin()
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

KEY = "test-ingest-key-1234567890"
PW = "correct-horse-battery-9"
SHIP = os.path.join(os.path.dirname(__file__), "..", "deploy", "ids", "rkmsiem-ship-eve.py")


def eve(i, src="45.33.32.156", sig="ET SCAN Nmap Scripting Engine User-Agent Detected", sev=2, et="alert", ts="2026-10-12T05:00:{:02d}.123456+0900"):
    e = {"timestamp": ts.format(i), "flow_id": 1000 + i, "event_type": et, "src_ip": src, "src_port": 50000 + i, "dest_ip": "10.0.0.53",
         "dest_port": 22, "proto": "TCP", "app_proto": "ssh", "host": "ids"}
    if et == "alert":
        e["alert"] = {"action": "allowed", "signature_id": 2024364, "signature": sig, "category": "Web Application Attack", "severity": sev}
    return e


def test_parser_maps_alert_and_skips_noise():
    p = PARSERS["suricata_eve"]
    d = p(json.dumps(eve(1, sev=1)), {})
    assert d["source"] == {"ip": "45.33.32.156", "port": 50001} and d["destination"]["port"] == 22
    assert d["event"]["action"] == "ids_alert" and d["event"]["severity"] == 1 and d["rule"]["id"] == "2024364"
    assert d["@timestamp"].startswith("2026-10-11T20:00:01")                               # +0900 → UTC
    with pytest.raises(Skip):
        p(json.dumps(eve(2, et="flow")), {})                                               # flow·stats 등은 저장 안 함
    assert p(json.dumps(eve(3, et="anomaly")), {})["event"]["action"] == "ids_anomaly"


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "s.db"), "soar.worker_poll_ms": 50}))
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("adm", PW, "admin", "t")
    for sid in ("http-json", "suricata-eve"):
        p.collectors[sid] = HttpCollector(p.sources()[sid], p.pipeline, p.db, p.metrics)
        p.collectors[sid].start()
    p.pipeline.start()
    yield p, app.test_client()
    p.pipeline.stop()


def ingest(c, sid, evs):
    return c.post(f"/api/ingest/{sid}?wait=1", headers={"X-API-Key": KEY, "Content-Type": "application/x-ndjson"},
                  data="\n".join(json.dumps(e) for e in evs) + "\n").get_json()


def test_ids_rules_and_correlation_with_login(ctx):
    p, c = ctx
    r = ingest(c, "suricata-eve", [eve(i) for i in range(3)] + [eve(9, et="flow")])
    assert r["stored"] == 3                                                                # flow 는 버림
    a = p.db.one("SELECT * FROM alerts WHERE rule_id='ids_alert'")
    assert a and a["severity"] == "medium" and a["event_count"] == 3
    assert ingest(c, "suricata-eve", [eve(i) for i in range(3)])["duplicates"] == 3       # 다시 보내도 중복 저장 안 함
    # 같은 IP 가 로그인 성공 → 상관 규칙 (네트워크 + 호스트)
    ingest(c, "http-json", [{"id": "ok1", "timestamp": "2026-10-11T20:10:00Z", "src_ip": "45.33.32.156", "user": "ubuntu",
                             "outcome": "success", "category": "authentication"}])
    x = p.db.one("SELECT * FROM alerts WHERE rule_id='ids_then_login'")
    assert x and x["severity"] == "critical" and x["level_id"] == "IDS_COMPROMISE"
    assert p.db.one("SELECT incident_id FROM alerts WHERE rule_id='ids_then_login'")["incident_id"] == a["incident_id"]   # 같은 사건으로 묶임


def test_suricata_source_auto_added_once(ctx):
    p, _ = ctx
    cur = p.config.get("sources")
    cur["sources"] = [s for s in cur["sources"] if s["id"] != "suricata-eve"]
    p.config.put("sources", "default", cur, "adm", "사용 안 함 — 직접 삭제")
    p._ensure_builtin_sources()
    assert all(s["id"] != "suricata-eve" for s in p.config.get("sources")["sources"])      # 지운 뒤에는 다시 넣지 않음


class _Sink(http.server.BaseHTTPRequestHandler):
    got, fail_next = [], [0]

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"])).decode()
        if _Sink.fail_next[0] > 0:
            _Sink.fail_next[0] -= 1
            self.send_response(503); self.end_headers(); return
        assert self.headers["X-API-Key"] == KEY
        _Sink.got += [json.loads(l)["flow_id"] for l in body.splitlines() if l]
        self.send_response(202); self.end_headers()

    def log_message(self, *a):
        pass


def test_shipper_tails_retries_and_survives_rotation(tmp_path):
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    evef, state = tmp_path / "eve.json", tmp_path / "st" / "state.json"
    evef.write_text("\n".join(json.dumps(eve(i)) for i in range(2)) + "\n")              # 첫 실행 전 기록 (START_AT=start 로 포함)
    env = dict(os.environ, RKMSIEM_URL=f"http://127.0.0.1:{srv.server_port}", RKMSIEM_INGEST_KEY=KEY, EVE_PATH=str(evef),
               STATE_FILE=str(state), START_AT="start")
    _Sink.got.clear(); _Sink.fail_next[0] = 1                                              # 첫 전송은 SIEM 장애로 실패
    proc = subprocess.Popen([sys.executable, SHIP], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        def wait(n):
            end = time.time() + 15
            while len(_Sink.got) < n and time.time() < end:
                time.sleep(.1)
        wait(2)
        assert _Sink.got == [1000, 1001]                                                  # 실패 뒤 재시도로 전달
        with open(evef, "a") as f:
            f.write(json.dumps(eve(5, et="flow")) + "\n" + json.dumps(eve(6)) + "\n" + '{"event_type": "alert", "partial')   # 쓰는 중인 줄
        wait(3)
        assert _Sink.got == [1000, 1001, 1006]                                            # flow 제외 · 덜 쓴 줄은 기다림
        if os.name == "nt":
            return                                                                        # 윈도우는 열린 파일 이름을 못 바꿈 (리눅스 logrotate 시험은 아래)
        os.replace(evef, tmp_path / "eve.json.1")                                         # logrotate
        evef.write_text(json.dumps(eve(7)) + "\n")
        wait(4)
        assert _Sink.got[-1] == 1007 and len(_Sink.got) == 4
    finally:
        proc.terminate(); proc.wait(5); srv.shutdown()
    assert json.loads(state.read_text())["offset"] > 0
