"""P7 통합: 실제 HTTP 서버 · UDP · 파일 수집 · SSE 를 띄워 전체 흐름을 검증 + 재시작 · 대량 입력 · 보존 정책 · 화면 데이터 일치."""
import json
import os
import socket
import threading
import time
import urllib.request

import pytest
from werkzeug.serving import make_server

from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings
from rkmsiem import yamlio

PW = "integration-pass-123"
KEY = "integration-ingest-key-0001"


def free_port(kind=socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture
def server(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    # 수집 소스를 테스트용으로: 임시 파일 · 임의 UDP 포트 · HTTP
    log = tmp_path / "auth.log"
    log.write_text("", encoding="utf-8")
    src = yamlio.load_file(os.path.join(config_dir, "sources.yaml"))
    udp = free_port(socket.SOCK_DGRAM)
    for s in src["sources"]:
        if s["type"] == "file":
            s["options"]["path"] = str(log)
            s["options"]["poll_sec"] = 0.1
        if s["type"] == "syslog_udp":
            s["options"]["port"] = udp
    with open(os.path.join(config_dir, "sources.yaml"), "w", encoding="utf-8") as f:
        f.write(yamlio.dumps(src))
    st = load_settings(config_dir, overrides={"database.path": str(tmp_path / "e2e.db"), "soar.worker_poll_ms": 50})
    p = Platform(st)
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("ops", PW, "admin", "test")
    app.extensions["rkmsiem_auth"].create_user("resp", PW, "responder", "test")
    p.start(collectors=True)
    port = free_port()
    srv = make_server("127.0.0.1", port, app, threaded=True)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    yield {"p": p, "base": f"http://127.0.0.1:{port}", "udp": udp, "log": log, "settings": st, "tmp": tmp_path}
    srv.shutdown()
    p.stop()


def call(base, path, method="GET", body=None, token=None, headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def login(base, user):
    return call(base, "/api/auth/login", "POST", {"username": user, "password": PW})[1]["token"]


def wait(cond, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        r = cond()
        if r:
            return r
        time.sleep(.1)
    return None


def test_full_flow_over_real_network(server):
    base, p = server["base"], server["p"]
    tok, rtok = login(base, "ops"), login(base, "resp")
    # SSE 를 실제 HTTP 로 구독
    _, t = call(base, "/api/stream/ticket", "POST", token=tok)
    got = []

    def listen():
        with urllib.request.urlopen(f"{base}/api/stream?ticket={t['ticket']}", timeout=30) as r:
            ev = None
            for raw in r:
                line = raw.decode().strip()
                if line.startswith("event:"):
                    ev = line[6:].strip()
                elif line.startswith("data:") and ev:
                    got.append((ev, json.loads(line[5:])))
                    if ev == "run" and got[-1][1]["data"]["state"] == "waiting_approval":
                        return
    th = threading.Thread(target=listen, daemon=True)
    th.start()
    time.sleep(.5)
    # 1) 파일 수집기: 반복 실패
    with open(server["log"], "a", encoding="utf-8") as f:
        for i in range(6):
            f.write(f"2026-10-12 01:12:{i:02d} FAIL user=backup ip=103.75.190.8\n")
    assert wait(lambda: p.db.scalar("SELECT COUNT(*) FROM events WHERE source_ip='103.75.190.8'") == 6)
    # 2) UDP syslog: 같은 IP 의 sshd 로그인 성공 (서로 다른 수집기에서 온 이벤트가 하나의 상관분석으로 이어짐)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"<38>1 2026-10-11T16:12:30Z gw sshd 9 - - Accepted password for backup from 103.75.190.8 port 2222 ssh2",
             ("127.0.0.1", server["udp"]))
    s.close()
    # 실패 5회 → high 사건, 이어서 성공 이벤트 → critical 로 상향될 때까지 대기
    inc = wait(lambda: [i for i in call(base, "/api/incidents", token=tok)[1]["items"] if i["severity"] == "critical"] or None)
    assert inc and len(call(base, "/api/incidents", token=tok)[1]["items"]) == 1
    run = wait(lambda: next((r for r in call(base, f"/api/runs?incident_id={inc[0]['id']}", token=tok)[1]["items"]
                             if r["state"] == "waiting_approval"), None))
    assert run, "플레이북이 승인 대기 상태가 되어야 함"
    th.join(10)
    kinds = {k for k, _ in got}
    assert {"ingest", "alert", "incident", "run"} <= kinds                      # 실시간 화면으로 전달된 이벤트
    # 3) 승인 (대응 담당자) → 다음 승인 → 완료
    for step in ("block_ip", "disable_account"):
        wait(lambda: call(base, f"/api/runs/{run['id']}", token=tok)[1]["state"] == "waiting_approval")
        code, _ = call(base, f"/api/runs/{run['id']}/steps/{step}/decision", "POST", {"approve": True, "reason": "e2e"}, token=rtok)
        assert code == 200
    assert wait(lambda: call(base, f"/api/runs/{run['id']}", token=tok)[1]["state"] == "succeeded")
    _, d = call(base, f"/api/incidents/{inc[0]['id']}", token=tok)
    srcs = {e["source_id"] for a in d["alerts"] for e in call(base, f"/api/alerts/{a['id']}", token=tok)[1]["evidence_events"]}
    assert {"sample-authlog", "syslog-udp"} <= srcs                              # 두 수집기의 근거가 한 사건에
    assert call(base, "/api/audit/verify", token=tok)[1]["ok"]
    # 4) 화면용 집계 = DB 실제 값
    _, ov = call(base, "/api/overview?from=0", token=tok)
    assert ov["totals"]["events"] == p.db.scalar("SELECT COUNT(*) FROM events")
    assert ov["totals"]["alerts"] == p.db.scalar("SELECT COUNT(*) FROM alerts")
    assert sum(x["fail"] for x in ov["series"]) == p.db.scalar("SELECT COUNT(*) FROM events WHERE outcome='failure'")
    code, ready = call(base, "/readyz")
    assert code == 200 and ready["ready"]


def test_bulk_ingest_throughput_and_backpressure(server):
    base, p = server["base"], server["p"]
    tok = login(base, "ops")
    n, batch, t0 = 5000, 500, time.time()
    for b in range(0, n, batch):
        evs = [{"id": f"bulk-{i}", "timestamp": f"2026-10-12T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z",
                "src_ip": f"198.18.{i % 250}.{(i // 250) % 250 + 1}", "user": f"u{i % 40}", "outcome": "failure", "category": "authentication"}
               for i in range(b, b + batch)]
        code, _ = call(base, "/api/ingest/http-json", "POST", evs, headers={"X-API-Key": KEY})
        assert code in (202, 429)
    assert wait(lambda: p.db.scalar("SELECT COUNT(*) FROM events WHERE source_id='http-json'") == n, 60)
    rate = n / (time.time() - t0)
    _, c = call(base, "/api/collectors", token=tok)
    assert c["pipeline"]["stored"] >= n and c["pipeline"]["dlq_pending"] == 0
    print(f"\n[bulk] {n} events in {time.time() - t0:.1f}s → {rate:.0f} ev/s")
    assert rate > 200                                                             # 로컬 단일 노드 최소 기대치


def test_restart_continues_detection(server):
    p, st = server["p"], server["settings"]
    with open(server["log"], "a", encoding="utf-8") as f:
        for i in range(6):
            f.write(f"2026-10-12 02:00:{i:02d} FAIL user=ops ip=203.0.113.10\n")
    assert wait(lambda: p.db.scalar("SELECT COUNT(*) FROM alerts WHERE rule_id='auth_bruteforce'") == 1)
    p.stop()                                                                     # 재시작
    p2 = Platform(st)
    p2.start(collectors=True)
    try:
        with open(server["log"], "a", encoding="utf-8") as f:
            for i in range(6, 12):
                f.write(f"2026-10-12 02:00:{i:02d} FAIL user=ops ip=203.0.113.10\n")
        assert wait(lambda: p2.db.scalar("SELECT level_id FROM alerts WHERE rule_id='auth_bruteforce'") == "BRUTEFORCE_HIGH")
        assert p2.db.scalar("SELECT COUNT(*) FROM alerts WHERE rule_id='auth_bruteforce'") == 1        # 같은 경보가 이어서 상향
        assert p2.db.scalar("SELECT COUNT(*) FROM events WHERE source_id='sample-authlog'") == 12       # 재시작 후 중복 수집 없음
    finally:
        p2.stop()


def test_retention_archives_and_keeps_audit(server):
    p = server["p"]
    with open(server["log"], "a", encoding="utf-8") as f:
        f.write("2026-10-12 03:00:00 FAIL user=a ip=203.0.113.99\n")
    assert wait(lambda: p.db.scalar("SELECT COUNT(*) FROM events") >= 1)
    audit_before = p.db.scalar("SELECT COUNT(*) FROM audit_log")
    rep = p.apply_retention(now=time.time() + 400 * 86400)                       # 400일 뒤라고 가정
    assert rep.get("events", 0) >= 1 and p.db.scalar("SELECT COUNT(*) FROM events") == 0
    arch = server["settings"].path("retention.archive_dir")
    assert any(f.startswith("events-") for f in os.listdir(arch))
    assert p.db.scalar("SELECT COUNT(*) FROM audit_log") > audit_before          # 감사 로그는 남고 기록이 추가됨
