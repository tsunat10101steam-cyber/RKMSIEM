"""P25: 윈도우 클라이언트 소켓 서버 — 등록·인증·하트비트·작업 푸시·결과·텔레메트리.
실제 RKMSIEM 플랫폼(Agents·pipeline) + 평문 소켓 클라이언트(TLS 는 ssl 래핑만 다름)."""
import json
import socket
import time

import pytest

from rkmsiem.agent_socket import AgentSocketServer
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings


@pytest.fixture
def srv(tmp_path, config_dir):
    p = Platform(load_settings(config_dir, overrides={
        "database.path": str(tmp_path / "a.db"), "soar.mode": "live",
        "agent_socket.enabled": True, "agent_socket.tls": False,
        "agent_socket.host": "127.0.0.1", "agent_socket.port": 0,
        "agent_socket.job_wait_sec": 5,
    }))
    p.start(collectors=True)
    s = AgentSocketServer(p, load_settings(config_dir, overrides={
        "database.path": str(tmp_path / "a.db"),
        "agent_socket.tls": False, "agent_socket.host": "127.0.0.1", "agent_socket.port": 0,
        "agent_socket.job_wait_sec": 5,
    }))
    s.p = p
    s.start()
    yield p, s
    s.stop()
    p.stop()


class Client:
    def __init__(self, port):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self.f = self.sock.makefile("rb")

    def send(self, obj):
        self.sock.sendall((json.dumps(obj) + "\n").encode())

    def recv(self, want=None, tries=100):
        for _ in range(tries):
            line = self.f.readline()
            if not line:
                raise AssertionError("연결이 닫힘")
            msg = json.loads(line)
            if want is None or msg.get("t") == want:
                return msg
        raise AssertionError(f"'{want}' 메시지를 못 받음")

    def close(self):
        self.sock.close()


def test_enroll_hello_job_result_telemetry(srv):
    p, s = srv
    code = p.agents.create_enroll("win1", "root")["code"]

    # 등록 → 토큰
    c = Client(s.port)
    c.send({"t": "enroll", "code": code, "hostname": "WIN-PC", "version": "1"})
    tok = c.recv("enrolled")["token"]
    assert tok.startswith("rka_")
    c.close()

    # 재접속 hello + allow 보고 → 온라인
    c = Client(s.port)
    c.send({"t": "hello", "token": tok, "version": "1",
            "allow": ["process_kill"], "inventory": {"hostname": "WIN-PC", "os": "windows"}})
    assert c.recv("welcome")["name"] == "win1"

    # 서버가 조치 요청 → 소켓으로 즉시 job 푸시
    job_id = p.agents.submit("win1", "process_kill", {"pid": 4321}, "root", reason="테스트")
    job = c.recv("job")
    assert job["id"] == job_id and job["action"] == "process_kill" and job["params"]["pid"] == 4321

    # 결과 보고 → SIEM 쪽에서 성공으로 마감
    c.send({"t": "result", "id": job_id, "ok": True, "result": {"killed": 4321}, "error": None})
    for _ in range(50):
        r = p.db.one("SELECT state, result FROM agent_jobs WHERE id=?", (job_id,))
        if r["state"] == "succeeded":
            break
        time.sleep(0.05)
    assert r["state"] == "succeeded" and json.loads(r["result"])["killed"] == 4321

    # 텔레메트리 → 파이프라인으로 들어가 이벤트로 저장
    before = p.db.scalar("SELECT COUNT(*) FROM events")
    c.send({"t": "telemetry", "source": "http-json", "events": [
        {"id": "w-1", "timestamp": "2026-10-19T00:00:01Z", "src_ip": "10.0.0.44", "user": "nmgt", "outcome": "failure", "category": "authentication"},
        {"id": "w-2", "timestamp": "2026-10-19T00:00:02Z", "src_ip": "10.0.0.44", "user": "nmgt", "outcome": "failure", "category": "authentication"},
    ]})
    for _ in range(60):
        if p.db.scalar("SELECT COUNT(*) FROM events") >= before + 2:
            break
        time.sleep(0.05)
    assert p.db.scalar("SELECT COUNT(*) FROM events") >= before + 2
    c.close()


def test_bad_token_rejected(srv):
    p, s = srv
    c = Client(s.port)
    c.send({"t": "hello", "token": "rka_nope"})
    assert c.recv("error")["error"] == "bad_token"
    c.close()


def test_garbage_first_message_rejected(srv):
    p, s = srv
    c = Client(s.port)
    c.send({"t": "nonsense"})
    assert "error" in c.recv("error")
    c.close()


def _load_winagent():
    import importlib.util
    import os
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web", "winagent", "rkmsiem-winagent.py")
    spec = importlib.util.spec_from_file_location("winagent", path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_windows_client_enrolls_and_executes_job(srv, tmp_path):
    """실제 윈도우 클라이언트 코드(stdlib)를 평문 소켓으로 서버에 붙여: 등록 → 작업 수신 → (가짜 taskkill) 실행 → 결과."""
    import threading
    import time
    wa = _load_winagent()
    p, s = srv
    code = p.agents.create_enroll("winpc", "root")["code"]

    ran = []

    def fake_run(argv, timeout=20):
        ran.append(argv)
        if argv[0] == "tasklist":
            return 0, '"notepad.exe","4321","Console","1","12,000 K"\n'
        return 0, ""                                             # taskkill 성공

    env = {"RKMSIEM_HOST": "127.0.0.1", "RKMSIEM_PORT": str(s.port), "RKMSIEM_INSECURE": "1",
           "ENROLL_CODE": code, "ALLOW": "process_kill,service_restart", "STATE_DIR": str(tmp_path / "wa")}
    cli = wa.AgentClient("127.0.0.1", s.port, env, run=fake_run)
    th = threading.Thread(target=cli.run_forever, daemon=True)
    th.start()

    # 온라인이 될 때까지 기다렸다가 조치 요청
    for _ in range(100):
        a = p.db.one("SELECT last_seen, allow FROM agents WHERE name='winpc'")
        if a and a["last_seen"] and "process_kill" in (a["allow"] or ""):
            break
        time.sleep(0.05)
    assert a and a["last_seen"], "클라이언트가 온라인이 안 됨"

    job_id = p.agents.submit("winpc", "process_kill", {"pid": 4321}, "root", reason="악성 프로세스")
    for _ in range(100):
        r = p.db.one("SELECT state, result FROM agent_jobs WHERE id=?", (job_id,))
        if r["state"] in ("succeeded", "failed"):
            break
        time.sleep(0.05)
    cli.stop.set()
    assert r["state"] == "succeeded", f"결과: {r['state']}"
    assert json.loads(r["result"])["pid"] == 4321
    assert ["taskkill", "/PID", "4321", "/F", "/T"] in ran                 # 실제로 taskkill 을 호출


def test_windows_client_refuses_protected_process(srv, tmp_path):
    """보호된 프로세스(lsass)는 클라이언트가 스스로 거부 — 서버가 털려도 못 죽임."""
    import threading
    import time
    wa = _load_winagent()
    p, s = srv
    code = p.agents.create_enroll("winpc2", "root")["code"]

    def fake_run(argv, timeout=20):
        if argv[0] == "tasklist":
            return 0, '"lsass.exe","700","Services","0","20,000 K"\n'
        return 0, ""

    env = {"RKMSIEM_HOST": "127.0.0.1", "RKMSIEM_PORT": str(s.port), "RKMSIEM_INSECURE": "1",
           "ENROLL_CODE": code, "ALLOW": "process_kill", "STATE_DIR": str(tmp_path / "wa2")}
    cli = wa.AgentClient("127.0.0.1", s.port, env, run=fake_run)
    threading.Thread(target=cli.run_forever, daemon=True).start()
    for _ in range(100):
        a = p.db.one("SELECT last_seen, allow FROM agents WHERE name='winpc2'")
        if a and a["last_seen"] and "process_kill" in (a["allow"] or ""):
            break
        time.sleep(0.05)

    job_id = p.agents.submit("winpc2", "process_kill", {"pid": 700}, "root")
    for _ in range(100):
        r = p.db.one("SELECT state, error FROM agent_jobs WHERE id=?", (job_id,))
        if r["state"] in ("succeeded", "failed"):
            break
        time.sleep(0.05)
    cli.stop.set()
    assert r["state"] == "failed" and "보호된 프로세스" in (r["error"] or "")
