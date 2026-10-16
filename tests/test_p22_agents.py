"""P22: 원격 조치 에이전트 — 실제 API 서버 + 실제 에이전트 프로세스(가짜 docker·systemctl)로 등록·보고·조치·거부·해제."""
import io
import json
import os
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request

import pytest
from waitress import create_server

from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENT = os.path.join(ROOT, "web", "agent", "rkmsiem-agent.py")

FAKE_DOCKER = r'''#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$1" in
  ps) echo '{"ID":"abc123def456","Names":"miner","Image":"xmrig:latest","State":"running","Status":"Up 5 minutes"}'
      echo '{"ID":"0011aa22bb33","Names":"db","Image":"postgres:16","State":"running","Status":"Up 2 hours"}' ;;
  stats) echo '{"Name":"miner","CPUPerc":"398.50%","MemUsage":"50MiB / 3GiB"}'
         echo '{"Name":"db","CPUPerc":"1.20%","MemUsage":"300MiB / 3GiB"}' ;;
  stop|restart) exit 0 ;;
  inspect) echo exited ;;
esac
'''
FAKE_SYSTEMCTL = r'''#!/bin/sh
echo "$@" >> "$FAKE_LOG"
case "$1" in
  list-units) echo "nginx.service loaded failed failed A high performance web server" ;;
  restart) exit 0 ;;
  is-active) echo active ;;
esac
'''


@pytest.fixture
def env(tmp_path, config_dir):
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "a.db"), "soar.mode": "live"}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("adm", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    srv = create_server(app, host="127.0.0.1", port=0, threads=8)
    threading.Thread(target=srv.run, daemon=True).start()
    base = f"http://127.0.0.1:{srv.effective_port}"
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("adm", "ana")}
    fake = tmp_path / "bin"
    fake.mkdir()
    for n, body in (("docker", FAKE_DOCKER), ("systemctl", FAKE_SYSTEMCTL)):
        (fake / n).write_text(body)
        (fake / n).chmod(0o755)
    procs = []
    yield p, c, (lambda u: {"Authorization": f"Bearer {tok[u]}"}), base, tmp_path, fake, procs
    for pr in procs:
        pr.kill()
    srv.close()
    p.terminal.stop()


def start_agent(base, tmp_path, fake, procs, code, allow="container_stop,container_restart,process_kill,service_restart"):
    envf = tmp_path / "agent.env"
    envf.write_text(f"RKMSIEM_URL={base}\nALLOW={allow}\nPROTECT_CONTAINERS=db\n")
    e = dict(os.environ, AGENT_ENV=str(envf), PATH=f"{fake}:{os.environ['PATH']}", FAKE_LOG=str(tmp_path / "fake.log"))
    out = subprocess.run([sys.executable, AGENT, "enroll", code], env=e, capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    assert "AGENT_TOKEN=rka_" in envf.read_text() and oct(envf.stat().st_mode)[-3:] == "600"
    pr = subprocess.Popen([sys.executable, AGENT], env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    procs.append(pr)
    return pr


def wait_for(fn, t=20):
    end = time.time() + t
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.3)
    raise AssertionError("시간 초과")


def test_agent_enroll_report_and_remote_actions(env):
    p, c, H, base, tmp_path, fake, procs = env
    assert c.post("/api/agents", headers=H("ana"), json={"name": "ids-server"}).status_code == 403
    assert c.post("/api/agents", headers=H("adm"), json={"name": "Bad Name"}).status_code == 400
    code = c.post("/api/agents", headers=H("adm"), json={"name": "ids-server"}).get_json()["code"]
    start_agent(base, tmp_path, fake, procs, code)
    # 같은 코드는 한 번만
    r = urllib.request.Request(base + "/api/agent/enroll", data=json.dumps({"code": code}).encode(), headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(r)
    assert e.value.code == 401

    a = wait_for(lambda: (x := c.get("/api/agents/ids-server", headers=H("ana")).get_json()) and x["online"] and x["info"].get("containers") and x)
    assert a["allow"] == ["container_stop", "container_restart", "process_kill", "service_restart"]
    miner = next(x for x in a["info"]["containers"] if x["name"] == "miner")
    assert miner["cpu"] == 398.5 and next(x for x in a["info"]["containers"] if x["name"] == "db")["protected"]
    assert a["info"]["failed_services"] == ["nginx.service"] and a["info"]["processes"]

    act = lambda u, **b: c.post("/api/agents/ids-server/actions", headers=H(u), json=b)
    assert act("ana", action="container_stop", container="miner", reason="x").status_code == 403
    assert act("adm", action="container_stop", container="miner").status_code == 400                     # 사유 필수
    r = act("adm", action="container_stop", container="miner", reason="크립토재킹 의심 CPU 398%")
    assert r.status_code == 200, r.get_json()
    assert r.get_json()["output"]["done"] == "stop"
    assert "stop -t 10 -- miner" in (tmp_path / "fake.log").read_text()

    r = act("adm", action="container_restart", container="db", reason="x")                              # 대상 서버가 보호
    assert r.status_code == 409 and "보호된 컨테이너" in r.get_json()["details"]
    r = act("adm", action="container_stop", container="miner; rm -rf /", reason="x")
    assert r.status_code == 409 and "형식" in r.get_json()["details"]
    r = act("adm", action="service_restart", service="nginx", reason="실패 상태 복구")
    assert r.status_code == 200 and r.get_json()["output"]["active"] == "active"
    r = act("adm", action="service_restart", service="sshd", reason="x")
    assert r.status_code == 409 and "보호된 서비스" in r.get_json()["details"]

    victim = subprocess.Popen(["sleep", "300"])
    procs.append(victim)
    with open(f"/proc/{victim.pid}/stat") as f:
        start = int(f.read().rsplit(")", 1)[1].split()[19])
    r = act("adm", action="process_kill", pid=victim.pid, start=start + 1, expect="sleep", reason="x")    # PID 재사용 방지
    assert r.status_code == 409 and "바뀌었습니다" in r.get_json()["details"]
    r = act("adm", action="process_kill", pid=victim.pid, start=start, expect="sleep", reason="채굴 프로세스")
    assert r.status_code == 200 and r.get_json()["output"]["exited"] is True
    assert victim.wait(5) is not None

    jobs = c.get("/api/agents/ids-server", headers=H("adm")).get_json()["jobs"]
    assert [(j["action"], j["state"]) for j in jobs][:4] == [("process_kill", "succeeded"), ("process_kill", "failed"), ("service_restart", "failed"), ("service_restart", "succeeded")]
    assert jobs[0]["requested_by"] == "adm" and jobs[0]["reason"] == "채굴 프로세스"
    assert [x for x in p.audit.list(200) if x["action"] == "manual.container_stop"]

    assert c.delete("/api/agents/ids-server", headers=H("adm")).status_code == 200
    wait_for(lambda: not c.get("/api/agents", headers=H("adm")).get_json()["items"])
    r = act("adm", action="container_stop", container="miner", reason="x")
    assert r.status_code == 409 and "없습니다" in r.get_json()["details"]


def test_agent_policy_limits_and_simulate(env, monkeypatch):
    p, c, H, base, tmp_path, fake, procs = env
    code = c.post("/api/agents", headers=H("adm"), json={"name": "web-01"}).get_json()["code"]
    start_agent(base, tmp_path, fake, procs, code, allow="")                                               # 보고만
    wait_for(lambda: c.get("/api/agents/web-01", headers=H("adm")).get_json()["online"])
    r = c.post("/api/agents/web-01/actions", headers=H("adm"), json={"action": "container_stop", "container": "miner", "reason": "x"})
    assert r.status_code == 409 and "허용하지 않았습니다" in r.get_json()["details"]
    assert c.post("/api/agent/poll", json={}).status_code == 401                                            # 토큰 없이 못 붙음
    assert c.post("/api/agent/poll", headers=H("adm"), json={}).status_code == 401                          # 사람 세션 토큰도 안 됨


def test_agent_package_hash_and_contents(env):
    p, c, H, *_ = env
    r = c.get("/agent/rkmsiem-agent.tgz")
    assert r.status_code == 200
    import hashlib
    sha = hashlib.sha256(r.data).hexdigest()
    assert r.headers["X-Content-SHA256"] == sha == c.get("/api/agents", headers=H("adm")).get_json()["install"]["sha256"]
    assert c.get("/agent/rkmsiem-agent.tgz").data == r.data                                                 # 같은 내용이면 같은 해시
    names = tarfile.open(fileobj=io.BytesIO(r.data)).getnames()
    assert sorted(names) == ["rkmsiem-agent/install-agent.sh", "rkmsiem-agent/rkmsiem-agent.py", "rkmsiem-agent/rkmsiem-agent.service"]
