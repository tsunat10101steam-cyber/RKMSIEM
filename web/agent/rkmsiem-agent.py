#!/usr/bin/env python3
"""RKMSIEM 원격 조치 에이전트 (대상 서버에서 root 로 실행, 표준 라이브러리만).

SIEM 으로 '나가서' 상태를 보고하고 할 일을 받아 온다 — 이 서버에 들어오는 포트는 열지 않는다.
  보고: 호스트·IP·부하·메모리 · 컨테이너(docker) · CPU 상위 프로세스 · 실패한 서비스
  조치: container_stop · container_restart · process_kill · service_restart  (ALLOW 에 있는 것만)

설정 /etc/rkmsiem-agent/agent.env (root 0600):
  RKMSIEM_URL=https://10.0.0.53:8443        SIEM 콘솔 주소
  RKMSIEM_TLS_FINGERPRINT=<SHA-256>          SIEM 인증서 지문 (자체 서명) — 다르면 연결하지 않음
  AGENT_TOKEN=rka_…                          등록하면 채워짐
  ALLOW=container_stop,container_restart,process_kill,service_restart     이 서버가 허용하는 조치 (비우면 보고만)
  PROTECT_SERVICES=ssh*,sshd*,systemd-*,dbus*,rkmsiem-agent*,docker*,containerd*,networking*,NetworkManager*
  PROTECT_PROCESSES=sshd,systemd,init,dockerd,containerd,rkmsiem-agent   이름(comm)이 이것이면 종료 거부
  PROTECT_CONTAINERS=                        이름 패턴 (쉼표) — 중지·재시작 거부

  rkmsiem-agent.py enroll <등록 코드>   등록 (설치 스크립트가 부름)
  rkmsiem-agent.py check                설정·연결 확인
"""
import fnmatch
import hashlib
import hmac
import http.client
import json
import os
import pwd
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse

VERSION = "1"
ENV_FILE = os.environ.get("AGENT_ENV", "/etc/rkmsiem-agent/agent.env")
ALL_ACTIONS = ("container_stop", "container_restart", "process_kill", "service_restart")
CONTAINER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SERVICE_RE = re.compile(r"^[A-Za-z0-9@._:-]{1,128}$")
running = True


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_env():
    env = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    except OSError:
        pass
    env.update({k: v for k, v in os.environ.items() if k.startswith(("RKMSIEM_", "AGENT_", "ALLOW", "PROTECT_"))})
    return env


CFG = load_env()
URL = CFG.get("RKMSIEM_URL", "").rstrip("/")
FP = CFG.get("RKMSIEM_TLS_FINGERPRINT", "").replace(":", "").strip().lower()
csv = lambda k, d="": [x.strip() for x in CFG.get(k, d).split(",") if x.strip()]
ALLOW = [a for a in csv("ALLOW", ",".join(ALL_ACTIONS)) if a in ALL_ACTIONS]
P_SERVICES = csv("PROTECT_SERVICES", "ssh*,sshd*,systemd-*,dbus*,rkmsiem-agent*,docker*,containerd*,networking*,NetworkManager*")
P_PROCS = csv("PROTECT_PROCESSES", "sshd,systemd,init,dockerd,containerd,containerd-shim,rkmsiem-agent")
P_CONTAINERS = csv("PROTECT_CONTAINERS", "")


class TLSMismatch(OSError):
    pass


class Refused(Exception):
    pass


# ---------------------------------------------------------------- SIEM 통신
def call(path, body, token=None, timeout=40):
    u = urllib.parse.urlsplit(URL)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if FP:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        conn.connect()
        if FP and not hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(), FP):
            conn.close()
            raise TLSMismatch("SIEM 인증서 지문이 다릅니다 — 연결하지 않음")
    elif u.scheme == "http":
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    else:
        raise OSError(f"RKMSIEM_URL 이 이상합니다: {URL!r}")
    try:
        hdr = {"Content-Type": "application/json", "User-Agent": f"rkmsiem-agent/{VERSION}"}
        if token:
            hdr["Authorization"] = f"Bearer {token}"
        conn.request("POST", path, body=json.dumps(body).encode(), headers=hdr)
        r = conn.getresponse()
        data = r.read(4 * 1024 * 1024)
        try:
            return r.status, json.loads(data or b"{}")
        except ValueError:
            return r.status, {"error": data[:200].decode("utf-8", "replace")}
    finally:
        conn.close()


# ---------------------------------------------------------------- 상태 수집
def sh(argv, timeout=10):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


_prev = {"t": None, "cpu": {}}
HZ = os.sysconf("SC_CLK_TCK")


def _stat(pid):
    with open(f"/proc/{pid}/stat") as f:
        s = f.read()
    comm = s[s.index("(") + 1:s.rindex(")")]
    rest = s[s.rindex(")") + 2:].split()
    return comm, int(rest[11]) + int(rest[12]), int(rest[19])        # comm, utime+stime, starttime(틱)


def processes(top=15):
    now, cur, rows = time.monotonic(), {}, []
    mem_total = meminfo().get("total", 1)
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        pid = int(d)
        try:
            comm, ticks, start = _stat(pid)
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read(400).replace(b"\0", b" ").decode("utf-8", "replace").strip()
            uid = os.stat(f"/proc/{pid}").st_uid
            with open(f"/proc/{pid}/statm") as f:
                rss = int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE")
        except (OSError, ValueError, IndexError):
            continue
        cur[(pid, start)] = ticks
        rows.append({"pid": pid, "start": start, "comm": comm, "cmd": cmd or f"[{comm}]", "uid": uid, "ticks": ticks, "rss": rss})
    dt = now - _prev["t"] if _prev["t"] else None
    for r in rows:
        before = _prev["cpu"].get((r["pid"], r["start"]))
        r["cpu"] = round((r["ticks"] - before) / HZ / dt * 100, 1) if dt and before is not None else 0.0
        r["mem"] = round(r["rss"] / 1024 / mem_total * 100, 1) if mem_total else 0.0
        try:
            r["user"] = pwd.getpwuid(r["uid"]).pw_name
        except KeyError:
            r["user"] = str(r["uid"])
        r["protected"] = r["comm"] in P_PROCS or r["pid"] in (1, os.getpid())
        del r["ticks"], r["rss"], r["uid"]
    _prev.update(t=now, cpu=cur)
    rows.sort(key=lambda r: (-r["cpu"], -r["mem"]))
    return rows[:top]


def meminfo():
    m = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":", 1)
                m[k] = int(v.split()[0])
    except OSError:
        return {}
    return {"total": m.get("MemTotal", 0), "available": m.get("MemAvailable", 0)}


def containers():
    if not shutil.which("docker"):
        return None
    rc, out, _ = sh(["docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}"])
    if rc != 0:
        return None
    rows = []
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        name = c.get("Names", "").split(",")[0]
        rows.append({"id": c.get("ID", "")[:12], "name": name, "image": c.get("Image"), "state": c.get("State"), "status": c.get("Status"),
                     "protected": any(fnmatch.fnmatch(name, p) for p in P_CONTAINERS)})
    rc, out, _ = sh(["docker", "stats", "--no-stream", "--format", "{{json .}}"], timeout=15)
    stats = {}
    for line in out.splitlines() if rc == 0 else []:
        try:
            s = json.loads(line)
            stats[s.get("Name")] = {"cpu": float(s.get("CPUPerc", "0%").rstrip("%") or 0), "mem": s.get("MemUsage")}
        except (ValueError, AttributeError):
            continue
    for r in rows:
        r.update(stats.get(r["name"], {"cpu": None, "mem": None}))
    rows.sort(key=lambda r: (r["state"] != "running", -(r["cpu"] or 0)))
    return rows[:60]


def failed_services():
    if not shutil.which("systemctl"):
        return []
    rc, out, _ = sh(["systemctl", "list-units", "--type=service", "--state=failed", "--no-legend", "--plain", "--no-pager"])
    return [line.split()[0] for line in out.splitlines() if line.strip()][:50] if rc == 0 else []


def ips():
    rc, out, _ = sh(["ip", "-4", "-o", "addr", "show", "scope", "global"])
    return [ln.split()[3].split("/")[0] for ln in out.splitlines() if len(ln.split()) > 3] if rc == 0 else []


def inventory():
    cs = containers()
    try:
        with open("/proc/loadavg") as f:
            load = [float(x) for x in f.read().split()[:3]]
        with open("/etc/os-release") as f:
            osname = next((ln.split("=", 1)[1].strip().strip('"') for ln in f if ln.startswith("PRETTY_NAME=")), "")
    except OSError:
        load, osname = None, ""
    return {"hostname": socket.gethostname(), "ips": ips(), "os": osname, "load": load, "cpus": os.cpu_count(), "mem": meminfo(),
            "docker": cs is not None, "containers": cs or [], "processes": processes(), "failed_services": failed_services(),
            "protect": {"services": P_SERVICES, "processes": P_PROCS, "containers": P_CONTAINERS}}


# ---------------------------------------------------------------- 조치
def do_container(action, p):
    name = str(p.get("container") or "")
    if not CONTAINER_RE.match(name):
        raise Refused(f"컨테이너 이름 형식이 아닙니다: {name!r}")
    if any(fnmatch.fnmatch(name, pat) for pat in P_CONTAINERS):
        raise Refused(f"보호된 컨테이너입니다 (PROTECT_CONTAINERS): {name}")
    if not shutil.which("docker"):
        raise Refused("이 서버에 docker 가 없습니다")
    verb = "stop" if action == "container_stop" else "restart"
    rc, out, err = sh(["docker", verb, "-t", "10", "--", name], timeout=60)
    if rc != 0:
        raise Refused(f"docker {verb} 실패: {(err or out).strip()[:300]}")
    rc, out, _ = sh(["docker", "inspect", "-f", "{{.State.Status}}", "--", name])
    return {"container": name, "done": verb, "state": out.strip() if rc == 0 else None}


def _gone(pid):
    """끝났는지 — 없거나 좀비(Z: 끝났고 부모가 거두기만 남음)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] in ("Z", "X")
    except OSError:
        return True


def do_kill(p):
    try:
        pid = int(p.get("pid"))
    except (TypeError, ValueError):
        raise Refused("pid 가 숫자가 아닙니다")
    if pid <= 1 or pid in (os.getpid(), os.getppid()):
        raise Refused(f"PID {pid} 는 종료할 수 없습니다")
    try:
        comm, _, start = _stat(pid)
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read(400).replace(b"\0", b" ").decode("utf-8", "replace")
    except OSError:
        raise Refused(f"PID {pid} 프로세스가 없습니다 (이미 끝남)")
    if p.get("start") is not None and int(p["start"]) != start:
        raise Refused(f"PID {pid} 는 그 사이 다른 프로세스로 바뀌었습니다 — 목록을 새로 보고 다시")
    if p.get("expect") and str(p["expect"]) not in cmd and str(p["expect"]) != comm:
        raise Refused(f"PID {pid} 의 명령이 예상과 다릅니다 ({comm})")
    if comm in P_PROCS:
        raise Refused(f"보호된 프로세스입니다 (PROTECT_PROCESSES): {comm}")
    os.kill(pid, signal.SIGTERM)
    for _ in range(50):
        time.sleep(0.1)
        if _gone(pid):
            return {"pid": pid, "comm": comm, "signal": "TERM", "exited": True}
    os.kill(pid, signal.SIGKILL)
    time.sleep(0.3)
    return {"pid": pid, "comm": comm, "signal": "KILL", "exited": _gone(pid)}


def do_service(p):
    name = str(p.get("service") or "")
    if not SERVICE_RE.match(name):
        raise Refused(f"서비스 이름 형식이 아닙니다: {name!r}")
    unit = name if "." in name else name + ".service"
    if any(fnmatch.fnmatch(unit, pat) or fnmatch.fnmatch(name, pat) for pat in P_SERVICES):
        raise Refused(f"보호된 서비스입니다 (PROTECT_SERVICES): {unit}")
    rc, out, err = sh(["systemctl", "restart", "--", unit], timeout=90)
    if rc != 0:
        raise Refused(f"systemctl restart 실패: {(err or out).strip()[:300]}")
    rc, out, _ = sh(["systemctl", "is-active", "--", unit])
    return {"service": unit, "active": out.strip()}


def execute(job):
    a, p = job.get("action"), job.get("params") or {}
    if a not in ALLOW:
        raise Refused(f"이 서버의 설정(ALLOW)에서 허용하지 않은 조치: {a}")
    if a in ("container_stop", "container_restart"):
        return do_container(a, p)
    if a == "process_kill":
        return do_kill(p)
    if a == "service_restart":
        return do_service(p)
    raise Refused(f"알 수 없는 조치: {a}")


# ---------------------------------------------------------------- 실행
def enroll(code):
    st, r = call("/api/agent/enroll", {"code": code, "hostname": socket.gethostname(), "version": VERSION})
    if st != 200 or "token" not in r:
        sys.exit(f"등록 실패 ({st}): {r.get('details') or r.get('error')}")
    lines = [ln for ln in open(ENV_FILE).read().splitlines() if not ln.startswith("AGENT_TOKEN=")] if os.path.exists(ENV_FILE) else []
    lines.append(f"AGENT_TOKEN={r['token']}")
    old = os.umask(0o077)
    with open(ENV_FILE + ".tmp", "w") as f:
        f.write("\n".join(lines) + "\n")
    os.umask(old)
    os.replace(ENV_FILE + ".tmp", ENV_FILE)
    os.chmod(ENV_FILE, 0o600)
    print(f"등록됨: 에이전트 이름 '{r['name']}'")


def main():
    token = CFG.get("AGENT_TOKEN", "")
    if not token:
        sys.exit(f"AGENT_TOKEN 이 없습니다 — {sys.argv[0]} enroll <등록 코드>")
    signal.signal(signal.SIGTERM, lambda *_: globals().__setitem__("running", False))
    log(f"시작: {URL} · 허용 조치 {', '.join(ALLOW) or '없음(보고만)'}")
    backoff, pending = 2, []
    while running:
        try:
            for res in pending[:]:
                st, _ = call(f"/api/agent/jobs/{res['id']}/result", {k: res[k] for k in ("ok", "result", "error")}, token, timeout=15)
                if st in (200, 404):
                    pending.remove(res)
            st, r = call("/api/agent/poll", {"inventory": inventory(), "allow": ALLOW, "version": VERSION, "results_pending": bool(pending)}, token)
            if st == 401:
                log("토큰이 거부됨 (콘솔에서 해제되었나요?) — 5분 뒤 다시")
                time.sleep(300)
                continue
            if st != 200:
                raise OSError(f"poll {st}: {r.get('error')}")
            for job in r.get("jobs") or []:
                log(f"작업 #{job['id']} {job['action']} {json.dumps(job.get('params'), ensure_ascii=False)}")
                try:
                    res = {"id": job["id"], "ok": True, "result": execute(job), "error": None}
                except Refused as e:
                    res = {"id": job["id"], "ok": False, "result": {}, "error": str(e)}
                except Exception as e:                  # noqa: BLE001
                    res = {"id": job["id"], "ok": False, "result": {}, "error": f"{type(e).__name__}: {e}"}
                log(f"  → {'성공' if res['ok'] else '실패: ' + res['error']}")
                pending.append(res)
            backoff = 2
            if not pending and not r.get("jobs"):
                time.sleep(1)
        except TLSMismatch as e:
            log(f"✘ {e}")
            time.sleep(60)
        except (OSError, ValueError, http.client.HTTPException) as e:
            log(f"연결 실패: {e} — {backoff}초 뒤 다시")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "enroll":
        enroll(sys.argv[2])
    elif len(sys.argv) >= 2 and sys.argv[1] == "check":
        print(json.dumps({"url": URL, "fingerprint": FP or None, "allow": ALLOW, "token": bool(CFG.get("AGENT_TOKEN")),
                          "inventory": {k: v for k, v in inventory().items() if k != "processes"}}, ensure_ascii=False, indent=1))
    else:
        main()
