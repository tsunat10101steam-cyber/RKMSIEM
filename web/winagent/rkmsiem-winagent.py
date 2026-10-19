#!/usr/bin/env python3
"""RKMSIEM 윈도우 클라이언트 (엔드포인트 에이전트) — TLS 소켓으로 SIEM 서버에 '나가서' 붙는다.

리눅스=서버, 윈도우=클라이언트. 표준 라이브러리만 사용 (PyInstaller 로 단일 exe).
  서버 → 클라이언트 : job (process_kill · service_restart) · ping
  클라이언트 → 서버 : hello|enroll · heartbeat(inventory·allow) · result · telemetry · pong

설정: 환경변수 또는 %ProgramData%\\RKMSIEM\\winagent.env (KEY=VALUE 줄)
  RKMSIEM_HOST=10.0.0.53            서버 주소 (필수)
  RKMSIEM_PORT=8452                 소켓 포트
  RKMSIEM_FINGERPRINT=<sha256 hex>  서버 인증서 지문 (자체 서명이면 필수 — 핀) · sudo /usr/share/rkmsiem/deploy/tls.sh --show
  ENROLL_CODE=rke_...               첫 실행 등록 코드 (콘솔에서 발급, 1회용) — 성공하면 토큰을 저장하고 다음부터 불필요
  ALLOW=process_kill,service_restart     이 PC 가 허용하는 조치 (비우면 보고·텔레메트리만)
  PROTECT_PROCESSES=System,wininit,csrss,services,lsass,winlogon,rkmsiem-winagent   종료 거부 (이미지 이름)
  PROTECT_SERVICES=WinDefend,RpcSs,Dnscache,LanmanServer,EventLog                   재시작 거부
  TELEMETRY=1                       보안 로그(실패 로그온 4625)를 서버로 올림
  STATE_DIR=...                     토큰 저장 위치 (기본 %ProgramData%\\RKMSIEM)
"""
import hashlib
import hmac
import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import threading
import time

VERSION = "1"
ALL_ACTIONS = ("process_kill", "service_restart")
HEARTBEAT_SEC = 30
TELEMETRY_SEC = 20
RECONNECT_MAX = 60


# ------------------------------------------------------------------ 설정
def _state_dir():
    d = os.environ.get("STATE_DIR")
    if d:
        return d
    base = os.environ.get("ProgramData") or os.path.expanduser("~")
    return os.path.join(base, "RKMSIEM")


def load_env():
    env = {}
    path = os.environ.get("WINAGENT_ENV") or os.path.join(_state_dir(), "winagent.env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    env.update({k: v for k, v in os.environ.items()
                if k in ("RKMSIEM_HOST", "RKMSIEM_PORT", "RKMSIEM_FINGERPRINT", "ENROLL_CODE",
                         "ALLOW", "PROTECT_PROCESSES", "PROTECT_SERVICES", "TELEMETRY", "STATE_DIR", "RKMSIEM_INSECURE")})
    return env


def csv(env, key, default=""):
    return [x.strip() for x in env.get(key, default).split(",") if x.strip()]


# ------------------------------------------------------------------ 조치 실행 (윈도우)
def run_cmd(argv, timeout=20):
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)


class Refused(Exception):
    pass


class Executor:
    """조치 실행기 — run 은 테스트에서 주입 가능. ALLOW·PROTECT_* 로 스스로 거부한다."""

    def __init__(self, env, run=run_cmd):
        self.run = run
        self.allow = [a for a in csv(env, "ALLOW", ",".join(ALL_ACTIONS)) if a in ALL_ACTIONS]
        self.p_procs = [x.lower() for x in csv(env, "PROTECT_PROCESSES",
                        "System,wininit,csrss,services,lsass,winlogon,smss,rkmsiem-winagent")]
        self.p_svcs = [x.lower() for x in csv(env, "PROTECT_SERVICES",
                       "WinDefend,RpcSs,Dnscache,LanmanServer,EventLog,Schedule")]

    def execute(self, action, params):
        if action not in self.allow:
            raise Refused(f"이 PC 설정(ALLOW)에서 허용하지 않은 조치: {action}")
        return getattr(self, f"do_{action}")(params)

    def do_process_kill(self, p):
        pid = int(p.get("pid"))
        name = self._image(pid)
        if name and name.lower() in self.p_procs:
            raise Refused(f"보호된 프로세스입니다 (PROTECT_PROCESSES): {name}")
        rc, out = self.run(["taskkill", "/PID", str(pid), "/F", "/T"])
        if rc != 0:
            raise Refused(f"taskkill 실패(rc={rc}): {out.strip()[:200]}")
        return {"pid": pid, "image": name}

    def do_service_restart(self, p):
        svc = str(p.get("service"))
        if svc.lower() in self.p_svcs:
            raise Refused(f"보호된 서비스입니다 (PROTECT_SERVICES): {svc}")
        self.run(["sc", "stop", svc])
        time.sleep(1)
        rc, out = self.run(["sc", "start", svc])
        if rc != 0:
            raise Refused(f"sc start 실패(rc={rc}): {out.strip()[:200]}")
        return {"service": svc}

    def _image(self, pid):
        rc, out = self.run(["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"])
        if rc == 0 and out.strip().startswith('"'):
            try:
                return out.strip().split('","')[0].strip('"').rsplit(".", 1)[0]
            except (IndexError, ValueError):
                return None
        return None


def inventory():
    return {"hostname": socket.gethostname(), "os": platform.platform(),
            "ips": _ips(), "agent_version": VERSION}


def _ips():
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(socket.gethostname(), None)})
    except OSError:
        return []


def collect_security_events(run=run_cmd):
    """보안 로그 실패 로그온(4625) → 정규화 이벤트 (최근 것만). 윈도우 아니면 []"""
    if platform.system() != "Windows":
        return []
    rc, out = run(["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/c:20", "/rd:true", "/f:text"], timeout=15)
    if rc != 0:
        return []
    evs, cur = [], {}
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("Account Name:") and "user" not in cur:
            cur["user"] = s.split(":", 1)[1].strip()
        elif s.startswith("Source Network Address:"):
            cur["src_ip"] = s.split(":", 1)[1].strip()
        elif s.startswith("Date:"):
            cur["timestamp"] = s.split(":", 1)[1].strip()
            if cur.get("user") and cur["user"] != "-":
                evs.append({"id": hashlib.sha1(line.encode()).hexdigest()[:16], "src_ip": cur.get("src_ip", ""),
                            "user": cur["user"], "outcome": "failure", "category": "authentication"})
            cur = {}
    return evs


# ------------------------------------------------------------------ 소켓 클라이언트
class AgentClient:
    def __init__(self, host, port, env, executor=None, run=run_cmd):
        self.host, self.port, self.env = host, int(port), env
        self.run = run
        self.ex = executor or Executor(env, run)
        self.fp = (env.get("RKMSIEM_FINGERPRINT") or "").replace(":", "").lower()
        self.insecure = env.get("RKMSIEM_INSECURE") == "1"
        self.state_dir = env.get("STATE_DIR") or _state_dir()
        self.sock = self.f = None
        self.wlock = threading.Lock()
        self.stop = threading.Event()
        self.telemetry = env.get("TELEMETRY") == "1"

    # 연결 (TLS 지문 핀) — tls 없이 쓰려면 RKMSIEM_INSECURE=1
    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=20)
        if self.insecure:
            self.sock = raw
        else:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE                         # 자체 서명 — 지문으로 직접 확인
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
            if not self.fp:
                raise OSError("RKMSIEM_FINGERPRINT 가 없습니다 — 서버 인증서 지문을 넣거나 RKMSIEM_INSECURE=1 (내부망 전용)")
            got = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(got, self.fp):
                self.sock.close()
                raise OSError("서버 인증서 지문이 다릅니다 — 연결하지 않음")
        self.sock.settimeout(HEARTBEAT_SEC * 3)
        self.f = self.sock.makefile("rb")

    def send(self, obj):
        data = (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self.wlock:
            self.sock.sendall(data)

    def _recv(self):
        line = self.f.readline(1 << 20)
        if not line:
            return None
        try:
            obj = json.loads(line)
        except ValueError:
            return {}
        return obj if isinstance(obj, dict) else {}

    # 토큰 저장/로드 (STATE_DIR — 설정에서 정한 위치)
    def _token_path(self):
        return os.path.join(self.state_dir, "token")

    def _load_token(self):
        try:
            with open(self._token_path(), encoding="utf-8") as f:
                return f.read().strip() or None
        except OSError:
            return None

    def _save_token(self, tok):
        os.makedirs(self.state_dir, exist_ok=True)
        with open(self._token_path(), "w", encoding="utf-8") as f:
            f.write(tok)

    def _drop_token(self):
        try:
            os.remove(self._token_path())
        except OSError:
            pass

    def handshake(self):
        """토큰이 있으면 hello(→welcome), 없거나 거부되면 enroll(→enrolled). allow·inventory 는 _loop 첫 하트비트로 올린다.
        서버는 bad_token 이면 연결을 닫으므로, 거부되면 토큰을 버리고 OSError 로 재접속 → 새 연결에서 enroll."""
        tok = self._load_token()
        if tok:
            self.send({"t": "hello", "token": tok, "version": VERSION,
                       "allow": self.ex.allow, "inventory": inventory()})
            if (self._recv() or {}).get("t") == "welcome":
                return True
            self._drop_token()                                  # 폐기된 토큰 — 버리고 재접속해서 재등록
            raise OSError("서버가 토큰을 거부함 — 재접속 후 재등록")
        code = self.env.get("ENROLL_CODE")
        if not code:
            raise OSError("등록 토큰이 없고 ENROLL_CODE 도 없습니다 — 콘솔에서 등록 코드를 발급해 ENROLL_CODE 로 넣으세요")
        self.send({"t": "enroll", "code": code, "hostname": socket.gethostname(), "version": VERSION})
        msg = self._recv()
        if (msg or {}).get("t") != "enrolled":
            raise OSError(f"등록 실패: {(msg or {}).get('error', msg)}")
        self._save_token(msg["token"])
        return True

    def run_forever(self):
        backoff = 2
        while not self.stop.is_set():
            try:
                self.connect()
                if not self.handshake():
                    raise OSError("핸드셰이크 실패")
                backoff = 2
                self._loop()
            except OSError as e:
                sys.stderr.write(f"연결 끊김/실패: {e} — {backoff}초 뒤 다시\n")
                if self.stop.wait(backoff):
                    break
                backoff = min(backoff * 2, RECONNECT_MAX)
            finally:
                self._close()

    def _loop(self):
        self.send({"t": "heartbeat", "version": VERSION, "allow": self.ex.allow, "inventory": inventory()})   # 바로 allow·상태 보고
        threading.Thread(target=self._heartbeat_loop, name="hb", daemon=True).start()
        if self.telemetry:
            threading.Thread(target=self._telemetry_loop, name="tel", daemon=True).start()
        while not self.stop.is_set():
            msg = self._recv()
            if msg is None:
                raise OSError("서버가 연결을 닫음")
            self._handle(msg)

    def _handle(self, msg):
        t = msg.get("t")
        if t == "job":
            jid, action, params = msg.get("id"), msg.get("action"), msg.get("params") or {}
            try:
                res = self.ex.execute(action, params)
                self.send({"t": "result", "id": jid, "ok": True, "result": res, "error": None})
            except Exception as e:                                  # noqa: BLE001  무슨 일이 있어도 결과는 보고
                self.send({"t": "result", "id": jid, "ok": False, "result": {}, "error": str(e)})
        elif t == "ping":
            self.send({"t": "pong"})

    def _heartbeat_loop(self):
        while not self.stop.is_set():
            if self.stop.wait(HEARTBEAT_SEC):
                return
            try:
                self.send({"t": "heartbeat", "version": VERSION, "allow": self.ex.allow, "inventory": inventory()})
            except OSError:
                return

    def _telemetry_loop(self):
        while not self.stop.is_set():
            if self.stop.wait(TELEMETRY_SEC):
                return
            evs = collect_security_events(self.run)
            if evs:
                try:
                    self.send({"t": "telemetry", "source": "http-json", "events": evs})
                except OSError:
                    return

    def _close(self):
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = self.f = None


def main():
    env = load_env()
    host = env.get("RKMSIEM_HOST")
    if not host:
        sys.stderr.write("RKMSIEM_HOST 가 필요합니다 (서버 주소)\n")
        return 2
    cli = AgentClient(host, env.get("RKMSIEM_PORT", "8452"), env)
    import signal
    signal.signal(signal.SIGTERM, lambda *_: cli.stop.set())
    try:
        cli.run_forever()
    except KeyboardInterrupt:
        cli.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
