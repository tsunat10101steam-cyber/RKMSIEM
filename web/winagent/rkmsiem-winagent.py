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
        with open(path, encoding="utf-8", errors="replace") as f:   # 설치 프로그램이 ANSI 로 쓴 주석 등에 관대하게
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
        self.connected = False                                  # 트레이 아이콘 상태
        self.last_event = "(아직 없음)"

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
        self.connected = True                                   # 트레이 상태 표시용
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
                self.last_event = f"{action} {params} → 성공"
                self.send({"t": "result", "id": jid, "ok": True, "result": res, "error": None})
            except Exception as e:                                  # noqa: BLE001  무슨 일이 있어도 결과는 보고
                self.last_event = f"{action} {params} → 실패: {e}"
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
        self.connected = False
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass
        self.sock = self.f = None


# ================================================================== 설치 마법사
ENV_KEYS = ("RKMSIEM_HOST", "RKMSIEM_PORT", "RKMSIEM_FINGERPRINT", "ENROLL_CODE",
            "ALLOW", "PROTECT_PROCESSES", "PROTECT_SERVICES", "TELEMETRY", "RKMSIEM_INSECURE")
TASK_NAME = "RKMSIEMAgent"


def env_path(state_dir=None):
    return os.path.join(state_dir or _state_dir(), "winagent.env")


def write_config(values, state_dir=None):
    """winagent.env 저장. 값에 줄바꿈·따옴표가 없게 정리 (설정 파일 형식 보호)."""
    d = state_dir or _state_dir()
    os.makedirs(d, exist_ok=True)
    lines = ["# RKMSIEM 윈도우 클라이언트 설정 (설치 마법사가 생성)"]
    for k in ENV_KEYS:
        v = str(values.get(k, "")).replace("\r", "").replace("\n", " ").strip()
        if v:
            lines.append(f"{k}={v}")
    path = env_path(d)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    return path


def probe_fingerprint(host, port, timeout=10):
    """서버에 TLS 로 붙어 인증서 SHA-256 지문을 가져온다 (마법사에서 사용자가 tls.sh --show 값과 대조)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, int(port)), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()


def test_connection(values):
    """설정값으로 실제 핸드셰이크까지 — (ok, 메시지). 등록 코드가 있으면 등록도 시도(1회용 소모 주의는 호출부에서)."""
    env = dict(values)
    cli = AgentClient(values.get("RKMSIEM_HOST", ""), values.get("RKMSIEM_PORT", "8452"), env)
    try:
        cli.connect()
    except OSError as e:
        return False, f"연결 실패: {e}"
    finally:
        pass
    cli._close()
    return True, "연결·인증서 지문 확인됨"


def service_exe():
    """설치된 exe 경로 (PyInstaller 로 얼리면 sys.executable 이 그 exe)."""
    return sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)


def build_service_cmd(exe):
    """부팅 시 SYSTEM 으로 자동 실행 — schtasks (콘솔 exe 를 서비스로 띄우는 SCM 배선보다 안정적)."""
    return ["schtasks", "/create", "/tn", TASK_NAME, "/tr", f'"{exe}"',
            "/sc", "onstart", "/ru", "SYSTEM", "/rl", "HIGHEST", "/f"]


def install_service(run=run_cmd):
    rc, out = run(build_service_cmd(service_exe()), timeout=30)
    if rc != 0:
        return False, f"작업 등록 실패(rc={rc}): {out.strip()[:200]}"
    run(["schtasks", "/run", "/tn", TASK_NAME], timeout=15)
    return True, f"'{TASK_NAME}' 작업으로 등록·시작됨 (부팅 시 자동 실행)"


def setup_gui():
    import tkinter as tk
    from tkinter import messagebox, ttk

    cur = load_env()
    root = tk.Tk()
    root.title("RKMSIEM 윈도우 클라이언트 설정")
    root.resizable(False, False)
    frm = ttk.Frame(root, padding=16)
    frm.grid()
    vals = {}

    def row(r, label, key, default="", show=None, width=46):
        ttk.Label(frm, text=label).grid(row=r, column=0, sticky="e", padx=(0, 8), pady=4)
        v = tk.StringVar(value=cur.get(key, default))
        ttk.Entry(frm, textvariable=v, width=width, show=show).grid(row=r, column=1, sticky="w", pady=4)
        vals[key] = v

    row(0, "서버 주소", "RKMSIEM_HOST")
    row(1, "포트", "RKMSIEM_PORT", "8452")
    row(2, "인증서 지문 (SHA-256)", "RKMSIEM_FINGERPRINT")
    row(3, "등록 코드 (rke_…)", "ENROLL_CODE")

    tel = tk.BooleanVar(value=cur.get("TELEMETRY") == "1")
    kill = tk.BooleanVar(value="process_kill" in (cur.get("ALLOW", "process_kill,service_restart")))
    svc = tk.BooleanVar(value="service_restart" in (cur.get("ALLOW", "process_kill,service_restart")))
    ttk.Checkbutton(frm, text="프로세스 종료 허용", variable=kill).grid(row=4, column=1, sticky="w")
    ttk.Checkbutton(frm, text="서비스 재시작 허용", variable=svc).grid(row=5, column=1, sticky="w")
    ttk.Checkbutton(frm, text="보안 로그(실패 로그온) 보고", variable=tel).grid(row=6, column=1, sticky="w")
    status = ttk.Label(frm, text="", foreground="#555", wraplength=380)
    status.grid(row=10, column=0, columnspan=2, sticky="w", pady=(10, 0))

    def collect():
        allow = ",".join([a for a, on in (("process_kill", kill.get()), ("service_restart", svc.get())) if on])
        return {"RKMSIEM_HOST": vals["RKMSIEM_HOST"].get().strip(),
                "RKMSIEM_PORT": vals["RKMSIEM_PORT"].get().strip() or "8452",
                "RKMSIEM_FINGERPRINT": vals["RKMSIEM_FINGERPRINT"].get().strip().replace(":", "").lower(),
                "ENROLL_CODE": vals["ENROLL_CODE"].get().strip(),
                "ALLOW": allow, "TELEMETRY": "1" if tel.get() else "0"}

    def do_fetch_fp():
        v = collect()
        try:
            fp = probe_fingerprint(v["RKMSIEM_HOST"], v["RKMSIEM_PORT"])
        except OSError as e:
            messagebox.showerror("지문 가져오기", f"실패: {e}")
            return
        vals["RKMSIEM_FINGERPRINT"].set(fp)
        messagebox.showinfo("지문 가져오기", f"서버 인증서 지문:\n{fp}\n\n서버에서 'tls.sh --show' 값과 같은지 꼭 확인하세요.")

    def do_test():
        ok, msg = test_connection(collect())
        status.config(text=msg, foreground="#1a7f37" if ok else "#b00")

    def do_save():
        write_config(collect())
        status.config(text="저장됨 — 창을 닫으면 적용됩니다 (트레이 재시작 또는 재로그인)", foreground="#1a7f37")

    def do_save_close():
        write_config(collect())
        root.destroy()

    btns = ttk.Frame(frm)
    btns.grid(row=11, column=0, columnspan=2, pady=(12, 0), sticky="w")
    ttk.Button(btns, text="지문 가져오기", command=do_fetch_fp).grid(row=0, column=0, padx=4)
    ttk.Button(btns, text="연결 테스트", command=do_test).grid(row=0, column=1, padx=4)
    ttk.Button(btns, text="저장", command=do_save).grid(row=0, column=2, padx=4)
    ttk.Button(btns, text="저장하고 닫기", command=do_save_close).grid(row=0, column=3, padx=4)
    root.mainloop()


def setup_console():
    """GUI 가 없을 때(헤드리스) — 질문해서 winagent.env 생성."""
    cur = load_env()

    def ask(label, key, default=""):
        d = cur.get(key, default)
        v = input(f"{label}{f' [{d}]' if d else ''}: ").strip()
        return v or d

    vals = {"RKMSIEM_HOST": ask("서버 주소", "RKMSIEM_HOST"),
            "RKMSIEM_PORT": ask("포트", "RKMSIEM_PORT", "8452"),
            "RKMSIEM_FINGERPRINT": ask("인증서 지문", "RKMSIEM_FINGERPRINT").replace(":", "").lower(),
            "ENROLL_CODE": ask("등록 코드 (rke_…)", "ENROLL_CODE"),
            "ALLOW": ask("허용 조치", "ALLOW", "process_kill,service_restart"),
            "TELEMETRY": ask("보안 로그 보고(1/0)", "TELEMETRY", "1")}
    path = write_config(vals)
    print(f"저장됨: {path}")
    if input("부팅 시 자동 실행 작업으로 등록할까요? (y/N): ").strip().lower() == "y":
        ok, msg = install_service()
        print(msg)
    return 0


# ================================================================== 트레이 아이콘
def _run_headless(env):
    host = env.get("RKMSIEM_HOST")
    if not host:
        sys.stderr.write("설정이 없습니다 — 먼저 'rkmsiem-winagent.exe --setup' 으로 설정하세요\n")
        return 2
    cli = AgentClient(host, env.get("RKMSIEM_PORT", "8452"), env)
    import signal
    try:
        signal.signal(signal.SIGTERM, lambda *_: cli.stop.set())
    except (ValueError, AttributeError):
        pass
    try:
        cli.run_forever()
    except KeyboardInterrupt:
        cli.stop.set()
    return 0


def tray_app(env):
    """트레이 아이콘(연결됨=초록/끊김=회색) + 우클릭 메뉴(상태·설정·종료). 에이전트는 백그라운드 스레드로 돈다."""
    try:
        import tkinter as tk
        from tkinter import ttk
        import pystray
        from PIL import Image, ImageDraw
    except Exception as e:                                      # noqa: BLE001  트레이 라이브러리 없음 → 헤드리스로
        sys.stderr.write(f"트레이를 쓸 수 없어 백그라운드로 실행합니다: {e}\n")
        return _run_headless(env)

    host = env.get("RKMSIEM_HOST")
    if not host:                                                # 설정이 없으면 먼저 설치 마법사
        return setup_gui() or 0
    cli = AgentClient(host, env.get("RKMSIEM_PORT", "8452"), env)
    threading.Thread(target=cli.run_forever, name="agent", daemon=True).start()

    root = tk.Tk()
    root.withdraw()                                             # 숨은 본체 (트레이만 보임)

    def icon_img(connected):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((8, 8, 56, 56), fill=(40, 180, 80) if connected else (150, 150, 150))
        return img

    st = {"win": None}

    def show_status():
        w = st["win"]
        if w is not None:
            try:
                w.deiconify(); w.lift(); return
            except tk.TclError:
                pass
        w = tk.Toplevel(root); st["win"] = w
        w.title("RKMSIEM 에이전트"); w.resizable(False, False)
        f = ttk.Frame(w, padding=16); f.grid()
        lbl = ttk.Label(f, font=("", 11)); lbl.grid(row=0, column=0, sticky="w")
        sub = ttk.Label(f, foreground="#555", wraplength=420, justify="left"); sub.grid(row=1, column=0, sticky="w", pady=(8, 0))

        def refresh():
            on = cli.connected
            lbl.config(text=("● 연결됨" if on else "○ 연결 끊김 (재시도 중)"),
                       foreground="#1a7f37" if on else "#b00")
            sub.config(text=f"서버: {host}:{env.get('RKMSIEM_PORT', '8452')}\n"
                            f"허용 조치: {', '.join(cli.ex.allow) or '없음 (보고만)'}\n"
                            f"마지막 조치: {cli.last_event}")
            if st["win"] is not None:
                w.after(1500, refresh)
        refresh()
        ttk.Button(f, text="설정 열기", command=open_settings).grid(row=2, column=0, sticky="w", pady=(12, 0))
        w.protocol("WM_DELETE_WINDOW", lambda: (w.withdraw()))   # 닫아도 트레이에 남음

    def open_settings():
        import subprocess                                       # 설정 마법사는 별도 프로세스로 (tkinter 다중 루트 회피)
        subprocess.Popen([sys.executable, "--setup"], close_fds=False)

    def do_quit(icon):
        cli.stop.set()
        icon.stop()
        try:
            root.after(0, root.destroy)
        except tk.TclError:
            pass

    menu = pystray.Menu(
        pystray.MenuItem("상태 / 메뉴", lambda i: root.after(0, show_status), default=True),
        pystray.MenuItem("설정", lambda i: root.after(0, open_settings)),
        pystray.MenuItem("종료", lambda i: do_quit(i)),
    )
    icon = pystray.Icon("rkmsiem", icon_img(False), "RKMSIEM 에이전트", menu)

    def watch():
        while not cli.stop.is_set():
            try:
                icon.icon = icon_img(cli.connected)
                icon.title = "RKMSIEM 에이전트 — " + ("연결됨" if cli.connected else "연결 끊김")
            except Exception:                                   # noqa: BLE001
                pass
            if cli.stop.wait(3):
                return
    threading.Thread(target=watch, name="tray-watch", daemon=True).start()
    icon.run_detached()
    root.mainloop()
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):                 # 윈도우 콘솔(cp1252)에서 한글 출력이 터지지 않게
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    if "--setup" in sys.argv:
        if "--console" in sys.argv:
            return setup_console()
        try:
            setup_gui()
            return 0
        except Exception as e:                                  # noqa: BLE001  GUI 불가 → 콘솔로
            sys.stderr.write(f"GUI 를 열 수 없어 콘솔 설정으로 전환합니다: {e}\n")
            return setup_console()
    env = load_env()
    if "--headless" in sys.argv:                               # 서비스/부팅용 (트레이 없이)
        return _run_headless(env)
    return tray_app(env)                                        # 기본: 트레이 아이콘


if __name__ == "__main__":
    sys.exit(main())
