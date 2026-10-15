"""웹 터미널: 토폴로지에서 SIEM 과 와이어로 이어진 기기에 SSH 로 접속해 브라우저에서 입력한다.

접근 조건 (전부 백엔드에서 검사 — 화면의 버튼 숨김은 편의일 뿐):
  - 권한 terminal:use (기본: 관리자만)
  - 대상 IP 가 '저장된' 토폴로지 배치에 있고, SIEM 종류의 기기에서 와이어를 따라 닿는 기기여야 함
  - 접속 중에 배치가 바뀌어 와이어가 끊기면 그 세션은 바로 종료
연결은 시스템 ssh 클라이언트를 가상 터미널(pty)에서 실행한다 — 비밀번호·호스트 키 확인은 터미널 안에서 사람이 직접 입력.
브라우저 ↔ 서버는 롱 폴링(출력) + POST(입력) 이라 waitress 그대로 동작한다 (웹소켓 불필요).
모든 열기/닫기는 감사 로그에, 출력 전체는 data/terminal/<id>.log 에 남긴다.
"""
import fcntl
import ipaddress
import logging
import os
import re
import secrets
import shutil
import signal
import struct
import subprocess
import termios
import threading
import time
from collections import deque

log = logging.getLogger("rkmsiem.terminal")
LOGIN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
# 구형 장비(오래된 스위치·라우터 펌웨어) 호환: 기본으로 꺼진 옛 암호 방식을 '목록 끝에 추가' 만 한다.
# 최신 방식이 먼저라 상대가 지원하면 그쪽이 고르고, 옛 방식만 아는 장비에서만 옛 방식으로 붙는다. 접속할 때 사람이 고른 경우에만.
LEGACY = {"KexAlgorithms": ("kex", ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"]),
          "HostKeyAlgorithms": ("key", ["ssh-rsa", "ssh-dss"]),
          "PubkeyAcceptedAlgorithms": ("key", ["ssh-rsa"]),
          "Ciphers": ("cipher", ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"]),
          "MACs": ("mac", ["hmac-sha1", "hmac-md5"])}
_legacy_cache = {}


def legacy_opts(ssh):
    """이 서버의 ssh 가 실제로 아는 옛 방식만 (배포판마다 빠진 것이 다름 — 예: OpenSSH 9.8+ 는 ssh-dss 없음).
    모르는 이름이 하나라도 섞이면 ssh 가 'Bad key types' 로 아예 시작하지 않는다."""
    if ssh not in _legacy_cache:
        known, out = {}, []
        for opt, (q, algs) in LEGACY.items():
            if q not in known:
                try:
                    known[q] = set(subprocess.run([ssh, "-Q", q], capture_output=True, text=True, timeout=5).stdout.split())
                except (OSError, subprocess.TimeoutExpired):
                    known[q] = set()
            ok = [a for a in algs if a in known[q]]
            if ok:
                out += ["-o", f"{opt}=+{','.join(ok)}"]
        _legacy_cache[ssh] = out
    return _legacy_cache[ssh]


BUF_MAX = 256 * 1024          # 세션마다 기억하는 최근 출력 (다시 붙을 때 화면 복원용)


class TerminalError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


def wired(layout, ip):
    """저장된 배치에서 SIEM 기기로부터 와이어를 따라 ip 기기까지의 경로(기기 목록). 닿지 않으면 None."""
    nodes = {n["id"]: n for n in (layout or {}).get("nodes", [])}
    adj = {k: set() for k in nodes}
    for l in (layout or {}).get("links", []):
        if l.get("from") in adj and l.get("to") in adj:
            adj[l["from"]].add(l["to"])
            adj[l["to"]].add(l["from"])
    starts = [k for k, n in nodes.items() if n.get("type") == "siem"]
    prev, todo = {k: None for k in starts}, deque(starts)
    while todo:
        cur = todo.popleft()
        n = nodes[cur]
        if n.get("ip") == ip and n.get("type") != "siem":
            path = []
            while cur is not None:
                path.append(nodes[cur])
                cur = prev[cur]
            return path[::-1]
        for nxt in sorted(adj[cur]):
            if nxt not in prev:
                prev[nxt] = cur
                todo.append(nxt)
    return None


def targets(layout):
    """접속할 수 있는 기기 (SIEM 과 와이어로 이어진, IP 가 있는 기기)."""
    out = []
    for n in (layout or {}).get("nodes", []):
        if n.get("ip") and n.get("type") != "siem":
            path = wired(layout, n["ip"])
            if path:
                out.append({"id": n["id"], "ip": n["ip"], "label": n.get("label") or "", "type": n.get("type"),
                            "hops": len(path) - 1, "path": [x.get("label") or x.get("ip") or x["id"] for x in path]})
    return out


class Session:
    def __init__(self, sid, owner, ip, login, port, proc, fd, logf):
        self.id, self.owner, self.ip, self.login, self.port = sid, owner, ip, login, port
        self.proc, self.fd, self.logf = proc, fd, logf
        self.created = self.last_active = time.time()
        self.buf, self.base = bytearray(), 0          # base = buf[0] 의 전체 출력 기준 위치
        self.bytes_in = self.bytes_out = 0
        self.closed, self.exit_code, self.reason = False, None, None
        self.legacy = False
        self.cond = threading.Condition()

    @property
    def end(self):
        return self.base + len(self.buf)

    def info(self):
        return {"id": self.id, "owner": self.owner, "ip": self.ip, "login": self.login, "port": self.port, "created": self.created,
                "last_active": self.last_active, "closed": self.closed, "exit_code": self.exit_code, "reason": self.reason, "legacy": self.legacy}


class TerminalManager:
    def __init__(self, platform):
        self.p = platform
        s = platform.settings
        self.enabled = bool(s.get("terminal.enabled", True))
        self.max_per_user = int(s.get("terminal.max_sessions_per_user", 3))
        self.idle_sec = int(s.get("terminal.idle_timeout_sec", 900))
        self.max_sec = int(s.get("terminal.max_duration_sec", 14400))
        self.ports = set(s.get("terminal.allowed_ports", [22, 2222]))
        base = os.path.dirname(platform.db.path) if platform.db.path != ":memory:" else os.getcwd()
        self.dir = s.path("terminal.dir") if s.get("terminal.dir") else os.path.join(base, "terminal")
        self.sessions = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._reaper = None

    # -------------------------------------------------------------- 조건
    def layout(self):
        return self.p.config.get("topology") or {"nodes": [], "links": []}

    def check(self, ip):
        if not self.enabled:
            raise TerminalError(403, "웹 터미널이 꺼져 있습니다 (settings.yaml terminal.enabled)")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise TerminalError(400, f"IP 형식 오류: {ip}")
        path = wired(self.layout(), ip)
        if not path:
            raise TerminalError(403, f"{ip} 는 토폴로지에서 SIEM 과 와이어로 연결돼 있지 않습니다 — 연결 후 '저장' 하세요")
        return path

    def argv(self, ip, login, port, legacy=False):
        ssh = shutil.which("ssh")
        if not ssh:
            raise TerminalError(503, "ssh 클라이언트가 없습니다 (sudo apt install openssh-client)")
        # -F /dev/null: 시스템·사용자 ssh 설정 무시 · EscapeChar=none: ~C 포워딩 등 탈출 명령 끔 · 포워딩/에이전트 전부 끔
        return [ssh, "-F", "/dev/null", "-o", "EscapeChar=none", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
                "-o", "PermitLocalCommand=no", "-o", "StrictHostKeyChecking=ask", "-o", f"UserKnownHostsFile={os.path.join(self.dir, 'known_hosts')}",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=4",
                *(legacy_opts(ssh) if legacy else []), "-p", str(port), "-l", login, ip]

    # -------------------------------------------------------------- 열기·닫기
    def open(self, user, ip, login, port=22, cols=100, rows=30, legacy=False):
        if not LOGIN_RE.match(login or ""):
            raise TerminalError(400, "접속 계정 이름 형식이 올바르지 않습니다")
        if port not in self.ports:
            raise TerminalError(400, f"허용된 SSH 포트가 아닙니다 ({', '.join(map(str, sorted(self.ports)))})")
        path = self.check(ip)
        with self.lock:
            mine = [x for x in self.sessions.values() if x.owner == user and not x.closed]
            if len(mine) >= self.max_per_user:
                raise TerminalError(429, f"동시에 열 수 있는 터미널은 {self.max_per_user}개입니다 — 쓰지 않는 창을 닫으세요")
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        argv = self.argv(ip, login, port, legacy=legacy)
        master, slave = os.openpty()
        _winsize(slave, rows, cols)
        env = {"TERM": "xterm-256color", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin", "HOME": self.dir}

        def ctty():                                    # 새 세션의 제어 터미널 = pty (ssh 가 비밀번호를 /dev/tty 로 묻기 때문)
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            if _prctl:                                 # 서비스가 받은 CAP_NET_ADMIN 을 ssh 에 물려주지 않음
                _prctl(47, 4, 0, 0, 0)                 # PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL
        try:
            proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, env=env, cwd=self.dir,
                                    start_new_session=True, preexec_fn=ctty, close_fds=True)
        except OSError as e:
            os.close(master)
            os.close(slave)
            raise TerminalError(500, f"터미널을 시작하지 못했습니다: {e}")
        os.close(slave)
        sid = secrets.token_urlsafe(12)
        logf = open(os.path.join(self.dir, f"{time.strftime('%Y%m%d-%H%M%S')}-{sid}.log"), "ab", buffering=0)
        os.chmod(logf.name, 0o600)
        logf.write(f"# {time.strftime('%Y-%m-%d %H:%M:%S')} {user} → {login}@{ip}:{port}{' (구형 장비 호환)' if legacy else ''}\n".encode())
        sess = Session(sid, user, ip, login, port, proc, master, logf)
        sess.legacy = bool(legacy)
        with self.lock:
            self.sessions[sid] = sess
        threading.Thread(target=self._pump, args=(sess,), daemon=True, name=f"term-{sid}").start()
        self._ensure_reaper()
        self.p.audit.record(user, "terminal.open", "host", ip, None,
                            {"session": sid, "login": login, "port": port, "legacy": bool(legacy), "path": [x.get("label") or x.get("ip") or x["id"] for x in path]})
        return sess

    def get(self, sid, user):
        sess = self.sessions.get(sid)
        if not sess or sess.owner != user:              # 남의 세션은 있다는 것도 알려 주지 않는다
            raise TerminalError(404, "터미널 세션이 없습니다")
        return sess

    def close(self, sess, reason="사용자가 닫음"):
        with sess.cond:
            if sess.closed:
                return
            sess.closed, sess.reason = True, reason
        try:
            os.killpg(sess.proc.pid, signal.SIGHUP)
        except OSError:
            pass
        try:
            sess.exit_code = sess.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(sess.proc.pid, signal.SIGKILL)
            except OSError:
                pass
            sess.exit_code = sess.proc.wait()
        sess.last_active = time.time()                   # 끝난 세션의 마지막 화면 보관 기준
        with sess.cond:
            sess.cond.notify_all()
        try:
            sess.logf.write(f"\n# {time.strftime('%Y-%m-%d %H:%M:%S')} 종료: {reason}\n".encode())
            sess.logf.close()
        except OSError:
            pass
        self.p.audit.record(sess.owner, "terminal.close", "host", sess.ip, reason,
                            {"session": sess.id, "seconds": round(time.time() - sess.created), "bytes_in": sess.bytes_in,
                             "bytes_out": sess.bytes_out, "exit_code": sess.exit_code})

    # -------------------------------------------------------------- 입출력
    def _pump(self, sess):
        while True:
            try:
                data = os.read(sess.fd, 65536)
            except OSError:                             # EIO = 반대편(ssh)이 끝남
                data = b""
            if not data:
                break
            with sess.cond:
                sess.buf += data
                sess.bytes_out += len(data)
                if len(sess.buf) > BUF_MAX:
                    cut = len(sess.buf) - BUF_MAX
                    del sess.buf[:cut]
                    sess.base += cut
                sess.cond.notify_all()
            try:
                sess.logf.write(data)
            except (OSError, ValueError):
                pass
        os.close(sess.fd)
        if not sess.closed:
            code = sess.proc.wait()
            self.close(sess, f"연결 종료 (코드 {code})")

    def read(self, sess, since, timeout=20):
        """since 이후의 출력. 새 출력이 없으면 timeout 까지 기다린다 (롱 폴링)."""
        deadline = time.time() + timeout
        with sess.cond:
            while sess.end <= since and not sess.closed:
                left = deadline - time.time()
                if left <= 0:
                    break
                sess.cond.wait(left)
            start = max(since, sess.base)
            data = bytes(sess.buf[start - sess.base:])
            return data, sess.end, sess.closed, start > since

    def write(self, sess, data):
        if sess.closed:
            raise TerminalError(410, "이미 종료된 터미널입니다")
        sess.last_active = time.time()
        sess.bytes_in += len(data)
        view = memoryview(data)
        while view:
            n = os.write(sess.fd, view)
            view = view[n:]

    def resize(self, sess, rows, cols):
        if not sess.closed:
            _winsize(sess.fd, rows, cols)
            try:
                os.killpg(sess.proc.pid, signal.SIGWINCH)
            except OSError:
                pass

    def list(self, user):
        return [x.info() for x in self.sessions.values() if x.owner == user and not x.closed]

    # -------------------------------------------------------------- 정리
    def _ensure_reaper(self):
        if self._reaper is None or not self._reaper.is_alive():
            self._reaper = threading.Thread(target=self._reap_loop, daemon=True, name="terminal-reaper")
            self._reaper.start()

    def _reap_loop(self):
        while not self._stop.wait(5):
            self.reap()
            with self.lock:
                if not self.sessions:
                    self._reaper = None
                    return

    def reap(self):
        now, layout = time.time(), self.layout()
        with self.lock:
            items = list(self.sessions.items())
        for sid, sess in items:
            if sess.closed:
                if now - sess.last_active > 300:          # 끝난 세션의 마지막 화면은 5분만 보관
                    with self.lock:
                        self.sessions.pop(sid, None)
                continue
            if not wired(layout, sess.ip):
                self.close(sess, "토폴로지에서 와이어 연결이 끊겨 종료")
            elif now - sess.last_active > self.idle_sec:
                self.close(sess, f"{self.idle_sec // 60}분 동안 입력이 없어 종료")
            elif now - sess.created > self.max_sec:
                self.close(sess, f"최대 사용 시간 {self.max_sec // 3600}시간 초과로 종료")

    def stop(self):
        self._stop.set()
        for sess in list(self.sessions.values()):
            self.close(sess, "서비스 종료")


def _load_prctl():
    try:
        import ctypes
        return ctypes.CDLL(None, use_errno=True).prctl
    except (OSError, AttributeError):
        return None


_prctl = _load_prctl()


def _winsize(fd, rows, cols):
    rows, cols = max(5, min(int(rows), 300)), max(20, min(int(cols), 500))
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
