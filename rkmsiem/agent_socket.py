"""Windows 클라이언트(엔드포인트 에이전트) 소켓 서버 — TLS 소켓 위 줄 단위 JSON.

HTTP 롱폴링 에이전트(agents.py)와 **같은 두뇌**(토큰·작업큐·결과·인벤토리)를 쓰고, 전송만 지속 소켓이다.
리눅스=서버, 윈도우=클라이언트. 클라이언트가 서버로 '나가서' 붙고(아웃바운드 1개), 서버는 그 위로 할 일을 내려보낸다.

메시지(한 줄 = compact JSON 1개, \\n 종료):
  클라이언트 → 서버 : hello(token)|enroll(code) · heartbeat(inventory·allow) · telemetry(events) · result(job) · pong
  서버 → 클라이언트 : welcome|enrolled · job · ping · error

작업은 Agents.take_jobs 가 조건변수로 즉시 깨어나 바로 밀어 준다 (롱폴링보다 지연 없음).
무엇을 허용할지는 **클라이언트**가 hello/heartbeat 의 allow 로 알려 준다 — SIEM 이 털려도 그 밖의 일은 못 함.
"""
import json
import logging
import socket
import ssl
import threading
import time

log = logging.getLogger("rkmsiem.agentsock")
MAX_LINE = 1 << 20                          # 한 줄 1 MiB 상한 (메모리 남용 방지)


def _dump(obj):
    return (json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


class AgentSocketServer:
    def __init__(self, platform, settings):
        self.p = platform
        cfg = settings.get("agent_socket") or {}
        self.host = cfg.get("host", "0.0.0.0")
        self.port = int(cfg.get("port", 8452))
        self.tls = bool(cfg.get("tls", True))
        self.cert = cfg.get("cert", "/etc/rkmsiem/tls/rkmsiem.crt")
        self.key = cfg.get("key", "/etc/rkmsiem/tls/rkmsiem.key")
        self.telemetry_source = cfg.get("telemetry_source", "http-json")
        self.job_wait = float(cfg.get("job_wait_sec", 20))
        self._srv = None
        self._stop = threading.Event()

    # ------------------------------------------------------------------ 수명
    def _ctx(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, self.key)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    def start(self):
        ctx = self._ctx() if self.tls else None                 # 인증서 문제는 여기서 바로 터지게 (조용히 평문 금지)
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(64)
        srv.settimeout(1.0)
        self.port = srv.getsockname()[1]                        # port=0 이면 실제 할당된 포트
        self._srv = srv
        threading.Thread(target=self._accept_loop, args=(srv, ctx), name="agentsock-accept", daemon=True).start()
        log.info("에이전트 소켓 서버 시작 %s:%d (tls=%s)", self.host, self.port, self.tls)
        return self

    def stop(self):
        self._stop.set()
        if self._srv:
            try:
                self._srv.close()
            except OSError:
                pass

    def _accept_loop(self, srv, ctx):
        while not self._stop.is_set():
            try:
                raw, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve, args=(raw, addr, ctx), name=f"agentsock-{addr[0]}", daemon=True).start()

    # ------------------------------------------------------------------ 연결 1개
    def _serve(self, raw, addr, ctx):
        ip = addr[0]
        try:
            sock = ctx.wrap_socket(raw, server_side=True) if ctx else raw
        except (ssl.SSLError, OSError) as e:
            log.warning("TLS 핸드셰이크 실패 %s: %s", ip, e)
            raw.close()
            return
        wlock = threading.Lock()
        pusher_stop = threading.Event()

        def send(obj):
            with wlock:
                sock.sendall(_dump(obj))

        try:
            sock.settimeout(90)
            rdr = sock.makefile("rb")
            agent = self._handshake(send, rdr, ip)
            if agent is None:
                return
            threading.Thread(target=self._push_jobs, args=(send, agent["id"], pusher_stop),
                             name=f"agentsock-push-{agent['name']}", daemon=True).start()
            while not self._stop.is_set():
                line = self._readline(rdr)
                if line is None:
                    break
                self._handle(send, agent, self._parse(line), ip)
        except (OSError, ssl.SSLError) as e:
            log.debug("에이전트 연결 종료 %s: %s", ip, e)
        except Exception:                                       # noqa: BLE001  핸들러 예외로 조용히 죽지 않게 — 로그 남기고 연결만 닫음
            log.exception("에이전트 연결 처리 중 오류 %s", ip)
        finally:
            pusher_stop.set()
            try:
                sock.close()
            except OSError:
                pass

    def _handshake(self, send, rdr, ip):
        line = self._readline(rdr)
        if line is None:
            return None
        msg = self._parse(line)
        t = msg.get("t")
        if t == "enroll":
            from .agents import AgentError
            try:
                res = self.p.agents.enroll(msg.get("code"), msg.get("hostname"), msg.get("version"), ip)
            except AgentError as e:
                send({"t": "error", "error": str(e)})
                return None
            send({"t": "enrolled", "name": res["name"], "token": res["token"]})
            return self.p.agents.resolve(res["token"])
        if t == "hello":
            agent = self.p.agents.resolve(msg.get("token"))
            if not agent:
                send({"t": "error", "error": "bad_token"})
                return None
            self.p.agents.heartbeat(agent, msg, ip)             # hello 에 담긴 inventory·allow·version 바로 반영
            send({"t": "welcome", "name": agent["name"]})
            return agent
        send({"t": "error", "error": "expected hello or enroll"})
        return None

    def _push_jobs(self, send, agent_id, stop):
        while not stop.is_set() and not self._stop.is_set():
            try:
                jobs = self.p.agents.take_jobs(agent_id, wait=self.job_wait)
            except Exception as e:                              # noqa: BLE001  작업 1건 오류로 연결을 끊지 않음
                log.warning("take_jobs 실패: %s", e)
                if stop.wait(2):
                    return
                continue
            for i, j in enumerate(jobs):
                if stop.is_set() or self._stop.is_set():        # 연결이 닫히는 중이면 집어 둔 작업을 다시 큐로 (유실·중복 전달 방지)
                    self.p.agents.requeue([x["id"] for x in jobs[i:]])
                    return
                try:
                    send({"t": "job", "id": j["id"], "action": j["action"], "params": j["params"]})
                except OSError:
                    self.p.agents.requeue([x["id"] for x in jobs[i:]])
                    stop.set()
                    return

    def _handle(self, send, agent, msg, ip):
        t = msg.get("t")
        if t == "heartbeat":
            self.p.agents.heartbeat(agent, msg, ip)
        elif t == "telemetry":
            self._ingest(msg.get("events") or [], msg.get("source"))
        elif t == "result":
            try:
                self.p.agents.finish(agent["id"], int(msg.get("id")), bool(msg.get("ok")), msg.get("result"), msg.get("error"))
            except (KeyError, ValueError, TypeError):
                pass                                            # 이미 끝났거나 모르는 작업 — 무시
        elif t == "ping":
            send({"t": "pong"})
        # pong 등 그 밖의 메시지는 무시 (keepalive)

    def _ingest(self, events, source):
        if not events:
            return
        sid = source or self.telemetry_source
        coll = self.p.collectors.get(sid)
        if coll is None or getattr(coll, "type_name", None) != "http":
            log.warning("telemetry: 수집 소스 '%s' 없음(또는 http 아님) — %d건 버림", sid, len(events))
            return
        body = json.dumps(events, ensure_ascii=False).encode("utf-8")
        for r in coll.records_from_body(body, "application/json"):
            if not self.p.pipeline.submit(r, block=False):
                break                                           # 큐 포화 — 나머지는 다음 하트비트에 다시

    # ------------------------------------------------------------------ 줄 읽기/파싱
    def _readline(self, rdr):
        line = rdr.readline(MAX_LINE + 1)
        if not line:
            return None
        if len(line) > MAX_LINE:
            raise OSError("line too long")
        return line

    @staticmethod
    def _parse(line):
        try:
            obj = json.loads(line)
        except ValueError:
            return {}
        return obj if isinstance(obj, dict) else {}
