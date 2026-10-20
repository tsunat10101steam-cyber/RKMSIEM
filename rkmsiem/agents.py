"""원격 조치 에이전트 — 대상 서버(IDS·웹 서버 등)에 설치한 rkmsiem-agent 가 SIEM 으로 '나가서' 할 일을 받아 간다.

- 등록: 콘솔에서 1회용 등록 코드(rke_…, 1시간) → 에이전트가 POST /api/agent/enroll → 에이전트 토큰(rka_…, DB 에는 해시만)
- 상태 보고 + 할 일 받기: POST /api/agent/poll (최대 25초 대기) — 컨테이너·프로세스·서비스 목록과 '이 서버가 허용한 조치'를 보고
- 결과: POST /api/agent/jobs/<id>/result
- 무엇을 허용할지는 대상 서버의 /etc/rkmsiem-agent/agent.env (ALLOW·PROTECT_*) 가 정한다 — SIEM 이 털려도 그 밖의 일은 못 함
"""
import hashlib
import json
import re
import secrets
import threading
import time

ACTIONS = {                     # 조치 → (설명, 필수 입력)
    "container_stop": ("컨테이너 중지", ("container",)),
    "container_restart": ("컨테이너 재시작", ("container",)),
    "process_kill": ("프로세스 종료", ("pid",)),
    "service_restart": ("서비스 재시작", ("service",)),
}
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
JOB_TTL = 120                   # 이 시간 안에 에이전트가 안 가져가면 만료
ONLINE_SEC = 90
MAX_INFO = 512 * 1024


def _sha(x):
    return hashlib.sha256(x.encode()).hexdigest()


class AgentError(Exception):
    pass


class Agents:
    def __init__(self, db, audit, bus=None):
        self.db, self.audit, self.bus = db, audit, bus
        self._cv = threading.Condition()

    # ---------------------------------------------------------------- 등록
    def create_enroll(self, name, actor, ttl=3600):
        if not NAME_RE.match(name or ""):
            raise AgentError("이름: 영문 소문자·숫자·-_ 32자 이하 (예: ids-server)")
        if self.db.one("SELECT 1 FROM agents WHERE name=? AND revoked_at IS NULL", (name,)):
            raise AgentError(f"'{name}' 에이전트가 이미 있습니다 — 다시 등록하려면 먼저 해제")
        code = "rke_" + secrets.token_urlsafe(24)
        now = time.time()
        self.db.execute("DELETE FROM agent_enroll WHERE expires_at < ? OR name=?", (now, name))
        self.db.execute("INSERT INTO agent_enroll (code_hash, name, created_by, created_at, expires_at) VALUES (?,?,?,?,?)",
                        (_sha(code), name, actor, now, now + ttl))
        self.audit.record(actor, "agent.enroll_code", "agent", name, None, {"ttl": ttl})
        return {"name": name, "code": code, "expires_at": now + ttl}

    def enroll(self, code, hostname, version, client_ip):
        now = time.time()
        with self.db.tx() as c:
            r = c.execute("SELECT * FROM agent_enroll WHERE code_hash=?", (_sha(code or ""),)).fetchone()
            if not r or r["used_at"] or r["expires_at"] < now:
                raise AgentError("등록 코드가 없거나 만료·사용됨 — 콘솔에서 새로 만드세요")
            c.execute("UPDATE agent_enroll SET used_at=? WHERE code_hash=?", (now, r["code_hash"]))
            tok = "rka_" + secrets.token_urlsafe(32)
            c.execute("DELETE FROM agents WHERE name=? AND revoked_at IS NOT NULL", (r["name"],))
            c.execute("INSERT INTO agents (name, token_hash, created_by, created_at, enrolled_at, last_seen, last_ip, hostname, version) "
                      "VALUES (?,?,?,?,?,?,?,?,?)", (r["name"], _sha(tok), r["created_by"], r["created_at"], now, now, client_ip,
                                                    str(hostname or "")[:128], str(version or "")[:32]))
            self.audit.record(f"agent:{r['name']}", "agent.enrolled", "agent", r["name"], None, {"ip": client_ip, "hostname": hostname}, conn=c)
        self._publish(r["name"])
        return {"name": r["name"], "token": tok}

    def revoke(self, name, actor):
        a = self.db.one("SELECT id FROM agents WHERE name=? AND revoked_at IS NULL", (name,))
        if not a:
            raise KeyError(name)
        now = time.time()
        self.db.execute("UPDATE agents SET revoked_at=?, token_hash=NULL WHERE id=?", (now, a["id"]))
        self.db.execute("UPDATE agent_jobs SET state='expired', finished_at=?, error='에이전트 해제' WHERE agent_id=? AND state IN ('queued','sent')", (now, a["id"]))
        self.audit.record(actor, "agent.revoke", "agent", name)
        self._publish(name)

    def resolve(self, token):
        if not token or not token.startswith("rka_"):
            return None
        return self.db.one("SELECT * FROM agents WHERE token_hash=? AND revoked_at IS NULL", (_sha(token),))

    # ---------------------------------------------------------------- 상태
    @staticmethod
    def _row(r, detail=False):
        info = json.loads(r["info"]) if r.get("info") else {}
        out = {"name": r["name"], "hostname": r["hostname"], "version": r["version"], "last_seen": r["last_seen"], "last_ip": r["last_ip"],
               "enrolled_at": r["enrolled_at"], "created_by": r["created_by"],
               "online": bool(r["last_seen"] and time.time() - r["last_seen"] < ONLINE_SEC),
               "allow": json.loads(r["allow"]) if r.get("allow") else [],
               "summary": {"ips": info.get("ips", []), "docker": info.get("docker", False), "containers": len(info.get("containers") or []),
                           "failed_services": len(info.get("failed_services") or []), "load": info.get("load"), "mem": info.get("mem")}}
        if detail:
            out["info"] = info
        return out

    def list(self):
        return [self._row(r) for r in self.db.all("SELECT * FROM agents WHERE revoked_at IS NULL ORDER BY name")]

    def get(self, name, detail=True):
        r = self.db.one("SELECT * FROM agents WHERE name=? AND revoked_at IS NULL", (name,))
        return self._row(r, detail) if r else None

    def by_hosts(self, hosts):
        """사건의 호스트 이름·IP 와 같은 에이전트 (사건 화면에서 원격 조치로 이어 주기)."""
        hs = {str(h).lower() for h in hosts if h}
        out = []
        for a in self.list():
            if (a["hostname"] or "").lower() in hs or a["name"] in hs or hs & set(a["summary"]["ips"]):
                out.append(a["name"])
        return out

    def jobs(self, name=None, limit=50):
        sql, args = "SELECT j.*, a.name AS agent FROM agent_jobs j JOIN agents a ON a.id = j.agent_id", []
        if name:
            sql, args = sql + " WHERE a.name=?", [name]
        rows = self.db.all(sql + " ORDER BY j.id DESC LIMIT ?", args + [limit])
        for r in rows:
            r["params"] = json.loads(r["params"])
            r["result"] = json.loads(r["result"]) if r["result"] else None
        return rows

    # ---------------------------------------------------------------- 에이전트 쪽 (폴링)
    def heartbeat(self, agent, body, client_ip):
        info = body.get("inventory") or {}
        raw = json.dumps(info, ensure_ascii=False)
        if len(raw) > MAX_INFO:
            info = {k: info.get(k) for k in ("hostname", "ips", "docker", "load", "mem", "os")}
            raw = json.dumps(dict(info, truncated=True), ensure_ascii=False)
        allow = [a for a in (body.get("allow") or []) if a in ACTIONS]
        self.db.execute("UPDATE agents SET last_seen=?, last_ip=?, info=?, allow=?, hostname=COALESCE(?, hostname), version=COALESCE(?, version) WHERE id=?",
                        (time.time(), client_ip, raw, json.dumps(allow), str(info.get("hostname") or "")[:128] or None,
                         str(body.get("version") or "")[:32] or None, agent["id"]))

    def take_jobs(self, agent_id, wait=25.0):
        deadline = time.time() + max(0.0, min(wait, 30.0))
        while True:
            now = time.time()
            self.db.execute("UPDATE agent_jobs SET state='expired', finished_at=?, error='에이전트가 가져가지 않음' WHERE agent_id=? AND state='queued' AND created_at < ?",
                            (now, agent_id, now - JOB_TTL))
            rows = self.db.all("SELECT id, action, params FROM agent_jobs WHERE agent_id=? AND state='queued' ORDER BY id LIMIT 10", (agent_id,))
            if rows:
                for r in rows:
                    self.db.execute("UPDATE agent_jobs SET state='sent', sent_at=? WHERE id=? AND state='queued'", (now, r["id"]))
                return [{"id": r["id"], "action": r["action"], "params": json.loads(r["params"])} for r in rows]
            left = deadline - time.time()
            if left <= 0:
                return []
            with self._cv:
                self._cv.wait(timeout=min(left, 5.0))

    def requeue(self, job_ids):
        """보낸 줄 알았던 작업을 다시 큐로 (연결이 끊겨 전달 못 한 경우) — 다른 연결이 집어 가게."""
        ids = [j for j in (job_ids or [])]
        if not ids:
            return
        qs = ",".join("?" * len(ids))
        self.db.execute(f"UPDATE agent_jobs SET state='queued', sent_at=NULL WHERE id IN ({qs}) AND state='sent'", ids)
        with self._cv:
            self._cv.notify_all()

    def finish(self, agent_id, job_id, ok, result, error):
        r = self.db.one("SELECT * FROM agent_jobs WHERE id=? AND agent_id=?", (job_id, agent_id))
        if not r or r["state"] not in ("sent", "queued"):
            raise KeyError(job_id)
        self.db.execute("UPDATE agent_jobs SET state=?, finished_at=?, result=?, error=? WHERE id=?",
                        ("succeeded" if ok else "failed", time.time(), json.dumps(result or {}, ensure_ascii=False)[:20000],
                         (str(error)[:2000] if error else None), job_id))
        with self._cv:
            self._cv.notify_all()

    # ---------------------------------------------------------------- SIEM 쪽 (조치 요청)
    def submit(self, name, action, params, actor, reason=None, incident_id=None):
        if action not in ACTIONS:
            raise AgentError(f"알 수 없는 원격 조치 {action}")
        a = self.db.one("SELECT * FROM agents WHERE name=? AND revoked_at IS NULL", (name or "",))
        if not a:
            raise AgentError(f"에이전트 '{name}' 이 없습니다")
        if not a["last_seen"] or time.time() - a["last_seen"] > ONLINE_SEC:
            raise AgentError(f"에이전트 '{name}' 이 연결되어 있지 않습니다 (마지막 연결 {int(time.time() - (a['last_seen'] or 0))}초 전)")
        if action not in json.loads(a["allow"] or "[]"):
            raise AgentError(f"'{name}' 서버의 에이전트 설정(ALLOW)에서 '{ACTIONS[action][0]}' 을 허용하지 않았습니다")
        for k in ACTIONS[action][1]:
            if params.get(k) in (None, ""):
                raise AgentError(f"{k} 가 필요합니다")
        cur = self.db.execute("INSERT INTO agent_jobs (agent_id, action, params, state, requested_by, reason, incident_id, created_at) VALUES (?,?,?,?,?,?,?,?)",
                              (a["id"], action, json.dumps(params, ensure_ascii=False), "queued", actor, reason, incident_id, time.time()))
        with self._cv:
            self._cv.notify_all()
        return cur.lastrowid

    def wait(self, job_id, timeout=45.0):
        deadline = time.time() + timeout
        while True:
            r = self.db.one("SELECT * FROM agent_jobs WHERE id=?", (job_id,))
            if r["state"] in ("succeeded", "failed", "expired"):
                return r
            left = deadline - time.time()
            if left <= 0:
                return r
            with self._cv:
                self._cv.wait(timeout=min(left, 1.0))

    def _publish(self, name):
        if self.bus:
            self.bus.publish("config", {"kind": "agents", "name": name})
