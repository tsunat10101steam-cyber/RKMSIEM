"""RKMSIEM API 클라이언트 (표준 라이브러리). 토큰 권한 밖의 요청은 핵심이 403 으로 거부한다."""
import json
import urllib.error
import urllib.parse
import urllib.request


class RKError(Exception):
    def __init__(self, status, msg):
        super().__init__(msg)
        self.status = status


class RK:
    def __init__(self, url, token, timeout=40):
        self.url, self.token, self.timeout = url.rstrip("/"), token, timeout

    def _req(self, method, path, body=None, timeout=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "User-Agent": "hsoar/1"})
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                j = json.loads(e.read() or b"{}")
            except ValueError:
                j = {}
            raise RKError(e.code, j.get("details") or j.get("error") or f"HTTP {e.code}")

    get = lambda self, path, **kw: self._req("GET", path, **kw)
    post = lambda self, path, body=None, **kw: self._req("POST", path, body or {}, **kw)

    def feed(self, after=None, wait=25, types=None):
        q = {} if after is None else {"after": after, "wait": wait}
        if types:
            q["types"] = ",".join(types)
        return self.get("/api/feed" + (f"?{urllib.parse.urlencode(q)}" if q else ""), timeout=wait + 15)

    def incident(self, iid):
        return self.get(f"/api/incidents/{int(iid)}")

    def targets(self, iid):
        return self.get(f"/api/incidents/{int(iid)}/targets")

    def act(self, iid, action, target, reason, duration_sec=None):
        b = {"action": action, "target": target, "reason": reason}
        if action == "block_ip":
            b["duration_sec"] = duration_sec
        return self.post(f"/api/incidents/{int(iid)}/actions", b, timeout=90)

    def decide(self, run_id, step_id, approve, reason):
        return self.post(f"/api/runs/{int(run_id)}/steps/{urllib.parse.quote(step_id)}/decision", {"approve": approve, "reason": reason})

    def run(self, run_id):
        return self.get(f"/api/runs/{int(run_id)}")

    def incidents(self, size=5):
        return self.get(f"/api/incidents?size={int(size)}&open=1")

    def overview(self):
        return self.get("/api/overview")

    def block(self, ip, reason, duration_sec=None):
        b = {"ip": ip, "reason": reason}
        if duration_sec:
            b["duration_sec"] = duration_sec
        return self.post("/api/blocklist", b)

    def unblock(self, ip, reason):
        return self._req("DELETE", f"/api/blocklist/{urllib.parse.quote(ip)}?reason={urllib.parse.quote(reason)}")
