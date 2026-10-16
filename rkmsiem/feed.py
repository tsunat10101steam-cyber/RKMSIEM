"""이벤트 피드 — 실시간 버스의 중요한 이벤트를 DB 에 순번과 함께 남겨, 추가 기능(HSOAR 등)이 API 토큰(feed:read)으로 이어 읽는다.

GET /api/feed?after=<seq>&wait=25&types=alert,incident
  after 없이 부르면 지금 마지막 순번만 돌려줌 (새로 붙는 쪽은 그 뒤부터) · 7일 지난 것은 지움
"""
import json
import threading
import time

TYPES = {"alert", "incident", "run", "notification", "blocklist", "agents", "task"}
KEEP_SEC = 7 * 86400
MAX_DATA = 64 * 1024


class Feed:
    def __init__(self, db):
        self.db = db
        self._cv = threading.Condition()

    def on_publish(self, kind, data):
        """Bus 리스너 — config 이벤트 중 차단·에이전트는 따로 이름을 붙여 남김."""
        if kind == "config" and isinstance(data, dict) and data.get("kind") in ("blocklist", "agents"):
            kind = data["kind"]
        if kind not in TYPES:
            return
        raw = json.dumps(data, ensure_ascii=False, default=str)
        if len(raw) > MAX_DATA:
            raw = json.dumps({"truncated": True, "id": (data or {}).get("id") if isinstance(data, dict) else None})
        self.db.execute("INSERT INTO event_feed (ts, type, data) VALUES (?,?,?)", (time.time(), kind, raw))
        with self._cv:
            self._cv.notify_all()

    def last(self):
        return self.db.scalar("SELECT COALESCE(MAX(seq), 0) FROM event_feed") or 0

    def read(self, after, types=None, limit=200, wait=0.0):
        deadline = time.time() + max(0.0, min(float(wait), 30.0))
        while True:
            sql, args = "SELECT seq, ts, type, data FROM event_feed WHERE seq > ?", [int(after)]
            if types:
                sql += f" AND type IN ({','.join('?' * len(types))})"
                args += list(types)
            rows = self.db.all(sql + " ORDER BY seq LIMIT ?", args + [min(int(limit), 1000)])
            if rows or time.time() >= deadline:
                for r in rows:
                    r["data"] = json.loads(r["data"])
                return rows
            with self._cv:
                self._cv.wait(timeout=min(deadline - time.time(), 5.0))

    def prune(self, now=None):
        return self.db.execute("DELETE FROM event_feed WHERE ts < ?", ((now or time.time()) - KEEP_SEC,)).rowcount
