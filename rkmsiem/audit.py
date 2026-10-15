"""감사 로그: 해시 체인으로 묶인 추가 전용 기록.

- 각 행의 hash = sha256(prev_hash + 정규화된 행 내용) → 중간 행을 바꾸면 이후 체인이 깨짐
- DB 트리거가 UPDATE/DELETE 를 막고, API 에는 수정·삭제 경로가 없다
"""
import hashlib
import time

from .db import dumps

GENESIS = "0" * 64


def _digest(prev, row):
    body = dumps([row["ts"], row["actor"], row["action"], row["target_type"], row["target_id"], row["reason"], row["detail"]])
    return hashlib.sha256((prev + body).encode()).hexdigest()


class AuditLog:
    def __init__(self, db, mask=None):
        self.db = db
        self.mask = mask or (lambda d: d)

    def record(self, actor, action, target_type=None, target_id=None, reason=None, detail=None, conn=None):
        row = {"ts": round(time.time(), 6), "actor": actor, "action": action, "target_type": target_type,
               "target_id": None if target_id is None else str(target_id), "reason": reason,
               "detail": dumps(self.mask(detail)) if detail is not None else None}

        def _write(c):
            prev = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = prev[0] if prev else GENESIS
            h = _digest(prev, row)
            c.execute("INSERT INTO audit_log (ts, actor, action, target_type, target_id, reason, detail, prev_hash, hash) "
                      "VALUES (?,?,?,?,?,?,?,?,?)",
                      (row["ts"], actor, action, target_type, row["target_id"], reason, row["detail"], prev, h))
            return h

        if conn is not None:          # 호출자 트랜잭션 안에서 함께 기록
            return _write(conn)
        with self.db.tx() as c:
            return _write(c)

    def verify(self):
        prev, n = GENESIS, 0
        for r in self.db.all("SELECT * FROM audit_log ORDER BY id"):
            if r["prev_hash"] != prev or _digest(prev, r) != r["hash"]:
                return {"ok": False, "broken_at": r["id"], "checked": n}
            prev, n = r["hash"], n + 1
        return {"ok": True, "checked": n}

    def list(self, limit=100, offset=0, target_type=None, target_id=None):
        sql, params = "SELECT * FROM audit_log", []
        conds = []
        if target_type:
            conds.append("target_type = ?"); params.append(target_type)
        if target_id is not None:
            conds.append("target_id = ?"); params.append(str(target_id))
        if conds:
            sql += " WHERE " + " AND ".join(conds)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        return self.db.all(sql, params)
