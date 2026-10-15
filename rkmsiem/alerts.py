"""경보 저장: 엔진의 변경(new/escalate/update)을 DB 에 반영하고, 재시작 시 열린 경보를 엔진에 돌려준다."""
import time

from .db import dumps, loads

_PERSIST = ("rule_id", "rule_version", "level_id", "title", "severity", "severity_rank", "risk_score", "group_key",
            "dedup_key", "first_ts", "last_ts", "event_count", "detail", "status", "sample")


def row_to_alert(r):
    a = dict(r)
    a["group"] = loads(a.pop("group_fields"), {})
    a["risk_basis"] = loads(a["risk_basis"], {})
    a["evidence"] = loads(a["evidence"], [])
    extra = a["risk_basis"].get("_extra", {})
    a.update({k: v for k, v in extra.items() if k not in a})
    a["sample"] = bool(a["sample"])
    return a


class AlertStore:
    def __init__(self, db, metrics=None):
        self.db, self.metrics = db, metrics

    def apply(self, changes, conn=None):
        """변경을 저장하고 id 를 채운다. 반환: 저장된 변경 목록(같은 형태)."""
        now = time.time()
        out = []

        def _do(c):
            for ch in changes:
                a = ch["alert"]
                basis = dict(a["risk_basis"], _extra={"rule_name": a.get("rule_name"), "basis": a.get("basis"),
                                                      "level_min": a.get("level_min"), "incident_key": a.get("incident_key"),
                                                      "tags": a.get("tags", [])})
                if a.get("id") is None:
                    e2e = (now - a["trigger_received_at"]) * 1000 if a.get("trigger_received_at") else None
                    cur = c.execute(
                        "INSERT INTO alerts (rule_id, rule_version, level_id, title, severity, severity_rank, risk_score, risk_basis, "
                        "group_key, group_fields, dedup_key, first_ts, last_ts, event_count, evidence, detail, status, created_at, "
                        "updated_at, sample, e2e_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (a["rule_id"], a["rule_version"], a["level_id"], a["title"], a["severity"], a["severity_rank"], a["risk_score"],
                         dumps(basis), a["group_key"], dumps(a["group"]), a["dedup_key"], a["first_ts"], a["last_ts"], a["event_count"],
                         dumps(a["evidence"]), a["detail"], a["status"], now, now, int(a["sample"]), e2e))
                    a["id"] = cur.lastrowid
                    a["created_at"] = now
                    if self.metrics and e2e is not None:
                        self.metrics.observe("e2e_event_to_alert_ms", e2e)
                else:
                    c.execute("UPDATE alerts SET level_id=?, title=?, severity=?, severity_rank=?, risk_score=?, risk_basis=?, "
                              "last_ts=?, event_count=?, evidence=?, detail=?, updated_at=?, sample=? WHERE id=?",
                              (a["level_id"], a["title"], a["severity"], a["severity_rank"], a["risk_score"], dumps(basis),
                               a["last_ts"], a["event_count"], dumps(a["evidence"]), a["detail"], now, int(a["sample"]), a["id"]))
                if self.metrics:
                    self.metrics.inc("alerts_total", op=ch["op"], rule=a["rule_id"])
                out.append(ch)

        if conn is not None:
            _do(conn)
        else:
            with self.db.tx() as c:
                _do(c)
        return out

    def open_for_warmup(self, since_ts):
        rows = self.db.all("SELECT * FROM alerts WHERE status != 'closed' AND last_ts >= ?", (since_ts,))
        out = []
        for r in rows:
            a = row_to_alert(r)
            a.setdefault("level_min", a["risk_basis"].get("level_min", 0))
            out.append(a)
        return out

    def get(self, alert_id):
        r = self.db.one("SELECT * FROM alerts WHERE id=?", (alert_id,))
        return row_to_alert(r) if r else None
