"""사건 관리: 경보 → 사건 생성/연결 · 상태 워크플로(설정) · 담당자 · 타임라인 · 감사."""
import time

from .db import dumps, loads
from .detect import RANK, SEV


class WorkflowError(ValueError):
    pass


class IncidentService:
    def __init__(self, db, config, audit, bus=None, metrics=None):
        self.db, self.config, self.audit, self.bus, self.metrics = db, config, audit, bus, metrics

    # ---------- 설정 ----------
    def workflow(self):
        return self.config.get("workflow")

    def terminal_states(self):
        return {s["id"] for s in self.workflow()["states"] if s.get("terminal")}

    def _window(self):
        return (self.workflow().get("grouping") or {}).get("window_sec", 86400)

    # ---------- 경보 연결 ----------
    def on_alerts(self, changes, conn):
        """같은 트랜잭션 안에서 호출됨. 반환: [(op, incident_id, alert)] — 새로 만들어진 사건 포함."""
        out = []
        for ch in changes:
            a = ch["alert"]
            if ch["op"] == "update":
                if a.get("incident_id"):
                    conn.execute("UPDATE incidents SET last_event_ts = MAX(COALESCE(last_event_ts, 0), ?), updated_at=? WHERE id=?",
                                 (a["last_ts"], time.time(), a["incident_id"]))
                continue
            if ch["op"] == "escalate":
                inc = a.get("incident_id")
                if inc:
                    self._raise_severity(conn, inc, a)
                    self._timeline(conn, inc, "alert_escalated", "system",
                                   {"alert_id": a["id"], "level": a["level_id"], "severity": a["severity"], "title": a["title"]})
                    out.append(("escalate", inc, a))
                continue
            inc_id, created = self._link(conn, a)
            a["incident_id"] = inc_id
            out.append(("created" if created else "linked", inc_id, a))
        return out

    def _corr(self, a):
        key = a.get("incident_key") or a["group"]
        return "|".join(f"{k}={v}" for k, v in sorted(key.items())), key

    def _link(self, conn, a):
        corr, fields = self._corr(a)
        term = sorted(self.terminal_states())
        q = "SELECT id FROM incidents WHERE correlation_key=? AND last_event_ts >= ?"
        params = [corr, a["first_ts"] - self._window()]
        if term:
            q += f" AND state NOT IN ({','.join('?' * len(term))})"
            params += term
        row = conn.execute(q + " ORDER BY id DESC LIMIT 1", params).fetchone()
        now = time.time()
        if row:
            inc = row[0]
            conn.execute("UPDATE alerts SET incident_id=? WHERE id=?", (inc, a["id"]))
            conn.execute("UPDATE incidents SET last_event_ts = MAX(COALESCE(last_event_ts,0), ?), updated_at=?, "
                         "risk_score = MAX(risk_score, ?) WHERE id=?", (a["last_ts"], now, a["risk_score"], inc))
            self._raise_severity(conn, inc, a)
            self._timeline(conn, inc, "alert_linked", "system", {"alert_id": a["id"], "rule_id": a["rule_id"], "title": a["title"],
                                                                  "severity": a["severity"]})
            return inc, False
        title = f"{a['title']} — " + ", ".join(f"{v}" for v in fields.values())
        cur = conn.execute("INSERT INTO incidents (title, state, severity, severity_rank, risk_score, correlation_key, correlation_fields, "
                           "created_at, updated_at, last_event_ts, sample) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                           (title, self.workflow()["initial"], a["severity"], a["severity_rank"], a["risk_score"], corr, dumps(fields),
                            now, now, a["last_ts"], int(a.get("sample", False))))
        inc = cur.lastrowid
        conn.execute("UPDATE alerts SET incident_id=? WHERE id=?", (inc, a["id"]))
        self._timeline(conn, inc, "created", "system", {"alert_id": a["id"], "rule_id": a["rule_id"], "title": a["title"],
                                                         "severity": a["severity"]})
        self.audit.record("system", "incident.create", "incident", inc, None, {"alert_id": a["id"], "correlation_key": corr}, conn=conn)
        if self.metrics:
            self.metrics.inc("incidents_created_total")
        return inc, True

    def _raise_severity(self, conn, inc, a):
        cur = conn.execute("SELECT severity_rank FROM incidents WHERE id=?", (inc,)).fetchone()
        if cur and a["severity_rank"] > cur[0]:
            conn.execute("UPDATE incidents SET severity=?, severity_rank=?, updated_at=? WHERE id=?",
                         (a["severity"], a["severity_rank"], time.time(), inc))
            self._timeline(conn, inc, "severity_changed", "system", {"to": a["severity"], "by_alert": a["id"]})

    def _timeline(self, conn, inc, kind, actor, detail):
        conn.execute("INSERT INTO incident_timeline (incident_id, ts, kind, actor, detail) VALUES (?,?,?,?,?)",
                     (inc, time.time(), kind, actor, dumps(detail)))

    # ---------- 사람의 조작 ----------
    def transition(self, inc_id, to, actor, reason=None):
        wf = self.workflow()
        with self.db.tx() as c:
            row = c.execute("SELECT state FROM incidents WHERE id=?", (inc_id,)).fetchone()
            if not row:
                raise KeyError(inc_id)
            frm = row[0]
            rule = next((t for t in wf["transitions"] if t["from"] == frm and to in t["to"]), None)
            if rule is None:
                raise WorkflowError(f"'{frm}' → '{to}' 전이는 허용되지 않습니다")
            if rule.get("require_reason") and not (reason or "").strip():
                raise WorkflowError("이 전이는 사유가 필요합니다")
            now = time.time()
            closed = now if to in self.terminal_states() else None
            c.execute("UPDATE incidents SET state=?, updated_at=?, closed_at=? WHERE id=?", (to, now, closed, inc_id))
            if closed:
                c.execute("UPDATE alerts SET status='closed', updated_at=? WHERE incident_id=?", (now, inc_id))
            self._timeline(c, inc_id, "state_changed", actor, {"from": frm, "to": to, "reason": reason})
            self.audit.record(actor, "incident.transition", "incident", inc_id, reason, {"from": frm, "to": to}, conn=c)
        if to == "false_positive" and self.metrics:
            for r in self.db.all("SELECT DISTINCT rule_id FROM alerts WHERE incident_id=?", (inc_id,)):
                self.metrics.inc("false_positive_total", rule=r["rule_id"])
        self._publish(inc_id)
        return self.get(inc_id)

    def assign(self, inc_id, assignee, actor):
        with self.db.tx() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE id=?", (inc_id,)).fetchone():
                raise KeyError(inc_id)
            c.execute("UPDATE incidents SET assignee=?, updated_at=? WHERE id=?", (assignee, time.time(), inc_id))
            self._timeline(c, inc_id, "assigned", actor, {"assignee": assignee})
            self.audit.record(actor, "incident.assign", "incident", inc_id, None, {"assignee": assignee}, conn=c)
        self._publish(inc_id)
        return self.get(inc_id)

    def comment(self, inc_id, text, actor):
        with self.db.tx() as c:
            if not c.execute("SELECT 1 FROM incidents WHERE id=?", (inc_id,)).fetchone():
                raise KeyError(inc_id)
            self._timeline(c, inc_id, "comment", actor, {"text": text[:4000]})
            self.audit.record(actor, "incident.comment", "incident", inc_id, None, {"length": len(text)}, conn=c)
        self._publish(inc_id)

    def add_timeline(self, inc_id, kind, actor, detail):
        with self.db.tx() as c:
            self._timeline(c, inc_id, kind, actor, detail)
        self._publish(inc_id)

    def set_severity(self, inc_id, severity, actor, reason):
        if severity not in SEV:
            raise ValueError(severity)
        with self.db.tx() as c:
            c.execute("UPDATE incidents SET severity=?, severity_rank=?, updated_at=? WHERE id=?", (severity, RANK[severity], time.time(), inc_id))
            self._timeline(c, inc_id, "severity_changed", actor, {"to": severity, "reason": reason})
            self.audit.record(actor, "incident.severity", "incident", inc_id, reason, {"to": severity}, conn=c)
        self._publish(inc_id)

    # ---------- 조회 ----------
    def get(self, inc_id):
        r = self.db.one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not r:
            return None
        r["correlation_fields"] = loads(r.get("correlation_fields"), {})
        r["state_label"] = next((s["label"] for s in self.workflow()["states"] if s["id"] == r["state"]), r["state"])
        r["allowed_transitions"] = sorted({x for t in self.workflow()["transitions"] if t["from"] == r["state"] for x in t["to"]})
        return r

    def detail(self, inc_id):
        inc = self.get(inc_id)
        if not inc:
            return None
        inc["timeline"] = [dict(t, detail=loads(t["detail"], {})) for t in
                           self.db.all("SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY ts, id", (inc_id,))]
        return inc

    def _publish(self, inc_id):
        if self.bus:
            inc = self.get(inc_id)
            self.bus.publish("incident", {"id": inc_id, "state": inc["state"], "severity": inc["severity"], "title": inc["title"],
                                          "assignee": inc.get("assignee")})
