"""플레이북 실행 엔진.

- 작업 정의(YAML 플레이북)와 실행기(액션 레지스트리)를 분리
- 단계: 조건(when) · 승인(approval) · 제한 시간(timeout_sec) · 재시도(retries, 일시적 오류만) · 실패 처리(on_failure)
- 실행 상태는 DB 에 저장되어 재시작 후 이어서 진행 (성공한 단계는 다시 실행하지 않음 = 멱등)
- 중단/취소 · 수동 승인/거절 · 승인 만료 · 보상 작업(compensate, 성공한 단계를 역순으로 되돌림)
- 모든 실행/승인/조치는 감사 로그에 실행 주체 · 사유 · 승인자 · 결과와 함께 남는다
"""
import logging
import threading
import time
import traceback

from ..conditions import Lists, check_all, render
from ..db import dumps, loads
from ..plugins import ACTIONS
from .actions import ActionError, TransientError

log = logging.getLogger("rkmsiem.soar")

DONE = {"succeeded", "skipped", "failed", "timed_out", "rejected", "compensated"}
RUN_FINAL = {"succeeded", "failed", "cancelled", "compensated"}


class ApprovalError(PermissionError):
    pass


class Ctx:
    """액션에 넘기는 실행 문맥 (필요한 서비스만 노출)."""

    def __init__(self, engine, run, step_id, actor):
        self.db, self.config, self.incidents, self.bus = engine.db, engine.config, engine.incidents, engine.bus
        self.run_id, self.step_id, self.incident_id, self.mode = run["id"], step_id, run["incident_id"], run["mode"]
        self.actor = actor
        self.lists = Lists(engine.config.get("lists"))
        self.response = engine.response


class PlaybookEngine:
    def __init__(self, db, config, audit, incidents, settings, bus=None, metrics=None):
        self.db, self.config, self.audit, self.incidents, self.bus, self.metrics = db, config, audit, incidents, bus, metrics
        self.settings = settings
        self.response = None            # Platform 이 Response(어댑터) 를 넣어 줌
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread = None
        self._lock = threading.Lock()

    # ================================================================ 트리거
    def mode(self):
        return self.settings.get("soar.mode", "simulate")

    def on_incident_results(self, results):
        """탐지→사건 연결 결과 [(op, incident_id, alert)] 를 받아 맞는 플레이북 실행을 만든다."""
        created = []
        pbs = self.config.all("playbook")
        for op, inc_id, alert in results:
            inc = self.incidents.get(inc_id) or {}
            ctx = {"alert": alert, "incident": {k: inc.get(k) for k in ("id", "title", "severity", "state", "correlation_key")}}
            for pb in pbs.values():
                if not pb.get("enabled", True):
                    continue
                on = pb["trigger"]["on"]
                if on == "alert" or (on == "incident" and op == "created"):
                    if check_all(pb["trigger"].get("where"), ctx, Lists(self.config.get("lists"))):
                        per = pb["trigger"].get("once_per", "alert" if on == "alert" else "incident")
                        dedup = f"{pb['id']}:{alert['id']}:{alert['level_id']}" if per == "alert" else f"{pb['id']}:incident:{inc_id}"
                        rid = self.create_run(pb, ctx, "system", dedup=dedup)
                        if rid:
                            created.append(rid)
        if created:
            self._wake.set()
        return created

    def run_manual(self, playbook_id, incident_id, actor):
        pb = self.config.get("playbook", playbook_id)
        if not pb or not pb.get("enabled", True):
            raise KeyError(playbook_id)
        inc = self.incidents.get(incident_id)
        if not inc:
            raise KeyError(f"incident {incident_id}")
        a = self.db.one("SELECT * FROM alerts WHERE incident_id=? ORDER BY severity_rank DESC, id LIMIT 1", (incident_id,))
        from ..alerts import row_to_alert
        ctx = {"alert": row_to_alert(a) if a else {}, "incident": {k: inc.get(k) for k in ("id", "title", "severity", "state", "correlation_key")}}
        rid = self.create_run(pb, ctx, actor, dedup=None)
        self._wake.set()
        return rid

    def create_run(self, pb, ctx, actor, dedup):
        now = time.time()
        alert = ctx.get("alert") or {}
        slim_alert = {k: alert.get(k) for k in ("id", "rule_id", "level_id", "title", "severity", "group", "group_key", "risk_score", "detail")}
        with self.db.tx() as c:
            try:
                cur = c.execute("INSERT INTO playbook_runs (playbook_id, playbook_version, incident_id, alert_id, state, mode, context, "
                                "requested_by, dedup_key, created_at, updated_at, sample) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                                (pb["id"], pb.get("_version") or self.config.version("playbook", pb["id"]) or 0, ctx["incident"].get("id"),
                                 alert.get("id"), "queued", self.mode(), dumps({"alert": slim_alert, "incident": ctx["incident"]}),
                                 actor, dedup, now, now, int(bool(alert.get("sample")))))
            except Exception as e:
                if "UNIQUE" in str(e):                    # 같은 경보에 같은 플레이북은 한 번만
                    return None
                raise
            rid = cur.lastrowid
            for i, s in enumerate(pb["steps"]):
                c.execute("INSERT INTO step_runs (run_id, step_id, idx, action, state, idem_key) VALUES (?,?,?,?,?,?)",
                          (rid, s["id"], i, s["action"], "pending", f"{rid}:{s['id']}"))
            self.audit.record(actor, "playbook.run.create", "run", rid, None,
                              {"playbook": pb["id"], "incident_id": ctx["incident"].get("id"), "alert_id": alert.get("id"), "mode": self.mode()}, conn=c)
        if self.metrics:
            self.metrics.inc("playbook_runs_total", state="queued", playbook=pb["id"])
        self._publish(rid)
        return rid

    # ================================================================ 작업자
    def start(self):
        # 비정상 종료로 'running' 에 멈춘 실행은 이어서 진행
        self.db.execute("UPDATE playbook_runs SET state='queued' WHERE state='running'")
        self.db.execute("UPDATE step_runs SET state='pending' WHERE state='running'")
        self._thread = threading.Thread(target=self._loop, name="soar", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        self._wake.set()
        if self._thread:
            self._thread.join(10)

    def alive(self):
        return bool(self._thread and self._thread.is_alive())

    def _loop(self):
        poll = self.settings.get("soar.worker_poll_ms", 300) / 1000
        while not self._stop.is_set():
            try:
                self.expire_approvals()
                for r in self.db.all("SELECT id FROM playbook_runs WHERE state='queued' ORDER BY id LIMIT 20"):
                    self.execute(r["id"])
            except Exception:
                log.exception("soar loop error")
            self._wake.wait(poll)
            self._wake.clear()

    def run_pending(self, max_rounds=20):
        """테스트·CLI 용: 대기 중인 실행을 동기로 끝까지 처리."""
        for _ in range(max_rounds):
            self.expire_approvals()
            rows = self.db.all("SELECT id FROM playbook_runs WHERE state='queued' ORDER BY id")
            if not rows:
                return
            for r in rows:
                self.execute(r["id"])

    # ================================================================ 실행
    def _approval_needed(self, step, act):
        policy = self.config.get("approval") or {}
        req = policy.get("require_approval_for", "destructive")
        mode = step.get("approval", "policy")
        if getattr(act, "destructive", False) and self.mode() == "live":
            return True                                      # live 파괴적 조치는 설정과 무관하게 항상 승인
        if mode == "required":
            return True
        if mode == "none":
            return False
        return req == "all" or (req == "destructive" and getattr(act, "destructive", False))

    def execute(self, run_id):
        with self._lock:
            run = self.db.one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
            if not run or run["state"] in RUN_FINAL or run["state"] == "waiting_approval":
                return
            pb = self.config.content_at("playbook", run["playbook_id"], run["playbook_version"]) or self.config.get("playbook", run["playbook_id"])
            if not pb:
                self._finish(run, "failed", "플레이북 정의를 찾을 수 없음")
                return
            now = time.time()
            self.db.execute("UPDATE playbook_runs SET state='running', started_at=COALESCE(started_at, ?), updated_at=? WHERE id=?",
                            (now, now, run_id))
            ctx = loads(run["context"], {})
            ctx["steps"], ctx["run"] = {}, {"id": run_id, "mode": run["mode"]}
            rows = {s["step_id"]: s for s in self.db.all("SELECT * FROM step_runs WHERE run_id=? ORDER BY idx", (run_id,))}
            for step in pb["steps"]:
                sr = rows[step["id"]]
                if sr["state"] in DONE:
                    ctx["steps"][step["id"]] = {"state": sr["state"], "output": loads(sr["output"], {})}
                    if sr["state"] in ("failed", "timed_out", "rejected") and step.get("on_failure", "abort") != "continue":
                        return self._on_step_failure(run, pb, step, ctx)
                    continue
                act = ACTIONS.get(step["action"])
                if act is None:
                    self._set_step(sr["id"], "failed", error=f"unknown action {step['action']}")
                    ctx["steps"][step["id"]] = {"state": "failed", "output": {}}
                    if step.get("on_failure", "abort") != "continue":
                        return self._on_step_failure(run, pb, step, ctx)
                    continue
                if not check_all(step.get("when"), ctx, Lists(self.config.get("lists"))):
                    self._set_step(sr["id"], "skipped")
                    ctx["steps"][step["id"]] = {"state": "skipped", "output": {}}
                    continue
                inp = render(step.get("input") or {}, ctx)
                if self._approval_needed(step, act):
                    ap = self.db.one("SELECT * FROM approvals WHERE run_id=? AND step_id=?", (run_id, step["id"]))
                    if ap is None:
                        self._request_approval(run, step, inp, act)
                        return
                    if ap["state"] == "pending":
                        self._set_run(run_id, "waiting_approval")
                        return
                    if ap["state"] in ("rejected", "expired"):
                        st = "rejected" if ap["state"] == "rejected" else "timed_out"
                        self._set_step(sr["id"], st, error=f"approval {ap['state']}: {ap.get('reason') or ''}")
                        ctx["steps"][step["id"]] = {"state": st, "output": {}}
                        if step.get("on_failure", "abort") != "continue":
                            return self._on_step_failure(run, pb, step, ctx)
                        continue
                state, out, err = self._run_action(run, step, sr, act, inp)
                ctx["steps"][step["id"]] = {"state": state, "output": out}
                if state != "succeeded" and step.get("on_failure", "abort") != "continue":
                    return self._on_step_failure(run, pb, step, ctx)
            self._finish(run, "succeeded")

    def _run_action(self, run, step, sr, act, inp):
        retries, backoff = step.get("retries", 0), step.get("retry_backoff_sec", 0.2)
        timeout = step.get("timeout_sec", 30)
        actor = f"playbook:{run['playbook_id']}"
        state, out, err = "failed", {}, None
        for attempt in range(1, retries + 2):
            t0 = time.time()
            self.db.execute("UPDATE step_runs SET state='running', attempts=?, input=?, started_at=COALESCE(started_at, ?) WHERE id=?",
                            (attempt, dumps(inp), t0, sr["id"]))
            box = {}

            def target():
                try:
                    box["out"] = act(Ctx(self, run, step["id"], actor), inp)
                except Exception as e:                      # noqa: BLE001
                    box["err"] = e

            th = threading.Thread(target=target, daemon=True)
            th.start()
            th.join(timeout)
            if th.is_alive():                              # 제한 시간 초과 (스레드는 결과를 버림)
                state, err = "timed_out", f"timeout after {timeout}s"
                transient = True
            elif "err" in box:
                e = box["err"]
                state, err = "failed", f"{type(e).__name__}: {e}"
                transient = isinstance(e, TransientError)
                if not isinstance(e, ActionError):
                    log.error("action crashed: %s", "".join(traceback.format_exception(e))[-2000:])
            else:
                state, out, err, transient = "succeeded", box.get("out") or {}, None, False
            if self.metrics:
                self.metrics.observe("step_ms", (time.time() - t0) * 1000, action=step["action"])
            if state == "succeeded" or not transient or attempt > retries:
                break
            time.sleep(backoff * attempt)
        self._set_step(sr["id"], state, out, err)
        self.audit.record(actor, f"action.{step['action']}", "run", run["id"], f"step {step['id']}",
                          {"state": state, "input": inp, "output": out, "error": err, "mode": run["mode"],
                           "destructive": getattr(act, "destructive", False)})
        if self.metrics:
            self.metrics.inc("steps_total", action=step["action"], state=state)
        return state, out, err

    def _on_step_failure(self, run, pb, step, ctx):
        mode = step.get("on_failure", "abort")
        if mode == "compensate":
            self.compensate(run["id"], f"playbook:{run['playbook_id']}", f"step {step['id']} failed")
            return
        self._finish(run, "failed", f"step {step['id']} {ctx['steps'][step['id']]['state']}")

    # ================================================================ 승인
    def _request_approval(self, run, step, inp, act):
        timeout = (self.config.get("approval") or {}).get("timeout_sec", 3600)
        now = time.time()
        with self.db.tx() as c:
            c.execute("INSERT OR IGNORE INTO approvals (run_id, step_id, state, requested_at, expires_at) VALUES (?,?,?,?,?)",
                      (run["id"], step["id"], "pending", now, now + timeout))
            c.execute("UPDATE step_runs SET state='waiting_approval', input=? WHERE run_id=? AND step_id=?", (dumps(inp), run["id"], step["id"]))
            c.execute("UPDATE playbook_runs SET state='waiting_approval', updated_at=? WHERE id=?", (now, run["id"]))
            self.audit.record(f"playbook:{run['playbook_id']}", "approval.request", "run", run["id"], f"step {step['id']}",
                              {"action": step["action"], "input": inp, "destructive": getattr(act, "destructive", False),
                               "mode": run["mode"], "expires_at": now + timeout}, conn=c)
        if run["incident_id"]:
            self.incidents.add_timeline(run["incident_id"], "approval_requested", "system",
                                        {"run_id": run["id"], "step_id": step["id"], "action": step["action"], "input": inp})
        self._publish(run["id"])

    def decide(self, run_id, step_id, actor, actor_role, approve, reason):
        policy = self.config.get("approval") or {}
        if actor_role not in policy.get("approver_roles", []):
            raise ApprovalError(f"역할 '{actor_role}' 은 승인할 수 없습니다")
        run = self.db.one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
        if not run:
            raise KeyError(run_id)
        if policy.get("forbid_self_approval", True) and run["requested_by"] == actor:
            raise ApprovalError("실행을 요청한 사람은 승인할 수 없습니다")
        if not (reason or "").strip():
            raise ApprovalError("승인/거절 사유가 필요합니다")
        with self.db.tx() as c:
            ap = c.execute("SELECT state FROM approvals WHERE run_id=? AND step_id=?", (run_id, step_id)).fetchone()
            if not ap or ap[0] != "pending":
                raise ApprovalError("대기 중인 승인 요청이 없습니다")
            st = "approved" if approve else "rejected"
            c.execute("UPDATE approvals SET state=?, decided_at=?, decided_by=?, reason=? WHERE run_id=? AND step_id=?",
                      (st, time.time(), actor, reason, run_id, step_id))
            c.execute("UPDATE playbook_runs SET state='queued', updated_at=? WHERE id=? AND state='waiting_approval'", (time.time(), run_id))
            self.audit.record(actor, f"approval.{st}", "run", run_id, reason, {"step_id": step_id, "role": actor_role}, conn=c)
        if run["incident_id"]:
            self.incidents.add_timeline(run["incident_id"], f"approval_{st}", actor, {"run_id": run_id, "step_id": step_id, "reason": reason})
        self._wake.set()
        self._publish(run_id)

    def expire_approvals(self):
        now = time.time()
        rows = self.db.all("SELECT run_id, step_id FROM approvals WHERE state='pending' AND expires_at < ?", (now,))
        for r in rows:
            with self.db.tx() as c:
                c.execute("UPDATE approvals SET state='expired', decided_at=? WHERE run_id=? AND step_id=? AND state='pending'",
                          (now, r["run_id"], r["step_id"]))
                c.execute("UPDATE playbook_runs SET state='queued' WHERE id=? AND state='waiting_approval'", (r["run_id"],))
                self.audit.record("system", "approval.expired", "run", r["run_id"], "승인 시간 초과", {"step_id": r["step_id"]}, conn=c)
        return len(rows)

    # ================================================================ 취소 · 보상
    def cancel(self, run_id, actor, reason, compensate=True):
        run = self.db.one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
        if not run:
            raise KeyError(run_id)
        if run["state"] in RUN_FINAL:
            raise ApprovalError(f"이미 끝난 실행입니다 ({run['state']})")
        with self.db.tx() as c:
            c.execute("UPDATE approvals SET state='expired', decided_at=?, reason='run cancelled' WHERE run_id=? AND state='pending'",
                      (time.time(), run_id))
            c.execute("UPDATE step_runs SET state='skipped' WHERE run_id=? AND state IN ('pending','waiting_approval')", (run_id,))
            self.audit.record(actor, "playbook.run.cancel", "run", run_id, reason, {"compensate": compensate}, conn=c)
        if compensate:
            self.compensate(run_id, actor, reason, final_state="cancelled")
        else:
            self._finish(run, "cancelled", reason)

    def compensate(self, run_id, actor, reason, final_state="compensated"):
        run = self.db.one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
        pb = self.config.content_at("playbook", run["playbook_id"], run["playbook_version"]) or {}
        ctx = loads(run["context"], {})
        ctx["steps"] = {s["step_id"]: {"state": s["state"], "output": loads(s["output"], {})}
                        for s in self.db.all("SELECT * FROM step_runs WHERE run_id=?", (run_id,))}
        done = self.db.all("SELECT * FROM step_runs WHERE run_id=? AND state='succeeded' ORDER BY idx DESC", (run_id,))
        defs = {s["id"]: s for s in pb.get("steps", [])}
        results = []
        for sr in done:
            comp = (defs.get(sr["step_id"]) or {}).get("compensate")
            if not comp:
                continue
            act = ACTIONS[comp["action"]]
            inp = render(comp.get("input") or {}, ctx)
            try:
                out = act(Ctx(self, run, sr["step_id"], actor), inp)
                self._set_step(sr["id"], "compensated", dict(loads(sr["output"], {}), compensation=out))
                results.append({"step": sr["step_id"], "ok": True})
            except Exception as e:                           # noqa: BLE001
                results.append({"step": sr["step_id"], "ok": False, "error": str(e)})
            self.audit.record(actor, f"compensate.{comp['action']}", "run", run_id, reason, {"step": sr["step_id"], "input": inp,
                                                                                             "result": results[-1]})
        self._finish(run, final_state, reason)
        return results

    # ================================================================ 사람의 직접 조치 (차단 목록 화면 등)
    def manual_action(self, action_name, inp, actor, reason):
        """승인 권한이 있는 사람이 직접 실행하는 조치 — 그 자체가 승인이므로 플레이북 승인 단계 없이 실행하고 감사에 남긴다."""
        act = ACTIONS[action_name]
        run = {"id": None, "incident_id": None, "mode": self.mode(), "playbook_id": "manual"}
        try:
            out = act(Ctx(self, run, action_name, actor), inp)
            ok, err = True, None
        except Exception as e:                       # noqa: BLE001
            out, ok, err = {}, False, str(e)
        self.audit.record(actor, f"manual.{action_name}", "manual", None, reason,
                          {"input": inp, "output": out, "error": err, "mode": run["mode"], "destructive": getattr(act, "destructive", False)})
        if not ok:
            raise ApprovalError(err)
        return out

    # ================================================================ 상태
    def _set_step(self, sid, state, output=None, error=None):
        self.db.execute("UPDATE step_runs SET state=?, output=COALESCE(?, output), error=?, finished_at=? WHERE id=?",
                        (state, dumps(output) if output is not None else None, error, time.time(), sid))

    def _set_run(self, run_id, state):
        self.db.execute("UPDATE playbook_runs SET state=?, updated_at=? WHERE id=?", (state, time.time(), run_id))
        self._publish(run_id)

    def _finish(self, run, state, error=None):
        now = time.time()
        self.db.execute("UPDATE playbook_runs SET state=?, error=?, finished_at=?, updated_at=? WHERE id=?", (state, error, now, now, run["id"]))
        self.audit.record(f"playbook:{run['playbook_id']}", "playbook.run.finish", "run", run["id"], error, {"state": state})
        if self.metrics:
            self.metrics.inc("playbook_runs_total", state=state, playbook=run["playbook_id"])
            self.metrics.observe("run_ms", (now - run["created_at"]) * 1000, playbook=run["playbook_id"])
        if run["incident_id"]:
            self.incidents.add_timeline(run["incident_id"], "playbook_finished", "system",
                                        {"run_id": run["id"], "playbook": run["playbook_id"], "state": state, "error": error})
        self._publish(run["id"])

    def _publish(self, run_id):
        if self.bus:
            r = self.db.one("SELECT id, playbook_id, state, incident_id, mode FROM playbook_runs WHERE id=?", (run_id,))
            self.bus.publish("run", r)

    def detail(self, run_id):
        r = self.db.one("SELECT * FROM playbook_runs WHERE id=?", (run_id,))
        if not r:
            return None
        r["context"] = loads(r["context"], {})
        r["steps"] = [dict(s, input=loads(s["input"], None), output=loads(s["output"], None))
                      for s in self.db.all("SELECT * FROM step_runs WHERE run_id=? ORDER BY idx", (run_id,))]
        r["approvals"] = self.db.all("SELECT * FROM approvals WHERE run_id=? ORDER BY id", (run_id,))
        return r
