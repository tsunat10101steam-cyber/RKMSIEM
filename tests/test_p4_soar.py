"""P4: 플레이북 — 자동 트리거 · 승인/거절/만료 · simulate/live · 멱등 · 보상 · 타임아웃/재시도 · 복구 · 안전장치."""
import time

import pytest

from rkmsiem import plugins
from rkmsiem.pipeline import make_record
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings
from rkmsiem.soar.actions import TransientError
from rkmsiem.soar.engine import ApprovalError


def make_platform(tmp_path, config_dir, mode="simulate"):
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "p.db"), "soar.mode": mode})
    return Platform(s)


def feed(p, lines, src="sample-authlog"):
    p.pipeline.process_batch([make_record(src, l) for l in lines])


def compromise_lines(ip="103.75.190.8", user="backup", n=6):
    lines = [f"2026-10-12 01:12:{i:02d} FAIL user={user} ip={ip}" for i in range(n)]
    return lines + [f"2026-10-12 01:12:{n + 5:02d} SUCCESS user={user} ip={ip}"]


def run_of(p, playbook):
    return p.db.one("SELECT * FROM playbook_runs WHERE playbook_id=? ORDER BY id DESC", (playbook,))


def steps(p, run_id):
    return {s["step_id"]: s for s in p.soar.detail(run_id)["steps"]}


def test_auto_trigger_approval_flow_simulate(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir)
    assert p.config_report["rejected"] == []
    feed(p, compromise_lines())
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    assert run and run["state"] == "waiting_approval" and run["mode"] == "simulate"
    st = steps(p, run["id"])
    assert st["reputation"]["output"]["verdict"] == "malicious"                 # 샘플 인텔
    assert st["escalate"]["state"] == "succeeded" and st["notify_soc"]["state"] == "succeeded"
    assert st["block_ip"]["state"] == "waiting_approval"
    with pytest.raises(ApprovalError):
        p.soar.decide(run["id"], "block_ip", "eve", "viewer", True, "ok")          # 권한 없는 역할
    with pytest.raises(ApprovalError):
        p.soar.decide(run["id"], "block_ip", "bob", "responder", True, "")         # 사유 없음
    p.soar.decide(run["id"], "block_ip", "bob", "responder", True, "악성 IP 확인")
    p.soar.run_pending()
    assert run_of(p, "compromise_response")["state"] == "waiting_approval"     # 다음 파괴적 단계(계정) 승인 대기
    p.soar.decide(run["id"], "disable_account", "bob", "responder", True, "침해 계정")
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    st = steps(p, run["id"])
    assert run["state"] == "succeeded"
    assert st["block_ip"]["output"]["simulated"] is True and st["disable_account"]["output"]["simulated"] is True
    assert p.db.scalar("SELECT COUNT(*) FROM blocklist") == 0                   # simulate → 실제 변경 없음
    inc = p.incidents.detail(run["incident_id"])
    assert inc["severity"] == "critical" and any(t["kind"] == "playbook_result" for t in inc["timeline"])
    acts = [a["action"] for a in p.audit.list(500)]
    assert "approval.approved" in acts and "action.block_ip" in acts and p.audit.verify()["ok"]
    approved = [a for a in p.audit.list(500) if a["action"] == "approval.approved"]
    assert {a["actor"] for a in approved} == {"bob"} and all(a["reason"] for a in approved)


def test_no_duplicate_runs_for_same_alert(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir)
    feed(p, compromise_lines())
    feed(p, [f"2026-10-12 01:13:{i:02d} FAIL user=backup ip=103.75.190.8" for i in range(3)])   # 같은 경보 갱신
    # COMPROMISE·NO_LOCKOUT 경보 2개 + 갱신이 있어도 once_per: incident → 사건당 1회
    assert p.db.scalar("SELECT COUNT(*) FROM playbook_runs WHERE playbook_id='compromise_response'") == 1


def test_reject_continues_without_action(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir, mode="live")
    feed(p, compromise_lines())
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    p.soar.decide(run["id"], "block_ip", "bob", "responder", False, "오탐 가능성")
    p.soar.run_pending()
    p.soar.decide(run["id"], "disable_account", "bob", "responder", False, "보류")
    p.soar.run_pending()
    st = steps(p, run["id"])
    assert st["block_ip"]["state"] == "rejected" and run_of(p, "compromise_response")["state"] == "succeeded"
    assert p.db.scalar("SELECT COUNT(*) FROM blocklist") == 0


def test_live_mode_block_idempotent_and_cancel_compensates(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir, mode="live")
    feed(p, compromise_lines())
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    p.soar.decide(run["id"], "block_ip", "bob", "responder", True, "차단")
    p.soar.run_pending()
    assert p.db.scalar("SELECT COUNT(*) FROM blocklist WHERE ip='103.75.190.8'") == 1
    # 같은 조치를 다시 실행해도 한 번만 반영
    from rkmsiem.soar.actions import block_ip
    from rkmsiem.soar.engine import Ctx
    out = block_ip(Ctx(p.soar, p.db.one("SELECT * FROM playbook_runs WHERE id=?", (run["id"],)), "block_ip", "t"), {"ip": "103.75.190.8"})
    assert out["already_blocked"] is True and p.db.scalar("SELECT COUNT(*) FROM blocklist") == 1
    p.soar.cancel(run["id"], "alice", "사업부 요청으로 해제", compensate=True)       # 승인 대기 중 취소 + 보상
    assert run_of(p, "compromise_response")["state"] == "cancelled"
    assert p.db.scalar("SELECT COUNT(*) FROM blocklist") == 0                   # 보상 작업으로 차단 해제
    assert steps(p, run["id"])["block_ip"]["state"] == "compensated"


def test_approval_expiry(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir)
    feed(p, compromise_lines())
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    p.db.execute("UPDATE approvals SET expires_at = ? WHERE run_id=?", (time.time() - 1, run["id"]))
    p.soar.run_pending()
    assert steps(p, run["id"])["block_ip"]["state"] == "timed_out"


def test_safety_guards(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir, mode="live")
    feed(p, compromise_lines(ip="10.20.30.40", user="root"))        # 사내망 IP + 보호 계정
    p.soar.run_pending()
    run = run_of(p, "compromise_response")
    if run["state"] == "waiting_approval":
        p.soar.decide(run["id"], "block_ip", "bob", "responder", True, "test")
        p.soar.run_pending()
    st = steps(p, run["id"])
    assert st["block_ip"]["state"] == "failed" and "사내망" in st["block_ip"]["error"]
    assert st["disable_account"]["state"] == "skipped"                         # protected_accounts → 조건에서 제외


def test_manual_run_self_approval_forbidden(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir)
    feed(p, compromise_lines())
    inc = p.db.scalar("SELECT id FROM incidents")
    pb = p.config.get("playbook", "manual_enrichment")
    pb["steps"].append({"id": "block", "action": "block_ip", "input": {"ip": "{{alert.group.source.ip}}"}})
    p.config.put("playbook", "manual_enrichment", pb, "admin")
    rid = p.soar.run_manual("manual_enrichment", inc, "alice")
    p.soar.run_pending()
    with pytest.raises(ApprovalError):
        p.soar.decide(rid, "block", "alice", "admin", True, "내가 요청")
    p.soar.decide(rid, "block", "bob", "admin", True, "확인")
    p.soar.run_pending()
    assert p.soar.detail(rid)["state"] == "succeeded"


calls = {"flaky": 0, "count": 0}


@plugins.action("test_flaky")
def _flaky(ctx, inp):
    calls["flaky"] += 1
    if calls["flaky"] < 3:
        raise TransientError("잠시 실패")
    return {"ok": True}


@plugins.action("test_slow")
def _slow(ctx, inp):
    time.sleep(1.0)
    return {}


@plugins.action("test_count")
def _count(ctx, inp):
    calls["count"] += 1
    return {"n": calls["count"]}


def test_retry_timeout_and_recovery(tmp_path, config_dir):
    p = make_platform(tmp_path, config_dir)
    feed(p, compromise_lines())
    inc = p.db.scalar("SELECT id FROM incidents")
    pb = {"id": "t_retry", "name": "t", "trigger": {"on": "manual"}, "steps": [
        {"id": "a", "action": "test_count"},
        {"id": "b", "action": "test_flaky", "retries": 3, "retry_backoff_sec": 0},
        {"id": "c", "action": "test_slow", "timeout_sec": 0.2, "on_failure": "abort"},
        {"id": "d", "action": "test_count"}]}
    p.config.put("playbook", "t_retry", pb, "admin")
    rid = p.soar.run_manual("t_retry", inc, "alice")
    p.soar.run_pending()
    st = steps(p, rid)
    assert st["b"]["state"] == "succeeded" and st["b"]["attempts"] == 3
    assert st["c"]["state"] == "timed_out" and st["d"]["state"] == "pending"
    assert p.soar.detail(rid)["state"] == "failed"
    # 비정상 종료 복구: 'running' 상태로 남은 실행을 재개해도 이미 성공한 단계는 다시 실행하지 않음
    calls["count"] = 0
    rid2 = p.soar.run_manual("t_retry", inc, "alice")
    p.db.execute("UPDATE step_runs SET state='succeeded', output='{}' WHERE run_id=? AND step_id IN ('a','b')", (rid2,))
    p.db.execute("UPDATE step_runs SET state='running' WHERE run_id=? AND step_id='c'", (rid2,))
    p.db.execute("UPDATE playbook_runs SET state='running' WHERE id=?", (rid2,))
    p.soar.start(); p.soar.stop()                                              # 시작 시 복구 처리
    p.soar.run_pending()
    assert calls["count"] == 0 and steps(p, rid2)["c"]["state"] == "timed_out"
