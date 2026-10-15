"""P3: 경보→사건 연결 · 워크플로 · 타임라인 · 감사."""
import pytest

from rkmsiem import validators
from rkmsiem.alerts import AlertStore
from rkmsiem.audit import AuditLog
from rkmsiem.configstore import ConfigStore
from rkmsiem.detect import Engine
from rkmsiem.incidents import IncidentService, WorkflowError
from rkmsiem.schemas import SchemaError

T0 = 1_760_000_000


@pytest.fixture
def env(db, config_dir):
    audit = AuditLog(db)
    cs = ConfigStore(db, config_dir, audit)
    validators.register(cs)
    rep = cs.bootstrap()
    assert rep["rejected"] == [] or all("playbook" in r["file"] for r in rep["rejected"])
    eng = Engine(cs.all("rule"), cs.get("detection"), cs.get("lists"))
    store, inc = AlertStore(db), IncidentService(db, cs, audit)

    def feed(evs):
        out = []
        for e in evs:
            ch = eng.process(e)
            with db.tx() as c:
                store.apply(ch, conn=c)
                out += inc.on_alerts(ch, c)
        return out
    return {"db": db, "feed": feed, "inc": inc, "audit": audit, "cs": cs}


def ev(i, sec, ip, user, ok=False):
    return {"id": i, "ts": T0 + sec, "sample": False,
            "doc": {"event": {"category": ["authentication"], "outcome": "success" if ok else "failure"},
                    "source": {"ip": ip}, "user": {"name": user}}}


def test_alerts_grouped_into_one_incident_per_ip(env):
    out = env["feed"]([ev(i, i * 5, "203.0.113.1", f"u{i % 6}") for i in range(60)])   # 계정 6개 × 10회 → bruteforce(KISA) + spray
    created = [o for o in out if o[0] == "created"]
    assert len(created) == 1
    inc_id = created[0][1]
    rules = {r["rule_id"] for r in env["db"].all("SELECT rule_id FROM alerts WHERE incident_id=?", (inc_id,))}
    assert rules >= {"auth_bruteforce", "password_spray"}
    d = env["inc"].detail(inc_id)
    assert d["state"] == "new" and d["severity"] == "critical"                  # 가장 높은 경보 심각도로 상향
    kinds = [t["kind"] for t in d["timeline"]]
    assert kinds[0] == "created" and "alert_linked" in kinds and "severity_changed" in kinds


def test_different_keys_make_different_incidents(env):
    env["feed"]([ev(i, i, "203.0.113.2", "a") for i in range(6)] + [ev(100 + i, i, "203.0.113.3", "a") for i in range(6)])
    assert env["db"].scalar("SELECT COUNT(*) FROM incidents") == 2


def test_workflow_transitions_and_reasons(env):
    env["feed"]([ev(i, i, "203.0.113.4", "a") for i in range(6)])
    i = env["db"].scalar("SELECT id FROM incidents")
    with pytest.raises(WorkflowError):
        env["inc"].transition(i, "resolved", "alice")                              # new → resolved 불가
    env["inc"].transition(i, "investigating", "alice")
    env["inc"].assign(i, "bob", "alice")
    env["inc"].transition(i, "resolved", "bob", "차단 완료")
    assert env["db"].scalar("SELECT status FROM alerts WHERE incident_id=?", (i,)) == "closed"
    with pytest.raises(WorkflowError):
        env["inc"].transition(i, "investigating", "bob")                           # 재오픈은 사유 필수
    env["inc"].transition(i, "investigating", "bob", "재발")
    acts = [a["action"] for a in env["audit"].list(100)][::-1]
    assert acts.count("incident.transition") == 3 and "incident.assign" in acts and "incident.create" in acts
    assert env["audit"].verify()["ok"]


def test_closed_incident_not_reused(env):
    env["feed"]([ev(i, i, "203.0.113.5", "a") for i in range(6)])
    i = env["db"].scalar("SELECT id FROM incidents")
    env["inc"].transition(i, "false_positive", "alice")
    env["feed"]([ev(100 + i, 5000 + i, "203.0.113.5", "a") for i in range(6)])     # 억제 기간 이후 새 경보
    assert env["db"].scalar("SELECT COUNT(*) FROM incidents") == 2


def test_workflow_config_semantic_validation(env):
    wf = env["cs"].get("workflow")
    wf["transitions"].append({"from": "new", "to": ["ghost"]})
    with pytest.raises(SchemaError):
        env["cs"].put("workflow", "default", wf, "admin")
