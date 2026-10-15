"""P2: 탐지 엔진 — 중복 억제·상향 · 예외 · 보정 · unless · 시뮬레이션/비교 · 재시작 복원 · 기존 결과와의 동등성."""
import copy
import os
import sys

import pytest

from rkmsiem.alerts import AlertStore
from rkmsiem.configstore import ConfigStore
from rkmsiem.detect import Engine, compare, simulate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
T0 = 1_760_000_000


@pytest.fixture
def cfg(db, config_dir):
    s = ConfigStore(db, config_dir)
    s.bootstrap()
    return {"rules": s.all("rule"), "policy": s.get("detection"), "lists": s.get("lists"), "store": s}


def auth(i, sec, ip, user, ok=False, cat="authentication", **extra):
    doc = {"event": {"category": [cat], "outcome": "success" if ok else "failure"}, "source": {"ip": ip}, "user": {"name": user}}
    doc.update(extra)
    return {"id": i, "ts": T0 + sec, "doc": doc, "sample": False, "received_at": None}


def run(engine, evs):
    out = []
    for e in evs:
        out += engine.process(e)
    return out


def test_dedup_and_escalation(cfg):
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    ch = run(eng, [auth(i, i * 5, "203.0.113.1", "admin") for i in range(12)])
    bf = [c for c in ch if c["alert"]["rule_id"] == "auth_bruteforce"]
    assert [c["op"] for c in bf][:1] == ["new"] and sum(c["op"] == "escalate" for c in bf) == 1
    assert len({id(c["alert"]) for c in bf}) == 1                         # 경보는 1개 (12건 → 중복 억제)
    a = bf[-1]["alert"]
    assert a["level_id"] == "BRUTEFORCE_HIGH" and a["severity"] == "critical" and a["event_count"] == 12
    assert a["risk_basis"]["severity_base"] == 90 and a["risk_score"] == pytest.approx(90 + 0.2 * 12)
    assert len(a["evidence"]) == 12                                        # 근거 이벤트


def test_new_alert_after_suppress_window(cfg):
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    first = run(eng, [auth(i, i, "203.0.113.2", "u") for i in range(5)])
    later = run(eng, [auth(100 + i, 5000 + i, "203.0.113.2", "u") for i in range(5)])   # 억제 기간(3600초) 지난 뒤
    assert sum(c["op"] == "new" for c in first + later if c["alert"]["rule_id"] == "auth_bruteforce") == 2


def test_exception_list_and_internal_modifier(cfg):
    lists = copy.deepcopy(cfg["lists"])
    lists["allowlist"]["values"] = ["198.51.100.0/24"]
    eng = Engine(cfg["rules"], cfg["policy"], lists)
    assert run(eng, [auth(i, i, "198.51.100.7", "u") for i in range(12)]) == []           # 예외 대역
    ch = run(eng, [auth(100 + i, i, "10.1.2.3", "kim") for i in range(5)])
    a = ch[-1]["alert"]
    assert a["severity"] == "medium" and a["risk_basis"]["modifiers"][0]["delta"] == -1    # 사내망 high → medium


def test_unless_rules_suppresses_slow(cfg):
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    ch = run(eng, [auth(i, i * 5, "203.0.113.3", "admin") for i in range(15)])          # 고속 → bruteforce 만
    assert {c["alert"]["rule_id"] for c in ch} == {"auth_bruteforce"}
    ch2 = run(eng, [auth(100 + i, i * 3600, "203.0.113.4", "admin") for i in range(10)])  # 저속 → slow
    assert {c["alert"]["rule_id"] for c in ch2} == {"slow_bruteforce"}


def test_sequence_compromise_and_reset(cfg):
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    evs = [auth(i, i * 10, "203.0.113.5", "oracle") for i in range(4)] + [auth(9, 50, "203.0.113.5", "oracle", ok=True)]
    assert not any(c["alert"]["level_id"] == "COMPROMISE" for c in run(eng, evs))         # 4회 후 성공 → 정상(초기화)
    evs = [auth(20 + i, 100 + i * 10, "203.0.113.5", "oracle") for i in range(5)] + [auth(30, 200, "203.0.113.5", "oracle", ok=True)]
    ids = {c["alert"]["level_id"] for c in run(eng, evs)}
    assert {"COMPROMISE", "NO_LOCKOUT"} <= ids


def test_match_rule_privilege_and_network_threshold(cfg):
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    pe = {"id": 1, "ts": T0, "doc": {"event": {"category": ["iam"], "action": "privilege_use", "outcome": "success"},
                                     "user": {"name": "intern"}}}
    ok = {"id": 2, "ts": T0, "doc": {"event": {"category": ["iam"], "action": "privilege_use"}, "user": {"name": "root"}}}
    assert [c["alert"]["level_id"] for c in eng.process(pe)] == ["PRIV_ESC"] and eng.process(ok) == []
    conns = [{"id": 10 + i, "ts": T0 + i, "doc": {"event": {"category": ["network"], "action": "connection_attempt"},
                                                  "source": {"ip": "203.0.113.70"}, "destination": {"port": 22}}} for i in range(25)]
    assert run(eng, conns)[-1]["alert"]["level_id"] == "CONN_FLOOD"


def test_disabled_rule_not_evaluated(cfg):
    rules = copy.deepcopy(cfg["rules"])
    rules["auth_bruteforce"]["enabled"] = False
    eng = Engine(rules, cfg["policy"], cfg["lists"])
    assert not any(c["alert"]["rule_id"] == "auth_bruteforce" for c in run(eng, [auth(i, i, "203.0.113.6", "a") for i in range(12)]))


def test_simulation_compare_before_after_rule_change(cfg):
    evs = [auth(i, i * 30, "203.0.113.8", "a") for i in range(3)] + [auth(10 + i, i * 30, "203.0.113.9", "b") for i in range(6)]
    before, _ = simulate(cfg["rules"], cfg["policy"], cfg["lists"], evs)
    rules = copy.deepcopy(cfg["rules"])
    rules["auth_bruteforce"]["levels"][0]["min"] = 3                              # 잠금 기준 5 → 3
    after, stats = simulate(rules, cfg["policy"], cfg["lists"], evs)
    diff = compare(before, after)
    assert [a["group_key"] for a in diff["added"]] == ["source.ip=203.0.113.8|user.name=a"]
    assert diff["removed"] == [] and stats["auth_bruteforce"]["matched"] == 9


def test_warmup_after_restart_continues_same_alert(cfg, db):
    store = AlertStore(db)
    eng = Engine(cfg["rules"], cfg["policy"], cfg["lists"])
    evs = [auth(i, i * 5, "203.0.113.10", "ops") for i in range(12)]
    for e in evs[:6]:
        store.apply(eng.process(e))
    assert db.scalar("SELECT COUNT(*) FROM alerts") == 1
    eng2 = Engine(cfg["rules"], cfg["policy"], cfg["lists"])                     # 재시작
    eng2.warmup(evs[:6], store.open_for_warmup(0))
    for e in evs[6:]:
        store.apply(eng2.process(e))
    rows = db.all("SELECT level_id, event_count FROM alerts")
    assert rows == [{"level_id": "BRUTEFORCE_HIGH", "event_count": 12}]               # 새 경보 없이 이어서 상향


def test_scenario_parity_with_previous_detector(cfg):
    """기존(하드코딩) 탐지기의 기대 결과와 새 설정 기반 엔진의 결과가 같은지."""
    sys.path.insert(0, ROOT)
    import gen_log
    evs = []
    for i, (t, st, u, ip) in enumerate(gen_log.build_events()):
        evs.append(auth(i, 0, ip, u, ok=(st == "SUCCESS")) | {"ts": t.timestamp()})
    alerts, _ = simulate(cfg["rules"], cfg["policy"], cfg["lists"], evs)
    rank = ["info", "low", "medium", "high", "critical"]
    per_ip = {}
    for a in alerts:
        ip = a["group"].get("source.ip")
        if ip:
            d = per_ip.setdefault(ip, {"ids": set(), "sev": "info"})
            d["ids"].add(a["level_id"])
            d["sev"] = max(d["sev"], a["severity"], key=rank.index)
    for ip, (level, must, must_not) in gen_log.EXPECTED.items():
        got = per_ip.get(ip)
        if level is None:
            assert got is None, ip
            continue
        assert got and got["sev"] == level and must <= got["ids"] and not (must_not & got["ids"]), (ip, got)
    assert set(per_ip) <= set(gen_log.EXPECTED)                                 # 배경 트래픽 오탐 없음
    assert any(a["rule_id"] == "distributed_attack" and a["group"]["user.name"] == "admin" for a in alerts)
