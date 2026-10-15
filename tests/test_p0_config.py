"""P0: 스키마 검증 · 설정 버전/롤백 · 감사 로그 무결성 · 마이그레이션."""
import os
import sqlite3

import pytest

from rkmsiem import schemas, settings, yamlio
from rkmsiem.audit import AuditLog
from rkmsiem.configstore import ConfigStore


def test_migrations_idempotent(db):
    assert db.migrate() == []          # 두 번째 실행은 아무것도 적용하지 않음
    assert db.scalar("SELECT COUNT(*) FROM schema_migrations") >= 1


def test_all_shipped_config_is_valid(db, config_dir):
    store = ConfigStore(db, config_dir)
    rep = store.bootstrap()
    assert rep["rejected"] == []
    assert len(store.all("rule")) >= 7 and len(store.all("playbook")) >= 4
    # 다시 가져와도 같은 내용이면 새 버전을 만들지 않음
    assert store.bootstrap()["imported"] == []


def test_invalid_rule_rejected_and_old_version_kept(db, config_dir):
    store = ConfigStore(db, config_dir)
    store.bootstrap()
    before = store.get("rule", "auth_bruteforce")
    bad = dict(before, levels=[{"id": "x", "min": 0, "severity": "nope", "title": "t"}])
    with pytest.raises(schemas.SchemaError):
        store.put("rule", "auth_bruteforce", bad, "tester")
    assert store.get("rule", "auth_bruteforce") == before


def test_broken_file_does_not_block_startup(db, config_dir):
    with open(os.path.join(config_dir, "rules", "zz_broken.yaml"), "w", encoding="utf-8") as f:
        f.write("id: zz_broken\nname: x\ntype: threshold\n")     # 필수 항목 누락
    rep = ConfigStore(db, config_dir).bootstrap()
    assert any("zz_broken" in r["file"] for r in rep["rejected"])
    assert "rule:auth_bruteforce" in rep["imported"]


def test_versioning_and_rollback(db, config_dir):
    audit = AuditLog(db)
    store = ConfigStore(db, config_dir, audit)
    store.bootstrap()
    r = store.get("rule", "auth_bruteforce")
    v1 = store.version("rule", "auth_bruteforce")
    r["window_sec"] = 600
    v2 = store.put("rule", "auth_bruteforce", r, "alice", "창 축소")
    assert v2 == v1 + 1 and store.get("rule", "auth_bruteforce")["window_sec"] == 600
    v3 = store.rollback("rule", "auth_bruteforce", v1, "alice")
    assert store.get("rule", "auth_bruteforce")["window_sec"] == 900 and v3 == v2 + 1
    hist = store.versions("rule", "auth_bruteforce")
    assert [h["version"] for h in hist] == [v3, v2, v1] and sum(h["active"] for h in hist) == 1
    assert {a["actor"] for a in audit.list() if a["action"] == "config.change"} >= {"alice"}


def test_change_listener_called(db, config_dir):
    store = ConfigStore(db, config_dir)
    store.bootstrap()
    seen = []
    store.on_change(lambda k, n: seen.append((k, n)))
    store.set_enabled("rule", "slow_bruteforce", False, "bob")
    assert seen == [("rule", "slow_bruteforce")] and store.get("rule", "slow_bruteforce")["enabled"] is False


def test_audit_chain_and_append_only(db):
    a = AuditLog(db)
    for i in range(5):
        a.record("u", "act", "t", i, None, {"i": i})
    assert a.verify() == {"ok": True, "checked": 5}
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE audit_log SET actor='x' WHERE id=2")
    with pytest.raises(sqlite3.DatabaseError):
        db.execute("DELETE FROM audit_log WHERE id=2")
    # 트리거를 우회해 조작했다고 가정 → 체인 검증이 잡아냄
    db.execute("DROP TRIGGER audit_no_update")
    db.execute("UPDATE audit_log SET actor='mallory' WHERE id=3")
    assert a.verify()["ok"] is False and a.verify()["broken_at"] == 3


def test_settings_env_override(config_dir):
    s = settings.load(config_dir, environ={"RKMSIEM_API__PORT": "9100", "RKMSIEM_SOAR__MODE": "live"})
    assert s.get("api.port") == 9100 and s.get("soar.mode") == "live"
    with pytest.raises(schemas.SchemaError):
        settings.load(config_dir, environ={"RKMSIEM_SOAR__MODE": "yolo"})


def test_yaml_roundtrip():
    assert yamlio.loads(yamlio.dumps({"a": [1, "한글"]})) == {"a": [1, "한글"]}
