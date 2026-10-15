"""P14: 업데이트 경로 — 기본 규칙 파일 갱신 반영 · 웹에서 고친 규칙 보존 · 이름 바뀐 규칙 정리 · 초기화 뒤 번호 재사용 없음."""
import shutil
import time

import pytest

from rkmsiem import yamlio
from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

KEY = "test-ingest-key-1234567890"
PW = "correct-horse-battery-9"


@pytest.fixture
def cfg(tmp_path, config_dir):
    d = tmp_path / "cfg"
    shutil.copytree(config_dir, d)
    return d


def boot(cfg, tmp_path, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    return Platform(load_settings(str(cfg), overrides={"database.path": str(tmp_path / "u.db"), "soar.worker_poll_ms": 50}))


def test_shipped_rule_updates_but_web_edits_are_kept(cfg, tmp_path, monkeypatch):
    p = boot(cfg, tmp_path, monkeypatch)
    assert p.config.get("rule", "auth_bruteforce")["levels"][1]["title"] == "무차별 대입 (심각)"
    web = p.config.get("rule", "slow_bruteforce")
    web["levels"][0]["title"] = "운영자가 바꾼 이름"
    p.config.put("rule", "slow_bruteforce", web, "admin", "웹에서 수정")
    # 업데이트: 두 규칙 파일이 모두 새 기본값으로 바뀜
    for rid, title in (("auth_bruteforce", "무차별 대입 (갱신)"), ("slow_bruteforce", "저속 대입 (갱신)")):
        f = cfg / "rules" / f"{rid}.yaml"
        d = yamlio.load_file(str(f))
        d["levels"][-1]["title"] = title
        f.write_text(yamlio.dumps(d), encoding="utf-8")
    rep = p.config.bootstrap()
    assert p.config.get("rule", "auth_bruteforce")["levels"][1]["title"] == "무차별 대입 (갱신)"       # 손대지 않은 규칙은 갱신
    assert p.config.get("rule", "slow_bruteforce")["levels"][0]["title"] == "운영자가 바꾼 이름"        # 웹 수정은 보존
    assert "rule:slow_bruteforce" in rep["kept_user_edit"]


def test_renamed_rule_is_retired(cfg, tmp_path, monkeypatch):
    old = yamlio.load_file(str(cfg / "rules" / "ids_alert.yaml"))
    old["id"] = "ids_suricata_alert"
    (cfg / "rules" / "ids_suricata_alert.yaml").write_text(yamlio.dumps(old), encoding="utf-8")     # 예전 설치에 남은 규칙
    p = boot(cfg, tmp_path, monkeypatch)
    rules = p.config.all("rule")
    assert rules["ids_alert"]["enabled"] is not False and rules["ids_suricata_alert"]["enabled"] is False


def test_ids_are_never_reused_after_reset(cfg, tmp_path, monkeypatch):
    p = boot(cfg, tmp_path, monkeypatch)
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("adm", PW, "admin", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    H = {"Authorization": "Bearer " + c.post("/api/auth/login", json={"username": "adm", "password": PW}).get_json()["token"]}

    def attack(ip, minute):
        evs = [{"id": f"{ip}-{minute}-{i}", "timestamp": f"2026-10-12T04:{minute:02d}:{i:02d}Z", "src_ip": ip, "user": "backup",
                "outcome": "failure", "category": "authentication"} for i in range(11)]
        c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs)
        return c.get("/api/incidents", headers=H).get_json()["items"][0]["id"]

    try:
        first = attack("45.33.32.10", 1)
        c.post(f"/api/incidents/{first}/assign", headers=H, json={"assignee": "adm"})
        c.post("/api/system/reset", headers=H, json={"scope": "all", "confirm": "초기화"})
        time.sleep(.2)
        second = attack("45.33.32.11", 30)
        assert second > first                                                                      # 같은 번호를 다시 쓰지 않음
        d = c.get(f"/api/incidents/{second}", headers=H).get_json()
        assert all(a["actor"] != "adm" for a in d["audit"])                                          # 예전 사건의 배정 기록이 섞이지 않음
    finally:
        p.pipeline.stop()
