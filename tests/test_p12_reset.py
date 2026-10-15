"""P12: 데이터 초기화(test/all) · 오탐 처리한 경보는 위협 수준에서 제외."""
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "r.db"), "soar.worker_poll_ms": 50}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("adm", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("adm", "ana")}
    yield p, c, (lambda u: {"Authorization": f"Bearer {tok[u]}"})
    p.pipeline.stop()


def attack(c, ip, user, minute):
    evs = [{"id": f"{ip}-{i}", "timestamp": f"2026-10-12T02:{minute:02d}:{i:02d}Z", "src_ip": ip, "user": user, "outcome": "failure",
            "category": "authentication"} for i in range(11)]
    evs.append({"id": f"{ip}-ok", "timestamp": f"2026-10-12T02:{minute:02d}:40Z", "src_ip": ip, "user": user, "outcome": "success",
                "category": "authentication"})
    assert c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs).get_json()["stored"] == 12


def threat(c, H):
    return c.get("/api/overview", headers=H("adm")).get_json()["threat"]["current"]["id"]


def test_reset_test_scope_keeps_real_attacks(ctx):
    p, c, H = ctx
    attack(c, "198.51.100.77", "rkmsmoke1234", 10)                 # 스모크테스트 흔적
    attack(c, "103.75.190.8", "backup", 20)                         # 실제 공격
    assert threat(c, H) == "severe"
    p.db.execute("INSERT INTO blocklist (ip, reason, added_at) VALUES ('198.51.100.77', 'smoke', ?)", (time.time(),))
    assert c.post("/api/system/reset", headers=H("ana"), json={"scope": "test"}).status_code == 403
    plan = c.post("/api/system/reset", headers=H("adm"), json={"scope": "test", "dry_run": True}).get_json()["counts"]
    assert plan["events"] == 12 and plan["alerts"] >= 2 and plan["incidents"] == 1 and plan["blocklist"] == 1
    assert p.db.scalar("SELECT COUNT(*) FROM events") == 24                                      # 미리보기는 지우지 않음
    r = c.post("/api/system/reset", headers=H("adm"), json={"scope": "test", "reason": "설치 확인 끝"}).get_json()
    assert r["counts"]["events"] == 12
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_ip LIKE '198.51.100.%'") == 0
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_ip='103.75.190.8'") == 12          # 실제 공격은 남음
    assert p.db.scalar("SELECT COUNT(*) FROM blocklist") == 0
    assert threat(c, H) == "severe"                                                               # 실제 침해가 남아 있으니 여전히 심각
    acts = [a["action"] for a in p.audit.list(30)]
    assert "data.reset" in acts and c.get("/api/audit/verify", headers=H("adm")).get_json()["ok"]


def test_false_positive_lowers_threat(ctx):
    p, c, H = ctx
    attack(c, "198.51.100.9", "rkmsmoke9", 30)
    assert threat(c, H) == "severe"
    iid = c.get("/api/incidents", headers=H("adm")).get_json()["items"][0]["id"]
    st = c.get(f"/api/incidents/{iid}", headers=H("adm")).get_json()
    for to in ("investigating", "false_positive"):
        if to in st["allowed_transitions"] or to == "false_positive":
            c.post(f"/api/incidents/{iid}/transition", headers=H("adm"), json={"to": to, "reason": "스모크테스트"})
    assert c.get(f"/api/incidents/{iid}", headers=H("adm")).get_json()["state"] == "false_positive"
    ov = c.get("/api/overview", headers=H("adm")).get_json()
    assert ov["threat"]["current"]["id"] != "severe" and ov["threat"]["reasons"]["false_positive_alerts"] >= 1
    assert ov["totals"]["severe_ips"] == 0


def test_reset_all_requires_confirm(ctx):
    p, c, H = ctx
    attack(c, "103.75.190.8", "backup", 40)
    assert c.post("/api/system/reset", headers=H("adm"), json={"scope": "all"}).status_code == 400
    r = c.post("/api/system/reset", headers=H("adm"), json={"scope": "all", "confirm": "초기화"}).get_json()
    assert r["counts"]["events"] == 12
    for t in ("events", "alerts", "incidents", "playbook_runs"):
        assert p.db.scalar(f"SELECT COUNT(*) FROM {t}") == 0
    assert p.db.scalar("SELECT COUNT(*) FROM users") == 2 and p.config.get("mail") is not None      # 사용자·설정은 남음
    assert threat(c, H) == "normal"
    attack(c, "103.75.190.8", "backup", 50)                                                        # 초기화 뒤에도 탐지 정상
    assert threat(c, H) == "severe"


def sudo_ev(i, cmd, user="rkmsiem"):
    return {"id": f"sudo-{i}-{user}", "timestamp": f"2026-10-12T03:00:{i:02d}Z", "user": user, "outcome": "success", "category": "iam",
            "action": "privilege_use", "message": f"{user} : PWD=/ ; USER=root ; COMMAND={cmd}"}


def test_service_helper_sudo_is_not_privilege_escalation(ctx):
    from rkmsiem import normalize
    p, c, H = ctx
    normalize.configure_self(user="rkmsiem", commands=["/usr/local/lib/rkmsiem/rkmsiem-account"])
    ing = lambda evs: c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs)   # noqa: E731
    ing([sudo_ev(1, "/usr/local/lib/rkmsiem/rkmsiem-account lock baduser"), sudo_ev(2, "/usr/local/lib/rkmsiem/rkmsiem-account check")])
    assert p.db.scalar("SELECT COUNT(*) FROM alerts WHERE rule_id='privilege_escalation'") == 0          # 서비스 자신의 헬퍼 → 경보 없음
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE action='service_helper'") == 2
    ing([sudo_ev(3, "/bin/bash -c /usr/local/lib/rkmsiem/rkmsiem-account x")])                        # 헬퍼를 흉내 낸 다른 명령
    ing([sudo_ev(4, "/usr/local/lib/rkmsiem/rkmsiem-account-evil")])
    ing([sudo_ev(5, "/usr/local/lib/rkmsiem/rkmsiem-account lock x", user="mallory")])                 # 다른 계정이 헬퍼 실행
    n = p.db.scalar("SELECT COUNT(*) FROM alerts WHERE rule_id='privilege_escalation'")
    assert n >= 2                                                                                     # 위 경우들은 계속 감시
    normalize.configure_self(user="nobody-else")
    ing([sudo_ev(6, "/usr/sbin/usermod -L rkmsmoke77")])                                              # 스모크테스트의 거부 시험 흔적
    r = c.post("/api/system/reset", headers=H("adm"), json={"scope": "test"}).get_json()["counts"]
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE message LIKE '%rkmsmoke%'") == 0 and r["events"] >= 1
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE user_name='mallory'") == 1                    # 실제 의심 기록은 남김
