"""P15: 네트워크 토폴로지(검증·상태·감지). 담당자·배정은 test_p16_staff.py."""
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"


class FakeSMTP:
    def __init__(self):
        self.box = []

    def __call__(self, *a):
        return self

    def send_message(self, m):
        self.box.append(m)

    def quit(self):
        pass


@pytest.fixture
def ctx(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db"), "soar.worker_poll_ms": 50,
                                                      "mail": {"enabled": True, "host": "smtp.test", "from": "soc@corp.test", "retry_backoff_sec": 0}}))
    smtp = FakeSMTP()
    p.mailer.smtp_factory = smtp
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("boss", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    c = app.test_client()
    login = lambda u, pw=PW: c.post("/api/auth/login", json={"username": u, "password": pw}).get_json().get("token")   # noqa: E731
    yield p, c, login, smtp
    p.pipeline.stop()


def H(t):
    return {"Authorization": f"Bearer {t}"}


def test_topology_layout_status_and_discover(ctx):
    p, c, login, _ = ctx
    boss, ana = login("boss"), login("ana")
    layout = {"nodes": [{"id": "siem", "type": "siem", "label": "SIEM", "ip": "1.1.12.135", "x": 0, "y": 0},
                        {"id": "kali", "type": "attacker", "ip": "45.33.32.9", "x": 200, "y": 0}],
              "links": [{"id": "l1", "from": "siem", "to": "kali", "label": "NAT"}]}
    assert c.put("/api/config/topology", headers=H(ana), json=layout).status_code == 403
    bad = dict(layout, links=layout["links"] + [{"id": "l2", "from": "kali", "to": "siem"}])
    assert c.put("/api/config/topology", headers=H(boss), json=bad).status_code == 400                  # 같은 두 기기 이중 연결
    assert c.put("/api/config/topology", headers=H(boss), json=dict(layout, links=[{"id": "x", "from": "siem", "to": "nope"}])).status_code == 400
    assert c.put("/api/config/topology", headers=H(boss), json=dict(layout, nodes=[dict(layout["nodes"][0], ip="999.1.1.1")], links=[])).status_code == 400
    assert c.put("/api/config/topology", headers=H(boss), json=layout).status_code == 200
    evs = [{"id": f"t{i}", "timestamp": f"2026-10-12T07:00:{i:02d}Z", "src_ip": "45.33.32.9", "user": "root", "outcome": "failure",
            "category": "authentication"} for i in range(11)]
    c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs)
    p.db.execute("INSERT INTO blocklist (ip, reason, added_at) VALUES ('45.33.32.9', 't', ?)", (time.time(),))
    r = c.get("/api/topology", headers=H(ana)).get_json()                                              # 보기는 일반 역할도
    st = r["status"]["45.33.32.9"]
    assert r["can_edit"] is False and st["severity"] == "critical" and st["blocked"] and st["open_alerts"] >= 1
    assert "1.1.12.135" not in r["status"] or not r["status"]["1.1.12.135"].get("severity")
    extra = c.get("/api/topology?ips=8.8.8.8", headers=H(boss)).get_json()["status"]
    assert "8.8.8.8" not in extra                                                                      # 기록 없는 IP 는 상태 없음
    d = c.get("/api/topology/discover", headers=H(boss)).get_json()["items"]
    k = next(x for x in d if x["ip"] == "45.33.32.9")
    assert "logs" in k["seen_by"] and k["suggest"] == "attacker" and k["events"] == 11
    assert c.get("/api/topology/discover", headers=H(ana)).status_code == 403


def test_topology_interfaces(ctx, monkeypatch):
    """한 기기에 IP 여러 개(라우터 f0/0·f0/1): 검증 · 상태 · 웹 터미널 경로 · 와이어 포트."""
    from rkmsiem import topology
    from rkmsiem.terminal import targets, wired
    p, c, login, _ = ctx
    boss = login("boss")
    gw = {"id": "gw", "type": "router", "label": "GATEWAY", "ip": "192.168.100.133", "x": 0, "y": 0,
          "interfaces": [{"name": "f0/0", "ip": "192.168.100.133", "prefix": 24}, {"name": "f0/1", "ip": "10.1.1.254", "prefix": 24}]}
    siem = {"id": "siem", "type": "siem", "label": "SIEM", "ip": "10.1.1.53", "x": 0, "y": 100}
    layout = {"nodes": [siem, gw], "links": [{"id": "l1", "from": "siem", "to": "gw", "to_if": "f0/1"}]}
    assert c.put("/api/config/topology", headers=H(boss), json=layout).status_code == 200
    # 어느 인터페이스 IP 로도 같은 기기 → 웹 터미널 대상
    assert [n["id"] for n in wired(layout, "10.1.1.254")] == ["siem", "gw"]
    assert [n["id"] for n in wired(layout, "192.168.100.133")] == ["siem", "gw"]
    t = targets(layout)[0]
    assert t["ips"] == ["192.168.100.133", "10.1.1.254"]
    # 상태 조회에 모든 IP 포함
    assert {"192.168.100.133", "10.1.1.254"} <= topology.layout_ips(layout)
    # 잘못된 것들
    bad = lambda **kw: c.put("/api/config/topology", headers=H(boss), json=dict(layout, **kw))   # noqa: E731
    r = bad(links=[{"id": "l1", "from": "siem", "to": "gw", "to_if": "f9/9"}])
    assert r.status_code == 400 and "f9/9" in str(r.get_json())
    dup = dict(gw, interfaces=gw["interfaces"] + [{"name": "f0/1", "ip": "10.9.9.9"}])
    assert bad(nodes=[siem, dup]).status_code == 400
    other = {"id": "pc", "type": "pc", "ip": "10.1.1.254", "x": 1, "y": 1}
    r = bad(nodes=[siem, gw, other])
    assert r.status_code == 400 and "인터페이스로 합치세요" in str(r.get_json())
    # 같은 두 기기 사이 두 번째 와이어는 포트를 지정하면 허용
    two = [{"id": "l1", "from": "siem", "to": "gw", "to_if": "f0/1"}, {"id": "l2", "from": "siem", "to": "gw", "to_if": "f0/0"}]
    assert bad(links=two).status_code == 200


def test_discover_merges_own_nics(ctx, monkeypatch):
    from rkmsiem import topology
    p, *_ = ctx
    monkeypatch.setattr(topology, "local_view", lambda: ({"192.168.100.128": {"iface": "ens33", "prefix": 24},
                                                          "10.1.1.53": {"iface": "ens37", "prefix": 24}}, {"192.168.100.2"}, {}))
    items = topology.discover(p)
    selfs = [x for x in items if "self" in x["seen_by"]]
    assert len(selfs) == 1 and [i["ip"] for i in selfs[0]["interfaces"]] == ["192.168.100.128", "10.1.1.53"]
    assert not any(x["ip"] == "10.1.1.53" for x in items if x is not selfs[0])
