"""P17: 웹 터미널 — 토폴로지에서 SIEM 과 와이어로 이어진 기기만 접속 가능."""
import base64
import time

import pytest

from rkmsiem.api import create_app
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings
from rkmsiem.terminal import targets, wired

PW = "correct-horse-battery-9"

LAYOUT = {"nodes": [{"id": "siem", "type": "siem", "label": "SIEM", "ip": "10.0.0.53", "x": 0, "y": 0},
                    {"id": "sw", "type": "switch", "label": "SW", "x": 100, "y": 0},
                    {"id": "web", "type": "server", "label": "web", "ip": "10.0.0.20", "x": 200, "y": 0},
                    {"id": "lone", "type": "pc", "label": "lone", "ip": "10.0.0.99", "x": 300, "y": 0}],
          "links": [{"id": "l1", "from": "siem", "to": "sw"}, {"id": "l2", "from": "sw", "to": "web"}]}


def test_wired_reachability():
    assert [n["id"] for n in wired(LAYOUT, "10.0.0.20")] == ["siem", "sw", "web"]
    assert wired(LAYOUT, "10.0.0.99") is None                     # 배치는 됐지만 와이어 없음
    assert wired(LAYOUT, "10.0.0.53") is None                     # SIEM 자신은 대상 아님
    assert wired(dict(LAYOUT, nodes=[n for n in LAYOUT["nodes"] if n["type"] != "siem"]), "10.0.0.20") is None
    assert [t["ip"] for t in targets(LAYOUT)] == ["10.0.0.20"]


@pytest.fixture
def ctx(tmp_path, config_dir):
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")}))
    p.terminal.argv = lambda ip, login, port: ["/bin/sh", "-c", f"echo READY {login}@{ip}:{port}; read x; echo got:$x; sleep 30"]
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("boss", PW, "admin", "t")
    auth.create_user("boss2", PW, "admin", "t")
    auth.create_user("ana", PW, "analyst", "t")
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("boss", "boss2", "ana")}
    H = lambda u: {"Authorization": f"Bearer {tok[u]}"}   # noqa: E731
    yield p, c, H
    p.terminal.stop()


def _read_until(c, H, sid, needle, since=0):
    buf = b""
    for _ in range(20):
        r = c.get(f"/api/terminal/{sid}?since={since}&wait=2", headers=H).get_json()
        buf += base64.b64decode(r["data"])
        since = r["next"]
        if needle in buf or r["closed"]:
            return buf, r
    return buf, r


def test_terminal_requires_wire_and_permission(ctx):
    p, c, H = ctx
    assert c.put("/api/config/topology", headers=H("boss"), json=LAYOUT).status_code == 200
    assert c.post("/api/terminal", headers=H("ana"), json={"ip": "10.0.0.20", "login": "root"}).status_code == 403
    r = c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.99", "login": "root"})
    assert r.status_code == 403 and "와이어" in r.get_json()["details"]
    assert c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.20", "login": "-oProxyCommand=x"}).status_code == 400
    assert c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.20", "login": "root", "port": 80}).status_code == 400
    assert [t["ip"] for t in c.get("/api/terminal", headers=H("boss")).get_json()["targets"]] == ["10.0.0.20"]


def test_terminal_session_io_and_wire_cut(ctx):
    p, c, H = ctx
    c.put("/api/config/topology", headers=H("boss"), json=LAYOUT)
    r = c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.20", "login": "ops", "cols": 120, "rows": 40})
    assert r.status_code == 201
    sid = r.get_json()["id"]
    assert c.get(f"/api/terminal/{sid}?wait=0", headers=H("boss2")).status_code == 404          # 남의 세션
    out, st = _read_until(c, H("boss"), sid, b"READY")
    assert b"READY ops@10.0.0.20:22" in out
    assert c.post(f"/api/terminal/{sid}/resize", headers=H("boss"), json={"cols": 80, "rows": 24}).status_code == 200
    assert c.post(f"/api/terminal/{sid}/input", headers=H("boss"), json={"data": "hello\r"}).status_code == 200
    out, st = _read_until(c, H("boss"), sid, b"got:hello", st["next"])
    assert b"got:hello" in out
    # 와이어를 끊고 저장 → 세션 종료
    cut = dict(LAYOUT, links=[LAYOUT["links"][0]])
    c.put("/api/config/topology", headers=H("boss"), json=cut)
    p.terminal.reap()
    st = c.get(f"/api/terminal/{sid}?since={st['next']}&wait=1", headers=H("boss")).get_json()
    assert st["closed"] and "와이어" in st["reason"]
    acts = [a["action"] for a in p.audit.list(50)]
    assert "terminal.open" in acts and "terminal.close" in acts


def test_terminal_session_limit(ctx):
    p, c, H = ctx
    c.put("/api/config/topology", headers=H("boss"), json=LAYOUT)
    for _ in range(p.terminal.max_per_user):
        assert c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.20", "login": "ops"}).status_code == 201
    assert c.post("/api/terminal", headers=H("boss"), json={"ip": "10.0.0.20", "login": "ops"}).status_code == 429


def test_permission_added_to_existing_rbac(tmp_path, config_dir):
    import os
    path = os.path.join(config_dir, "rbac.yaml")
    with open(path, encoding="utf-8") as f:
        txt = f.read()
    with open(path, "w", encoding="utf-8") as f:
        f.write(txt.replace(", terminal:use]", "]"))                 # 예전 설치의 권한 표
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "t.db")}))
    assert "terminal:use" in p.config.get("rbac")["roles"]["admin"]["permissions"]
    assert "terminal:use" not in p.config.get("rbac")["roles"]["analyst"]["permissions"]
