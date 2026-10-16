"""P24: HSOAR 추가 기능 — 실제 RKMSIEM API 서버 + HSOAR 엔진(전용 토큰·피드), Slack 만 가짜.
사건 카드·정책 제안(dry)·자동 실행(on)·상한·킬 스위치·버튼 권한·승인 버튼·사람 할 일·/hsoar 명령."""
import json
import os
import sys
import threading

import pytest
from waitress import create_server

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.platform import Platform
from rkmsiem.settings import load as load_settings

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "deploy", "addons", "hsoar"))
from hsoar import policy as pol  # noqa: E402
from hsoar.core import Engine  # noqa: E402
from hsoar.rk import RK  # noqa: E402
from hsoar.store import Store  # noqa: E402

KEY = "test-ingest-key-1234567890"
BOSS, STRANGER = "U0BOSS0001", "U0NOBODY01"


class FakeChat:
    def __init__(self):
        self.msgs, self.updates, self.eph, self.n = [], [], [], 0

    def post(self, blocks, text, thread_ts=None):
        self.n += 1
        self.msgs.append({"ts": str(self.n), "blocks": blocks, "text": text, "thread": thread_ts})
        return {"channel": "C0TEST", "ts": str(self.n)}

    def update(self, channel, ts, blocks, text):
        self.updates.append({"ts": ts, "text": text})

    def ephemeral(self, channel, user, text):
        self.eph.append((user, text))

    def buttons(self, pred=lambda m: True):
        return [e for m in self.msgs if pred(m) for b in m["blocks"] if b["type"] == "actions" for e in b["elements"]]


@pytest.fixture
def env(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    p = Platform(load_settings(config_dir, overrides={"database.path": str(tmp_path / "h.db"), "soar.mode": "live"}))
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    srv = create_server(app, host="127.0.0.1", port=0, threads=8)
    threading.Thread(target=srv.run, daemon=True).start()
    tok = auth.create_api_token("addon-hsoar", ["feed:read", "alerts:read", "incidents:read", "incidents:write", "runs:read",
                                                "playbooks:run", "runs:approve", "runs:cancel"], "root (addon)")["token"]
    rk = RK(f"http://127.0.0.1:{srv.effective_port}", tok)
    chat = FakeChat()

    def make(policy=None, mode=None):
        pl = json.loads(json.dumps(policy or pol.DEFAULT))
        if mode:
            pl["auto"]["mode"] = mode
        return Engine(rk, chat, pl, Store(str(tmp_path / "state.json")), [BOSS], "https://10.0.0.53:8443")
    c = app.test_client()
    yield p, c, chat, make
    srv.close()
    p.pipeline.stop()
    p.terminal.stop()


def attack(c, ip="103.75.190.8", user="backup", success=True, tag="a"):
    evs = [{"id": f"{tag}-{i}", "timestamp": f"2026-10-12T02:10:{i:02d}Z", "src_ip": ip, "user": user, "outcome": "failure",
            "category": "authentication"} for i in range(12)]
    if success:
        evs.append({"id": f"{tag}-ok", "timestamp": "2026-10-12T02:10:40Z", "src_ip": ip, "user": user, "outcome": "success", "category": "authentication"})
    assert c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs).status_code == 200


def click(eng, chat, label, user=BOSS):
    b = next(e for e in chat.buttons() if e["text"]["text"].startswith(label))
    return eng.on_click(user, "boss" if user == BOSS else "nobody", b["value"], "C0TEST", "1")


def test_cards_suggestions_and_buttons_dry(env):
    p, c, chat, make = env
    eng = make()
    eng.poll(wait=0)                                        # 처음: 지금 위치부터
    attack(c)
    assert eng.poll(wait=0) > 0
    cards = [m for m in chat.msgs if m["text"].startswith("사건 #")]
    assert len(cards) == 1 and "103.75.190.8" in cards[0]["blocks"][0]["text"]["text"]             # 같은 사건은 카드 1번
    sugg = [m["text"] for m in chat.msgs if m["text"].startswith("제안")]
    assert "제안 IP 차단 103.75.190.8" in sugg and "제안 계정 잠금 backup" in sugg                   # dry: 자동 등급도 제안만
    assert not p.db.one("SELECT 1 FROM blocklist")

    r = click(eng, chat, "실행: IP 차단", user=STRANGER)                                            # 허용 안 된 사람
    assert "권한이 없습니다" in r and chat.eph and not p.db.one("SELECT 1 FROM blocklist")
    r = click(eng, chat, "실행: IP 차단")
    assert r.startswith("✔ IP 차단 `103.75.190.8` (1시간)") and chat.updates[-1]["text"] == r
    row = p.db.one("SELECT added_by, reason FROM blocklist WHERE ip='103.75.190.8'")
    assert row["added_by"] == "token:addon-hsoar" and "Slack @boss" in row["reason"]
    eng.poll(wait=0)
    assert len([m for m in chat.msgs if m["text"].startswith("사건 #")]) == 1                      # 다시 올리지 않음
    r = click(eng, chat, "실행: 계정 잠금")
    assert "✔ 계정 잠금 `backup`" in r


def test_auto_on_cap_and_kill_switch(env):
    p, c, chat, make = env
    policy = json.loads(json.dumps(pol.DEFAULT))
    policy["auto"]["max_per_hour"] = 1
    eng = make(policy, mode="on")
    eng.poll(wait=0)
    attack(c, "103.75.190.8", "backup", success=False, tag="a")
    eng.poll(wait=0)
    auto = [m for m in chat.msgs if m["text"].startswith("자동 조치")]
    assert [m["text"] for m in auto] == ["자동 조치 IP 차단 103.75.190.8"]
    assert p.db.one("SELECT reason FROM blocklist WHERE ip='103.75.190.8'")["reason"].startswith("사건 #")
    attack(c, "45.155.205.9", "oracle", success=False, tag="b")                                   # 상한(1/시간) → 제안으로
    eng.poll(wait=0)
    assert any(m["text"] == "제안 IP 차단 45.155.205.9" and "시간당 자동 상한" in m["blocks"][0]["text"]["text"] for m in chat.msgs)
    assert not p.db.one("SELECT 1 FROM blocklist WHERE ip='45.155.205.9'")
    # 되돌리기 버튼
    r = click(eng, chat, "차단 해제")
    assert r.startswith("✔ 차단 해제") and not p.db.one("SELECT 1 FROM blocklist WHERE ip='103.75.190.8'")
    # 킬 스위치
    assert "권한이 없습니다" in eng.on_command(STRANGER, "nobody", "pause") or "쓸 수 없습니다" in eng.on_command(STRANGER, "nobody", "pause")
    assert "멈췄습니다" in eng.on_command(BOSS, "boss", "pause")
    eng.store["auto_log"] = []
    attack(c, "193.32.162.7", "test", success=False, tag="c")
    eng.poll(wait=0)
    assert any(m["text"] == "제안 IP 차단 193.32.162.7" and "pause" in m["blocks"][0]["text"]["text"] for m in chat.msgs)
    assert "다시 켰습니다" in eng.on_command(BOSS, "boss", "resume")
    assert "*off*" in eng.on_command(BOSS, "boss", "auto off") and eng.mode() == "off"


def test_approval_buttons_and_tasks(env):
    p, c, chat, make = env
    eng = make()
    eng.poll(wait=0)
    attack(c, success=False)
    p.soar.run_pending()                                     # bruteforce_triage → block_ip 승인 대기 (live)
    eng.poll(wait=0)
    appr = [m for m in chat.msgs if m["text"].startswith("승인 요청")]
    assert appr and "block_ip" in appr[0]["text"]
    btn = next(e for b in appr[0]["blocks"] if b["type"] == "actions" for e in b["elements"] if e["text"]["text"] == "승인")
    r = eng.on_click(BOSS, "boss", btn["value"], "C0TEST", appr[0]["ts"])
    assert r.startswith("✅ 승인"), r
    rid = json.loads(btn["value"])["r"]
    p.soar.run_pending()
    run = p.soar.detail(rid)
    assert run["approvals"][0]["state"] == "approved" and "Slack @boss" in run["approvals"][0]["reason"]
    assert run["approvals"][0]["decided_by"] == "token:addon-hsoar"
    # 사람 할 일
    iid = p.db.one("SELECT id FROM incidents ORDER BY id LIMIT 1")["id"]
    p.soar.run_manual("runbook_cryptojacking", iid, "adm")
    p.soar.run_pending()
    eng.poll(wait=0)
    task = [m for m in chat.msgs if m["text"].startswith("사람 할 일")]
    assert task and "☐" in task[0]["blocks"][0]["text"]["text"]


def test_commands(env):
    p, c, chat, make = env
    eng = make()
    attack(c, success=False)
    s = eng.on_command(BOSS, "boss", "status")
    assert "위협 수준" in s and "자동 모드 *dry*" in s
    assert "#" in eng.on_command(STRANGER, "nobody", "incidents")                                  # 조회는 누구나
    assert "쓸 수 없습니다" in eng.on_command(STRANGER, "nobody", "block 198.51.100.9 1h x")
    assert "사유" in eng.on_command(BOSS, "boss", "block 198.51.100.9 1h")
    assert eng.on_command(BOSS, "boss", "block 198.51.100.9 1h 스캔 반복").startswith("✔ 차단 `198.51.100.9` (1시간)")
    assert p.db.one("SELECT reason FROM blocklist WHERE ip='198.51.100.9'")["reason"].endswith("Slack @boss (U0BOSS0001)")
    assert "⚠️ 실패" in eng.on_command(BOSS, "boss", "block 10.1.2.3 1h 사내망")                      # 핵심의 보호 목록
    assert eng.on_command(BOSS, "boss", "unblock 198.51.100.9 오탐").startswith("✔ 차단 해제")
    assert "HSOAR" in eng.on_command(BOSS, "boss", "")


def test_policy_validation_and_plan():
    bad = json.loads(json.dumps(pol.DEFAULT))
    bad["rules"][0]["do"]["action"] = "rm_rf"
    with pytest.raises(pol.PolicyError):
        pol.validate(bad)
    a = {"rule_id": "auth_bruteforce", "severity": "high", "group": {"source.ip": "1.2.3.4"}}
    assert pol.plan(pol.DEFAULT, a) == []                                                        # critical 미만
    a["severity"] = "critical"
    assert [(r["do"]["action"], v) for r, v in pol.plan(pol.DEFAULT, a)] == [("block_ip", "1.2.3.4")]


def test_slack_transport_routes_payloads(monkeypatch):
    """Socket Mode 요청 → 바로 ack → 작업 스레드에서 엔진 호출 (버튼 · /hsoar)."""
    import time
    from types import SimpleNamespace
    pytest.importorskip("slack_sdk")                    # HSOAR 설치 때 받는 의존성 — 없으면 건너뜀
    import slack_sdk.socket_mode as sm
    import slack_sdk.webhook as wh
    from hsoar import slackio

    acks, sent, calls = [], [], []

    class FakeClient:
        def __init__(self, app_token, web_client):
            self.socket_mode_request_listeners = []

        def send_socket_mode_response(self, r):
            acks.append(r.envelope_id)

        def connect(self):
            pass

    class FakeHook:
        def __init__(self, url):
            self.url = url

        def send(self, **kw):
            sent.append(kw)

    class Eng:
        def on_click(self, *a):
            calls.append(("click", a))

        def on_command(self, uid, name, text):
            calls.append(("cmd", uid, text))
            return "ok:" + text

    monkeypatch.setattr(sm, "SocketModeClient", FakeClient)
    monkeypatch.setattr(wh, "WebhookClient", FakeHook)
    cl = slackio.serve(Eng(), "xapp-test", web=None)
    lst = cl.socket_mode_request_listeners[0]
    lst(cl, SimpleNamespace(type="interactive", envelope_id="e1", payload={
        "type": "block_actions", "user": {"id": "U1", "username": "boss"}, "channel": {"id": "C1"}, "container": {"message_ts": "9.9"},
        "actions": [{"value": '{"k":"dismiss"}'}]}))
    lst(cl, SimpleNamespace(type="slash_commands", envelope_id="e2", payload={"user_id": "U1", "user_name": "boss", "text": "pause", "response_url": "https://hooks"}))
    lst(cl, SimpleNamespace(type="slash_commands", envelope_id="e3", payload={"user_id": "U1", "user_name": "boss", "text": "status", "response_url": "https://hooks"}))
    for _ in range(50):
        if len(sent) == 2 and calls:
            break
        time.sleep(0.05)
    assert acks == ["e1", "e2", "e3"]
    assert ("click", ("U1", "boss", '{"k":"dismiss"}', "C1", "9.9")) in calls
    assert {s["text"]: s["response_type"] for s in sent} == {"ok:pause": "in_channel", "ok:status": "ephemeral"}     # 조치 명령은 채널에 보임
