"""P10: 메일(SMTP) · 알림 묶음 · 정기 보고서 일정 · PDF 보고서 · 관련 API. 실제 메일은 보내지 않음(가짜 SMTP)."""
import smtplib
import time
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from rkmsiem.api import create_app
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.mailer import MailError
from rkmsiem.platform import Platform
from rkmsiem.reports import font_status
from rkmsiem.settings import load as load_settings

PW = "correct-horse-battery-9"
KEY = "test-ingest-key-1234567890"


class FakeSMTP:
    def __init__(self, box, fail=None):
        self.box, self.fail = box, fail

    def __call__(self, host, port, security, timeout):
        if self.fail:
            e = self.fail.pop(0)
            if e:
                raise e
        return self

    def send_message(self, m):
        self.box.append(m)

    def quit(self):
        pass


@pytest.fixture
def env(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    s = load_settings(config_dir, overrides={
        "database.path": str(tmp_path / "m.db"), "soar.worker_poll_ms": 50,
        "mail": {"enabled": True, "host": "smtp.test", "port": 587, "security": "starttls", "from": "RKMSIEM <soc@corp.test>",
                 "retries": 2, "retry_backoff_sec": 0, "max_per_hour": 5, "allowed_recipients": ["@corp.test"],
                 "alerts": {"enabled": True, "to": ["soc@corp.test"], "min_severity": "high", "batch_sec": 60, "approvals": True}},
        "reports": {"schedule": [{"name": "daily", "every": "day", "at": "09:00", "period_hours": 24, "to": ["boss@corp.test"], "enabled": True}],
                    "incident_on_close": {"enabled": True, "to": ["boss@corp.test"]}}})
    p = Platform(s)
    box = []
    p.mailer.smtp_factory = FakeSMTP(box)
    yield p, box
    p.stop()


def test_recipients_allowlist_and_format(env):
    p, box = env
    with pytest.raises(MailError, match="허용 목록"):
        p.mailer.send("test", "attacker@evil.test", "x", "y", wait=True)
    with pytest.raises(MailError, match="형식"):
        p.mailer.send("test", "not-an-address", "x", "y", wait=True)
    with pytest.raises(MailError, match="없습니다"):
        p.mailer.send("test", [], "x", "y", wait=True)
    assert box == []


def test_send_with_attachment_prefix_and_audit(env):
    p, box = env
    mid = p.mailer.send("manual", ["A@Corp.test", "a@corp.test"], "제목\r\nBcc: x@evil.test", "본문",
                        attachments=[("r.pdf", b"%PDF-1.4 x", "application/pdf")], actor="admin1", wait=True)
    r = p.mailer.result(mid)
    assert r["status"] == "sent" and r["recipients"] == "a@corp.test"            # 중복·대소문자 정리
    m = box[0]
    assert m["Subject"].startswith("[RKMSIEM] 제목") and "\n" not in m["Subject"] and m["Bcc"] is None   # 헤더 주입 차단
    assert [a.get_filename() for a in m.iter_attachments()] == ["r.pdf"]
    assert any(a["action"] == "mail.send" and a["actor"] == "admin1" for a in p.audit.list(20))


def test_retry_permanent_failure_and_hourly_limit(env):
    p, box = env
    p.mailer.smtp_factory = FakeSMTP(box, fail=[OSError("connection refused"), None])
    r = p.mailer.result(p.mailer.send("test", "soc@corp.test", "a", "b", wait=True))
    assert r["status"] == "sent" and r["attempts"] == 2
    p.mailer.smtp_factory = FakeSMTP(box, fail=[smtplib.SMTPAuthenticationError(535, b"bad creds")] * 3)
    r = p.mailer.result(p.mailer.send("test", "soc@corp.test", "a", "b", wait=True))
    assert r["status"] == "failed" and r["attempts"] == 1 and "로그인 실패" in r["error"]      # 인증 오류는 재시도 안 함
    p.mailer.smtp_factory = FakeSMTP(box)
    for _ in range(4):                                  # 성공 1 + 4 = 한도 5 (실패한 메일은 세지 않음)
        p.mailer.send("test", "soc@corp.test", "a", "b", wait=True)
    with pytest.raises(MailError, match="시간당"):
        p.mailer.send("test", "soc@corp.test", "a", "b", wait=True)


def test_alert_batching_and_severity_filter(env):
    p, box = env
    n = p.notifier
    for sev, title in (("critical", "침해 의심"), ("high", "KISA 초과"), ("medium", "저속 공격")):
        n.on_message({"type": "alert", "data": {"op": "new", "severity": sev, "title": title, "group": {"source.ip": "203.0.113.5"}, "incident_id": 1}})
    n.flush()                                           # batch_sec 안 됨 → 아직 안 보냄
    assert box == []
    n.flush(force=True)
    p.mailer._deliver(p.mailer.q.get_nowait())         # 작업자 스레드 대신 직접 처리
    assert len(box) == 1
    body = box[0].get_content()
    assert "침해 의심" in body and "KISA 초과" in body and "저속 공격" not in body and box[0]["Subject"].startswith("[RKMSIEM] 긴급 2건")


def test_schedule_sends_once_per_day(env, monkeypatch):
    p, box = env
    import rkmsiem.reports as rep
    monkeypatch.setattr(rep, "summary_pdf", lambda p_, f, t: b"%PDF-fake")
    tz = ZoneInfo(p.settings.get("timezone", "UTC"))
    before = datetime(2026, 10, 14, 8, 59, tzinfo=tz).timestamp()
    after = datetime(2026, 10, 14, 9, 5, tzinfo=tz).timestamp()
    assert p.notifier.run_schedule(before) == []
    assert p.notifier.run_schedule(after) == ["report:daily"]
    assert p.notifier.run_schedule(after + 60) == []                         # 같은 날 두 번 안 보냄
    r = p.db.one("SELECT * FROM mail_log WHERE kind='report:daily'")
    assert r["ref"] == "2026-10-14" and r["recipients"] == "boss@corp.test"


@pytest.mark.skipif(not font_status(load_settings())[0], reason="한글 폰트 없음")
def test_pdf_reports_and_api(tmp_path, config_dir, monkeypatch):
    monkeypatch.setenv("RKMSIEM_INGEST_KEYS", KEY)
    s = load_settings(config_dir, overrides={"database.path": str(tmp_path / "r.db"), "soar.worker_poll_ms": 50,
                                             "mail": {"enabled": True, "host": "smtp.test", "from": "soc@corp.test", "retry_backoff_sec": 0,
                                                      "allowed_recipients": ["@corp.test"], "alerts": {"to": ["soc@corp.test"]}}})
    p = Platform(s)
    box = []
    p.mailer.smtp_factory = FakeSMTP(box)
    app = create_app(p)
    auth = app.extensions["rkmsiem_auth"]
    auth.create_user("adm", PW, "admin", "t")
    auth.create_user("view", PW, "viewer", "t")
    p.collectors["http-json"] = HttpCollector(p.sources()["http-json"], p.pipeline, p.db, p.metrics)
    p.collectors["http-json"].start()
    p.pipeline.start()
    p.soar.start()
    c = app.test_client()
    tok = {u: c.post("/api/auth/login", json={"username": u, "password": PW}).get_json()["token"] for u in ("adm", "view")}
    H = lambda u: {"Authorization": f"Bearer {tok[u]}"}   # noqa: E731
    evs = [{"id": f"m{i}", "timestamp": f"2026-10-12T01:12:{i:02d}Z", "src_ip": "103.75.190.8", "user": "backup", "outcome": "failure",
            "category": "authentication", "message": "<34>Failed password for backup"} for i in range(11)]
    evs.append({"id": "ok", "timestamp": "2026-10-12T01:12:30Z", "src_ip": "103.75.190.8", "user": "backup", "outcome": "success", "category": "authentication"})
    c.post("/api/ingest/http-json?wait=1", headers={"X-API-Key": KEY}, json=evs)
    iid = c.get("/api/incidents", headers=H("view")).get_json()["items"][0]["id"]
    time.sleep(1)
    r = c.get(f"/api/reports/incident/{iid}.pdf", headers=H("view"))
    assert r.status_code == 200 and r.mimetype == "application/pdf" and r.data[:5] == b"%PDF-" and len(r.data) > 5000
    r = c.get("/api/reports/summary.pdf", headers=H("view"))
    assert r.status_code == 200 and r.data[:5] == b"%PDF-"
    assert c.post(f"/api/reports/incident/{iid}/email", headers=H("view"), json={}).status_code == 403
    r = c.post(f"/api/reports/incident/{iid}/email", headers=H("adm"), json={"to": "boss@corp.test"}).get_json()
    assert r["status"] == "sent" and box[-1].get_payload()[-1].get_filename() == f"rkmsiem-incident-{iid}.pdf"
    assert c.post(f"/api/reports/incident/{iid}/email", headers=H("adm"), json={"to": "x@evil.test"}).status_code == 400
    assert c.post("/api/reports/summary/email", headers=H("adm"), json={}).get_json()["status"] == "sent"
    assert c.post("/api/mail/test", headers=H("adm"), json={"to": "soc@corp.test"}).get_json()["status"] == "sent"
    st = c.get("/api/mail", headers=H("adm")).get_json()
    assert st["status"]["configured"] and st["pdf_font"]["ok"] and len(st["log"]) >= 3
    p.soar.stop()
    p.pipeline.stop()


def test_send_email_action_respects_mode_allowlist_and_idempotency(env):
    from types import SimpleNamespace

    from rkmsiem.plugins import ACTIONS
    from rkmsiem.soar.actions import ActionError
    p, box = env
    ctx = SimpleNamespace(response=p.response, run_id=7, step_id="mail", incident_id=None, actor="playbook:x", mode="simulate")
    out = ACTIONS["send_email"](ctx, {"to": "soc@corp.test", "subject": "s", "body": "b"})
    assert out["status"] == "simulated" and box == []                                 # simulate 모드는 실제로 안 보냄
    assert ACTIONS["send_email"](ctx, {"to": "soc@corp.test"})["status"] == "already_sent"
    ctx2 = SimpleNamespace(**dict(vars(ctx), run_id=8, mode="live"))
    with pytest.raises(ActionError, match="허용 목록"):
        ACTIONS["send_email"](ctx2, {"to": "x@evil.test"})
    assert ACTIONS["send_email"](ctx2, {"to": "soc@corp.test", "subject": "live"})["status"] == "queued"
