"""P8 Ubuntu 운영: 실제 auth.log/journald 형식 · 운영 설정 유효성 · nftables/계정 헬퍼 어댑터(명령 검증) ·
live 모드 플레이북 → 실제 명령 호출 · 위협 인텔 피드 · 비밀번호 변경 · 차단 목록 API · 자가 점검."""
import json
import os
import shutil
import sys
import textwrap
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from rkmsiem import yamlio
from rkmsiem.api import create_app
from rkmsiem.collectors.journald import JournaldCollector
from rkmsiem.intel import FeedUpdater, IntelIndex, parse_feed
from rkmsiem.parsers import Skip, parse_journald, parse_linux_syslog
from rkmsiem.pipeline import make_record
from rkmsiem.platform import Platform
from rkmsiem.response import AccountHelper, NftFirewall, Response, ResponseError
from rkmsiem.settings import load as load_settings

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROD_SOURCES = yamlio.load_file(os.path.join(ROOT, "deploy", "config", "sources.yaml"))
AUTH = next(s for s in PROD_SOURCES["sources"] if s["id"] == "ubuntu-authlog")
OPT = AUTH["options"]
NOW = datetime(2026, 10, 13, 17, 0, tzinfo=ZoneInfo("Asia/Seoul"))


# ------------------------------------------------------------ 실제 Ubuntu 로그 형식
@pytest.mark.parametrize("line,want", [
    ("Oct 13 16:47:05 web1 sshd[1234]: Failed password for invalid user admin from 203.0.113.9 port 50022 ssh2",
     ("authentication", "failure", "admin", "203.0.113.9", "ssh_login")),
    ("Oct  3 09:01:02 web1 sshd[99]: Failed password for root from 203.0.113.10 port 4242 ssh2",
     ("authentication", "failure", "root", "203.0.113.10", "ssh_login")),
    ("2026-10-13T16:47:05.123456+09:00 web1 sshd[1234]: Accepted publickey for deploy from 2001:db8::5 port 51000 ssh2: ED25519 SHA256:abc",
     ("authentication", "success", "deploy", "2001:db8::5", "ssh_login")),
    ("2026-10-13T16:47:06.000001+09:00 web1 sshd-session[77]: Failed password for kim from 198.51.100.4 port 1 ssh2",
     ("authentication", "failure", "kim", "198.51.100.4", "ssh_login")),
    ("Oct 13 16:47:07 web1 sshd[1]: Invalid user test from 203.0.113.11 port 222",
     ("authentication", "unknown", "test", "203.0.113.11", "ssh_invalid_user")),
    ("Oct 13 16:50:01 web1 sudo:     kim : TTY=pts/0 ; PWD=/home/kim ; USER=root ; COMMAND=/usr/bin/apt update",
     ("iam", "success", "kim", None, "privilege_use")),
    ("Oct 13 16:50:02 web1 sudo:      kim : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/kim ; USER=root ; COMMAND=/bin/ls",
     ("authentication", "failure", "kim", None, "sudo_auth")),
    ("Oct 13 16:51:00 web1 su: pam_unix(su-l:session): session opened for user root(uid=0) by kim(uid=1000)",
     ("iam", "success", "kim", None, "privilege_use")),
    ("Oct 13 16:52:00 web1 CRON[555]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
     ("host", "unknown", None, None, None)),
])
def test_real_ubuntu_authlog_lines(line, want):
    d = parse_linux_syslog(line, OPT, _now=NOW)
    got = (d["event"]["category"][0], d["event"]["outcome"], (d.get("user") or {}).get("name"),
           (d.get("source") or {}).get("ip"), d["event"].get("action"))
    assert got == want
    assert d["host"]["name"] == "web1"


def test_timestamps_both_formats_and_year_boundary():
    a = parse_linux_syslog("Oct 13 16:47:05 h sshd[1]: x", OPT, _now=NOW)
    assert a["@timestamp"] == datetime(2026, 10, 13, 7, 47, 5, tzinfo=timezone.utc).isoformat()   # KST → UTC
    b = parse_linux_syslog("2026-10-13T16:47:05.5+09:00 h sshd[1]: x", OPT)
    assert datetime.fromisoformat(b["@timestamp"]).timestamp() == pytest.approx(datetime(2026, 10, 13, 7, 47, 5, 500000, tzinfo=timezone.utc).timestamp())
    jan1 = datetime(2027, 1, 1, 0, 5, tzinfo=ZoneInfo("Asia/Seoul"))
    c = parse_linux_syslog("Dec 31 23:59:58 h sshd[1]: x", OPT, _now=jan1)                # 연말 경계 → 작년
    assert c["@timestamp"].startswith("2026-12-31")


def test_drop_unmatched_skips_noise():
    with pytest.raises(Skip):
        parse_linux_syslog("Oct 13 16:52:00 h CRON[1]: session opened", dict(OPT, drop_unmatched=True), _now=NOW)


def test_journald_json():
    j = {"__CURSOR": "s=1;i=2", "__REALTIME_TIMESTAMP": str(int(NOW.timestamp() * 1e6)), "SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "web1",
         "_PID": "10", "PRIORITY": "6", "MESSAGE": list(b"Failed password for root from 203.0.113.12 port 1 ssh2")}
    d = parse_journald(json.dumps(j), OPT)
    assert d["event"]["outcome"] == "failure" and d["source"]["ip"] == "203.0.113.12" and d["host"]["name"] == "web1"


# ------------------------------------------------------------ 운영 설정 + 실제 로그 → 탐지
@pytest.fixture
def prod_config(tmp_path, config_dir):
    for f in os.listdir(os.path.join(ROOT, "deploy", "config")):
        shutil.copy(os.path.join(ROOT, "deploy", "config", f), os.path.join(config_dir, f))
    return config_dir


def make_prod_platform(tmp_path, cfgdir, **over):
    o = {"database.path": str(tmp_path / "prod.db"), "intel_feed_dir": str(tmp_path / "feeds"), "geo.geolite2_db": "",
         "archive": None}
    o.pop("archive")
    o.update(over)
    return Platform(load_settings(cfgdir, overrides=o))


def test_production_config_valid_and_detects_real_logs(tmp_path, prod_config):
    p = make_prod_platform(tmp_path, prod_config)
    assert p.config_report["rejected"] == []
    assert p.response.firewall is not None and p.response.accounts is not None    # 운영 설정 = 실제 어댑터
    lines = [f"Oct 13 16:47:{i:02d} web1 sshd[{100 + i}]: Failed password for deploy from 203.0.113.50 port {40000 + i} ssh2" for i in range(11)]
    lines.append("Oct 13 16:47:30 web1 sshd[200]: Accepted password for deploy from 203.0.113.50 port 40100 ssh2")
    p.pipeline.process_batch([make_record("ubuntu-authlog", l) for l in lines])
    ids = {r["level_id"] for r in p.db.all("SELECT level_id FROM alerts")}
    assert {"BRUTEFORCE_HIGH", "COMPROMISE", "NO_LOCKOUT"} <= ids
    assert p.db.scalar("SELECT COUNT(*) FROM events WHERE sample=1") == 0                     # 운영엔 샘플 없음


def test_production_config_rejects_bad_regex(tmp_path, prod_config):
    src = yamlio.load_file(os.path.join(prod_config, "sources.yaml"))
    src["sources"][0]["options"]["extract"][0]["pattern"] = "Failed ((("
    open(os.path.join(prod_config, "sources.yaml"), "w", encoding="utf-8").write(yamlio.dumps(src))
    p = make_prod_platform(tmp_path, prod_config)
    assert any("sources.yaml" in r["file"] and "정규식" in r["error"] for r in p.config_report["rejected"])


# ------------------------------------------------------------ 어댑터 (실제 명령 인자 검증)
class FakeRunner:
    def __init__(self, fail=None):
        self.calls, self.fail = [], fail or {}
        self.nft = set()

    def run(self, argv, timeout=15):
        self.calls.append(list(argv))
        if "add" in argv and "element" in argv:
            self.nft.add(argv[-1].strip("{} ").split()[0])
            return 0, "", ""
        if "delete" in argv and "element" in argv:
            ip = argv[-1].strip("{} ")
            if ip in self.nft:
                self.nft.discard(ip)
                return 0, "", ""
            return 1, "", "Error: Could not process rule: No such file or directory"
        if argv[-2:] in (["lock", "bob"], ["lock", "bob", "--kill-sessions"][:2]) or "lock" in argv:
            if "root" in argv:
                return 4, '{"ok":false,"error":"protected account"}\n', ""
            return 0, json.dumps({"ok": True, "op": argv[-2] if argv[-1].startswith("--") else argv[-2], "user": "bob", "uid": 1001}) + "\n", ""
        if "unlock" in argv:
            return 0, '{"ok":true,"op":"unlock","user":"bob","uid":1001}\n', ""
        if "list" in argv or "check" in argv:
            return 0, "ok", ""
        return 0, "", ""


def test_nft_commands_exact():
    r = FakeRunner()
    fw = NftFirewall({"nft": "/usr/sbin/nft", "table": "rkmsiem"}, r)
    fw.block("203.0.113.7", 3600)
    fw.block("2001:db8::7")
    assert r.calls[0] == ["/usr/sbin/nft", "add", "element", "inet", "rkmsiem", "blocklist4", "{ 203.0.113.7 timeout 3600s }"]
    assert r.calls[1] == ["/usr/sbin/nft", "add", "element", "inet", "rkmsiem", "blocklist6", "{ 2001:db8::7 }"]
    assert fw.unblock("203.0.113.7")["was_present"] is True
    assert fw.unblock("203.0.113.7")["was_present"] is False             # 이미 없으면 오류 아님
    with pytest.raises(ValueError):
        fw.block("1.2.3.4; rm -rf /")                                     # 형식 검증 (셸도 안 거침)


def test_account_helper_validation_and_parse():
    r = FakeRunner()
    h = AccountHelper({"helper": "/usr/local/lib/rkmsiem/rkmsiem-account", "sudo": True, "kill_sessions": True}, r)
    out = h.lock("bob")
    assert r.calls[-1] == ["sudo", "-n", "/usr/local/lib/rkmsiem/rkmsiem-account", "lock", "bob", "--kill-sessions"]
    assert out["ok"] and out["uid"] == 1001
    with pytest.raises(ResponseError):
        h.lock("Bob; reboot")                                             # 실행 전에 거부
    assert len(r.calls) == 1
    with pytest.raises(ResponseError):
        h.lock("root")                                                    # 헬퍼가 거부(rc=4)


def test_reconcile_reapplies_unexpired(tmp_path, prod_config):
    p = make_prod_platform(tmp_path, prod_config)
    r = FakeRunner()
    p.response = Response(p.settings, runner=r)
    now = time.time()
    p.db.execute("INSERT INTO blocklist (ip, added_at, expires_at) VALUES ('203.0.113.1', ?, ?)", (now, now + 600))
    p.db.execute("INSERT INTO blocklist (ip, added_at, expires_at) VALUES ('203.0.113.2', ?, ?)", (now - 900, now - 1))
    p.db.execute("INSERT INTO blocklist (ip, added_at, expires_at) VALUES ('203.0.113.3', ?, NULL)", (now,))
    assert p.response.reconcile(p.db) == {"reapplied": 2, "failed": 0}
    assert r.nft == {"203.0.113.1", "203.0.113.3"} and p.db.scalar("SELECT COUNT(*) FROM blocklist") == 2


def test_live_playbook_executes_real_commands(tmp_path, prod_config):
    p = make_prod_platform(tmp_path, prod_config, **{"soar.mode": "live"})
    r = FakeRunner()
    p.response = Response(p.settings, runner=r)
    p.response.intel = IntelIndex({"entries": [{"indicator": "203.0.113.0/24", "verdict": "malicious"}]}, str(tmp_path))
    p.soar.response = p.response
    lines = [f"Oct 13 16:47:{i:02d} web1 sshd[1]: Failed password for bob from 203.0.113.60 port {i} ssh2" for i in range(6)]
    lines.append("Oct 13 16:47:20 web1 sshd[1]: Accepted password for bob from 203.0.113.60 port 99 ssh2")
    p.pipeline.process_batch([make_record("ubuntu-authlog", l) for l in lines])
    p.soar.run_pending()
    run = p.db.one("SELECT * FROM playbook_runs WHERE playbook_id='compromise_response'")
    assert run["state"] == "waiting_approval" and not r.calls                  # 승인 전에는 아무 명령도 안 함
    p.soar.decide(run["id"], "block_ip", "ops", "responder", True, "확인")
    p.soar.run_pending()
    assert ["/usr/sbin/nft", "add", "element", "inet", "rkmsiem", "blocklist4", "{ 203.0.113.60 timeout 86400s }"] in r.calls
    p.soar.decide(run["id"], "disable_account", "ops", "responder", True, "확인")
    p.soar.run_pending()
    assert any(c[:5] == ["sudo", "-n", "/usr/local/lib/rkmsiem/rkmsiem-account", "lock", "bob"] for c in r.calls)
    assert p.db.one("SELECT state FROM playbook_runs WHERE id=?", (run["id"],))["state"] == "succeeded"
    steps = {s["step_id"]: s for s in p.soar.detail(run["id"])["steps"]}
    assert steps["escalate"]["state"] == "succeeded"                         # 평판 malicious → 심각도 상향
    assert steps["block_ip"]["output"]["backend"] == "nftables"


def test_never_block_guard_and_manual_api(tmp_path, prod_config):
    lists = yamlio.load_file(os.path.join(prod_config, "lists.yaml"))
    lists["never_block"]["values"] = ["203.0.113.200/32"]
    open(os.path.join(prod_config, "lists.yaml"), "w", encoding="utf-8").write(yamlio.dumps(lists))
    p = make_prod_platform(tmp_path, prod_config, **{"soar.mode": "live"})
    r = FakeRunner()
    p.response = Response(p.settings, runner=r)
    p.soar.response = p.response
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("resp", "responder-pass-123", "responder", "t")
    app.extensions["rkmsiem_auth"].create_user("view", "viewer-pass-12345", "viewer", "t")
    c = app.test_client()
    tok = c.post("/api/auth/login", json={"username": "resp", "password": "responder-pass-123"}).get_json()["token"]
    vtok = c.post("/api/auth/login", json={"username": "view", "password": "viewer-pass-12345"}).get_json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    assert c.post("/api/blocklist", headers=H, json={"ip": "203.0.113.200", "reason": "x"}).status_code == 403    # 차단 금지 대역
    assert c.post("/api/blocklist", headers=H, json={"ip": "10.1.1.1", "reason": "x"}).status_code == 403         # 사내망
    assert not r.calls
    assert c.post("/api/blocklist", headers={"Authorization": f"Bearer {vtok}"}, json={"ip": "203.0.113.9", "reason": "x"}).status_code == 403
    rr = c.post("/api/blocklist", headers=H, json={"ip": "203.0.113.9", "reason": "수동 차단", "duration_sec": 600})
    assert rr.status_code == 201 and "203.0.113.9" in r.nft
    assert c.get("/api/blocklist", headers=H).get_json()["items"][0]["ip"] == "203.0.113.9"
    assert c.delete("/api/blocklist/203.0.113.9?reason=test", headers=H).status_code == 200 and "203.0.113.9" not in r.nft
    acts = [a["action"] for a in p.audit.list(100)]
    assert "manual.block_ip" in acts and "manual.unblock_ip" in acts


def test_password_change(tmp_path, prod_config):
    p = make_prod_platform(tmp_path, prod_config)
    app = create_app(p)
    app.extensions["rkmsiem_auth"].create_user("ana", "first-password-1", "analyst", "t")
    c = app.test_client()
    tok = c.post("/api/auth/login", json={"username": "ana", "password": "first-password-1"}).get_json()["token"]
    H = {"Authorization": f"Bearer {tok}"}
    assert c.post("/api/me/password", headers=H, json={"current": "wrong", "new": "second-password-2"}).status_code == 401
    assert c.post("/api/me/password", headers=H, json={"current": "first-password-1", "new": "short"}).status_code == 400
    assert c.post("/api/me/password", headers=H, json={"current": "first-password-1", "new": "second-password-2"}).status_code == 200
    assert c.get("/api/me", headers=H).status_code == 401                                   # 기존 세션 로그아웃
    assert c.post("/api/auth/login", json={"username": "ana", "password": "second-password-2"}).status_code == 200


# ------------------------------------------------------------ journald 수집기 (가짜 journalctl 프로세스)
def test_journald_collector_cursor_resume(tmp_path, prod_config):
    fake = tmp_path / "fake_journalctl.py"
    fake.write_text(textwrap.dedent(f"""
        import json, sys, time
        open(r"{tmp_path / 'argv.log'}", "a").write(" ".join(sys.argv[1:]) + "\\n")
        start = 0
        if "--after-cursor" in sys.argv:
            start = int(sys.argv[sys.argv.index("--after-cursor") + 1].split("=")[1]) + 1
        for i in range(start, 3):
            print(json.dumps({{"__CURSOR": f"c={{i}}", "__REALTIME_TIMESTAMP": str(1760000000000000 + i * 1000000),
                              "SYSLOG_IDENTIFIER": "sshd", "_HOSTNAME": "h", "MESSAGE": f"Failed password for u from 203.0.113.{{i}} port 1 ssh2"}}), flush=True)
        time.sleep(30)
    """), encoding="utf-8")
    p = make_prod_platform(tmp_path, prod_config)
    src = dict(next(s for s in p.sources().values() if s["type"] == "journald"), enabled=True)
    src["options"] = dict(src["options"], journalctl=[sys.executable, str(fake)])
    p.config.put("sources", "default", {"sources": [src]}, "t")
    p.pipeline.start()
    c = JournaldCollector(src, p.pipeline, p.db, p.metrics)
    c.start()
    try:
        end = time.time() + 10
        while time.time() < end and p.db.scalar("SELECT COUNT(*) FROM events") < 3:
            time.sleep(.1)
        assert p.db.scalar("SELECT COUNT(*) FROM events WHERE source_ip LIKE '203.0.113.%'") == 3
        time.sleep(.3)
        c.stop()
        c = JournaldCollector(src, p.pipeline, p.db, p.metrics)          # 재시작 → 커서 이후부터
        c.start()
        time.sleep(1.5)
        argv = (tmp_path / "argv.log").read_text().splitlines()
        assert "--since now" in argv[0] and "--after-cursor c=2" in argv[-1]
        assert p.db.scalar("SELECT COUNT(*) FROM events") == 3                # 중복 없음
    finally:
        c.stop()
        p.pipeline.stop()


# ------------------------------------------------------------ 위협 인텔
def test_feed_parsing_and_lookup(tmp_path):
    assert [str(n) for n in parse_feed("# c\n1.2.3.0/24\n5.6.7.8 ; SBL1\n;x\n2001:db8::/32\nbad\n")] == ["1.2.3.0/24", "5.6.7.8/32", "2001:db8::/32"]
    (tmp_path / "f1.txt").write_text("203.0.113.0/24\n203.0.113.128/25\n", encoding="utf-8")
    idx = IntelIndex({"entries": [{"indicator": "203.0.113.130", "verdict": "suspicious", "confidence": 10}],
                      "feeds": [{"name": "f1", "verdict": "malicious", "confidence": 80}]}, str(tmp_path))
    assert idx.lookup("203.0.113.130")["verdict"] == "malicious"           # 겹치는 범위 → 더 강한 판정
    assert idx.lookup("10.1.2.3")["verdict"] == "internal"                 # 사설 대역은 평판 대상 아님
    assert idx.lookup("8.8.8.8")["verdict"] == "unknown"
    assert idx.feed_counts == {"f1": 2}


def test_feed_updater(tmp_path):
    cfg = type("C", (), {"get": lambda self, k, d=None: {"feeds": [{"name": "a", "url": "https://x/a", "refresh_hours": 1}]}})()
    calls, updated = [], []
    up = FeedUpdater(cfg, str(tmp_path), lambda: updated.append(1), fetch=lambda u: calls.append(u) or "203.0.113.0/24\n")
    assert up.refresh()["a"]["entries"] == 1 and updated
    assert up.refresh() == up.status and len(calls) == 1                     # 갱신 주기 전에는 다시 받지 않음
    up.fetch = lambda u: "<html>error</html>"
    assert up.refresh(force=True)["a"]["ok"] is False
    assert (tmp_path / "a.txt").read_text() == "203.0.113.0/24\n"           # 실패해도 기존 목록 유지
    with pytest.raises(ValueError):
        FeedUpdater._fetch("http://insecure/feed")


def test_doctor_reports(tmp_path, prod_config):
    from rkmsiem.doctor import run_checks
    p = make_prod_platform(tmp_path, prod_config)
    p.response = Response(p.settings, runner=FakeRunner())
    res = {c["check"]: c for c in run_checks(p.settings, p)}
    assert res["config"]["status"] == "ok" and res["firewall"]["status"] == "ok" and res["account_lock"]["status"] == "ok"
    assert res["users"]["status"] == "fail"                                 # 아직 사용자 없음 → 실패로 알려 줌
    assert res["soar_mode"]["status"] == "warn" and res["never_block"]["status"] == "warn"
