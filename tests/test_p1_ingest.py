"""P1: 파서 · 정규화 · 멱등성 · DLQ · 백프레셔 · 파일 체크포인트 · UDP syslog · 마스킹."""
import json
import socket
import time
from datetime import datetime

import pytest

from rkmsiem import logutil
from rkmsiem.bus import Bus
from rkmsiem.collectors.file_tail import FileTailCollector
from rkmsiem.collectors.http import HttpCollector
from rkmsiem.collectors.syslog_udp import SyslogUdpCollector
from rkmsiem.metrics import Metrics
from rkmsiem.parsers import ParseError, parse_authlog, parse_json, parse_syslog
from rkmsiem.pipeline import Pipeline, make_record
from rkmsiem.settings import load as load_settings

AUTH_OPT = {"timezone": "Asia/Seoul", "category": "authentication", "outcome_map": {"FAIL": "failure", "SUCCESS": "success"}}
SOURCES = {
    "auth": {"id": "auth", "type": "file", "parser": "authlog", "dataset": "auth", "options": AUTH_OPT},
    "js": {"id": "js", "type": "http", "parser": "json", "dataset": "js",
           "options": {"timezone": "UTC", "field_map": {"@timestamp": "t", "source.ip": "ip", "user.name": "u", "event.outcome": "o", "event.id": "id"}}},
    "sys": {"id": "sys", "type": "syslog_udp", "parser": "syslog", "dataset": "syslog",
            "options": {"host": "127.0.0.1", "port": 0, "timezone": "UTC", "extract": [
                {"program": "sshd", "pattern": r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9.]+)",
                 "category": "authentication", "outcome": "failure"}]}},
}


@pytest.fixture
def pipe(db, config_dir):
    s = load_settings(config_dir, overrides={"pipeline.queue_size": 50, "pipeline.batch_size": 20, "pipeline.enqueue_timeout_sec": 0.05})
    p = Pipeline(db, s, Metrics(), Bus(), lambda: SOURCES)
    seen = []
    p.add_handler(lambda evs: seen.extend(evs))
    p.seen = seen
    return p


def wait_for(cond, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(.05)
    return False


# ---------------- 파서 ----------------
def test_authlog_parser_and_timezone():
    d = parse_authlog("2026-10-12 09:00:01 FAIL user=admin ip=203.0.113.50", AUTH_OPT)
    assert d["event"]["outcome"] == "failure" and d["source"]["ip"] == "203.0.113.50" and d["user"]["name"] == "admin"
    assert datetime.fromisoformat(d["@timestamp"]).hour == 0      # 09:00 KST = 00:00 UTC
    with pytest.raises(ParseError):
        parse_authlog("garbage line", AUTH_OPT)
    bad_ip = parse_authlog("2026-10-12 09:00:01 FAIL user=a ip=999.1.1.1", AUTH_OPT)
    assert "source" not in bad_ip and bad_ip["labels"]["parse_warnings"]


def test_json_parser_mapping():
    d = parse_json(json.dumps({"t": "2026-10-12T00:00:00Z", "ip": "1.2.3.4", "u": "x", "o": "FAILURE"}), SOURCES["js"]["options"])
    assert d["event"]["outcome"] == "failure" and d["source"]["ip"] == "1.2.3.4"
    with pytest.raises(ParseError):
        parse_json("[1,2]", SOURCES["js"]["options"])
    with pytest.raises(ParseError):
        parse_json(json.dumps({"ip": "1.2.3.4"}), SOURCES["js"]["options"])   # 시각 없음


def test_syslog_rfc3164_and_5424():
    opt = SOURCES["sys"]["options"]
    d = parse_syslog("<38>Oct 12 09:00:01 gw sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 22 ssh2", opt)
    assert d["event"]["outcome"] == "failure" and d["user"]["name"] == "admin" and d["source"]["ip"] == "198.51.100.7"
    d2 = parse_syslog("<86>1 2026-10-12T00:00:01Z gw cron 77 - - job done", opt)
    assert d2["event"]["category"] == ["host"] and d2["host"]["name"] == "gw"
    with pytest.raises(ParseError):
        parse_syslog("no pri", opt)


# ---------------- 파이프라인 ----------------
def test_idempotent_duplicates_and_dlq(pipe, db):
    line = "2026-10-12 09:00:01 FAIL user=admin ip=203.0.113.50"
    recs = [make_record("auth", line, idem_key="k1"), make_record("auth", line, idem_key="k1"),
            make_record("auth", "### broken ###", idem_key="k2"), make_record("nope", "x", idem_key="k3"),
            make_record("auth", "2026-10-12 09:00:02 SUCCESS user=admin ip=203.0.113.50", idem_key="k4")]
    pipe.process_batch(recs)
    assert db.scalar("SELECT COUNT(*) FROM events") == 2          # 중복 1건 제거, 실패 2건 제외
    assert db.scalar("SELECT COUNT(*) FROM dlq WHERE stage='parse'") == 2
    assert db.scalar("SELECT COUNT(*) FROM raw_events WHERE status='failed'") == 2   # 원본 보존
    pipe.process_batch([make_record("auth", line, idem_key="k1")])                     # 재전송
    assert db.scalar("SELECT COUNT(*) FROM events") == 2
    assert len(pipe.seen) == 2


def test_dlq_replay_after_config_fix(pipe, db):
    pipe.process_batch([make_record("auth", "2026-10-12 09:00:01 DENY user=a ip=1.1.1.1", idem_key="r1")])
    assert db.one("SELECT outcome FROM events")["outcome"] == "unknown"            # 모르는 상태값은 unknown 으로 저장
    # 송신 측이 시각 필드 이름을 'time' 으로 보냄 → 현재 매핑('t')으로는 시각 없음 → DLQ
    pipe.process_batch([make_record("js", '{"time":"2026-10-12T00:00:00Z","ip":"1.1.1.1"}', idem_key="r2")])
    assert db.scalar("SELECT COUNT(*) FROM dlq WHERE replayed=0") == 1
    assert pipe.replay_dlq()["failed"] == 1                                          # 설정 그대로면 여전히 실패
    SOURCES["js"]["options"]["field_map"]["@timestamp"] = "time"                     # 설정 수정
    try:
        assert pipe.replay_dlq() == {"replayed": 1, "failed": 0}
        assert db.scalar("SELECT COUNT(*) FROM events WHERE source_id='js'") == 1
        assert db.scalar("SELECT status FROM raw_events WHERE idem_key='r2'") == "ok"
        assert any(e["source_id"] == "js" for e in pipe.seen)                       # 재처리분도 탐지 처리기로 전달
    finally:
        SOURCES["js"]["options"]["field_map"]["@timestamp"] = "t"


def test_backpressure_rejects_when_full(pipe):
    accepted = sum(pipe.submit(make_record("auth", f"l{i}"), timeout=0.01) for i in range(80))
    assert accepted == 50 and pipe.metrics.total("ingest_rejected_total") == 30      # 큐 크기 50


def test_burst_is_fully_processed(pipe, db):
    pipe.start()
    try:
        n = 0
        for i in range(400):                                    # 큐(50)보다 훨씬 많은 입력 → 막히면 재시도
            rec = make_record("auth", f"2026-10-12 10:{i // 60:02d}:{i % 60:02d} FAIL user=u{i % 7} ip=10.9.0.{i % 200}")
            while not pipe.submit(rec, timeout=0.5):
                pass
            n += 1
        assert wait_for(lambda: db.scalar("SELECT COUNT(*) FROM events") == n, 15)
    finally:
        pipe.stop()


def test_file_tail_checkpoint_resume_and_truncate(pipe, db, tmp_path):
    log = tmp_path / "a.log"
    log.write_text("".join(f"2026-10-12 09:00:{i:02d} FAIL user=u ip=10.0.0.{i}\n" for i in range(5)), encoding="utf-8")
    cfg = dict(SOURCES["auth"], options=dict(AUTH_OPT, path=str(log), poll_sec=0.1))
    pipe.start()
    c = FileTailCollector(cfg, pipe, db, pipe.metrics)
    c.start()
    try:
        assert wait_for(lambda: db.scalar("SELECT COUNT(*) FROM events") == 5)
        c.stop()
        with open(log, "a", encoding="utf-8") as f:              # 중지 중에 추가된 줄
            f.write("2026-10-12 09:01:00 SUCCESS user=u ip=10.0.0.9\n")
        c = FileTailCollector(cfg, pipe, db, pipe.metrics)
        c.start()
        assert wait_for(lambda: db.scalar("SELECT COUNT(*) FROM events") == 6)
        time.sleep(.4)
        assert db.scalar("SELECT COUNT(*) FROM events") == 6      # 재시작해도 중복 없음
        log.write_text("2026-10-12 09:02:00 FAIL user=z ip=10.0.0.8\n", encoding="utf-8")   # 잘림(truncate)
        assert wait_for(lambda: db.scalar("SELECT COUNT(*) FROM events") == 7)
    finally:
        c.stop()
        pipe.stop()


def test_syslog_udp_end_to_end(pipe, db):
    pipe.start()
    c = SyslogUdpCollector(SOURCES["sys"], pipe, db, pipe.metrics)
    c.start()
    try:
        assert wait_for(lambda: c.bound is not None)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"<38>Oct 12 09:00:01 gw sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2", c.bound)
        s.close()
        assert wait_for(lambda: db.scalar("SELECT COUNT(*) FROM events WHERE source_id='sys' AND user_name='root'") == 1)
        assert c.status()["received"] == 1
    finally:
        c.stop()
        pipe.stop()


def test_http_body_formats():
    c = HttpCollector(SOURCES["js"], None, None, None)
    assert len(c.records_from_body(b'[{"id":"a"},{"id":"b"}]', "application/json")) == 2
    assert len(c.records_from_body(b'{"id":"a"}\n{"id":"b"}\n', "application/x-ndjson")) == 2
    r = c.records_from_body(b'{"id":"same"}', "application/json")[0]
    assert r["idem_key"] == "js:id:same"                           # 송신 측 id → 멱등성 키


def test_submit_and_wait_reports(pipe, db):
    pipe.start()
    try:
        recs = [make_record("auth", "2026-10-12 09:00:01 FAIL user=a ip=1.1.1.1", idem_key="w1"),
                make_record("auth", "bad", idem_key="w2")]
        res = pipe.submit_and_wait(recs, timeout=5)
        assert res["stored"] == 1 and res["failed"] == 1
    finally:
        pipe.stop()


def test_masking():
    assert "hunter2" not in logutil.mask_text("login password=hunter2 ok")
    assert "abc.def" not in logutil.mask_text("Authorization: Bearer abc.def")
    assert logutil.mask({"user": "a", "Password": "x", "nested": {"api_key": "k"}}) == {"user": "a", "Password": "***", "nested": {"api_key": "***"}}
