"""P9: AbuseIPDB 평판 조회 — 판정 · 캐시 · 한도(429) · 키 오류 · 피드와 합치기 · 실패해도 계속 · 키 비노출."""
import json

from rkmsiem.abuseipdb import AbuseError, AbuseIPDB, lookup
from rkmsiem.intel import IntelIndex

KEY = "test-key-not-real-0000"


class Fake:
    def __init__(self, *responses):
        self.responses, self.calls = list(responses), []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, headers))
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def ok(score, reports=3, white=False, remaining="998"):
    body = {"data": {"ipAddress": "x", "abuseConfidenceScore": score, "totalReports": reports, "numDistinctUsers": 2,
                     "countryCode": "CN", "isp": "Example ISP", "usageType": "Data Center/Web Hosting/Transit",
                     "isWhitelisted": white, "isTor": False, "lastReportedAt": "2026-10-13T00:00:00+00:00"}}
    return 200, {"X-RateLimit-Limit": "1000", "X-RateLimit-Remaining": remaining}, json.dumps(body).encode()


class Resp:
    def __init__(self, ab, intel_cfg=None, feed_dir="."):
        self.abuseipdb, self.intel = ab, IntelIndex(intel_cfg or {}, feed_dir)


def test_verdicts_cache_and_key_header():
    t = [1000.0]
    f = Fake(ok(90), ok(30), ok(0, 0), ok(0, 0, white=True))
    ab = AbuseIPDB({}, KEY, fetch=f, clock=lambda: t[0])
    assert ab.check("203.0.113.1")["verdict"] == "malicious"
    assert ab.check("203.0.113.1")["cached"] is True and len(f.calls) == 1          # 캐시
    assert ab.check("203.0.113.2")["verdict"] == "suspicious"
    assert ab.check("203.0.113.3")["verdict"] == "unknown"
    assert ab.check("203.0.113.4")["verdict"] == "clean"
    url, headers = f.calls[0]
    assert headers["Key"] == KEY and KEY not in url and "ipAddress=203.0.113.1" in url and "maxAgeInDays=90" in url
    assert ab.status()["remaining"] == 998 and ab.status()["limit"] == 1000
    t[0] += 21601                                                                      # TTL 지나면 다시 조회
    f.responses.append(ok(10))
    assert ab.check("203.0.113.1")["cached"] is False and len(f.calls) == 5


def test_quota_and_bad_key_pause_lookups():
    t = [0.0]
    f = Fake((429, {"Retry-After": "120"}, b"{}"))
    ab = AbuseIPDB({}, KEY, fetch=f, clock=lambda: t[0])
    for _ in range(2):
        try:
            ab.check("198.51.100.5"); assert False
        except AbuseError as e:
            assert "한도" in str(e)
    assert len(f.calls) == 1                                                           # 멈춘 동안 다시 안 두드림
    t[0] = 121
    f.responses.append((401, {}, b'{"errors":[{"detail":"Authentication failed"}]}'))
    try:
        ab.check("198.51.100.5"); assert False
    except AbuseError as e:
        assert "키" in str(e) and KEY not in str(e)


def test_disabled_without_key():
    ab = AbuseIPDB({"enabled": True}, "")
    assert ab.enabled is False
    r = lookup(Resp(ab), "8.8.8.8")
    assert r["verdict"] == "unknown" and "abuseipdb" not in r


def test_lookup_merges_with_feeds_and_survives_failure(tmp_path):
    (tmp_path / "drop.txt").write_text("203.0.113.0/24\n")
    cfg = {"feeds": [{"name": "drop", "url": "https://x", "verdict": "malicious", "confidence": 70}]}
    # 피드가 malicious 인데 AbuseIPDB 가 낮게 봐도 더 위험한 판정 유지
    r = lookup(Resp(AbuseIPDB({}, KEY, fetch=Fake(ok(5))), cfg, str(tmp_path)), "203.0.113.9")
    assert r["verdict"] == "malicious" and r["source"] == "feed:drop+abuseipdb" and r["abuseipdb"]["score"] == 5
    # 피드에 없지만 AbuseIPDB 가 악성
    r = lookup(Resp(AbuseIPDB({}, KEY, fetch=Fake(ok(100, 250))), cfg, str(tmp_path)), "192.0.2.10")
    assert r["verdict"] == "malicious" and r["confidence"] == 100 and "250" in r["note"]
    # AbuseIPDB 연결 실패 → 피드 결과로 계속, 오류는 결과에 기록
    r = lookup(Resp(AbuseIPDB({}, KEY, fetch=Fake(OSError("timed out"))), cfg, str(tmp_path)), "203.0.113.9")
    assert r["verdict"] == "malicious" and "연결 실패" in r["abuseipdb"]["error"]
    # 사설 대역은 외부로 묻지 않음
    f = Fake()
    r = lookup(Resp(AbuseIPDB({}, KEY, fetch=f), cfg, str(tmp_path)), "10.1.2.3")
    assert r["verdict"] == "internal" and f.calls == []
