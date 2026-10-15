"""AbuseIPDB IP 평판 조회 (https://www.abuseipdb.com — API v2 /check).

- API 키는 환경 변수 RKMSIEM_ABUSEIPDB_KEY 에서만 읽는다 (설정 파일·DB·로그·실행 결과에 남기지 않음)
- 무료 한도(하루 1,000건)를 아끼려고 같은 IP 결과는 cache_ttl_sec 동안 메모리에 재사용
- 응답 헤더 X-RateLimit-Remaining 으로 남은 한도를 추적하고, 다 쓰면(429) 다음 날까지 조회를 멈춘다
- 실패해도 플레이북은 멈추지 않는다 — 호출하는 쪽(lookup)이 공개 피드·로컬 인텔 결과로 계속 진행
"""
import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import OrderedDict

from .intel import VERDICT_RANK

log = logging.getLogger("rkmsiem.abuseipdb")
URL = "https://api.abuseipdb.com/api/v2/check"
KEY_ENV = "RKMSIEM_ABUSEIPDB_KEY"
CACHE_MAX = 10000


class AbuseError(Exception):
    pass


def _http(url, headers, timeout):
    """GET → (상태 코드, 응답 헤더, 본문). HTTP 오류도 상태 코드로 돌려준다."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read(64 * 1024)


class AbuseIPDB:
    def __init__(self, cfg, api_key, fetch=None, clock=time.time):
        cfg = cfg or {}
        self.key = (api_key or "").strip()
        self.enabled = bool(cfg.get("enabled", True)) and bool(self.key)
        self.max_age = int(cfg.get("max_age_days", 90))
        self.timeout = float(cfg.get("timeout_sec", 5))
        self.ttl = int(cfg.get("cache_ttl_sec", 21600))
        self.mal, self.sus = int(cfg.get("malicious_score", 75)), int(cfg.get("suspicious_score", 25))
        self.fetch, self.clock = fetch or _http, clock
        self._cache = OrderedDict()
        self._lock = threading.Lock()
        self.remaining = self.limit = None
        self.blocked_until = 0           # 한도 소진(429) 또는 키 오류 시 이 시각까지 조회 안 함
        self.last_error = None
        self.calls = self.cache_hits = 0

    @classmethod
    def from_settings(cls, settings, environ=None, **kw):
        import os
        env = os.environ if environ is None else environ
        return cls((settings.get("reputation") or {}).get("abuseipdb"), env.get(KEY_ENV), **kw)

    def verdict(self, score, whitelisted):
        if whitelisted:
            return "clean"
        if score >= self.mal:
            return "malicious"
        if score >= self.sus:
            return "suspicious"
        return "unknown"

    def check(self, ip):
        if not self.enabled:
            raise AbuseError("AbuseIPDB 키가 설정되지 않음")
        now = self.clock()
        with self._lock:
            hit = self._cache.get(ip)
            if hit and hit[0] > now:
                self._cache.move_to_end(ip)
                self.cache_hits += 1
                return dict(hit[1], cached=True)
        if now < self.blocked_until:
            raise AbuseError(f"조회 일시 중지 ({self.last_error})")
        q = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": self.max_age})
        try:
            status, headers, body = self.fetch(f"{URL}?{q}", {"Key": self.key, "Accept": "application/json",
                                                              "User-Agent": "rkmsiem-intel/1"}, self.timeout)
        except OSError as e:                                   # 연결 실패 · 시간 초과 · DNS
            self.last_error = f"연결 실패: {e}"
            raise AbuseError(self.last_error)
        self.calls += 1
        h = {k.lower(): v for k, v in (headers or {}).items()}
        if h.get("x-ratelimit-remaining") is not None:
            try:
                self.remaining, self.limit = int(h["x-ratelimit-remaining"]), int(h.get("x-ratelimit-limit") or 0) or None
            except ValueError:
                pass
        if status == 429:
            retry = h.get("retry-after")
            self.blocked_until = now + (int(retry) if str(retry or "").isdigit() else 3600)
            self.remaining = 0
            self.last_error = "하루 조회 한도 소진 (429)"
            raise AbuseError(self.last_error)
        if status in (401, 403):
            self.blocked_until = now + 600                    # 잘못된 키로 계속 두드리지 않게
            self.last_error = f"API 키 거부 ({status}) — 키 확인"
            raise AbuseError(self.last_error)
        if status != 200:
            self.last_error = f"HTTP {status}"
            raise AbuseError(self.last_error)
        try:
            d = json.loads(body)["data"]
        except (ValueError, KeyError, TypeError):
            self.last_error = "응답 형식 오류"
            raise AbuseError(self.last_error)
        score = int(d.get("abuseConfidenceScore") or 0)
        out = {"verdict": self.verdict(score, bool(d.get("isWhitelisted"))), "score": score,
               "total_reports": int(d.get("totalReports") or 0), "distinct_users": int(d.get("numDistinctUsers") or 0),
               "last_reported_at": d.get("lastReportedAt"), "country": d.get("countryCode"), "isp": d.get("isp"),
               "domain": d.get("domain"), "usage_type": d.get("usageType"), "is_tor": bool(d.get("isTor")),
               "whitelisted": bool(d.get("isWhitelisted")), "checked_at": now}
        self.last_error = None
        with self._lock:
            self._cache[ip] = (now + self.ttl, out)
            self._cache.move_to_end(ip)
            while len(self._cache) > CACHE_MAX:
                self._cache.popitem(last=False)
        return dict(out, cached=False)

    def status(self):
        return {"enabled": self.enabled, "remaining": self.remaining, "limit": self.limit, "calls": self.calls,
                "cache_hits": self.cache_hits, "cached_ips": len(self._cache), "last_error": self.last_error,
                "paused_until": self.blocked_until if self.blocked_until > self.clock() else None}


def lookup(response, ip):
    """IP 평판 = 로컬 인텔·공개 피드 + AbuseIPDB 중 더 위험한 판정. AbuseIPDB 실패는 결과에 적고 계속."""
    idx = response.intel if response else None
    base = idx.lookup(ip) if idx else {"verdict": "unknown", "confidence": 0, "source": None, "note": None}
    out = {"ip": ip, "verdict": base["verdict"], "confidence": base.get("confidence", 0), "source": base.get("source"),
           "note": base.get("note"), "sample_data": bool(idx and idx.sample and base.get("source") == "local")}
    if base["verdict"] == "internal":
        return out
    ab = getattr(response, "abuseipdb", None)
    if not ab or not ab.enabled:
        return out
    try:
        a = ab.check(ip)
    except AbuseError as e:
        out["abuseipdb"] = {"error": str(e)}
        return out
    out["abuseipdb"] = a
    sources = [s for s in (base.get("source"), "abuseipdb") if s]
    if (VERDICT_RANK.get(a["verdict"], 0), a["score"]) > (VERDICT_RANK.get(out["verdict"], 0), out["confidence"]):
        out.update(verdict=a["verdict"], confidence=a["score"],
                   note=f"AbuseIPDB 점수 {a['score']} · 신고 {a['total_reports']}건 · {a.get('country') or '?'} {a.get('isp') or ''}".strip())
    elif out["verdict"] == "unknown" and a["verdict"] == "clean":
        out.update(verdict="clean", note="AbuseIPDB 허용 목록(whitelisted)")
    out["source"] = "+".join(sources)
    return out
