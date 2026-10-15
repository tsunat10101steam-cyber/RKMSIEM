"""위협 인텔(IP 평판): 로컬 항목(config/intel.yaml entries) + 공개 차단 목록 피드(feeds).

- 피드는 설정된 https URL 에서만 주기적으로 내려받아 data/feeds/<이름>.txt 에 원자적으로 저장
  (관리자 설정 외의 URL 은 쓰지 않음 · 크기 상한 · 시간 제한)
- 조회는 정렬된 정수 구간 + 이분 탐색 (수만 개 CIDR 도 빠르게)
- 사설/예약 대역은 평판 대상이 아님 (FireHOL level1 등은 bogon 으로 10/8 을 포함하기 때문)
"""
import bisect
import ipaddress
import logging
import os
import threading
import time
import urllib.request

log = logging.getLogger("rkmsiem.intel")
VERDICT_RANK = {"unknown": 0, "suspicious": 1, "malicious": 2}
MAX_FEED_BYTES = 20 * 1024 * 1024
# 평판 대상이 아닌 대역 (사설·루프백·링크로컬·CGNAT·예약). 문서용 대역은 일반 주소처럼 취급.
_NON_ROUTABLE = {4: [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                       "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "240.0.0.0/4")],
                 6: [ipaddress.ip_network(n) for n in ("fc00::/7", "fe80::/10", "::1/128")]}


def parse_feed(text):
    """CIDR/IP 목록 텍스트 → 네트워크 목록. '#', ';' 주석, 'x/y ; SBL...' 형식 허용."""
    nets = []
    for line in text.splitlines():
        tok = line.split("#", 1)[0].split(";", 1)[0].strip().split()
        if not tok:
            continue
        try:
            nets.append(ipaddress.ip_network(tok[0], strict=False))
        except ValueError:
            continue
    return nets


class _Ranges:
    def __init__(self):
        self.starts, self.ends, self.meta = [], [], []

    @classmethod
    def build(cls, items):                       # items: [(network, meta)]
        r = cls()
        for net, meta in sorted(items, key=lambda x: int(x[0].network_address)):
            s, e = int(net.network_address), int(net.broadcast_address)
            r.starts.append(s), r.ends.append(e), r.meta.append(meta)
        # 겹치는 구간을 고려해 앞쪽 최대 끝값을 누적 (포함 여부 판정용)
        r.maxend = []
        m = -1
        for e in r.ends:
            m = max(m, e)
            r.maxend.append(m)
        return r

    def find(self, ip_int):
        i = bisect.bisect_right(self.starts, ip_int) - 1
        best = None
        while i >= 0 and self.maxend[i] >= ip_int:
            if self.ends[i] >= ip_int:
                m = self.meta[i]
                if best is None or (VERDICT_RANK.get(m["verdict"], 0), m.get("confidence", 0)) > \
                        (VERDICT_RANK.get(best["verdict"], 0), best.get("confidence", 0)):
                    best = m
            i -= 1
        return best


class IntelIndex:
    def __init__(self, intel_cfg, feed_dir):
        items = {4: [], 6: []}
        for e in (intel_cfg or {}).get("entries", []):
            net = ipaddress.ip_network(e["indicator"], strict=False)
            items[net.version].append((net, {"verdict": e.get("verdict", "suspicious"), "confidence": e.get("confidence", 50),
                                             "source": "local", "note": e.get("note")}))
        self.feed_counts = {}
        for f in (intel_cfg or {}).get("feeds", []):
            if f.get("enabled", True) is False:
                continue
            path = os.path.join(feed_dir, f"{f['name']}.txt")
            if not os.path.exists(path):
                self.feed_counts[f["name"]] = 0
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                nets = parse_feed(fh.read())
            self.feed_counts[f["name"]] = len(nets)
            meta = {"verdict": f.get("verdict", "malicious"), "confidence": f.get("confidence", 70), "source": f"feed:{f['name']}",
                    "note": f.get("description")}
            for n in nets:
                items[n.version].append((n, meta))
        self.r = {v: _Ranges.build(items[v]) for v in (4, 6)}
        self.sample = bool((intel_cfg or {}).get("sample"))

    def lookup(self, ip):
        a = ipaddress.ip_address(ip)
        if any(a in n for n in _NON_ROUTABLE.get(a.version, ())) or a.is_multicast or a.is_unspecified:
            return {"verdict": "internal", "confidence": 0, "source": "range-check", "note": "사설/예약 대역"}
        return self.r[a.version].find(int(a)) or {"verdict": "unknown", "confidence": 0, "source": None, "note": None}


class FeedUpdater:
    """설정된 피드를 refresh_hours 마다 내려받는다. 실패해도 마지막 파일을 계속 사용."""

    def __init__(self, config, feed_dir, on_update, fetch=None):
        self.config, self.dir, self.on_update = config, feed_dir, on_update
        self.fetch = fetch or self._fetch
        self.status = {}
        self._stop = threading.Event()

    @staticmethod
    def _fetch(url, timeout=30):
        if not url.startswith("https://"):
            raise ValueError("피드는 https URL 만 허용")
        req = urllib.request.Request(url, headers={"User-Agent": "rkmsiem-intel/1"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = r.read(MAX_FEED_BYTES + 1)
        if len(data) > MAX_FEED_BYTES:
            raise ValueError("피드가 너무 큼")
        return data.decode("utf-8", "replace")

    def refresh(self, force=False):
        os.makedirs(self.dir, exist_ok=True)
        changed = False
        for f in (self.config.get("intel") or {}).get("feeds", []):
            if f.get("enabled", True) is False:
                continue
            path = os.path.join(self.dir, f"{f['name']}.txt")
            age = time.time() - os.path.getmtime(path) if os.path.exists(path) else None
            if not force and age is not None and age < f.get("refresh_hours", 24) * 3600:
                continue
            try:
                text = self.fetch(f["url"])
                n = len(parse_feed(text))
                if n == 0:
                    raise ValueError("유효한 항목이 0개 — 형식 변경 의심, 기존 파일 유지")
                tmp = path + ".tmp"
                with open(tmp, "w", encoding="utf-8") as fh:
                    fh.write(text)
                os.replace(tmp, path)
                self.status[f["name"]] = {"ok": True, "entries": n, "updated_at": time.time()}
                changed = True
            except Exception as e:                    # noqa: BLE001
                log.warning("feed %s update failed: %s", f["name"], e)
                self.status[f["name"]] = {"ok": False, "error": str(e)[:300], "updated_at": time.time()}
        if changed:
            self.on_update()
        return self.status

    def loop(self):
        while not self._stop.is_set():
            try:
                self.refresh()
            except Exception:
                log.exception("feed loop")
            self._stop.wait(600)

    def stop(self):
        self._stop.set()
