"""IP → 국가 위치 어댑터.

- 운영: MaxMind GeoLite2-City.mmdb (maxminddb 패키지) → 실제 국가·좌표 (모든 국가)
- 개발: DB 가 없으면 설정된 샘플 표로 '추정' (UI 에 SAMPLE 표시). 샘플 파일도 비우면 위치 없음.
"""
import json
import os

_NUM = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "iso3166_numeric.json"), encoding="utf-8"))


class Locator:
    def __init__(self, settings, lists):
        self.lists = lists
        self.reader = None
        db_file = settings.path("geo.geolite2_db") if settings.get("geo.geolite2_db") else None
        try:
            if db_file and os.path.exists(db_file):
                import maxminddb
                self.reader = maxminddb.open_database(db_file)
        except Exception:                 # noqa: BLE001 — 패키지 없음/DB 손상 → 샘플/없음
            self.reader = None
        sample = settings.path("geo.sample_file") if settings.get("geo.sample_file") else None
        data = {"countries": {}, "octets": {}}
        if not self.reader and sample and os.path.exists(sample):
            with open(sample, encoding="utf-8") as f:
                data = json.load(f)
        self.sample_countries, self.octets = data["countries"], data["octets"]
        self.source = "GeoLite2" if self.reader else ("sample" if self.octets else "none")    # GeoLite2 = 실제 mmdb (MaxMind 또는 DB-IP)
        self.db_name = None
        if self.reader:
            try:
                self.db_name = self.reader.metadata().database_type        # 예: GeoLite2-City, DBIP-City-Lite
            except Exception:     # noqa: BLE001
                self.db_name = "mmdb"
        self.server = {"name": settings.get("geo.server_name", "server"), "lat": settings.get("geo.server_lat", 0),
                       "lon": settings.get("geo.server_lon", 0)}
        self._cache = {}

    def lookup(self, ip):
        """{"cc", "name", "num", "lat", "lon"} 또는 None(사내망·조회 불가)."""
        if ip in self._cache:
            return self._cache[ip]
        out = None
        if ip and not self.lists.contains("internal_networks", ip):
            if self.reader:
                try:
                    rec = self.reader.get(ip) or {}
                except ValueError:
                    rec = {}
                c = rec.get("country") or rec.get("registered_country") or {}
                loc = rec.get("location") or {}
                cc = c.get("iso_code")
                if cc and loc.get("latitude") is not None:
                    names = c.get("names") or {}
                    out = {"cc": cc, "name": names.get("ko") or names.get("en") or cc, "num": _NUM.get(cc),
                           "lat": loc["latitude"], "lon": loc["longitude"]}
            elif self.octets and ":" not in ip:
                a, b = (int(x) for x in ip.split(".")[:2])
                cands = self.octets.get(str(a))
                if cands:
                    cc = cands[b % len(cands)]
                    c = self.sample_countries.get(cc)
                    if c:
                        out = {"cc": cc, "name": c["name"], "num": c["num"], "lat": c["lat"], "lon": c["lon"]}
        self._cache[ip] = out
        if len(self._cache) > 200000:
            self._cache.clear()
        return out
