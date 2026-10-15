#!/bin/bash
# 위치 DB 받기/갱신: DB-IP Lite City (무료 · 가입 불필요 · 매달 갱신 · CC BY 4.0 — 콘솔에 출처 표시)
#   sudo /usr/local/lib/rkmsiem/geoip-update          (install.sh 가 설치, 매달 5일 rkmsiem-geoip.timer 가 자동 실행)
# MaxMind GeoLite2 를 쓰려면 이 스크립트 대신 geoipupdate 로 같은 경로에 받으면 됨 (README).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
DEST="${1:-/var/lib/rkmsiem/GeoLite2-City.mmdb}"      # settings.yaml 의 geo.geolite2_db 와 같은 경로
PY=/opt/rkmsiem/venv/bin/python
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# 이번 달 파일이 아직 없으면(월초) 지난달 파일
for M in "$(date +%Y-%m)" "$(date -d "$(date +%Y-%m-01) -1 month" +%Y-%m)"; do
	URL="https://download.db-ip.com/free/dbip-city-lite-$M.mmdb.gz"
	echo "==> $URL"
	if curl -fsSL --retry 2 --max-time 600 -o "$TMP/db.gz" "$URL"; then break; fi
	rm -f "$TMP/db.gz"
done
[ -s "$TMP/db.gz" ] || { echo "내려받기 실패 — 서버의 인터넷·DNS 를 확인하세요 (curl -I https://download.db-ip.com)" >&2; exit 1; }
gunzip -c "$TMP/db.gz" > "$TMP/db.mmdb"

# 쓰기 전에 실제로 열리고 조회되는지 확인 (깨진 파일로 바꾸지 않음)
"$PY" - "$TMP/db.mmdb" <<'PY'
import sys, maxminddb
r = maxminddb.open_database(sys.argv[1])
rec = r.get("8.8.8.8") or {}
cc, loc = (rec.get("country") or {}).get("iso_code"), rec.get("location") or {}
assert cc and loc.get("latitude") is not None, "조회 결과가 비어 있음 — 형식이 다름"
print(f"  확인: {r.metadata().database_type} · 8.8.8.8 → {cc}")
PY

install -m 0640 -o root -g rkmsiem "$TMP/db.mmdb" "$DEST.new"
mv -f "$DEST.new" "$DEST"
echo "==> 위치 DB 저장: $DEST ($(du -h "$DEST" | cut -f1))"
systemctl try-restart rkmsiem && echo "==> 서비스 재시작 — 콘솔에서 dashboard map 확인"
