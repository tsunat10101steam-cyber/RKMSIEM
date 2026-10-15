#!/bin/bash
# Suricata IDS 서버에서 실행: RKMSIEM 으로 IDS 경보를 보내는 전송기 설치
#   sudo ./install-ship.sh --siem https://10.0.0.53:8443 --fingerprint <SIEM 인증서 SHA-256 지문>
#   (지문은 SIEM 서버에서: sudo rkmsiem-setup → 상태, 또는 sudo /usr/share/rkmsiem/deploy/tls.sh --show)
#   https 를 아직 안 켠 SIEM:  --siem http://10.0.0.53:8088
# 수집 키는 실행 중에 물어봄 (화면·명령 기록에 남지 않음). SIEM 서버에서: sudo grep INGEST_KEYS /etc/rkmsiem/rkmsiem.env
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
SIEM="https://10.0.0.53:8443"; FP=""
while [ $# -gt 0 ]; do case "$1" in --siem) SIEM="$2"; shift 2;; --fingerprint) FP="$2"; shift 2;; *) echo "알 수 없는 옵션 $1" >&2; exit 1;; esac; done
FP="$(printf %s "$FP" | tr -d ': ' | tr 'A-F' 'a-f')"
[ -z "$FP" ] || printf %s "$FP" | grep -qE '^[0-9a-f]{64}$' || { echo "지문 형식 오류 (SHA-256 16진수 64자)" >&2; exit 1; }
case "$SIEM" in https://*) [ -n "$FP" ] || echo "! https 인데 --fingerprint 가 없습니다 — SIEM 이 자체 서명 인증서면 연결이 거부됩니다";; esac
HERE="$(cd "$(dirname "$0")" && pwd)"

command -v python3 >/dev/null || { echo "python3 가 필요합니다: sudo apt install -y python3" >&2; exit 1; }
EVE=/var/log/suricata/eve.json
[ -f "$EVE" ] || echo "! $EVE 가 아직 없습니다 — Suricata 설치·실행 후 자동으로 읽기 시작합니다"

echo "==> SIEM 연결 확인: $SIEM"
if [ -n "$FP" ]; then
	GOT="$(echo | timeout 5 openssl s_client -connect "$(printf %s "$SIEM" | sed -E 's#^https://##; s#/.*##')" 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
	if [ "$GOT" = "$FP" ]; then echo "  인증서 지문 일치"; else echo "  ! 인증서 지문 불일치 또는 연결 안 됨 (받은 값: ${GOT:-없음})"; fi
	curl -fsS -k --max-time 5 "$SIEM/readyz" >/dev/null && echo "  연결됨" || echo "  ! 연결 안 됨 — SIEM 의 ufw 에서 이 서버 IP 를 허용했는지 확인 (설치는 계속)"
else
	curl -fsS --max-time 5 "$SIEM/readyz" >/dev/null && echo "  연결됨" || echo "  ! 연결 안 됨 — SIEM 의 ufw 에서 이 서버 IP 를 허용했는지 확인 (설치는 계속)"
fi

install -d -m 0755 /usr/local/lib/rkmsiem-ship
install -m 0755 "$HERE/rkmsiem-ship-eve.py" /usr/local/lib/rkmsiem-ship/rkmsiem-ship-eve.py
install -d -m 0700 /var/lib/rkmsiem-ship
if [ ! -f /etc/rkmsiem-ship.env ] || ! grep -q '^RKMSIEM_INGEST_KEY=.' /etc/rkmsiem-ship.env; then
	read -rsp "RKMSIEM 수집 키 (SIEM 의 RKMSIEM_INGEST_KEYS 값): " K; echo
	# 붙여 넣을 때 딸려 오는 줄바꿈(CR)·공백·'RKMSIEM_INGEST_KEYS=' 앞부분·쉼표 뒤 다른 키를 정리
	K="$(printf %s "$K" | tr -d '\r\n\t ' | sed 's/^RKMSIEM_INGEST_KEYS=//; s/,.*//')"
	[ -n "$K" ] || { echo "키가 비었습니다" >&2; exit 1; }
	if ! printf %s "$K" | grep -qE '^[A-Za-z0-9._~+/=-]+$'; then
		echo "✘ 키에 쓸 수 없는 문자가 있습니다 (한글·특수문자?) — SIEM 의 값을 다시 복사하세요" >&2; exit 1
	fi
	umask 077
	printf "RKMSIEM_URL=%s\nRKMSIEM_INGEST_KEY=%s\nRKMSIEM_TLS_FINGERPRINT=%s\nEVE_PATH=%s\nEVENT_TYPES=alert,anomaly\nSTART_AT=end\n" "$SIEM" "$K" "$FP" "$EVE" > /etc/rkmsiem-ship.env
	unset K; umask 022
else
	sed -i "s#^RKMSIEM_URL=.*#RKMSIEM_URL=$SIEM#" /etc/rkmsiem-ship.env
	sed -i '/^RKMSIEM_TLS_FINGERPRINT=/d' /etc/rkmsiem-ship.env; echo "RKMSIEM_TLS_FINGERPRINT=$FP" >> /etc/rkmsiem-ship.env
fi
chmod 600 /etc/rkmsiem-ship.env
install -m 0644 "$HERE/rkmsiem-ship-eve.service" /etc/systemd/system/rkmsiem-ship-eve.service
systemctl daemon-reload
systemctl enable --now rkmsiem-ship-eve
sleep 2
systemctl --no-pager --lines=5 status rkmsiem-ship-eve || true
echo
echo "완료. 로그: journalctl -u rkmsiem-ship-eve -f"
echo "시험: Kali 등에서 nmap -sS 10.0.0.53 처럼 IDS 가 보는 망(HOME_NET) 안의 주소로 스캔 → RKMSIEM 콘솔의 경보에 'IDS 탐지' 가 뜨는지 확인"
