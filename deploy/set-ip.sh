#!/bin/bash
# 서버 IP 를 고정 주소로 바꾼다 (Ubuntu netplan) — SSH 로 접속한 채 실행해도 안전하게:
#
#   sudo ./deploy/set-ip.sh 10.0.0.53/24                 # 게이트웨이 기본: 같은 대역의 .2 (VMware NAT)
#   sudo ./deploy/set-ip.sh 10.0.0.53/24 --gw 10.0.0.2 --dns 8.8.8.8,1.1.1.1 --iface ens33
#   (새 주소로 다시 SSH 접속한 뒤)  sudo ./deploy/set-ip.sh --confirm
#
# 하는 일: 기존 netplan 백업 → 고정 IP 설정 하나로 교체(cloud-init 의 네트워크 재작성 끔) → 적용
#          → 롤백 타이머(기본 5분). 새 주소로 다시 접속해 --confirm 하지 않으면 이전 설정으로 자동 복구.
# IP 가 바뀌는 순간 지금 SSH 세션은 끊긴다(정상). VMware 의 NAT 포트 포워딩 대상도 새 IP 로 바꿔야 한다(끝에 안내).
set -euo pipefail

ADDR=""; GW=""; DNS="8.8.8.8,1.1.1.1"; IFACE=""; ROLLBACK=300
UNIT=rkmsiem-ip-rollback; STATE=/var/lib/rkmsiem-netchange
while [ $# -gt 0 ]; do
	case "$1" in
		--gw) GW="$2"; shift ;;
		--dns) DNS="$2"; shift ;;
		--iface) IFACE="$2"; shift ;;
		--rollback) ROLLBACK="$2"; shift ;;
		--confirm)
			[ "$(id -u)" -eq 0 ] || { echo "root 로 실행하세요: sudo $0 --confirm" >&2; exit 1; }
			if systemctl is-active --quiet "$UNIT.timer"; then
				systemctl stop "$UNIT.timer"; echo "✔ 롤백 취소 — 새 IP 설정을 유지합니다."
			else
				echo "롤백 타이머가 없습니다 (이미 확정됐거나 시간이 지나 복구됨)."
			fi
			ip -4 -br addr show scope global; exit 0 ;;
		-h|--help) sed -n '2,10p' "$0"; exit 0 ;;
		-*) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
		*) ADDR="$1" ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || { echo "root 로 실행하세요: sudo $0 $*" >&2; exit 1; }
[ -n "$ADDR" ] || { echo "새 주소를 주세요. 예) sudo $0 10.0.0.53/24" >&2; exit 2; }
command -v netplan >/dev/null || { echo "netplan 이 없습니다 (Ubuntu 18.04+ 필요)" >&2; exit 1; }

# 형식 검사 + 게이트웨이 기본값(.2 = VMware NAT 게이트웨이)
read -r ADDR GW NET < <(python3 - "$ADDR" "$GW" <<'PY'
import ipaddress, sys
a, gw = sys.argv[1], sys.argv[2]
if "/" not in a: a += "/24"
i = ipaddress.ip_interface(a)
if i.version != 4 or i.ip in (i.network.network_address, i.network.broadcast_address): sys.exit("주소가 올바르지 않습니다: " + a)
g = ipaddress.ip_address(gw) if gw else i.network.network_address + 2
if g not in i.network or g == i.ip: sys.exit(f"게이트웨이 {g} 가 {i.network} 안에 없거나 서버 주소와 같습니다")
print(i.with_prefixlen, g, i.network)
PY
) || exit 2
DNS_LIST="$(tr ',' ' ' <<<"$DNS" | xargs | sed 's/ /, /g')"
IFACE="${IFACE:-$(ip -4 route show default | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')}"
[ -n "$IFACE" ] && ip link show "$IFACE" >/dev/null 2>&1 || { echo "네트워크 장치를 찾지 못했습니다. --iface ens33 처럼 지정하세요." >&2; exit 1; }
OLD="$(ip -4 -o addr show dev "$IFACE" scope global | awk '{print $4}' | head -1)"

echo "장치 $IFACE : ${OLD:-없음} → $ADDR  (게이트웨이 $GW · DNS $DNS_LIST)"
echo "롤백: ${ROLLBACK}초 안에 새 주소로 접속해 'sudo $0 --confirm' 하지 않으면 원래대로 돌아갑니다."
read -r -p "계속할까요? [y/N] " yn; [[ "$yn" =~ ^[Yy] ]] || exit 0

# 1) 백업 + 롤백 스크립트
BK="$STATE/backup-$(date +%Y%m%d-%H%M%S)"; mkdir -p "$BK/netplan"
cp -a /etc/netplan/. "$BK/netplan/" 2>/dev/null || true
CLOUD=/etc/cloud/cloud.cfg.d/99-rkmsiem-disable-network-config.cfg
cat > "$BK/rollback.sh" <<EOF
#!/bin/sh
# set-ip.sh 자동 롤백 — 이전 netplan 으로 복구
rm -f /etc/netplan/*.yaml "$CLOUD"
cp -a "$BK/netplan/." /etc/netplan/
netplan apply
logger -t rkmsiem-set-ip "IP 변경 롤백 완료 ($BK)"
EOF
chmod 700 "$BK/rollback.sh"

# 2) 새 설정 (기존 yaml 은 dhcp 등이 겹치므로 치우고 하나만 둔다)
rm -f /etc/netplan/*.yaml
cat > /etc/netplan/01-rkmsiem-static.yaml <<EOF
# set-ip.sh 가 만든 고정 IP 설정 (이전 설정 백업: $BK)
network:
  version: 2
  ethernets:
    $IFACE:
      dhcp4: false
      dhcp6: false
      addresses: [$ADDR]
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [$DNS_LIST]
EOF
chmod 600 /etc/netplan/01-rkmsiem-static.yaml
# cloud-init 이 재부팅 때 50-cloud-init.yaml(DHCP)을 다시 만들지 않게
[ -d /etc/cloud/cloud.cfg.d ] && echo "network: {config: disabled}" > "$CLOUD"
if ! netplan generate; then
	echo "✘ 설정 검사 실패 → 원래대로 복구" >&2; sh "$BK/rollback.sh"; exit 1
fi

# 3) 롤백 타이머 → 적용 (이 시점에 SSH 가 끊길 수 있음)
systemctl stop "$UNIT.timer" 2>/dev/null || true; systemctl reset-failed "$UNIT.service" 2>/dev/null || true
systemd-run --quiet --unit="$UNIT" --on-active="${ROLLBACK}s" /bin/sh "$BK/rollback.sh"
NEWIP="${ADDR%/*}"
cat <<EOF

==> 적용합니다. 지금 SSH 가 끊기면 정상입니다.
  1) VMware: 편집 → 가상 네트워크 편집기 → VMnet8(NAT) → 서브넷 $NET
     (DHCP 대역이 $NEWIP 와 겹치지 않게) → NAT 설정 → 게이트웨이 $GW → 포트 포워딩의 대상 IP 를 모두 $NEWIP 로
     (예: 호스트 8443 → $NEWIP:8443, 호스트 8444 → $NEWIP:8444, 호스트 2222 → $NEWIP:22 — HTTPS 를 안 켰다면 8088·8090)
  2) ${ROLLBACK}초 안에 새 주소로 다시 접속 후:  sudo $0 --confirm
  3) 콘솔 settings → 메일 → 콘솔 주소 '지금 주소', IDS 전송기는 --siem https://$NEWIP:8443 로 다시 설치
     HTTPS 를 켰다면 인증서에 새 IP 를 넣기: sudo $(dirname "$0")/tls.sh --renew  (지문이 바뀌므로 IDS 전송기도 새 지문으로)
EOF
netplan apply
sleep 2
ip -4 -br addr show dev "$IFACE"
