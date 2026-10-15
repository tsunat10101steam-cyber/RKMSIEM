#!/bin/bash
# IDS 서버(Ubuntu)에 Suricata 설치·설정 — VMware NAT 망(VMnet8)을 무차별 모드로 감시
#   sudo ./install-suricata.sh --iface ens33 --home-net 10.0.0.0/24
# 하는 일: Suricata(OISF 공식 PPA) 설치 · HOME_NET/감시 NIC 지정 · ET Open 규칙 + 실습용 규칙 · 무차별 모드 유지 · 설정 검사 · 실행
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
IFACE=""; HOME_NET="10.0.0.0/24"
while [ $# -gt 0 ]; do case "$1" in
	--iface) IFACE="$2"; shift 2;; --home-net) HOME_NET="$2"; shift 2;;
	*) echo "알 수 없는 옵션 $1" >&2; exit 1;; esac; done
if [ -z "$IFACE" ]; then
	IFACE="$(ip route show default | awk '/default/ {print $5; exit}')"
	echo "감시 NIC 를 지정하지 않아 기본 경로 NIC($IFACE)를 씁니다 — 다르면 --iface 로 지정"
fi
ip link show "$IFACE" >/dev/null 2>&1 || { echo "NIC '$IFACE' 가 없습니다: ip -br link" >&2; exit 1; }
step() { echo; echo "==> $*"; }
CONF=/etc/suricata/suricata.yaml

step "Suricata 설치 (OISF 공식 PPA)"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=300 install -y software-properties-common >/dev/null
add-apt-repository -y ppa:oisf/suricata-stable >/dev/null
apt-get -o DPkg::Lock::Timeout=300 update >/dev/null
apt-get -o DPkg::Lock::Timeout=300 install -y suricata jq python3 >/dev/null
suricata -V

step "설정: HOME_NET=$HOME_NET · 감시 NIC=$IFACE"
[ -f "$CONF.orig" ] || cp -a "$CONF" "$CONF.orig"                        # 원본 보관 (되돌리기: cp suricata.yaml.orig suricata.yaml)
sed -i -E "s|^(\s*HOME_NET:).*|\1 \"[$HOME_NET]\"|" "$CONF"
# af-packet 의 첫 interface 를 감시 NIC 로 (기본값 eth0 또는 이전 설정값)
awk -v ifc="$IFACE" '
	/^af-packet:/ { inaf=1 }
	inaf && /^[^ #-]/ && !/^af-packet:/ { inaf=0 }
	inaf && !done && /^[[:space:]]*-[[:space:]]*interface:/ { sub(/interface:.*/, "interface: " ifc); done=1 }
	{ print }' "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"
grep -q "^\s*community-id:\s*true" "$CONF" || sed -i -E "s|^(\s*)community-id:\s*false|\1community-id: true|" "$CONF"
grep -E "^\s*HOME_NET:|^\s*- interface: $IFACE" "$CONF" | head -2

step "규칙: ET Open (suricata-update) + 실습용 로컬 규칙"
suricata-update >/dev/null 2>&1 && echo "  ET Open 받음" || echo "  ! suricata-update 실패 (인터넷·DNS 확인) — 실습용 규칙만으로 계속"
install -d /etc/suricata/rules
cat > /etc/suricata/rules/local.rules <<'EOF'
# RKMSIEM 실습용 — 확실히 잡히도록 단순한 기준
alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH brute force suspected"; flow:to_server; flags:S; threshold: type both, track by_src, count 5, seconds 60; classtype:attempted-admin; sid:9000001; rev:1;)
alert tcp any any -> $HOME_NET any (msg:"LOCAL TCP SYN port scan"; flags:S; threshold: type both, track by_src, count 30, seconds 10; classtype:attempted-recon; sid:9000002; rev:1;)
alert icmp any any -> $HOME_NET any (msg:"LOCAL ICMP ping sweep"; itype:8; threshold: type both, track by_src, count 10, seconds 10; classtype:misc-activity; sid:9000003; rev:1;)
EOF
grep -q "/etc/suricata/rules/local.rules" "$CONF" || sed -i '/^rule-files:/a\  - /etc/suricata/rules/local.rules' "$CONF"

step "무차별 모드 (다른 VM 사이 트래픽도 보이게, 재부팅해도 유지)"
cat > /etc/systemd/system/ids-promisc@.service <<'EOF'
[Unit]
Description=IDS 감시 NIC 무차별 모드 (%i)
After=network-online.target
Before=suricata.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ip link set %i promisc on
ExecStop=/usr/sbin/ip link set %i promisc off

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "ids-promisc@$IFACE" >/dev/null
ip -d link show "$IFACE" | grep -q promiscuity\ [1-9] && echo "  $IFACE 무차별 모드 켜짐"

step "설정 검사"
if ! suricata -T -c "$CONF" -v > /tmp/suricata-test.log 2>&1; then
	tail -20 /tmp/suricata-test.log
	echo "✘ 설정 검사 실패 — 위 오류를 확인하세요 (원본: $CONF.orig)"; exit 1
fi
echo "  설정 정상"

step "실행"
systemctl enable suricata >/dev/null
systemctl restart suricata
for i in $(seq 1 30); do [ -s /var/log/suricata/eve.json ] && break; sleep 1; done
systemctl --no-pager --lines=3 status suricata || true
cat <<EOF

완료.
  경보 보기:  sudo tail -f /var/log/suricata/eve.json | jq -c 'select(.event_type=="alert") | {src: .src_ip, sig: .alert.signature}'
  다음 단계:  sudo ./install-ship.sh --siem https://10.0.0.53:8443 --fingerprint <지문>   (RKMSIEM 으로 보내기)
EOF
