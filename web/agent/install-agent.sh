#!/bin/bash
# RKMSIEM 원격 조치 에이전트 설치 (대상 서버에서, root)
#   sudo ./install-agent.sh --siem https://10.0.0.53:8443 --fingerprint <SIEM 인증서 지문> --code <등록 코드>
#   sudo ./install-agent.sh --uninstall
# 등록 코드·명령은 SIEM 콘솔의 'dashboard agents' → 에이전트 추가 에서 만듦 (1시간 · 1회용)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
SIEM=""; FP=""; CODE=""; LIB=/usr/local/lib/rkmsiem-agent; ETC=/etc/rkmsiem-agent; ENVF=$ETC/agent.env
while [ $# -gt 0 ]; do case "$1" in
	--siem) SIEM="$2"; shift 2;; --fingerprint) FP="$2"; shift 2;; --code) CODE="$2"; shift 2;;
	--uninstall) systemctl disable --now rkmsiem-agent 2>/dev/null || true; rm -f /etc/systemd/system/rkmsiem-agent.service; rm -rf "$LIB" "$ETC"
		systemctl daemon-reload; echo "에이전트를 지웠습니다 (SIEM 콘솔에서도 '해제' 하세요)"; exit 0;;
	*) echo "알 수 없는 옵션 $1" >&2; exit 1;; esac; done
command -v python3 >/dev/null || { echo "python3 가 필요합니다: sudo apt install -y python3" >&2; exit 1; }
[ -n "$SIEM" ] || { echo "--siem https://<SIEM>:8443 이 필요합니다" >&2; exit 1; }
FP="$(printf %s "$FP" | tr -d ': ' | tr 'A-F' 'a-f')"
[ -z "$FP" ] || printf %s "$FP" | grep -qE '^[0-9a-f]{64}$' || { echo "지문 형식 오류 (SHA-256 16진수 64자)" >&2; exit 1; }
case "$SIEM" in https://*) [ -n "$FP" ] || { echo "https 인데 --fingerprint 가 없습니다" >&2; exit 1; };; esac
HERE="$(cd "$(dirname "$0")" && pwd)"

install -d -m 0755 "$LIB"; install -m 0755 "$HERE/rkmsiem-agent.py" "$LIB/rkmsiem-agent.py"
install -d -m 0700 "$ETC"
if [ ! -f "$ENVF" ]; then
	umask 077
	cat > "$ENVF" <<CONF
# RKMSIEM 원격 조치 에이전트 — 이 서버가 SIEM 에 허용하는 것 (바꾸면: sudo systemctl restart rkmsiem-agent)
RKMSIEM_URL=$SIEM
RKMSIEM_TLS_FINGERPRINT=$FP
# 허용 조치 (지우면 그 조치는 SIEM 이 요청해도 거부 · 비우면 상태 보고만)
ALLOW=container_stop,container_restart,process_kill,service_restart
# 어떤 경우에도 건드리지 않음 (패턴, 쉼표)
PROTECT_SERVICES=ssh*,sshd*,systemd-*,dbus*,rkmsiem-agent*,docker*,containerd*,networking*,NetworkManager*
PROTECT_PROCESSES=sshd,systemd,init,dockerd,containerd,containerd-shim,rkmsiem-agent
PROTECT_CONTAINERS=
CONF
	umask 022
else
	sed -i "s#^RKMSIEM_URL=.*#RKMSIEM_URL=$SIEM#; s#^RKMSIEM_TLS_FINGERPRINT=.*#RKMSIEM_TLS_FINGERPRINT=$FP#" "$ENVF"
fi
chmod 600 "$ENVF"
if [ -n "$CODE" ]; then
	echo "==> SIEM 에 등록"
	AGENT_ENV="$ENVF" python3 "$LIB/rkmsiem-agent.py" enroll "$CODE"
elif ! grep -q '^AGENT_TOKEN=.' "$ENVF"; then
	echo "등록 코드가 없습니다 — --code <콘솔에서 만든 코드>" >&2; exit 1
fi
install -m 0644 "$HERE/rkmsiem-agent.service" /etc/systemd/system/rkmsiem-agent.service
systemctl daemon-reload
systemctl enable --now rkmsiem-agent
systemctl restart rkmsiem-agent
sleep 2
systemctl --no-pager --lines=4 status rkmsiem-agent || true
echo
echo "완료. 허용 조치·보호 목록: sudo nano $ENVF  (바꾼 뒤 sudo systemctl restart rkmsiem-agent)"
echo "로그: journalctl -u rkmsiem-agent -f · 지우기: sudo $0 --uninstall"
