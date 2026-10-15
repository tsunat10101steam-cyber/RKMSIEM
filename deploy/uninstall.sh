#!/bin/bash
# RKMSIEM 제거:  sudo ./deploy/uninstall.sh [--purge]   (--purge: 설정·데이터·감사 로그까지 삭제)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
systemctl disable --now rkmsiem rkmsiem-staff rkmsiem-geoip.timer 2>/dev/null || true
rm -f /etc/systemd/system/rkmsiem.service /etc/systemd/system/rkmsiem-staff.service /usr/local/sbin/rkmsiem-staff /etc/systemd/system/rkmsiem-geoip.service /etc/systemd/system/rkmsiem-geoip.timer
rm -rf /etc/systemd/system/rkmsiem.service.d
systemctl daemon-reload
nft delete table inet rkmsiem 2>/dev/null || true          # 차단 해제
rm -f /etc/sudoers.d/rkmsiem; rm -rf /usr/local/lib/rkmsiem /opt/rkmsiem
if [ "${1:-}" = "--purge" ]; then
	rm -rf /etc/rkmsiem /var/lib/rkmsiem
	userdel rkmsiem 2>/dev/null || true
	echo "완전히 제거했습니다 (설정·데이터 포함)."
else
	echo "프로그램을 제거했습니다. 설정(/etc/rkmsiem)·데이터(/var/lib/rkmsiem)는 남겨 두었습니다."
fi
