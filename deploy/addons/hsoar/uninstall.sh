#!/bin/bash
# HSOAR 제거 — deploy/addon.sh uninstall hsoar 가 부름 (그 뒤 핵심이 토큰 폐기 · /etc/rkmsiem/addons/hsoar 삭제)
set -uo pipefail
systemctl disable --now rkmsiem-hsoar 2>/dev/null
rm -f /etc/systemd/system/rkmsiem-hsoar.service
systemctl daemon-reload
rm -rf /opt/rkmsiem-hsoar /var/lib/rkmsiem-hsoar
userdel rkmsiem-hsoar 2>/dev/null
echo "HSOAR 서비스·프로그램 제거 (Slack 앱은 api.slack.com/apps 에서 직접 지우세요)"
