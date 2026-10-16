#!/bin/bash
# HSOAR 상태 — 설정·RKMSIEM·Slack 연결 확인 + 최근 로그
systemctl --no-pager --lines=0 status rkmsiem-hsoar 2>/dev/null | head -3
echo
sudo -u rkmsiem-hsoar env ADDON_DIR=/etc/rkmsiem/addons/hsoar HSOAR_STATE=/var/lib/rkmsiem-hsoar PYTHONPATH=/opt/rkmsiem-hsoar \
	/opt/rkmsiem-hsoar/venv/bin/python -m hsoar check
echo; echo "최근 로그:"; journalctl -u rkmsiem-hsoar -n 15 --no-pager -o cat 2>/dev/null
