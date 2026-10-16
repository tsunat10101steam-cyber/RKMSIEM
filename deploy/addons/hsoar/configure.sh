#!/bin/bash
# HSOAR 설정 (whiptail) — Slack 토큰 · 채널 · 허용된 사람 · 콘솔 주소
set -uo pipefail
D=/etc/rkmsiem/addons/hsoar; F=$D/hsoar.env; APP=/opt/rkmsiem-hsoar
[ -f "$F" ] || { echo "HSOAR 가 설치되어 있지 않습니다" >&2; exit 1; }
get() { sed -n "s/^$1=//p" "$F" | tail -1; }
setv() { local tmp; tmp="$(mktemp)"; grep -v "^$1=" "$F" > "$tmp"; printf '%s=%s\n' "$1" "$2" >> "$tmp"; cat "$tmp" > "$F"; rm -f "$tmp"; }
H=22; W=78
whiptail --title "HSOAR 설정 (1/6)" --msgbox "Slack 앱 만들기 (한 번만):

1) https://api.slack.com/apps → Create New App → From an app manifest
2) 워크스페이스 고르기 → 아래 파일 내용을 붙여 넣기 → Create
   $APP/slack-manifest.yaml
3) Install to Workspace → 'Bot User OAuth Token' (xoxb-…) 복사
4) Basic Information → App-Level Tokens → Generate
   (scope: connections:write) → xapp-… 복사
5) 알림 받을 채널에서: /invite @hsoar" $H $W || exit 0
v="$(whiptail --title "HSOAR 설정 (2/6)" --passwordbox "Bot User OAuth Token (xoxb-…)\n비워 두면 지금 값 유지" 10 $W 3>&1 1>&2 2>&3)" || exit 0
[ -n "$v" ] && { [[ "$v" == xoxb-* ]] || { whiptail --msgbox "xoxb- 로 시작해야 합니다" 8 50; exit 1; }; setv SLACK_BOT_TOKEN "$v"; }
v="$(whiptail --title "HSOAR 설정 (3/6)" --passwordbox "App-Level Token (xapp-…, connections:write)\n비워 두면 지금 값 유지" 10 $W 3>&1 1>&2 2>&3)" || exit 0
[ -n "$v" ] && { [[ "$v" == xapp-* ]] || { whiptail --msgbox "xapp- 로 시작해야 합니다" 8 50; exit 1; }; setv SLACK_APP_TOKEN "$v"; }
v="$(whiptail --title "HSOAR 설정 (4/6)" --inputbox "알림 채널 ID (C…) — 채널 이름 누르기 → 맨 아래 채널 ID" 10 $W "$(get SLACK_CHANNEL)" 3>&1 1>&2 2>&3)" || exit 0
[[ -z "$v" || "$v" =~ ^[CG][A-Z0-9]{6,}$ ]] || { whiptail --msgbox "채널 ID 형식이 아닙니다 (C… )" 8 50; exit 1; }; setv SLACK_CHANNEL "$v"
v="$(whiptail --title "HSOAR 설정 (5/6)" --inputbox "버튼·조치를 쓸 수 있는 Slack 사용자 ID (쉼표)\n프로필 → ⋮ → 멤버 ID 복사 (U…)" 11 $W "$(get ALLOWED_USERS)" 3>&1 1>&2 2>&3)" || exit 0
v="$(printf %s "$v" | tr -d ' ')"; [[ -z "$v" || "$v" =~ ^([UW][A-Z0-9]{6,})(,[UW][A-Z0-9]{6,})*$ ]] || { whiptail --msgbox "U… 형식의 ID 를 쉼표로" 8 50; exit 1; }; setv ALLOWED_USERS "$v"
ip="$(ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]; exit}')"
v="$(whiptail --title "HSOAR 설정 (6/6)" --inputbox "메시지에 넣을 RKMSIEM 콘솔 주소" 10 $W "$(get CONSOLE_URL || true)" 3>&1 1>&2 2>&3)" || exit 0
[ -n "$v" ] || v="https://$ip:8443"; setv CONSOLE_URL "$v"
chmod 0640 "$F"; chgrp rkmsiem-hsoar "$F"
systemctl restart rkmsiem-hsoar
sleep 3
whiptail --title "HSOAR 확인" --scrolltext --msgbox "$("$(dirname "$0")/status.sh" 2>&1 | head -40)" $H $W
