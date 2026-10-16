#!/bin/bash
# HSOAR 설치 — deploy/addon.sh install hsoar 가 부름 (ADDON_ENV · ADDON_DIR 를 넘겨 줌)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; APP=/opt/rkmsiem-hsoar; STATE=/var/lib/rkmsiem-hsoar; U=rkmsiem-hsoar
: "${ADDON_DIR:?}" "${ADDON_ENV:?}"
echo "==> 서비스 계정 $U"
id "$U" >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$U"
echo "==> 프로그램 → $APP (slack_sdk 설치)"
command -v python3 >/dev/null || { echo "python3 가 필요합니다" >&2; exit 1; }
python3 -c 'import venv, ensurepip' 2>/dev/null || apt-get -o DPkg::Lock::Timeout=300 install -y python3-venv >/dev/null
install -d -m 0755 "$APP"
[ -x "$APP/venv/bin/python" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade "slack_sdk>=3.33,<4"
rm -rf "$APP/hsoar"; cp -r "$HERE/hsoar" "$APP/hsoar"; find "$APP/hsoar" -name '__pycache__' -prune -exec rm -rf {} +
install -m 0644 "$HERE/slack-manifest.yaml" "$APP/slack-manifest.yaml"
echo "==> 설정 $ADDON_DIR · 상태 $STATE"
install -d -m 0750 -o "$U" -g "$U" "$STATE"
chgrp "$U" "$ADDON_DIR" "$ADDON_ENV"; chmod 0750 "$ADDON_DIR"; chmod 0640 "$ADDON_ENV"
if [ ! -f "$ADDON_DIR/hsoar.env" ]; then
	umask 027
	cat > "$ADDON_DIR/hsoar.env" <<CONF
# HSOAR 설정 — sudo rkmsiem-setup → 추가 기능 → HSOAR → 설정 (바꾸면 sudo systemctl restart rkmsiem-hsoar)
SLACK_BOT_TOKEN=
SLACK_APP_TOKEN=
SLACK_CHANNEL=
# 버튼·조치 명령을 쓸 수 있는 Slack 사용자 ID (쉼표) — 프로필 → ⋮ → 멤버 ID 복사 (U…)
ALLOWED_USERS=
CONSOLE_URL=
CONF
	umask 022
fi
chgrp "$U" "$ADDON_DIR/hsoar.env"; chmod 0640 "$ADDON_DIR/hsoar.env"
if [ ! -f "$ADDON_DIR/policy.json" ]; then
	PYTHONPATH="$APP" "$APP/venv/bin/python" -c 'import json; from hsoar.policy import DEFAULT; print(json.dumps(DEFAULT, ensure_ascii=False, indent=2))' > "$ADDON_DIR/policy.json"
fi
chgrp "$U" "$ADDON_DIR/policy.json"; chmod 0640 "$ADDON_DIR/policy.json"
install -m 0644 "$HERE/rkmsiem-hsoar.service" /etc/systemd/system/rkmsiem-hsoar.service
systemctl daemon-reload
systemctl enable --now rkmsiem-hsoar
systemctl restart rkmsiem-hsoar
echo
echo "설치됨. 다음: Slack 앱 만들기 → 토큰·채널 넣기 (setup 메뉴 '설정')"
echo "  Slack 앱 설명서: $APP/slack-manifest.yaml  (api.slack.com/apps → From an app manifest 에 붙여 넣기)"
echo "  자동 대응 등급: $ADDON_DIR/policy.json  (기본 dry — 제안만, 사람이 버튼으로 실행)"
