#!/bin/bash
# RKMSIEM 추가 기능 관리 — 'sudo rkmsiem-setup → 추가 기능' 이 부름 (직접 실행도 가능)
#   sudo ./deploy/addon.sh list                (탭 구분: id · 상태 · 이름 · 설명)
#   sudo ./deploy/addon.sh install <id>
#   sudo ./deploy/addon.sh uninstall <id>
#   sudo ./deploy/addon.sh configure <id>     추가 기능의 설정 화면 (addon.conf 의 CONFIGURE)
#   sudo ./deploy/addon.sh status <id>        상태 확인 (addon.conf 의 STATUS)
#
# 추가 기능 = deploy/addons/<id>/ (addon.conf · install.sh · uninstall.sh). 핵심과는 API 로만 이야기한다:
#   설치할 때 핵심이 그 추가 기능 전용 API 토큰(addon-<id>, addon.conf 의 SCOPES 만)을 만들어
#   /etc/rkmsiem/addons/<id>/addon.env (root 0600) 에 넣어 줌 → 추가 기능은 http://127.0.0.1:8088 으로 접속
#   제거하면 토큰도 폐기 — 핵심은 수동 운영으로 그대로
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"; ADDONS="$HERE/addons"; STATE=/etc/rkmsiem/addons
CMD="${1:-list}"; AID="${2:-}"

rk_cli() {     # 서비스와 같은 계정·환경으로 python -m rkmsiem …
	systemd-run --quiet --pipe --wait --collect -p User=rkmsiem -p EnvironmentFile=/etc/rkmsiem/rkmsiem.env \
		-p Environment=RKMSIEM_CONFIG_DIR=/etc/rkmsiem/config -p WorkingDirectory=/opt/rkmsiem \
		/opt/rkmsiem/venv/bin/python -m rkmsiem "$@"
}
load() {
	[[ "$1" =~ ^[a-z][a-z0-9-]{0,31}$ ]] && [ -f "$ADDONS/$1/addon.conf" ] || { echo "추가 기능 '$1' 이 없습니다" >&2; exit 2; }
	ID=""; NAME=""; DESC=""; VERSION=""; AVAILABLE=0; SCOPES=""; SERVICE=""; CONFIGURE=""; STATUS=""
	# shellcheck disable=SC1090
	. "$ADDONS/$1/addon.conf"
}
status_of() {
	if [ -f "$STATE/$1/installed" ]; then echo "설치됨"; elif [ "$AVAILABLE" = 1 ]; then echo "설치 안 됨"; else echo "준비 중"; fi
}

case "$CMD" in
list)
	for f in "$ADDONS"/*/addon.conf; do
		[ -f "$f" ] || continue
		id="$(basename "$(dirname "$f")")"; load "$id"
		printf '%s\t%s\t%s\t%s\n' "$id" "$(status_of "$id")" "$NAME" "$DESC"
	done ;;
install)
	[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
	load "$AID"
	[ "$AVAILABLE" = 1 ] || { echo "$NAME 은(는) 아직 준비 중입니다 — 다음 업데이트에서 설치할 수 있습니다." >&2; exit 3; }
	[ -x "$ADDONS/$AID/install.sh" ] || { echo "$ADDONS/$AID/install.sh 가 없습니다" >&2; exit 1; }
	echo "==> $NAME 전용 API 토큰 (권한: $SCOPES)"
	# shellcheck disable=SC2086
	TOKEN="$(rk_cli addon-token create "$AID" $SCOPES)"
	chmod o+x /etc/rkmsiem                       # 추가 기능 서비스 계정이 자기 폴더까지 들어갈 수 있게 (목록은 못 봄)
	install -d -m 0755 "$STATE"
	install -d -m 0700 "$STATE/$AID"
	umask 077
	printf 'RKMSIEM_URL=http://127.0.0.1:8088\nRKMSIEM_TOKEN=%s\nRKMSIEM_ADDON=%s\n' "$TOKEN" "$AID" > "$STATE/$AID/addon.env"
	umask 022; unset TOKEN
	echo "==> $NAME 설치"
	if ! ADDON_ENV="$STATE/$AID/addon.env" ADDON_DIR="$STATE/$AID" "$ADDONS/$AID/install.sh"; then
		echo "✘ 설치 실패 — 토큰 폐기" >&2
		rk_cli addon-token revoke "$AID" >/dev/null || true
		rm -rf "${STATE:?}/$AID"
		exit 1
	fi
	printf 'VERSION=%s\nINSTALLED_AT=%s\n' "$VERSION" "$(date -Is)" > "$STATE/$AID/installed"
	echo "완료: $NAME v$VERSION" ;;
uninstall)
	[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
	load "$AID"
	[ -f "$STATE/$AID/installed" ] || { echo "$NAME 은(는) 설치되어 있지 않습니다" >&2; exit 2; }
	[ -x "$ADDONS/$AID/uninstall.sh" ] && ADDON_DIR="$STATE/$AID" "$ADDONS/$AID/uninstall.sh" || true
	[ -n "$SERVICE" ] && systemctl disable --now "$SERVICE" 2>/dev/null || true
	rk_cli addon-token revoke "$AID"
	rm -rf "${STATE:?}/$AID"
	echo "$NAME 을(를) 제거했습니다 (핵심 기능은 그대로)" ;;
configure|status)
	[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
	load "$AID"
	[ -f "$STATE/$AID/installed" ] || { echo "$NAME 은(는) 설치되어 있지 않습니다" >&2; exit 2; }
	S="$CONFIGURE"; [ "$CMD" = status ] && S="$STATUS"
	[ -n "$S" ] && [ -x "$ADDONS/$AID/$S" ] || { echo "$NAME 에는 이 기능이 없습니다" >&2; exit 2; }
	exec "$ADDONS/$AID/$S" ;;
*) sed -n '2,12p' "$0"; exit 2 ;;
esac
