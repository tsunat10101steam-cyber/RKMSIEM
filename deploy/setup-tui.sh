#!/bin/bash
# RKMSIEM 설치·점검 화면 (터미널 GUI · whiptail)
#   .deb 로 받았으면:  sudo rkmsiem-setup          압축 파일이면:  sudo ./deploy/setup-tui.sh
# 화살표·스페이스·엔터로 고른다. 실제 작업은 install.sh / smoketest.sh / update.sh / uninstall.sh 가 하고,
# 이 화면은 옵션 선택 · 진행률 · 결과 정리만 맡는다. 전체 기록: /var/log/rkmsiem/
set -uo pipefail
SELF="$(readlink -f "$0")"
SRC="$(cd "$(dirname "$SELF")/.." && pwd)"
[ "$(id -u)" -eq 0 ] || exec sudo "$SELF" "$@"
ETC=/etc/rkmsiem; ENVF=$ETC/rkmsiem.env; STAFFENV=$ETC/staff.env; LOGDIR=/var/log/rkmsiem
install -d -m 0750 "$LOGDIR"
case "$(locale charmap 2>/dev/null)" in UTF-8) ;; *) export LANG=C.UTF-8 LC_ALL=C.UTF-8 ;; esac
if ! command -v whiptail >/dev/null 2>&1; then
	echo "화면 도구(whiptail) 설치 중…"; apt-get -o DPkg::Lock::Timeout=300 install -y whiptail >/dev/null || { echo "whiptail 설치 실패" >&2; exit 1; }
fi
# 콘솔과 같은 검정·초록 배색
export NEWT_COLORS='root=white,black window=white,black border=green,black shadow=black,black title=brightgreen,black
textbox=white,black button=black,green actbutton=black,brightgreen compactbutton=white,black checkbox=white,black
actcheckbox=black,green entry=white,black label=white,black listbox=white,black actlistbox=black,green
sellistbox=white,black actsellistbox=black,brightgreen helpline=black,green roottext=green,black emptyscale=,black fullscale=,green'

dims() {
	local l=24 c=80 sz; sz="$(stty size </dev/tty 2>/dev/null)" && [ -n "$sz" ] && { l=${sz% *}; c=${sz#* }; }   # $( ) 안에서도 실제 터미널 크기
	H=$(( l - 4 < 22 ? l - 4 : 22 )); W=$(( c - 6 < 78 ? c - 6 : 78 )); LH=$(( H - 9 ))
	[ "$H" -ge 12 ] || H=12; [ "$W" -ge 50 ] || W=50; [ "$LH" -ge 3 ] || LH=3
}
msg()      { dims; whiptail --title "$1" --msgbox "$2" "$H" "$W"; }
ask()      { dims; whiptail --title "$1" --yes-button "${3:-예}" --no-button "${4:-아니오}" --yesno "$2" "$H" "$W"; }
ask_no()   { dims; whiptail --title "$1" --defaultno --yes-button "${3:-예}" --no-button "${4:-아니오}" --yesno "$2" "$H" "$W"; }
input()    { dims; local h; h=$(( $(printf '%b' "$2" | wc -l) + 9 )); [ "$h" -le "$H" ] || h=$H
             whiptail --title "$1" --inputbox "$2" "$h" "$W" "${3:-}" 3>&1 1>&2 2>&3; }
secret()   { dims; whiptail --title "$1" --passwordbox "$2" 10 "$W" 3>&1 1>&2 2>&3; }
showfile() { dims; whiptail --title "$1" --scrolltext --textbox "$2" "$H" "$W"; }
installed() { [ -f "$ETC/config/settings.yaml" ]; }
envval() { sed -n "s/^$1=//p" "$2" 2>/dev/null | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'; }
host_ips() { ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]}'; }

# 명령을 돌리며 "==> 단계" / "== N." 줄을 세어 진행률 막대로 보여 준다. 출력 전체는 로그 파일에.
run_gauge() {
	local title="$1" total="$2" log="$3"; shift 3
	: > "$log"; chmod 0640 "$log"
	dims
	{ "$@" </dev/null 2>&1; echo "__RC__=$?"; } | tee -a "$log" | awk -v total="$total" '
		{ gsub(/\033\[[0-9;]*[A-Za-z]/, ""); gsub(/\r/, "") }
		/^__RC__=/ { next }
		/^==> / || /^== [0-9]/ { n++; step = $0; sub(/^==>? +/, "", step) }
		NF { p = int(n * 100 / total); if (p > 99) p = 99
		     printf "XXX\n%d\n[%d/%d] %s\n\n%s\nXXX\n", p, n, total, step, $0; fflush() }' \
	| whiptail --title "$title" --gauge "시작하는 중…" 12 "$W" 0
	local rc; rc="$(sed -n 's/^__RC__=//p' "$log" | tail -1)"
	return "${rc:-1}"
}

show_failure() {   # $1 제목  $2 로그
	local t; t="$(mktemp)"
	{ echo "실패했습니다. 마지막 기록:"; echo; tail -n 40 "$2" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g'; echo; echo "전체 기록: $2"; } > "$t"
	showfile "$1 — 실패" "$t"; rm -f "$t"
}

valid_nets() {     # 쉼표·공백 구분 IP/대역 → 정규화해서 한 줄에 하나 (틀린 값이 있으면 실패)
	python3 - "$1" <<'PY'
import ipaddress, re, sys
items = [x for x in re.split(r"[,\s]+", sys.argv[1]) if x]
try:
    nets = [ipaddress.ip_network(x, strict=False) for x in items]
    print("\n".join(str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n) for n in nets))   # 단일 주소는 /32 없이 (ufw 표기와 같게)
except ValueError as e:
    print(e, file=sys.stderr); sys.exit(1)
PY
}

# ufw 출력은 서버 언어에 따라 번역됨("상태: 활성"·"허용") — 판단·파싱은 항상 영어 출력으로
ufw() { LANGUAGE= LC_ALL=C command ufw "$@"; }
ufw_active() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; }

tls_on() { [ -e /etc/nginx/sites-enabled/rkmsiem ] && [ -s "$ETC/tls/rkmsiem.crt" ]; }
http_exposed() { [ "$(envval RKMSIEM_API__HOST "$ENVF")" = 0.0.0.0 ] && ! tls_on; }
tls_fp() { openssl x509 -in "$ETC/tls/rkmsiem.crt" -noout -fingerprint -sha256 2>/dev/null | sed 's/.*=//'; }

# 방화벽이 꺼져 있으면 켤지 묻기 — 창을 띄우므로 $( ) 밖에서 부를 것. 결과 문구는 UFW_MSG 에
ufw_offer() {
	UFW_MSG=""
	ufw_active || ! command -v ufw >/dev/null 2>&1 && return 0
	if ask "방화벽" "방화벽(ufw)이 꺼져 있어 같은 망의 모든 기기가 콘솔 로그인 화면까지 올 수 있습니다.\n\nufw 를 켜고 고른 곳만 허용할까요?\n(SSH 22번은 자동으로 허용해 접속이 끊기지 않습니다)" "켜기" "그대로"; then
		ufw allow OpenSSH >/dev/null 2>&1 || ufw allow 22/tcp >/dev/null
		ufw --force enable >/dev/null && UFW_MSG="방화벽(ufw)을 켰습니다 (SSH 허용).\n"
	fi
}

# HTTPS(nginx, 8443·8444) 켜기 — 앱(8088·8090)은 이 서버 안(127.0.0.1)에서만. 창 없음, 결과 문구 출력
tls_enable() {
	tls_on && ! http_exposed && return 0
	local log="$LOGDIR/tls-$(date +%Y%m%d-%H%M%S).log"
	if "$SRC/deploy/tls.sh" > "$log" 2>&1; then printf 'HTTPS 를 켰습니다 (자체 서명 인증서 · 기록: %s).\n' "$log"
	else printf '✘ HTTPS 켜기 실패 — %s 확인\n' "$log"; return 1; fi
}

# 다른 PC 에서 접속 허용 (설치 화면용, 창 없음): HTTPS 켜고 고른 곳만 8443·8444·8445 허용
open_access() {
	local nets="$1" out n
	out="$(tls_enable)" || { printf '%s\n' "$out"; return; }
	if ufw_active; then
		for n in $nets; do
			ufw allow from "$n" to any port 8443 proto tcp >/dev/null
			ufw allow from "$n" to any port 8444 proto tcp >/dev/null
			ufw allow from "$n" to any port 8445 proto tcp >/dev/null
			out+="${out:+\n}허용: $n → 8443(콘솔) · 8444(담당자 관리) · 8445(연동 화면)"
		done
	fi
	printf '%b\n인증서 지문(SHA-256): %s\n브라우저가 처음 한 번 경고하면 인증서 정보의 지문이 위와 같은지 확인하고 진행하세요.\n' "$out" "$(tls_fp)"
}

# ── 외부 접속: 고를 수 있는 후보 ──
allowed_srcs() { ufw status 2>/dev/null | awk '$1 ~ /^8443(\/tcp)?$/ && $2 == "ALLOW" {print $3}' | sort -u; }
blocked_srcs() {   # 최근 이 서버의 웹 포트로 오다가 방화벽에 막힌 출발지 (많이 온 순)
	{ tail -n 3000 /var/log/ufw.log 2>/dev/null; journalctl -k -q --since -3d 2>/dev/null | tail -n 3000; } \
		| grep 'UFW BLOCK' | grep -E 'DPT=(8443|8444|8445|8088|8090) ' | sed -n 's/.* SRC=\([0-9.]*\) .*/\1/p' \
		| sort | uniq -c | sort -rn | awk '{print $2}' | head -5
}
access_candidates() {   # 한 줄에 "주소<TAB>설명<TAB>ON|OFF"
	local -A seen=()
	_cand() { [ -n "$1" ] && [ -z "${seen[$1]:-}" ] || return 0; seen[$1]=1; printf '%s\t%s\t%s\n' "$1" "$2" "$3"; }
	local s
	for s in $(allowed_srcs); do _cand "$s" "지금 허용됨 (끄면 허용 해제)" ON; done
	for s in $(blocked_srcs); do _cand "$s" "최근 접속하려다 방화벽에 막힌 주소 ← 보통 이것" OFF; done
	s="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p')"; [ -n "$s" ] || { s="${SSH_CLIENT:-}"; s="${s%% *}"; }
	_cand "$s" "지금 이 서버에 SSH 로 접속한 PC" OFF
	while read -r one net; do
		_cand "$one" "같은 망의 .1 — VMware 호스트 PC(노트북) 주소인 경우가 많음" OFF
		_cand "$net" "이 서버와 같은 망 전체 (편하지만 넓게 열림)" OFF
	done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | python3 -c '
import ipaddress, sys
for l in sys.stdin:
    n = ipaddress.ip_interface(l.strip()).network
    if n.prefixlen < 31: print(n.network_address + 1, n)')
}

admin_login_ok() {   # $1 비밀번호 → 로그인되면 0
	local u; u="$(envval RKMSIEM_ADMIN_USER "$ENVF")"
	RK_U="${u:-admin}" RK_P="$1" python3 -c 'import json,os;print(json.dumps({"username":os.environ["RK_U"],"password":os.environ["RK_P"]}))' \
		| curl -fsS -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8088/api/auth/login 2>/dev/null | grep -q '"token"'
}

urls() {
	local ip
	if tls_on; then for ip in $(host_ips); do printf '  https://%s:8443\n' "$ip"; done
	elif http_exposed; then for ip in $(host_ips); do printf '  http://%s:8088  ⚠ 암호화 없음 — 메뉴 "외부 접속"으로 HTTPS 전환\n' "$ip"; done
	else printf '  http://127.0.0.1:8088  (이 서버에서만 — 다른 PC 는 메뉴 "외부 접속")\n'; fi
}

# ───────────────────────────── 설치 ─────────────────────────────
do_install() {
	if installed; then
		ask "설치" "RKMSIEM 이 이미 설치되어 있습니다.\n\n새 버전을 적용하려면 '업데이트'를 쓰세요. (설정·데이터 보존)\n그래도 설치를 다시 실행할까요? (코드만 갱신, 설정·데이터·비밀번호는 그대로)" "다시 실행" "취소" || return
	fi
	dims
	local opts; opts="$(whiptail --title "설치 ① 옵션" --separate-output --checklist \
		"스페이스로 켜고 끄고, 엔터로 다음" "$H" "$W" "$LH" \
		lock  "계정 잠금 사용 (침해된 계정을 승인 후 잠금)" ON \
		live  "live 모드 (승인된 차단·잠금을 실제로 실행 — 처음엔 끄기 권장)" OFF \
		begin "기존 auth.log 도 처음부터 분석" OFF 3>&1 1>&2 2>&3)" || return
	local args=()
	grep -qx lock <<<"$opts" || args+=(--no-account-lock)
	grep -qx live <<<"$opts" && args+=(--live)
	grep -qx begin <<<"$opts" && args+=(--from-beginning)
	local admin; admin="$(input "설치 ② 관리자" "웹 콘솔 관리자 아이디 (첫 비밀번호는 admin — 로그인 후 바로 바꾸세요)" admin)" || return
	[ -n "$admin" ] && [ "$admin" != admin ] && args+=(--admin-user "$admin")
	local me nets=""; me="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9.]*\)).*/\1/p')"
	if ask "설치 ③ 접속" "다른 PC(노트북·윈도우 등)의 브라우저에서 웹 콘솔에 접속할까요?\n\n아니오: 이 서버 안에서만 (http://127.0.0.1:8088)" "접속 허용" "이 서버만"; then
		while :; do
			nets="$(input "설치 ③ 접속 허용" "접속할 PC 의 IP 또는 대역 (쉼표로 여러 개)\n예) 10.0.0.1, 192.168.41.0/24" "${me}")" || { nets=""; break; }
			nets="$(valid_nets "$nets" 2>/tmp/rk.err)" && [ -n "$nets" ] && break
			msg "입력 확인" "IP/대역 형식이 아닙니다: $(cat /tmp/rk.err)"
		done
	fi
	local summary="옵션: ${args[*]:-(기본값)}\n관리자: ${admin:-admin} / 첫 비밀번호 admin\n외부 접속: ${nets:-없음 (이 서버만)}"
	ask "설치 ④ 확인" "아래대로 설치합니다. 몇 분 걸립니다 (패키지 내려받기).\n\n$summary" "설치 시작" "취소" || return
	local log="$LOGDIR/install-$(date +%Y%m%d-%H%M%S).log" total
	total="$(grep -c '^[[:space:]]*step "' "$SRC/deploy/install.sh")"; grep -qx lock <<<"$opts" || total=$((total - 1))
	if ! run_gauge "설치 중" "$total" "$log" "$SRC/deploy/install.sh" "${args[@]}"; then
		show_failure "설치" "$log"; return
	fi
	local extra=""
	if [ -n "$nets" ]; then ufw_offer; extra="$UFW_MSG$(open_access "$nets")\n"; fi
	msg "설치 완료" "RKMSIEM 설치가 끝났습니다.\n\n웹 콘솔:\n$(urls)\n\n아이디 ${admin:-admin} / 비밀번호 admin\n⚠ 로그인하자마자 콘솔에서 'passwd' 로 바꾸세요 (12자 이상)\n\n${extra}${nets:+접속할 PC IP 는 콘솔 settings → 목록 → 차단 금지 에도 넣어 두세요.\n}전체 기록: $log"
	staff_admin_offer
	ask "자체 점검" "설치가 실제로 동작하는지 자체 점검(스모크 테스트)을 돌릴까요?\n\n가짜 SSH 공격 로그를 넣어 수집 → 탐지 → 사건 → 플레이북 → 차단 → 계정 잠금을 차례로 확인하고, 시험 기록은 끝나면 지웁니다. (약 1분)" "점검 시작" "나중에" && do_smoke
}

staff_admin_offer() {
	local db=/var/lib/rkmsiem/staff/staff.db n
	n="$(sudo -u rkmsiem python3 -c 'import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM admins WHERE active=1").fetchone()[0])' "$db" 2>/dev/null || echo 0)"
	[ "$n" = 0 ] || return 0
	ask "담당자 관리 앱" "담당자 관리 앱(8090)의 관리자 계정이 아직 없습니다. 지금 만들까요?\n\n(아이디 admin · 비밀번호 12자 이상, 다음 화면에서 두 번 입력)" "만들기" "나중에" || return 0
	clear; echo "== 담당자 관리 앱 관리자 admin 만들기 (비밀번호는 화면에 안 보입니다)"; echo
	/usr/local/sbin/rkmsiem-staff admin add admin && echo && echo "만들었습니다." || echo "실패 — 나중에: sudo rkmsiem-staff admin add admin"
	echo; read -rp "엔터를 누르면 돌아갑니다 " _
}

# ───────────────────────────── 자체 점검 ─────────────────────────────
do_smoke() {
	installed || { msg "자체 점검" "아직 설치되지 않았습니다. 먼저 '설치'를 하세요."; return; }
	curl -fsS http://127.0.0.1:8088/readyz >/dev/null 2>&1 || { msg "자체 점검" "서비스가 응답하지 않습니다.\n\n확인: systemctl status rkmsiem\n로그: journalctl -u rkmsiem -n 50"; return; }
	local pw=""
	if ! admin_login_ok "$(envval RKMSIEM_ADMIN_PASSWORD "$ENVF")"; then
		pw="$(secret "자체 점검 — 로그인" "관리자 비밀번호를 바꾸셨네요. 지금 비밀번호를 넣어 주세요.\n(점검이 끝나면 잊어버리고 어디에도 저장하지 않습니다)")" || return
		admin_login_ok "$pw" || { msg "자체 점검" "로그인 실패 — 비밀번호를 확인하세요.\n(여러 번 틀리면 1분 동안 막힙니다)"; return; }
	fi
	local log="$LOGDIR/smoketest-$(date +%Y%m%d-%H%M%S).log" rc res pass fail
	SMOKE_ADMIN_PASSWORD="$pw" run_gauge "자체 점검 중" 7 "$log" "$SRC/deploy/smoketest.sh"; rc=$?
	res="$(mktemp)"
	pass="$(grep -c '^  ✔' "$log")"; fail="$(grep -c '^  ✘' "$log")"
	{
		[ "$rc" = 0 ] && echo "✔ 모두 통과했습니다 (통과 $pass)" || echo "✘ 실패 $fail · 통과 $pass — ✘ 줄을 확인하세요"
		echo
		sed -n -e 's/\x1b\[[0-9;]*[A-Za-z]//g' -e '/^== /{s/^== /■ /;p}' -e '/^  [✔✘!-] /p' "$log"
		echo; echo "전체 기록: $log"
	} > "$res"
	showfile "자체 점검 결과 — 통과 $pass · 실패 $fail" "$res"; rm -f "$res"
}

# ───────────────────────────── 업데이트 ─────────────────────────────
REPO=tsunat10101steam-cyber/RKMSIEM
pkg_ver()    { dpkg-query -W -f='${Version}' rkmsiem 2>/dev/null; }
latest_ver() {   # GitHub 최신 릴리스 번호 (v31 → 31). 인터넷이 안 되면 빈 값
	curl -fsS -m 6 "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
		| python3 -c 'import sys,json;print(json.load(sys.stdin)["tag_name"].lstrip("v"))' 2>/dev/null
}
newer_available() {   # 0: GitHub 에 더 새 버전이 있음 (LATEST 에 번호)
	local cur; cur="$(pkg_ver)"; LATEST="$(latest_ver)"
	[ -n "$cur" ] && [ -n "$LATEST" ] && dpkg --compare-versions "$LATEST" gt "$cur"
}

# GitHub 최신 .deb 를 받아 패키지만 바꾼다 (서비스 적용은 그다음 update.sh)
fetch_latest() {
	local deb=/tmp/rkmsiem_latest.deb log="$1"
	{
		echo "==> 최신 버전 내려받기 (v$LATEST)"
		curl -fSL --retry 3 -o "$deb" "https://github.com/$REPO/releases/latest/download/rkmsiem_all.deb" || exit 1
		echo "==> 패키지 교체"
		DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y "$deb" || exit 1
		rm -f "$deb"
	} >> "$log" 2>&1
}

do_update() {
	installed || { msg "업데이트" "아직 설치되지 않았습니다. '설치'를 하세요."; return; }
	local ver online=0; ver="$(pkg_ver)"
	if [ -n "$ver" ]; then
		if newer_available; then
			online=1
		elif [ -n "$LATEST" ]; then
			ask "업데이트" "이미 최신 버전입니다 (v$ver).\n\n그래도 지금 버전을 서비스에 다시 적용할까요?" "다시 적용" "취소" || return
		else
			ask "업데이트" "GitHub 에 접속하지 못해 새 버전을 확인하지 못했습니다.\n\n지금 받아 둔 버전(v$ver)을 적용할까요?" "적용" "취소" || return
		fi
	fi
	if [ "$online" = 1 ]; then
		ask "업데이트" "새 버전이 있습니다:  v$ver  →  v$LATEST\n\n받아서 적용할까요?\n\n· 현재 코드·설정·DB 를 /var/backups/rkmsiem 에 먼저 백업\n· 설정·데이터·비밀번호·웹에서 바꾼 값은 그대로\n· 잠깐 서비스가 멈췄다 다시 켜집니다" "업데이트" "취소" || return
	elif [ -z "$ver" ]; then
		ask "업데이트" "이 폴더의 버전($SRC)으로 업데이트합니다.\n\n· 현재 코드·설정·DB 를 /var/backups/rkmsiem 에 먼저 백업\n· 설정·데이터·비밀번호·웹에서 바꾼 값은 그대로" "업데이트" "취소" || return
	fi
	if [ "$online" = 1 ]; then
		local dl="$LOGDIR/update-$(date +%Y%m%d-%H%M%S).log"
		: > "$dl"
		{ echo "XXX"; echo 30; echo "v$LATEST 내려받는 중…"; echo "XXX"; fetch_latest "$dl"; echo "__RC__=$?" >> "$dl"; } \
			| { dims; whiptail --title "업데이트" --gauge "v$LATEST 내려받는 중…" 9 "$W" 10; }
		grep -q '^__RC__=0$' "$dl" || { show_failure "업데이트 — 내려받기" "$dl"; return; }
		exec "$SELF" --apply-update     # 새 패키지의 화면·update.sh 로 이어서 적용
	fi
	apply_update
}

apply_update() {
	local log="$LOGDIR/update-$(date +%Y%m%d-%H%M%S).log" total
	total=$(( $(grep -c '^[[:space:]]*step "' "$SRC/deploy/install.sh") + 3 ))
	if run_gauge "업데이트 중" "$total" "$log" "$SRC/deploy/update.sh"; then
		local t; t="$(mktemp)"
		{ echo "업데이트가 끝났습니다 (지금 $(pkg_ver || echo 원본))."; echo; echo "웹 콘솔:"; urls; echo; sed -n '/되돌릴 수/,$p' "$log"; echo; echo "전체 기록: $log"; } > "$t"
		showfile "업데이트 완료" "$t"; rm -f "$t"
		if http_exposed && ask "보안 — HTTPS 전환" "웹 콘솔이 지금 http(암호화 없음)로 망에 열려 있습니다.\n로그인 비밀번호 · 세션 토큰 · 웹 터미널에 치는 장비 비밀번호가 같은 망에서 그대로 보입니다.\n\n지금 HTTPS 로 바꿀까요?\n· 접속 주소가 https://<서버>:8443 (담당자 관리 8444) 으로 바뀝니다\n· 방화벽 허용은 그대로 옮겨집니다\n· VMware NAT 포트 포워딩도 8443·8444 로 바꿔야 합니다" "HTTPS 로 전환" "나중에"; then
			local tl="$LOGDIR/tls-$(date +%Y%m%d-%H%M%S).log"
			if "$SRC/deploy/tls.sh" > "$tl" 2>&1; then showfile "HTTPS 전환 완료" "$tl"; else show_failure "HTTPS 전환" "$tl"; fi
		fi
	else
		show_failure "업데이트" "$log"
	fi
}

# ───────────────────────────── 외부 접속 ─────────────────────────────
do_access() {
	installed || { msg "외부 접속" "아직 설치되지 않았습니다."; return; }
	local out="" t
	if ! tls_on || http_exposed; then
		ask "외부 접속 — HTTPS" "다른 PC 에서 접속하려면 HTTPS 를 켭니다.\n\n· 접속 주소: https://<서버>:8443 (담당자 관리 8444)\n· 앱(8088·8090)은 이 서버 안에서만\n· 자체 서명 인증서 — 처음 접속 때 브라우저가 한 번 경고" "켜기" "취소" || return
		dims; whiptail --title "외부 접속" --infobox "HTTPS 켜는 중… (nginx 설치·인증서 생성, 1분 안쪽)" 8 "$W"
		out="$(tls_enable)" || { msg "외부 접속" "$out"; return; }
		out+="\n"
	fi
	ufw_offer; out+="$UFW_MSG"
	if ! ufw_active; then
		msg "외부 접속" "${out}방화벽(ufw)이 꺼져 있어 같은 망 어디서나 https 8443·8444 에 접속할 수 있습니다.\n\n접속 주소:\n$(urls)"
		return
	fi
	# 후보 고르기 (스페이스로 켜고 끄기) — 지금 허용된 곳은 켜진 채로 나오고, 끄면 허용이 지워짐
	local args=() a b c sel now nets n
	while IFS=$'\t' read -r a b c; do args+=("$a" "$b" "$c"); done < <(access_candidates)
	args+=("직접입력" "목록에 없는 IP·대역 직접 입력" OFF)
	dims
	sel="$(whiptail --title "외부 접속 허용 (HTTPS 8443·8444·8445)" --separate-output --ok-button "적용" --cancel-button "취소" --checklist \
		"접속할 PC 를 스페이스로 고르고 엔터. 노트북에서 접속이 안 됐다면 '막힌 주소' 를 고르세요." "$H" "$W" "$LH" "${args[@]}" 3>&1 1>&2 2>&3)" || return
	if grep -qx 직접입력 <<<"$sel"; then
		while :; do
			t="$(input "직접 입력" "허용할 IP 또는 대역 (쉼표로 여러 개)\n예) 192.168.100.1, 10.1.1.0/24")" || { t=""; break; }
			t="$(valid_nets "$t" 2>/tmp/rk.err)" && break
			msg "입력 확인" "IP/대역 형식이 아닙니다: $(cat /tmp/rk.err)"
		done
		sel="$(grep -vx 직접입력 <<<"$sel"; printf '%s\n' "$t")"
	fi
	nets="$(grep -v '^$' <<<"$sel" | while read -r n; do [ "$n" = Anywhere ] && echo Anywhere || valid_nets "$n"; done | sort -u)"
	now="$(allowed_srcs)"
	if [ -z "$nets" ] && [ -n "$now" ]; then
		ask_no "외부 접속" "아무것도 고르지 않았습니다. 지금 허용된 곳을 모두 지울까요?\n(지우면 다른 PC 에서 콘솔에 접속할 수 없습니다)" "모두 지우기" "취소" || return
	fi
	for n in $now; do grep -qxF "$n" <<<"$nets" && continue
		if [ "$n" = Anywhere ]; then ufw delete allow 8443/tcp >/dev/null; ufw delete allow 8444/tcp >/dev/null; ufw delete allow 8445/tcp >/dev/null
		else for pt in 8443 8444 8445; do ufw delete allow from "$n" to any port $pt proto tcp >/dev/null; done; fi
		out+="허용 해제: $n\n"
	done
	for n in $nets; do grep -qxF "$n" <<<"$now" && continue
		for pt in 8443 8444 8445; do ufw allow from "$n" to any port $pt proto tcp >/dev/null; done
		out+="허용 추가: $n → 8443(콘솔) · 8444(담당자 관리) · 8445(연동 화면)\n"
	done
	t="$(mktemp)"
	{ printf '%b' "${out:-바뀐 것이 없습니다.\n}"; echo
	  echo "지금 허용된 곳:"; allowed_srcs | sed 's/^/  /'; [ -n "$(allowed_srcs)" ] || echo "  (없음)"
	  echo; echo "접속 주소:"; urls
	  echo; echo "인증서 지문(SHA-256): $(tls_fp)"
	  echo "  브라우저가 처음 한 번 경고하면 인증서 정보의 지문이 위와 같은지 확인하고 진행"
	  echo; echo "접속할 PC IP 는 콘솔 settings → 목록 → 차단 금지 에도 넣어 두세요."
	  echo "방화벽이 PC 별로 동작하는지는 콘솔 'dashboard doctor' 의 access_path 로 확인"; } > "$t"
	showfile "외부 접속 — 결과" "$t"; rm -f "$t"
}

# ───────────────────────────── 상태 ─────────────────────────────
do_status() {
	local t s; t="$(mktemp)"
	{
		if ! installed; then echo "설치되지 않았습니다."; else
			echo "■ 서비스"
			for s in rkmsiem rkmsiem-staff; do printf '  %-15s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"; done
			curl -fsS http://127.0.0.1:8088/readyz >/dev/null 2>&1 && echo "  준비 상태       정상 (readyz)" || echo "  준비 상태       응답 없음 — journalctl -u rkmsiem -n 50"
			echo; echo "■ 접속 주소"; urls
			echo; echo "■ HTTPS"
			if tls_on; then echo "  켜짐 (nginx · 8443 콘솔 · 8444 담당자 관리 · 8445 연동 화면)"; echo "  인증서 지문 $(tls_fp)"
			elif http_exposed; then echo "  ⚠ 꺼짐 — 콘솔이 http 로 망에 열려 있음 (비밀번호가 평문). 메뉴 4 로 HTTPS 전환"
			else echo "  꺼짐 (콘솔은 이 서버 안에서만)"; fi
			echo; echo "■ 듣는 포트"; ss -ltn 2>/dev/null | awk 'NR > 1 && $4 ~ /:(8088|8090|8443|8444|8445)$/ {print "  " $4}'
			echo; echo "■ 방화벽 (8443·8444·8445 · 예전 8088·8090)"
			if ufw_active; then ufw status | awk '$1 ~ /^(8088|8090|8443|8444|8445)(\/tcp)?$/ {print "  " $0}'; else echo "  ufw 꺼짐 (모든 곳에서 접속 가능)"; fi
			echo; echo "■ 차단 테이블"; nft list set inet rkmsiem blocklist4 2>/dev/null | sed -n 's/^\s*elements = /  차단 중: /p' | head -3
			nft list table inet rkmsiem >/dev/null 2>&1 && echo "  table inet rkmsiem 있음" || echo "  table inet rkmsiem 없음"
			echo; echo "■ 버전"; echo "  $(dpkg-query -W -f='패키지 ${Version}' rkmsiem 2>/dev/null || echo "원본 $SRC")"
			echo; echo "■ 최근 기록"; ls -1t "$LOGDIR" 2>/dev/null | head -5 | sed "s#^#  $LOGDIR/#"
		fi
	} > "$t"
	showfile "상태" "$t"; rm -f "$t"
}

# ───────────────────────────── 제거 ─────────────────────────────
do_remove() {
	installed || [ -f /etc/systemd/system/rkmsiem.service ] || { msg "제거" "설치되어 있지 않습니다."; return; }
	ask_no "제거" "RKMSIEM 서비스를 멈추고 프로그램을 제거할까요?\n\n(차단 목록이 풀립니다)" "제거" "취소" || return
	local arg="" log="$LOGDIR/uninstall-$(date +%Y%m%d-%H%M%S).log"
	ask_no "제거 — 데이터" "설정·데이터·감사 로그까지 모두 지울까요?\n\n예: 완전히 삭제 (되돌릴 수 없음)\n아니오: 설정(/etc/rkmsiem)·데이터(/var/lib/rkmsiem)는 남김 — 다시 설치하면 이어서 씀" "모두 삭제" "남기기" && arg=--purge
	"$SRC/deploy/uninstall.sh" $arg > "$log" 2>&1
	msg "제거" "$(tail -n 5 "$log")\n\n$(dpkg-query -W rkmsiem >/dev/null 2>&1 && echo "패키지 파일도 지우려면: sudo apt remove rkmsiem")"
}

# ───────────────────────────── 추가 기능 ─────────────────────────────
do_addons() {
	installed || { msg "추가 기능" "먼저 RKMSIEM 을 설치하세요."; return; }
	while :; do
		local args=() id st name desc sel log
		while IFS=$'\t' read -r id st name desc; do args+=("$id" "$name — $st"); done < <("$SRC/deploy/addon.sh" list)
		[ ${#args[@]} -gt 0 ] || { msg "추가 기능" "설치할 수 있는 추가 기능이 없습니다."; return; }
		dims
		sel="$(whiptail --title "추가 기능" --ok-button "선택" --cancel-button "뒤로" --menu \
			"핵심(RKMSIEM)은 사람이 운영하고, 자동화는 추가 기능으로 붙였다 뗐다 합니다.\n추가 기능은 전용 API 토큰(정해진 권한만)으로만 핵심과 이야기합니다." \
			"$H" "$W" "$LH" "${args[@]}" 3>&1 1>&2 2>&3)" || return
		IFS=$'\t' read -r id st name desc < <("$SRC/deploy/addon.sh" list | awk -F'\t' -v k="$sel" '$1 == k')
		log="$LOGDIR/addon-$id-$(date +%Y%m%d-%H%M%S).log"
		case "$st" in
			"준비 중") msg "$name" "$desc\n\n아직 준비 중입니다 — 다음 업데이트에서 설치할 수 있게 됩니다." ;;
			"설치됨")
				ask_no "$name" "$desc\n\n설치되어 있습니다. 제거할까요?\n(전용 토큰이 폐기되고, 핵심은 수동 운영으로 그대로)" "제거" "취소" || continue
				if "$SRC/deploy/addon.sh" uninstall "$id" > "$log" 2>&1; then showfile "$name 제거" "$log"; else show_failure "$name 제거" "$log"; fi ;;
			*)
				ask "$name" "$desc\n\n설치할까요?" "설치" "취소" || continue
				if "$SRC/deploy/addon.sh" install "$id" > "$log" 2>&1; then showfile "$name 설치" "$log"; else show_failure "$name 설치" "$log"; fi ;;
		esac
	done
}

# ───────────────────────────── 메인 ─────────────────────────────
[ "${RKMSIEM_TUI_LIB:-}" = 1 ] && return 0 2>/dev/null     # 시험용: 함수만 불러오기
case "${1:-}" in
	--install) do_install; exit ;;
	--smoke) do_smoke; exit ;;
	--apply-update) apply_update ;;          # 새 버전을 받은 뒤 이어서 (그다음 메뉴로)
esac
UPD=""; newer_available && UPD="   ★ 새 버전 v$LATEST — '업데이트'"
while :; do
	dims
	state="설치 안 됨"; installed && state="설치됨 · 서비스 $(systemctl is-active rkmsiem 2>/dev/null)"
	v="$(pkg_ver)"; [ -n "$v" ] && state="v$v · $state"
	choice="$(whiptail --title "RKMSIEM 설치·점검" --ok-button "선택" --cancel-button "끝내기" --menu \
		"상태: $state${UPD:+\n$UPD}\n\n화살표로 고르고 엔터" "$H" "$W" "$LH" \
		1 "설치" \
		2 "자체 점검 (스모크 테스트)" \
		3 "업데이트 (받은 새 버전 적용)" \
		4 "외부 접속 허용 (HTTPS · 다른 PC 에서 웹 콘솔)" \
		5 "상태 보기" \
		6 "추가 기능 (HSOAR 등)" \
		7 "제거" 3>&1 1>&2 2>&3)" || break
	case "$choice" in
		1) do_install ;; 2) do_smoke ;; 3) do_update ;; 4) do_access ;; 5) do_status ;; 6) do_addons ;; 7) do_remove ;;
	esac
done
clear
