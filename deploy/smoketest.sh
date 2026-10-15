#!/bin/bash
# RKMSIEM 실동작 검증 (설치한 Ubuntu 서버에서):  sudo ./deploy/smoketest.sh
#
# 실제 경로로 확인한다 — 가짜/모의 없음:
#   1) 실제 sshd 형식 로그를 logger 로 auth.log 에 기록 → 파일 수집기가 읽음 → 탐지 → 사건 → 플레이북
#   2) (live 모드) 승인 → nftables 세트에 실제로 들어갔는지 nft 로 확인 → 해제 → 빠졌는지 확인
#   3) 계정 잠금 헬퍼: 임시 계정을 만들어 실제로 잠그고(passwd -S, chage) 해제한 뒤 삭제
# 테스트 IP 는 문서용 대역 198.51.100.0/24 (인터넷에 존재하지 않음 → 차단해도 영향 없음).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요" >&2; exit 1; }
ETC=/etc/rkmsiem; BASE=http://127.0.0.1:8088
# env 파일을 셸로 실행(source)하지 않고 글자 그대로 읽는다 — 비밀번호의 $ ! " 등이 해석되지 않게
envval() { sed -n "s/^$1=//p" "$ETC/rkmsiem.env" | tail -1 | sed -e "s/^'\(.*\)'\$/\1/" -e 's/^"\(.*\)"$/\1/'; }
RKMSIEM_ADMIN_USER="$(envval RKMSIEM_ADMIN_USER)"; RKMSIEM_ADMIN_USER="${RKMSIEM_ADMIN_USER:-admin}"
RKMSIEM_ADMIN_PASSWORD="$(envval RKMSIEM_ADMIN_PASSWORD)"
PASS=0; FAIL=0
ok()  { echo "  ✔ $*"; PASS=$((PASS+1)); }
bad() { echo "  ✘ $*"; FAIL=$((FAIL+1)); }
j()   { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' "$@"; }

TEST_IP="198.51.100.$((RANDOM % 200 + 20))"
TEST_USER="rkmsmoke$((RANDOM % 9000 + 1000))"
echo "== 0. 로그인 · 자가 점검"
# 특수문자(! " \ $ 등)가 있어도 깨지지 않게 JSON 은 파이썬으로 만든다
login() {
	RK_U="$RKMSIEM_ADMIN_USER" RK_P="$1" python3 -c 'import json,os;print(json.dumps({"username":os.environ["RK_U"],"password":os.environ["RK_P"]}))' \
		| curl -fsS -H 'Content-Type: application/json' --data-binary @- $BASE/api/auth/login 2>/dev/null | j 'd["token"]' 2>/dev/null
}
TOKEN="$(login "$RKMSIEM_ADMIN_PASSWORD" || true)"
if [ -z "$TOKEN" ]; then                       # 설치 후 비밀번호를 바꾼 경우 → 직접 입력 (명령 기록에 남지 않음)
	read -rsp "  $RKMSIEM_ADMIN_USER 비밀번호를 입력하세요 (화면에 안 보임): " PW; echo
	TOKEN="$(login "$PW" || true)"
	[ -n "$TOKEN" ] || { echo "로그인 실패 — 비밀번호 확인 또는 1분 뒤 재시도(로그인 시도 제한)"; exit 1; }
fi
MODE="$(api $BASE/api/me | j 'd["mode"]')"
api $BASE/api/system/doctor | j '"\n".join(("  " + {"ok":"✔","warn":"!","fail":"✘"}[c["status"]] + " " + c["check"] + " — " + c["detail"]) for c in d["checks"])'
echo "  모드: $MODE · 테스트 IP: $TEST_IP · 테스트 계정: $TEST_USER"

echo "== 1. 실제 로그 경로: logger → rsyslog → /var/log/auth.log → 수집 → 탐지"
useradd -m -s /bin/bash "$TEST_USER"
cleanup() {
	userdel -r "$TEST_USER" >/dev/null 2>&1 || true
	nft delete element inet rkmsiem blocklist4 "{ $TEST_IP }" >/dev/null 2>&1 || true
}
trap cleanup EXIT
for i in $(seq 1 11); do
	logger -p auth.info -t sshd -i "Failed password for $TEST_USER from $TEST_IP port $((40000+i)) ssh2"
done
logger -p auth.info -t sshd -i "Accepted password for $TEST_USER from $TEST_IP port 40099 ssh2"
for i in $(seq 1 30); do
	N="$(api "$BASE/api/events?ip=$TEST_IP" | j 'd["total"]')"
	[ "$N" -ge 12 ] && break; sleep 1
done
[ "${N:-0}" -ge 12 ] && ok "이벤트 수집·정규화: $N 건 (source=ubuntu-authlog)" || bad "이벤트 수집 실패 ($N 건) — journalctl -u rkmsiem"
ALERTS="$(api "$BASE/api/alerts?ip=$TEST_IP" | j '" ".join(sorted(a["level_id"] for a in d["items"]))')"
[[ "$ALERTS" == *BRUTEFORCE_HIGH* && "$ALERTS" == *COMPROMISE* ]] && ok "탐지: $ALERTS" || bad "탐지 결과 이상: '$ALERTS'"
INC="$(api "$BASE/api/alerts?ip=$TEST_IP" | j 'd["items"][0]["incident_id"]')"
[ -n "$INC" ] && [ "$INC" != None ] && ok "사건 생성: #$INC" || bad "사건 없음"

echo "== 2. 플레이북 · 승인 · 실제 차단"
RUN=""
for i in $(seq 1 20); do
	RUN="$(api "$BASE/api/runs?incident_id=$INC&playbook_id=compromise_response" | j 'next((r["id"] for r in d["items"] if r["state"]=="waiting_approval"), "")')"
	[ -n "$RUN" ] && break; sleep 1
done
[ -n "$RUN" ] && ok "침해 대응 플레이북 #$RUN 승인 대기" || bad "플레이북이 승인 대기에 오지 않음"
if [ -n "$RUN" ]; then
	api -X POST -d '{"approve":true,"reason":"smoketest"}' "$BASE/api/runs/$RUN/steps/block_ip/decision" >/dev/null && ok "block_ip 승인"
	sleep 2
	OUT="$(api "$BASE/api/runs/$RUN" | j 'json.dumps(next(s for s in d["steps"] if s["step_id"]=="block_ip").get("output"))' 2>/dev/null || true)"
	if [ "$MODE" = live ]; then
		if nft list set inet rkmsiem blocklist4 | grep -q "$TEST_IP"; then ok "nftables 에 실제 차단됨: $TEST_IP"; else bad "nft 세트에 없음 — 출력: $OUT"; fi
	else
		[[ "$OUT" == *simulated* ]] && ok "simulate 모드: 실제 차단 없이 기록만 ($OUT)" || bad "simulate 결과 이상: $OUT"
	fi
	api -X POST -d '{"approve":false,"reason":"smoketest — 테스트 계정은 아래에서 헬퍼로 직접 검증"}' "$BASE/api/runs/$RUN/steps/disable_account/decision" >/dev/null || true
	if [ "$MODE" = live ]; then
		api -X DELETE "$BASE/api/blocklist/$TEST_IP?reason=smoketest" >/dev/null
		sleep 1
		if nft list set inet rkmsiem blocklist4 | grep -q "$TEST_IP"; then bad "해제 후에도 nft 에 남아 있음"; else ok "차단 해제 확인 (nft 세트에서 빠짐)"; fi
	fi
fi

echo "== 3. 계정 잠금 헬퍼 (실제 usermod)"
if [ -x /usr/local/lib/rkmsiem/rkmsiem-account ]; then
	sudo -u rkmsiem sudo -n /usr/local/lib/rkmsiem/rkmsiem-account lock "$TEST_USER" >/dev/null && ok "헬퍼 lock 실행 (서비스 계정 권한 → sudoers)"
	LC_ALL=C passwd -S "$TEST_USER" | awk '{print $2}' | grep -q '^L' && ok "비밀번호 잠김 (passwd -S = L)" || bad "비밀번호 잠금 안 됨"
	# 언어 설정과 무관하게 /etc/shadow 8번째 칸(만료일)을 직접 본다 — 비어 있으면 만료 없음
	expday() { getent shadow "$TEST_USER" | cut -d: -f8; }
	[ -n "$(expday)" ] && ok "계정 만료 설정 (키 인증 SSH 도 거부)" || bad "만료 설정 안 됨"
	sudo -u rkmsiem sudo -n /usr/local/lib/rkmsiem/rkmsiem-account lock root >/dev/null 2>&1 && bad "root 잠금이 허용됨!" || ok "root 잠금 거부 확인"
	sudo -u rkmsiem sudo -n /usr/local/lib/rkmsiem/rkmsiem-account unlock "$TEST_USER" >/dev/null && ok "헬퍼 unlock 실행"
	[ -z "$(expday)" ] && ok "만료 해제 확인" || bad "만료 해제 안 됨 (만료일 칸: $(expday))"
	sudo -u rkmsiem sudo -n /usr/sbin/usermod -L "$TEST_USER" >/dev/null 2>&1 && bad "서비스 계정이 usermod 를 직접 실행할 수 있음!" || ok "헬퍼 외 명령은 sudo 거부 (최소 권한)"
else
	echo "  - 계정 잠금 헬퍼 미설치 (--no-account-lock) — 건너뜀"
fi

echo "== 4. 담당자 관리 앱 연동"
STAFF_PORT="$(sed -n 's/^STAFF_PORT=//p' "$ETC/staff.env" 2>/dev/null | tail -1)"
if curl -fsS "http://127.0.0.1:${STAFF_PORT:-8090}/healthz" >/dev/null 2>&1; then ok "담당자 관리 앱 응답 (포트 ${STAFF_PORT:-8090})"; else bad "담당자 관리 앱 응답 없음 — systemctl status rkmsiem-staff"; fi
SYNC="$(api -X POST "$BASE/api/staff/sync" 2>/dev/null | j '"활성 담당자 %s명" % d["count"]' 2>/dev/null || true)"
[ -n "$SYNC" ] && ok "RKMSIEM 이 명단을 가져옴 ($SYNC)" || bad "명단 가져오기 실패 — 콘솔 'dashboard team' 의 연동 상태 확인"

echo "== 5. 감사 로그"
[ "$(api $BASE/api/audit/verify | j 'd["ok"]')" = True ] && ok "감사 로그 해시 체인 무결" || bad "감사 로그 체인 깨짐"

echo "== 6. 테스트 기록 정리 (위협 수준이 '심각'으로 남지 않게)"
if [ "${KEEP_TEST_DATA:-0}" = 1 ]; then
	echo "  - KEEP_TEST_DATA=1 — 테스트 기록을 남겨 둠 (나중에: 콘솔 settings → 데이터 초기화)"
else
	R="$(api -X POST -d '{"scope":"test","reason":"smoketest 자동 정리"}' "$BASE/api/system/reset" \
		| j '" · ".join(f"{k} {v}" for k, v in d["counts"].items())' 2>/dev/null || true)"
	[ -n "$R" ] && ok "테스트 이벤트·경보·사건 삭제 ($R)" || bad "테스트 기록 정리 실패 — 콘솔 settings → 데이터 초기화에서 직접"
fi

echo
echo "결과: 통과 $PASS · 실패 $FAIL   (테스트 계정·차단·기록은 자동 정리됨 — 남기려면 KEEP_TEST_DATA=1 sudo -E ./smoketest.sh)"
[ "$FAIL" -eq 0 ]
