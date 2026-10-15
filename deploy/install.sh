#!/bin/bash
# RKMSIEM 설치 (Ubuntu 22.04 / 24.04) — 프로젝트 루트에서 실행:  sudo ./deploy/install.sh [옵션]
#
#   --live               설치 직후부터 live 모드 (승인된 차단·잠금이 실제로 실행됨). 기본은 simulate
#   --no-account-lock    계정 잠금 헬퍼/sudoers 를 설치하지 않고 서비스를 더 강하게 격리
#   --from-beginning     기존 auth.log 전체를 처음부터 분석 (기본: 설치 이후 로그만)
#   --admin-user NAME    초기 관리자 이름 (기본 admin)
#
# 하는 일: 패키지 설치 → 서비스 계정 → /opt/rkmsiem(venv) → /etc/rkmsiem(설정·비밀) → /var/lib/rkmsiem(데이터)
#          → nftables 차단 테이블 → 계정 잠금 헬퍼(+sudoers) → systemd 서비스 → 담당자 관리 앱(8090) → 자가 점검
# 다시 실행해도 안전(설정·데이터·비밀번호는 덮어쓰지 않음, 코드만 갱신).
set -euo pipefail

LIVE=0; ACCOUNT_LOCK=1; FROM_BEGINNING=0; ADMIN_USER=admin
while [ $# -gt 0 ]; do
	case "$1" in
		--live) LIVE=1 ;;
		--no-account-lock) ACCOUNT_LOCK=0 ;;
		--from-beginning) FROM_BEGINNING=1 ;;
		--admin-user) ADMIN_USER="$2"; shift ;;
		*) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || { echo "root 로 실행하세요: sudo $0" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$SRC/rkmsiem/__main__.py" ] || { echo "프로젝트 루트를 찾을 수 없습니다 ($SRC)" >&2; exit 1; }
. /etc/os-release
case "${VERSION_ID:-}" in 22.04|24.04|24.10|25.04) ;; *) echo "⚠ 검증 대상은 Ubuntu 22.04/24.04 입니다 (현재 ${PRETTY_NAME:-unknown}). 계속합니다." ;; esac

APP=/opt/rkmsiem; ETC=/etc/rkmsiem; DATA=/var/lib/rkmsiem; LIB=/usr/local/lib/rkmsiem
step() { printf '\n\033[1;32m==> %s\033[0m\n' "$*"; }

step "네트워크 · DNS 확인"
grep -qw "$(hostname)" /etc/hosts || { echo "127.0.1.1 $(hostname)" >> /etc/hosts; echo "  /etc/hosts 에 호스트 이름 $(hostname) 추가 (sudo 경고 해결)"; }
if ! getent hosts archive.ubuntu.com >/dev/null 2>&1; then
	cat >&2 <<'EOF'
✘ DNS 이름 해석이 안 됩니다 (패키지를 받을 수 없음). 아래를 실행한 뒤 다시 설치하세요:
    sudo sed -i 's/^#\?DNS=.*/DNS=8.8.8.8 1.1.1.1/' /etc/systemd/resolved.conf
    sudo ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf && sudo systemctl restart systemd-resolved
    getent hosts archive.ubuntu.com      # IP 가 나오면 해결
EOF
	exit 1
fi
echo "  DNS 정상"

step "시계 확인"
# 시계가 늦으면 apt 가 "Release file ... is not valid yet" 으로 실패하고, 로그 시각·탐지 창도 어긋난다
# → 패키지 서버의 HTTP Date 헤더와 비교해 1분 넘게 차이 나면 맞추고 NTP 를 켠다
SKEW="$(python3 - <<'PY' 2>/dev/null || true
import time, urllib.request, email.utils
r = urllib.request.urlopen(urllib.request.Request("http://archive.ubuntu.com/", method="HEAD"), timeout=8)
print(int(email.utils.parsedate_to_datetime(r.headers["Date"]).timestamp() - time.time()))
PY
)"
if [ -z "$SKEW" ]; then
	echo "  ! 서버 시각을 가져오지 못해 건너뜀"
elif [ "${SKEW#-}" -gt 60 ]; then
	echo "  시계가 ${SKEW}초 어긋나 있습니다 → 맞춤"
	date -s "@$(( $(date +%s) + SKEW ))" >/dev/null
	timedatectl set-ntp true 2>/dev/null || true
	hwclock --systohc 2>/dev/null || true
	echo "  현재 시각: $(date '+%F %T %Z')"
else
	echo "  시계 정상 (차이 ${SKEW}초)"
fi

step "패키지 설치"
export DEBIAN_FRONTEND=noninteractive
# 부팅 직후엔 자동 업데이트(unattended-upgrades)가 apt 잠금을 잡고 있는 경우가 많다 → 알리고 최대 15분 기다림
if pgrep -f 'unattended-upgr|apt.systemd.daily|apt-get|dpkg' >/dev/null 2>&1; then
	echo "  다른 apt/자동 업데이트가 실행 중입니다 — 끝날 때까지 기다립니다 (최대 15분, 진행 상황은 아래에 표시)"
	pgrep -af 'unattended-upgr|apt.systemd.daily|apt-get|dpkg' | head -5 | sed 's/^/    /'
fi
APT_OPTS=(-o DPkg::Lock::Timeout=900 -o Acquire::Retries=3)
apt-get "${APT_OPTS[@]}" update
apt-get "${APT_OPTS[@]}" install -y python3 python3-venv python3-pip nftables sudo curl rsyslog fonts-nanum openssh-client
systemctl enable --now rsyslog >/dev/null 2>&1 || true
PYV="$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' || { echo "Python 3.10 이상 필요 (현재 $PYV)" >&2; exit 1; }

step "서비스 계정 rkmsiem"
id rkmsiem >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --no-create-home --shell /usr/sbin/nologin rkmsiem
usermod -aG adm,systemd-journal rkmsiem

step "코드 → $APP"
install -d -m 0755 "$APP"
rm -rf "$APP/rkmsiem" "$APP/web" "$APP/staffdir"
cp -r "$SRC/rkmsiem" "$SRC/web" "$SRC/staffdir" "$APP/"
cp "$SRC/requirements.txt" "$SRC/deploy/requirements-ubuntu.txt" "$SRC/README.md" "$APP/"
find "$APP/rkmsiem" "$APP/staffdir" -name '__pycache__' -prune -exec rm -rf {} +
[ -d "$APP/venv" ] || python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/requirements.txt" -r "$APP/requirements-ubuntu.txt"
chown -R root:root "$APP"

step "설정 → $ETC (기존 설정은 보존)"
install -d -m 0750 -o root -g rkmsiem "$ETC" "$ETC/config"
if [ ! -f "$ETC/config/settings.yaml" ]; then
	cp -r "$SRC/config/." "$ETC/config/"
	cp "$SRC/deploy/config/"*.yaml "$ETC/config/"              # 운영용 덮어쓰기 (실제 로그·실제 인텔·샘플 없음)
	[ "$FROM_BEGINNING" = 1 ] && sed -i 's/from_beginning: false /from_beginning: true  /' "$ETC/config/sources.yaml"
	[ "$LIVE" = 1 ] && sed -i 's/^  mode: simulate /  mode: live     /' "$ETC/config/settings.yaml"
	[ "$ACCOUNT_LOCK" = 0 ] && sed -i '/^  accounts:/,/^  assets:/ s/backend: helper /backend: none   /' "$ETC/config/settings.yaml"
	SYS_TZ="$(cat /etc/timezone 2>/dev/null || timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
	sed -i "s#^timezone: .*#timezone: $SYS_TZ#" "$ETC/config/settings.yaml"
	sed -i "s#timezone: Asia/Seoul#timezone: $SYS_TZ#g" "$ETC/config/sources.yaml"
	# 자기 차단 방지(현재 SSH 접속 IP) · 관리자 권한 사용 승인 목록(sudo 그룹)
	ADMIN_IP="${SSH_CLIENT:-}"; ADMIN_IP="${ADMIN_IP%% *}"   # 콘솔 접속·sudo 로 비어 있을 수 있음 → who -m 으로 보완
	[ -n "$ADMIN_IP" ] || ADMIN_IP="$(who -m 2>/dev/null | sed -n 's/.*(\([0-9a-fA-F:.]*\)).*/\1/p')"
	SUDO_MEMBERS="$(getent group sudo | cut -d: -f4)"
	RK_ADMIN_IP="$ADMIN_IP" RK_SUDO="$SUDO_MEMBERS" RK_SUDO_USER="${SUDO_USER:-}" "$APP/venv/bin/python" - "$ETC/config/lists.yaml" <<'PY'
import os, sys, ipaddress
sys.path.insert(0, "/opt/rkmsiem")
from rkmsiem import yamlio
p = sys.argv[1]
d = yamlio.load_file(p)
ip = os.environ.get("RK_ADMIN_IP", "").strip()
if ip:
    try:
        net = str(ipaddress.ip_network(ip + ("/32" if ":" not in ip else "/128"), strict=False))
        d["never_block"]["values"] = sorted(set(d["never_block"]["values"]) | {net})
        print(f"  never_block += {net} (현재 SSH 접속)")
    except ValueError:
        pass
users = [u for u in os.environ.get("RK_SUDO", "").split(",") if u]
d["privileged_users"]["values"] = sorted(set(d["privileged_users"]["values"]) | set(users) | {"root"})
print(f"  privileged_users = {d['privileged_users']['values']}")
su = os.environ.get("RK_SUDO_USER", "")
if su:
    d["protected_accounts"]["values"] = sorted(set(d["protected_accounts"]["values"]) | {su})
    print(f"  protected_accounts += {su} (설치한 관리자 계정은 자동 잠금 금지)")
open(p, "w", encoding="utf-8").write(yamlio.dumps(d))
PY
fi
chown -R root:rkmsiem "$ETC/config"; find "$ETC/config" -type d -exec chmod 0750 {} +; find "$ETC/config" -type f -exec chmod 0640 {} +

if [ ! -f "$ETC/rkmsiem.env" ]; then
	ADMIN_PW=admin                                                   # 첫 로그인 admin / admin — 로그인 후 'passwd' 로 바꾸세요
	INGEST_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
	umask 077
	cat > "$ETC/rkmsiem.env" <<EOF
# RKMSIEM 비밀 정보 (root 0600) — systemd 가 읽어 서비스에 전달
RKMSIEM_ADMIN_USER=$ADMIN_USER
RKMSIEM_ADMIN_PASSWORD=$ADMIN_PW
RKMSIEM_INGEST_KEYS=$INGEST_KEY
RKMSIEM_LOG_LEVEL=INFO
# nginx 뒤에서 운영하면 1 (X-Forwarded-For 신뢰)
RKMSIEM_API__TRUSTED_PROXIES=0
EOF
	umask 022
	FIRST_INSTALL=1
else
	FIRST_INSTALL=0
fi
# 웹에서 입력하는 비밀번호·API 키 암호화 키 (없을 때만 추가 — 바꾸면 저장된 값을 다시 입력해야 함)
if ! grep -q '^RKMSIEM_SECRET_KEY=' "$ETC/rkmsiem.env"; then
	printf '# 웹 설정 화면의 비밀 값 암호화 키 (지우거나 바꾸면 웹에서 넣은 비밀번호·API 키를 다시 입력)\nRKMSIEM_SECRET_KEY=%s\n' \
		"$(python3 -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')" >> "$ETC/rkmsiem.env"
fi
# 담당자 관리 앱 연동 키 · 주소 (없을 때만 추가 — 키는 화면·로그에 나오지 않고 두 서비스의 비밀 파일에만 들어감)
if ! grep -q '^RKMSIEM_STAFF_SYNC_KEY=' "$ETC/rkmsiem.env"; then
	printf '# 담당자 관리 앱 연동 키 (staff.env 의 STAFF_SYNC_KEYS 와 같은 값)\nRKMSIEM_STAFF_SYNC_KEY=%s\n' \
		"$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ETC/rkmsiem.env"
fi
# root 전용 점검 키 (설치 자가 점검·smoketest 용 — 이 서버 안에서만 통함, 첫 비밀번호 변경·2단계 인증과 무관)
if ! grep -q '^RKMSIEM_LOCAL_TOKEN=' "$ETC/rkmsiem.env"; then
	printf '# root 전용 점검 키 (이 서버 안 127.0.0.1 요청만 · 감사 로그에 root@local 로 남음)\nRKMSIEM_LOCAL_TOKEN=%s\n' \
		"$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')" >> "$ETC/rkmsiem.env"
fi
grep -q '^RKMSIEM_STAFF__URL=' "$ETC/rkmsiem.env" || echo 'RKMSIEM_STAFF__URL=http://127.0.0.1:8090' >> "$ETC/rkmsiem.env"
chown root:root "$ETC/rkmsiem.env"; chmod 0600 "$ETC/rkmsiem.env"
STAFF_KEY="$(sed -n 's/^RKMSIEM_STAFF_SYNC_KEY=//p' "$ETC/rkmsiem.env" | tail -1)"
if [ ! -f "$ETC/staff.env" ]; then
	# 콘솔(8088)을 외부에 열어 둔 서버라면 담당자 관리 앱도 같은 방식으로 (방화벽 허용은 아래 안내대로 직접)
	STAFF_HOST="$(sed -n 's/^RKMSIEM_API__HOST=//p' "$ETC/rkmsiem.env" | tail -1)"
	# 환경 변수가 아니라 settings.yaml 의 api.host 로 열어 둔 경우도 따라감
	[ -n "$STAFF_HOST" ] || STAFF_HOST="$(sed -n '/^api:/,/^[a-z]/ s/^  host: *\([0-9.:a-fA-F]*\).*/\1/p' "$ETC/config/settings.yaml" | head -1)"
	API_PORT="$(sed -n 's/^RKMSIEM_API__PORT=//p' "$ETC/rkmsiem.env" | tail -1)"
	umask 077
	cat > "$ETC/staff.env" <<EOF
# RKMSIEM 담당자 관리 앱 (root 0600) — systemd 가 읽어 rkmsiem-staff 서비스에 전달
STAFF_SYNC_KEYS=$STAFF_KEY
STAFF_HOST=${STAFF_HOST:-127.0.0.1}
STAFF_PORT=8090
# 명단이 바뀌면 RKMSIEM 에 바로 알림 (RKMSIEM 이 연동 API 로 다시 가져감)
STAFF_NOTIFY_URL=http://127.0.0.1:${API_PORT:-8088}/api/staff/hook
EOF
	umask 022
	echo "  $ETC/staff.env 생성 (담당자 관리 앱 · 연동 키 공유)"
elif ! grep -q "^STAFF_SYNC_KEYS=.*$STAFF_KEY" "$ETC/staff.env"; then
	echo "  ⚠ $ETC/staff.env 의 STAFF_SYNC_KEYS 가 rkmsiem.env 의 RKMSIEM_STAFF_SYNC_KEY 와 다릅니다 — 명단을 가져오지 못합니다"
fi
chown root:root "$ETC/staff.env"; chmod 0600 "$ETC/staff.env"

step "데이터 → $DATA"
install -d -m 0750 -o rkmsiem -g rkmsiem "$DATA" "$DATA/archive" "$DATA/feeds" "$DATA/staff"

step "nftables 차단 테이블"
install -m 0644 "$SRC/deploy/rkmsiem.nft" "$ETC/rkmsiem.nft"
nft -c -f "$ETC/rkmsiem.nft"                                   # 문법 검사
nft -f "$ETC/rkmsiem.nft"
nft list table inet rkmsiem >/dev/null && echo "  table inet rkmsiem 준비됨"

if [ "$ACCOUNT_LOCK" = 1 ]; then
	step "계정 잠금 헬퍼 + sudoers"
	install -d -m 0755 "$LIB"
	install -m 0755 -o root -g root "$SRC/deploy/rkmsiem-account" "$LIB/rkmsiem-account"
	PROTECTED="$("$APP/venv/bin/python" -c "import sys;sys.path.insert(0,'/opt/rkmsiem');from rkmsiem import yamlio;print(' '.join(yamlio.load_file('$ETC/config/lists.yaml')['protected_accounts']['values']))")"
	printf 'MIN_UID=1000\nPROTECTED_ACCOUNTS="%s"\n' "$PROTECTED" > "$ETC/account-helper.conf"
	chown root:root "$ETC/account-helper.conf"; chmod 0644 "$ETC/account-helper.conf"
	install -m 0440 -o root -g root "$SRC/deploy/sudoers.rkmsiem" /tmp/rkmsiem.sudoers
	if ! visudo -cf /tmp/rkmsiem.sudoers >/dev/null; then
		rm -f /tmp/rkmsiem.sudoers
		echo "✘ sudoers 검사 실패 — 계정 잠금 없이 설치하려면: sudo ./deploy/install.sh --no-account-lock" >&2; exit 1
	fi
	mv /tmp/rkmsiem.sudoers /etc/sudoers.d/rkmsiem
	sudo -u rkmsiem sudo -n "$LIB/rkmsiem-account" check
	rm -f /etc/systemd/system/rkmsiem.service.d/hardening.conf
else
	rm -f /etc/sudoers.d/rkmsiem
	install -d /etc/systemd/system/rkmsiem.service.d
	install -m 0644 "$SRC/deploy/hardening-no-account-lock.conf" /etc/systemd/system/rkmsiem.service.d/hardening.conf
fi

step "nginx 예시 설정 → $ETC/nginx-rkmsiem.conf (직접 적용)"
install -m 0644 "$SRC/deploy/nginx-rkmsiem.conf" "$ETC/nginx-rkmsiem.conf"

step "systemd 서비스"
install -m 0644 "$SRC/deploy/rkmsiem.service" /etc/systemd/system/rkmsiem.service
# 위치 DB(DB-IP Lite) 갱신 스크립트 + 매달 타이머 (처음 받기는 직접: sudo /usr/local/lib/rkmsiem/geoip-update)
install -d -m 0755 "$LIB"
install -m 0755 -o root -g root "$SRC/deploy/geoip-update.sh" "$LIB/geoip-update"
install -m 0644 "$SRC/deploy/rkmsiem-geoip.service" "$SRC/deploy/rkmsiem-geoip.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now rkmsiem-geoip.timer >/dev/null 2>&1 || true
systemctl enable rkmsiem >/dev/null
systemctl restart rkmsiem
for i in $(seq 1 30); do
	curl -fsS http://127.0.0.1:8088/readyz >/dev/null 2>&1 && break
	sleep 1
done
if curl -fsS http://127.0.0.1:8088/readyz >/dev/null 2>&1; then echo "  서비스 준비 완료"; else
	echo "✘ 서비스가 준비되지 않았습니다: journalctl -u rkmsiem -n 50"; exit 1; fi

step "담당자 관리 앱 (rkmsiem-staff, 별도 서비스)"
# 관리 명령: sudo rkmsiem-staff admin add <이름> · admin passwd <이름> (비밀번호는 화면에 안 보이게 입력받음)
cat > /usr/local/sbin/rkmsiem-staff <<'EOF'
#!/bin/sh
# RKMSIEM 담당자 관리 앱 명령 (서비스 계정·DB 로 실행)
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요: sudo rkmsiem-staff $*" >&2; exit 1; }
cd /opt/rkmsiem && exec sudo -u rkmsiem env STAFF_DB=/var/lib/rkmsiem/staff/staff.db /opt/rkmsiem/venv/bin/python -m staffdir "$@"
EOF
chmod 0755 /usr/local/sbin/rkmsiem-staff
STAFF_DB="$DATA/staff/staff.db"
if [ ! -f "$STAFF_DB" ]; then                                   # 처음 한 번: 예전 담당자 정보(이름·팀·연락처)를 담당자 관리 앱으로 옮김
	/usr/local/sbin/rkmsiem-staff import-rkmsiem --if-empty "$DATA/rkmsiem.db" | sed 's/^/  /'
fi
install -m 0644 "$SRC/deploy/rkmsiem-staff.service" /etc/systemd/system/rkmsiem-staff.service
systemctl daemon-reload
systemctl enable rkmsiem-staff >/dev/null
systemctl restart rkmsiem-staff
STAFF_PORT="$(sed -n 's/^STAFF_PORT=//p' "$ETC/staff.env" | tail -1)"; STAFF_PORT="${STAFF_PORT:-8090}"
for i in $(seq 1 20); do
	curl -fsS "http://127.0.0.1:$STAFF_PORT/healthz" >/dev/null 2>&1 && break
	sleep 1
done
if curl -fsS "http://127.0.0.1:$STAFF_PORT/healthz" >/dev/null 2>&1; then echo "  담당자 관리 앱 준비 완료 (포트 $STAFF_PORT)"; else
	echo "✘ 담당자 관리 앱이 준비되지 않았습니다: journalctl -u rkmsiem-staff -n 50 (RKMSIEM 은 마지막 명단으로 계속 동작)"; fi
STAFF_ADMINS="$(sudo -u rkmsiem python3 -c 'import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute("SELECT COUNT(*) FROM admins WHERE active=1").fetchone()[0])' "$STAFF_DB" 2>/dev/null || echo 0)"

step "자가 점검 (서비스 권한으로)"
set -a; . "$ETC/rkmsiem.env"; set +a
if [ -n "${RKMSIEM_LOCAL_TOKEN:-}" ]; then
	curl -fsS -H "X-RKMSIEM-Local: $RKMSIEM_LOCAL_TOKEN" http://127.0.0.1:8088/api/system/doctor | python3 -c '
import sys, json
r = json.load(sys.stdin)
for c in r["checks"]:
    print(" ", {"ok":"✔","warn":"!","fail":"✘"}[c["status"]], c["status"].ljust(4), c["check"].ljust(22), c["detail"])'
else
	echo "  (점검 키가 없어 자동 점검을 건너뜀 — 웹 콘솔에서 'dashboard doctor')"
fi

cat <<EOF

────────────────────────────────────────────────────────────
 RKMSIEM 설치 완료
  웹 콘솔 : http://127.0.0.1:8088  (다른 PC 에서는 HTTPS: sudo rkmsiem-setup → 외부 접속 허용, 또는 sudo $SRC/deploy/tls.sh)
            원격에서 볼 때: ssh -L 8088:127.0.0.1:8088 <이 서버>
  모드    : $( [ "$LIVE" = 1 ] && echo "live (승인된 차단·잠금이 실제 실행)" || echo "simulate (실제 조치 안 함 — 확인 후 $ETC/config/settings.yaml 의 soar.mode 를 live 로)")
  설정    : $ETC/config   비밀: $ETC/rkmsiem.env   데이터: $DATA
  로그    : journalctl -u rkmsiem -f
  동작 검증: sudo $SRC/deploy/smoketest.sh
  담당자 관리: 이 서버 안 http://127.0.0.1:$STAFF_PORT · HTTPS 를 켜면 https://<이 서버>:8444  (서비스 rkmsiem-staff · DB $STAFF_DB)
  첫 로그인: 아이디 $ADMIN_USER / 비밀번호 admin → 바로 새 비밀번호(12자 이상)를 정하게 됩니다 · 그다음 콘솔에서 mfa setup
EOF
if [ "${STAFF_ADMINS:-0}" = 0 ]; then
	echo "  담당자 관리 앱 관리자가 아직 없습니다. 아래 명령으로 만드세요 (비밀번호는 화면에 안 보이게 두 번 입력):"
	echo "      sudo rkmsiem-staff admin add admin"
fi
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
	ALLOW8088="$(ufw status 2>/dev/null | awk '$1 ~ /^8088(\/tcp)?$/ && $2 == "ALLOW" {print $3}' | sort -u)"
	if ! ufw status 2>/dev/null | grep -qE "^$STAFF_PORT(/tcp)? "; then
		echo "  ufw 사용 중 — 담당자 관리 앱($STAFF_PORT)은 아직 허용되지 않았습니다. 콘솔(8088)과 같은 곳만 열려면:"
		for src in $ALLOW8088; do
			[ "$src" = Anywhere ] && echo "      sudo ufw allow $STAFF_PORT/tcp" || echo "      sudo ufw allow from $src to any port $STAFF_PORT proto tcp"
		done
		[ -n "$ALLOW8088" ] || echo "      sudo ufw allow from <접속할 PC IP> to any port $STAFF_PORT proto tcp"
	fi
fi
if [ "$FIRST_INSTALL" = 1 ]; then
	echo "  초기 관리자: 아이디 $ADMIN_USER / 비밀번호 admin"
	echo "               ⚠ 누구나 아는 값입니다 — 로그인 후 바로 콘솔에서 'passwd' 로 바꾸세요 (12자 이상)"
fi
echo "  지도 위치(선택): GeoLite2 무료 계정 → geoipupdate 로 $DATA/GeoLite2-City.mmdb 저장 (README)"
echo "────────────────────────────────────────────────────────────"
