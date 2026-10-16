#!/bin/bash
# RKMSIEM HTTPS 켜기 — nginx 가 TLS 를 맡고, 앱(8088·8090)은 이 서버 안(127.0.0.1)에서만 받는다.
#
#   sudo ./deploy/tls.sh                  켜기 (다시 실행해도 안전 · 인증서는 있으면 그대로)
#   sudo ./deploy/tls.sh --renew          인증서 새로 만들기 (서버 IP 를 바꾼 뒤 등)
#   sudo ./deploy/tls.sh --san 1.2.3.4    인증서에 주소 추가 (VMware 호스트 IP·도메인 등, 쉼표로 여러 개)
#   sudo ./deploy/tls.sh --show           접속 주소·인증서 지문 보기
#   sudo ./deploy/tls.sh --disable        끄기 (예전처럼 http 로 직접 — 권장하지 않음)
#
# 접속:  https://<서버>:8443  (웹 콘솔)   https://<서버>:8444  (담당자 관리)
#        https://<서버>:8445  (연동 화면 — 콘솔의 connect 가 iframe 으로 엶. 콘솔과 다른 출처라 연동 제품 페이지가 콘솔 로그인에 닿지 못함)
# 인증서는 자체 서명이라 브라우저가 처음 한 번 경고한다. 지문(SHA-256)이 아래 출력과 같은지 확인하고 진행하거나,
# /etc/rkmsiem/tls/rkmsiem.crt 를 PC 의 '신뢰할 수 있는 루트 인증 기관'에 넣으면 경고가 사라진다.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요: sudo $0 $*" >&2; exit 1; }
ETC=/etc/rkmsiem; ENVF=$ETC/rkmsiem.env; STAFFENV=$ETC/staff.env; TLS=$ETC/tls
CRT=$TLS/rkmsiem.crt; KEY=$TLS/rkmsiem.key; SITE=/etc/nginx/sites-available/rkmsiem; LINK=/etc/nginx/sites-enabled/rkmsiem
CONSOLE=8443; STAFF=8444; CONNECT=8445
MODE=enable; RENEW=0; EXTRA=""
while [ $# -gt 0 ]; do
	case "$1" in
		--renew) RENEW=1 ;;
		--san) EXTRA="$2"; shift ;;
		--show) MODE=show ;;
		--disable) MODE=disable ;;
		-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
		*) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
	esac
	shift
done
[ -f "$ENVF" ] || { echo "RKMSIEM 이 설치되어 있지 않습니다 ($ENVF 없음)" >&2; exit 1; }

host_ips() { ip -4 -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); print a[1]}'; }
fingerprint() { openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/.*=//'; }
setenv() {   # 파일 키 값 — 있으면 바꾸고 없으면 추가
	if grep -q "^$2=" "$1"; then sed -i "s#^$2=.*#$2=$3#" "$1"; else echo "$2=$3" >> "$1"; fi
}
# ufw 출력은 서버 언어에 따라 번역됨("상태: 활성"·"허용") — 판단·파싱은 항상 영어 출력으로
ufw() { LANGUAGE= LC_ALL=C command ufw "$@"; }
ufw_on() { command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; }
wait_ready() { for _ in $(seq 1 40); do curl -fsS "$1" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }
show() {
	echo "접속 주소:"
	for ip in $(host_ips); do echo "  웹 콘솔      https://$ip:$CONSOLE"; done
	for ip in $(host_ips); do echo "  담당자 관리  https://$ip:$STAFF"; done
	for ip in $(host_ips); do echo "  연동 화면    https://$ip:$CONNECT  (콘솔 connect 가 엶 — 직접 열 일은 없음)"; done
	echo "인증서 지문 (SHA-256 — 브라우저 경고 화면의 인증서 정보와 같은지 확인):"
	echo "  $(fingerprint)"
	echo "  IDS 전송기: install-ship.sh --siem https://<이 서버>:$CONSOLE --fingerprint $(fingerprint | tr -d ':')"
	echo "인증서 파일 (PC 에 신뢰 등록하면 경고 없음): $CRT"
	echo "  유효 기간: $(openssl x509 -in "$CRT" -noout -enddate | sed 's/notAfter=//')"
	echo "  주소: $(openssl x509 -in "$CRT" -noout -ext subjectAltName 2>/dev/null | tail -1 | sed 's/^ *//')"
}

if [ "$MODE" = show ]; then
	[ -f "$CRT" ] && [ -e "$LINK" ] || { echo "HTTPS 가 아직 꺼져 있습니다 — sudo $0"; exit 1; }
	show; exit 0
fi

if [ "$MODE" = disable ]; then
	rm -f "$LINK"; systemctl reload nginx 2>/dev/null || true
	setenv "$ENVF" RKMSIEM_API__HOST 0.0.0.0; setenv "$ENVF" RKMSIEM_API__TRUSTED_PROXIES 0
	[ -f "$STAFFENV" ] && { setenv "$STAFFENV" STAFF_HOST 0.0.0.0; setenv "$STAFFENV" STAFF_TRUSTED_PROXIES 0; }
	systemctl restart rkmsiem rkmsiem-staff 2>/dev/null || true
	echo "HTTPS 를 껐습니다. 웹 콘솔은 다시 http://<서버>:8088 (암호화 없음 — 비밀번호가 망에 그대로 보입니다)"
	echo "방화벽(ufw)의 8088·8090 허용은 직접 다시 넣으세요."
	exit 0
fi

echo "==> nginx · openssl 준비"
if ! command -v nginx >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
	FRESH_NGINX=1
	apt-get -o DPkg::Lock::Timeout=300 install -y nginx-light openssl >/dev/null 2>&1 \
		|| apt-get -o DPkg::Lock::Timeout=300 install -y nginx openssl
else
	FRESH_NGINX=0
fi
# 방금 설치한 nginx 의 기본 페이지(80번)는 끈다 — 열어 둘 이유가 없음
[ "$FRESH_NGINX" = 1 ] && rm -f /etc/nginx/sites-enabled/default

echo "==> 인증서"
install -d -m 0700 "$TLS"
if [ "$RENEW" = 1 ] || [ ! -s "$CRT" ] || [ ! -s "$KEY" ]; then
	SAN="DNS:$(hostname),DNS:localhost,IP:127.0.0.1"
	for ip in $(host_ips); do SAN+=",IP:$ip"; done
	for x in ${EXTRA//,/ }; do
		if [[ "$x" =~ ^[0-9.]+$ || "$x" == *:* ]]; then SAN+=",IP:$x"; else SAN+=",DNS:$x"; fi
	done
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 825 \
		-subj "/CN=RKMSIEM $(hostname)/O=RKMSIEM" -keyout "$KEY.new" -out "$CRT.new" \
		-addext "subjectAltName=$SAN" -addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
	chmod 600 "$KEY.new"; chmod 644 "$CRT.new"
	mv -f "$KEY.new" "$KEY"; mv -f "$CRT.new" "$CRT"
	echo "  새 인증서: $SAN"
else
	echo "  있는 인증서 사용 (새로 만들려면 --renew)"
fi

echo "==> nginx 설정 → $SITE"
rm -f "$ETC/nginx/grafana.conf"                                  # v39~40 의 /grafana/ 임베드 (연동 화면 8445 로 바뀜)
V6="#"; [ -f /proc/net/if_inet6 ] && V6=""                     # IPv6 를 끈 서버에서는 [::] 을 듣지 않음
cat > "$SITE" <<EOF
# RKMSIEM HTTPS (deploy/tls.sh 가 만듦 — 직접 고치면 다음 실행 때 덮어씀)
# 앱은 127.0.0.1 에서만 받고, 밖에서는 이 TLS 포트로만 들어온다.
server {                                    # 웹 콘솔
    listen $CONSOLE ssl;
$V6    listen [::]:$CONSOLE ssl;
    server_name _;
    server_tokens off;
    ssl_certificate     $CRT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;          # 서버 블록 안에 둠 — 배포판 nginx.conf 의 전역 값과 겹치지 않게
    ssl_session_cache shared:rkmsiem:5m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    error_page 497 =301 https://\$host:\$server_port\$request_uri;     # http:// 로 오면 https:// 로
    client_max_body_size 2m;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_set_header Host \$http_host;
    proxy_set_header X-Forwarded-For \$remote_addr;                   # 덧붙이지 않고 덮어씀 (위조 방지)
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-RKMSIEM-Connect "";                            # 연동 화면 표시는 8445 에서만

    location /connect/ { return 404; }      # 연동 화면은 콘솔과 다른 출처(8445)에서만
    location /api/stream {                  # 실시간(SSE)
        proxy_pass http://127.0.0.1:8088;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 1h;
    }
    location /api/terminal {                # 웹 터미널 (롱 폴링)
        proxy_pass http://127.0.0.1:8088;
        proxy_buffering off;
        proxy_read_timeout 90s;
    }
    location / {
        proxy_pass http://127.0.0.1:8088;
        proxy_read_timeout 180s;            # PDF 보고서 생성
    }
}

server {                                    # 연동 화면 (connect) — /connect/ 만, 로그인 확인·전달은 앱이
    listen $CONNECT ssl;
$V6    listen [::]:$CONNECT ssl;
    server_name _;
    server_tokens off;
    ssl_certificate     $CRT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:rkmsiem:5m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    error_page 497 =301 https://\$host:\$server_port\$request_uri;
    client_max_body_size 10m;
    location /connect/ {
        proxy_pass http://127.0.0.1:8088;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-RKMSIEM-Connect 1;
        proxy_buffering off;
        proxy_read_timeout 300s;
    }
    location / { return 404; }
}

server {                                    # 담당자 관리 앱
    listen $STAFF ssl;
$V6    listen [::]:$STAFF ssl;
    server_name _;
    server_tokens off;
    ssl_certificate     $CRT;
    ssl_certificate_key $KEY;
    ssl_protocols TLSv1.2 TLSv1.3;          # 서버 블록 안에 둠 — 배포판 nginx.conf 의 전역 값과 겹치지 않게
    ssl_session_cache shared:rkmsiem:5m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    error_page 497 =301 https://\$host:\$server_port\$request_uri;
    client_max_body_size 2m;
    location / {
        proxy_pass http://127.0.0.1:8090;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto https;
    }
}
EOF
ln -sf "$SITE" "$LINK"
nginx -t 2>&1 | sed 's/^/  /'

echo "==> 앱은 이 서버 안에서만 받기 (127.0.0.1) · nginx 를 믿을 수 있는 프록시로"
setenv "$ENVF" RKMSIEM_API__HOST 127.0.0.1
setenv "$ENVF" RKMSIEM_API__TRUSTED_PROXIES 1
if [ -f "$STAFFENV" ]; then
	setenv "$STAFFENV" STAFF_HOST 127.0.0.1
	setenv "$STAFFENV" STAFF_TRUSTED_PROXIES 1
	setenv "$STAFFENV" STAFF_CONSOLE_URL ""
fi

echo "==> 방화벽 (ufw)"
if ufw_on; then
	# 8088·8090 을 허용했던 곳을 그대로 8443·8444 로 옮기고, 예전 http 허용은 지운다
	srcs="$(ufw status 2>/dev/null | awk '$1 ~ /^(8088|8090)(\/tcp)?$/ && $2 == "ALLOW" {print $3}' | sort -u)"
	for s in $srcs; do
		if [ "$s" = Anywhere ]; then ufw allow "$CONSOLE/tcp" >/dev/null; ufw allow "$STAFF/tcp" >/dev/null
		else ufw allow from "$s" to any port "$CONSOLE" proto tcp >/dev/null; ufw allow from "$s" to any port "$STAFF" proto tcp >/dev/null; fi
		echo "  허용: $s → $CONSOLE · $STAFF"
	done
	# 콘솔(8443)을 허용한 곳은 연동 화면(8445)도
	for s in $(ufw status 2>/dev/null | awk -v p="$CONSOLE" '($1 == p || $1 == p"/tcp") && $2 == "ALLOW" {print $3}' | sort -u); do
		if [ "$s" = Anywhere ]; then ufw allow "$CONNECT/tcp" >/dev/null; else ufw allow from "$s" to any port "$CONNECT" proto tcp >/dev/null; fi
	done
	while read -r n; do [ -n "$n" ] && ufw --force delete "$n" >/dev/null; done < <(ufw status numbered 2>/dev/null \
		| awk -F'[][]' '/ (8088|8090)(\/tcp)? .*ALLOW/ {print $2}' | sort -rn)
	[ -n "$srcs" ] && echo "  예전 http 허용(8088·8090) 삭제" || echo "  ! 허용된 곳이 없습니다 — 메뉴 '외부 접속 허용' 에서 PC IP 를 넣으세요"
else
	echo "  ufw 꺼짐 — $CONSOLE·$STAFF·$CONNECT 는 같은 망 어디서나 접속 가능 (8088·8090 은 이제 밖에서 닫힘)"
fi

echo "==> 서비스 다시 시작"
systemctl restart rkmsiem
systemctl restart rkmsiem-staff 2>/dev/null || true
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl reload nginx || systemctl restart nginx
if wait_ready "http://127.0.0.1:8088/healthz" && curl -fsSk --max-time 5 "https://127.0.0.1:$CONSOLE/healthz" >/dev/null; then
	echo "  https 응답 정상"
else
	echo "  ! https 응답 확인 실패 — sudo nginx -t · journalctl -u nginx -n 30 · journalctl -u rkmsiem -n 30"
fi
echo
show
echo
echo "VMware NAT 포트 포워딩을 쓰면: 호스트 $CONSOLE → 이 서버:$CONSOLE, 호스트 $STAFF → 이 서버:$STAFF, 호스트 $CONNECT → 이 서버:$CONNECT (연동 화면) 로 바꾸세요 (8088·8090 포워딩은 지워도 됨)."
echo "IDS 전송기를 쓰고 있었다면 위 'IDS 전송기' 명령으로 다시 설치해야 합니다 (http 8088 은 이제 밖에서 닫힘)."
