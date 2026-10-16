#!/bin/bash
# Grafana 를 RKMSIEM 콘솔 안에 띄우기 — https://<서버>:8443/grafana/ 로 붙이고 RKMSIEM 로그인으로 들어간다.
#
#   sudo ./deploy/grafana-embed.sh                                   Grafana 가 이 서버(127.0.0.1:3000)에 있을 때
#   sudo ./deploy/grafana-embed.sh --upstream http://10.0.0.60:3000  다른 서버(또는 도커)의 Grafana
#   sudo ./deploy/grafana-embed.sh --public-url https://10.0.0.53:8443   브라우저가 접속하는 주소 (기본: 이 서버 첫 IP)
#   sudo ./deploy/grafana-embed.sh --keep-direct                     Grafana 의 3000 포트 직접 접속도 그대로 둠
#   sudo ./deploy/grafana-embed.sh --disable                         끄기
#
# 동작: 브라우저 → nginx(8443) /grafana/ → [RKMSIEM 에 로그인 확인 (auth_request)] → Grafana
#       Grafana 는 nginx 가 넣어 준 X-WEBAUTH-USER(rk-<계정>) · X-WEBAUTH-ROLE 헤더로 로그인 (auth.proxy).
#       RKMSIEM 에서 로그아웃하면 Grafana 도 바로 막힌다. 콘솔에서: grafana · grafana overview
# 먼저 HTTPS(deploy/tls.sh)가 켜져 있어야 한다.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요: sudo $0 $*" >&2; exit 1; }
HERE="$(cd "$(dirname "$0")" && pwd)"; SRC="$(dirname "$HERE")"
ETC=/etc/rkmsiem; ENVF=$ETC/rkmsiem.env; SITE=/etc/nginx/sites-available/rkmsiem; CONF=$ETC/nginx/grafana.conf
DROPIN=/etc/systemd/system/grafana-server.service.d/rkmsiem-embed.conf
PROV=/etc/grafana/provisioning/dashboards/rkmsiem.yaml; DASHDIR=/var/lib/grafana/dashboards/rkmsiem
CONSOLE=8443; UPSTREAM=http://127.0.0.1:3000; PUBLIC=""; KEEP_DIRECT=0; MODE=enable
while [ $# -gt 0 ]; do
	case "$1" in
		--upstream) UPSTREAM="$2"; shift ;;
		--public-url) PUBLIC="$2"; shift ;;
		--keep-direct) KEEP_DIRECT=1 ;;
		--disable) MODE=disable ;;
		-h|--help) sed -n '2,13p' "$0"; exit 0 ;;
		*) echo "알 수 없는 옵션: $1" >&2; exit 2 ;;
	esac
	shift
done
[ -f "$ENVF" ] || { echo "RKMSIEM 이 설치되어 있지 않습니다 ($ENVF 없음)" >&2; exit 1; }
setenv() { if grep -q "^$2=" "$1"; then sed -i "s#^$2=.*#$2=$3#" "$1"; else echo "$2=$3" >> "$1"; fi; }
local_grafana() { systemctl cat grafana-server >/dev/null 2>&1; }

if [ "$MODE" = disable ]; then
	rm -f "$CONF"; setenv "$ENVF" RKMSIEM_GRAFANA__ENABLED false
	nginx -t >/dev/null 2>&1 && systemctl reload nginx
	if [ -f "$DROPIN" ]; then rm -f "$DROPIN"; systemctl daemon-reload; systemctl restart grafana-server || true; fi
	systemctl restart rkmsiem
	echo "Grafana 임베드를 껐습니다 (/grafana/ 경로 삭제 · Grafana 설정은 원래대로)."
	exit 0
fi

# 입력 검사 — nginx 설정에 그대로 들어가므로 엄격하게
UPSTREAM="${UPSTREAM%/}"
[[ "$UPSTREAM" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ || "$UPSTREAM" =~ ^https?://\[[0-9A-Fa-f:]+\](:[0-9]{1,5})?$ ]] \
	|| { echo "--upstream 형식: http://호스트:포트 (경로 없이)  예) http://127.0.0.1:3000" >&2; exit 2; }
[ -n "$PUBLIC" ] || PUBLIC="https://$(ip -4 -o addr show scope global | awk '{split($4, a, "/"); print a[1]; exit}'):$CONSOLE"
PUBLIC="${PUBLIC%/}"
[[ "$PUBLIC" =~ ^https://[A-Za-z0-9.:\[\]-]+$ ]] || { echo "--public-url 형식: https://주소:8443" >&2; exit 2; }

echo "==> HTTPS(nginx) 확인"
[ -f "$SITE" ] && [ -e /etc/nginx/sites-enabled/rkmsiem ] || { echo "  HTTPS 가 꺼져 있습니다 — 먼저 sudo $HERE/tls.sh" >&2; exit 1; }
if ! grep -q "include $ETC/nginx/\*.conf" "$SITE"; then
	echo "  nginx 설정이 예전 형식 → tls.sh 로 다시 만듦 (인증서는 그대로)"
	"$HERE/tls.sh" >/dev/null
fi
if ! nginx -V 2>&1 | grep -q http_auth_request_module; then
	echo "  nginx 에 auth_request 모듈이 없음 → 전체 nginx 로 교체"
	apt-get -o DPkg::Lock::Timeout=300 install -y nginx-full >/dev/null 2>&1 || apt-get -o DPkg::Lock::Timeout=300 install -y nginx
	nginx -V 2>&1 | grep -q http_auth_request_module || { echo "  ✘ auth_request 모듈을 쓸 수 없습니다" >&2; exit 1; }
fi

echo "==> nginx /grafana/ → $UPSTREAM"
install -d -m 0755 "$ETC/nginx"
cat > "$CONF" <<EOF
# Grafana 임베드 (deploy/grafana-embed.sh 가 만듦 — 직접 고치면 다음 실행 때 덮어씀)
location = /_rk_grafana_auth {              # 로그인 확인: RKMSIEM 이 /grafana/ 전용 쿠키(rk_gf)를 검사
    internal;
    proxy_pass http://127.0.0.1:8088/api/grafana/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host \$http_host;
    proxy_set_header X-Forwarded-For \$remote_addr;
}
location /grafana/ {
    auth_request /_rk_grafana_auth;
    auth_request_set \$rk_user \$upstream_http_x_rk_user;
    auth_request_set \$rk_role \$upstream_http_x_rk_role;
    error_page 401 = @rk_grafana_login;
    proxy_pass $UPSTREAM;                   # 경로를 그대로 넘김 (Grafana serve_from_sub_path)
    proxy_http_version 1.1;
    proxy_set_header Host \$http_host;
    proxy_set_header X-Forwarded-For \$remote_addr;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-WEBAUTH-USER \$rk_user;    # 브라우저가 보낸 같은 이름 헤더는 여기서 덮어씀 (위조 방지)
    proxy_set_header X-WEBAUTH-ROLE \$rk_role;
    proxy_set_header Authorization "";
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection \$rk_conn_upgrade;
    proxy_read_timeout 300s;
}
location @rk_grafana_login {
    default_type text/html;
    return 401 '<!doctype html><meta charset="utf-8"><body style="background:#111217;color:#ccc;font:14px sans-serif;padding:24px">RKMSIEM 로그인이 필요합니다 — 콘솔에서 <b>grafana</b> 명령으로 여세요.</body>';
}
EOF
chmod 644 "$CONF"
if ! nginx -t 2>/dev/null; then nginx -t 2>&1 | sed 's/^/  /'; rm -f "$CONF"; echo "  ✘ nginx 설정 오류 → 되돌림" >&2; exit 1; fi

HOST="${UPSTREAM#*://}"; HOST="${HOST%:*}"; HOST="${HOST#[}"; HOST="${HOST%]}"
if local_grafana && [[ "$HOST" =~ ^(127\.0\.0\.1|localhost|::1)$ ]]; then
	echo "==> Grafana 설정 (이 서버의 grafana-server) → $DROPIN"
	install -d -m 0755 "$(dirname "$DROPIN")"
	{
		echo "# deploy/grafana-embed.sh 가 만듦 — RKMSIEM 콘솔 임베드 (/grafana/ · RKMSIEM 로그인)"
		echo "[Service]"
		echo "Environment=GF_SERVER_ROOT_URL=$PUBLIC/grafana/"
		echo "Environment=GF_SERVER_SERVE_FROM_SUB_PATH=true"
		[ "$KEEP_DIRECT" = 1 ] || echo "Environment=GF_SERVER_HTTP_ADDR=127.0.0.1"
		echo "Environment=GF_SECURITY_ALLOW_EMBEDDING=true"
		echo "Environment=GF_SECURITY_COOKIE_SECURE=true"
		echo "Environment=GF_SECURITY_COOKIE_SAMESITE=strict"
		echo "Environment=GF_AUTH_PROXY_ENABLED=true"
		echo "Environment=GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER"
		echo "Environment=GF_AUTH_PROXY_HEADER_PROPERTY=username"
		echo "Environment=GF_AUTH_PROXY_HEADERS=Role:X-WEBAUTH-ROLE"
		echo "Environment=GF_AUTH_PROXY_AUTO_SIGN_UP=true"
		echo "Environment=\"GF_AUTH_PROXY_WHITELIST=127.0.0.1, ::1\""
		echo "Environment=GF_USERS_AUTO_ASSIGN_ORG_ROLE=Viewer"
	} > "$DROPIN"
	if [ -f "$SRC/web/grafana/rkmsiem-overview.json" ] && [ -d /etc/grafana/provisioning/dashboards ]; then
		install -d -m 0755 "$DASHDIR"; install -m 0644 "$SRC/web/grafana/rkmsiem-overview.json" "$DASHDIR/"
		cat > "$PROV" <<EOF
# deploy/grafana-embed.sh 가 만듦 — RKMSIEM 대시보드 (Prometheus 데이터 소스는 Grafana 에 직접 추가)
apiVersion: 1
providers:
  - name: rkmsiem
    folder: RKMSIEM
    type: file
    allowUiUpdates: true
    options: {path: $DASHDIR}
EOF
		echo "  대시보드 'RKMSIEM 보안 개요' 자동 등록 (폴더 RKMSIEM)"
	fi
	systemctl daemon-reload; systemctl restart grafana-server
	[ "$KEEP_DIRECT" = 1 ] && echo "  ! 3000 포트 직접 접속이 열려 있음 — 같은 망에서 X-WEBAUTH-USER 헤더를 위조할 수 없게 화이트리스트(127.0.0.1)만 믿음" \
		|| echo "  Grafana 는 이제 이 서버 안(127.0.0.1:3000)에서만 받음 — 밖에서는 $PUBLIC/grafana/ 로"
else
	cat <<EOF
==> Grafana 쪽 설정 (이 서버에 grafana-server 가 없거나 다른 곳에 있음 — 직접 넣으세요)
  grafana.ini 또는 도커 환경 변수:
    GF_SERVER_ROOT_URL=$PUBLIC/grafana/
    GF_SERVER_SERVE_FROM_SUB_PATH=true
    GF_SECURITY_ALLOW_EMBEDDING=true
    GF_SECURITY_COOKIE_SECURE=true
    GF_SECURITY_COOKIE_SAMESITE=strict
    GF_AUTH_PROXY_ENABLED=true
    GF_AUTH_PROXY_HEADER_NAME=X-WEBAUTH-USER
    GF_AUTH_PROXY_HEADER_PROPERTY=username
    GF_AUTH_PROXY_HEADERS=Role:X-WEBAUTH-ROLE
    GF_AUTH_PROXY_AUTO_SIGN_UP=true
    GF_AUTH_PROXY_WHITELIST=<RKMSIEM 서버 IP>      (도커로 같은 서버면 172.16.0.0/12 처럼 도커 대역)
  ! 화이트리스트가 없으면 Grafana 3000 포트에 닿는 누구나 헤더로 아무 계정이 될 수 있습니다.
    Grafana 3000 포트는 RKMSIEM 서버에서만 닿게 막으세요 (방화벽 또는 도커 -p 127.0.0.1:3000:3000).
  대시보드: Grafana → Dashboards → New → Import → $SRC/web/grafana/rkmsiem-overview.json
EOF
fi

echo "==> RKMSIEM 켜기"
setenv "$ENVF" RKMSIEM_GRAFANA__ENABLED true
systemctl restart rkmsiem
systemctl reload nginx
cat <<EOF

완료 — 콘솔에서:  grafana   (또는 dashboard grafana · grafana overview)
  Grafana 계정은 RKMSIEM 계정 앞에 rk- 가 붙어 자동으로 만들어짐 (관리자 → Admin, 나머지 → Viewer)
  Prometheus 데이터 소스: settings → API 토큰 에서 metrics:read 토큰을 만들어 scrape 설정에 (docs/GRAFANA.md)
EOF
