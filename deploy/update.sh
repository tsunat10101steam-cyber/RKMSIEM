#!/bin/bash
# RKMSIEM 업데이트 — 새 버전을 푼 폴더에서 실행:  sudo ./deploy/update.sh
#
# 1) 현재 코드·설정·DB 를 /var/backups/rkmsiem/<시각>/ 에 백업
# 2) 새 버전에 추가된 규칙·플레이북 파일만 설정 폴더에 복사 (이미 있는 파일은 건드리지 않음 — 직접 고친 내용 보존)
# 3) install.sh 로 코드·패키지·서비스 갱신 (설정·데이터·비밀번호·모드는 그대로)
# 4) 서비스 상태 확인. 문제가 있으면 마지막에 출력되는 되돌리기 명령을 실행
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요: sudo $0" >&2; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
[ -f /etc/rkmsiem/config/settings.yaml ] || { echo "설치된 RKMSIEM 이 없습니다. 먼저 sudo ./deploy/install.sh" >&2; exit 1; }

TS="$(date +%Y%m%d-%H%M%S)"
BK="/var/backups/rkmsiem/$TS"
echo "==> 백업 → $BK"
install -d -m 0700 "$BK"
systemctl stop rkmsiem
systemctl stop rkmsiem-staff 2>/dev/null || true                      # 담당자 관리 앱 (있으면)
cp -a /opt/rkmsiem "$BK/opt-rkmsiem"
cp -a /etc/rkmsiem "$BK/etc-rkmsiem"
cp -a /var/lib/rkmsiem/rkmsiem.db* "$BK/" 2>/dev/null || true      # 서비스를 멈춘 상태라 DB 가 일관됨
[ -d /var/lib/rkmsiem/staff ] && cp -a /var/lib/rkmsiem/staff "$BK/staff"
echo "  백업 완료 ($(du -sh "$BK" | cut -f1))"

echo "==> 규칙·플레이북 기본값 갱신 (웹 콘솔에서 직접 바꾼 규칙·플레이북은 서비스가 그대로 유지)"
for d in rules playbooks; do
	for f in "$SRC/config/$d/"*.yaml; do
		[ -e "$f" ] || continue
		dst="/etc/rkmsiem/config/$d/$(basename "$f")"
		if [ ! -e "$dst" ]; then cp "$f" "$dst" && echo "  + $d/$(basename "$f")"
		elif ! cmp -s "$f" "$dst"; then cp "$f" "$dst" && echo "  ~ $d/$(basename "$f")"; fi
	done
done
# 이름이 바뀐 예전 규칙 파일 정리 (DB 의 예전 규칙은 서비스가 꺼 둠)
for old in ids_suricata_alert; do
	[ -e "/etc/rkmsiem/config/rules/$old.yaml" ] && rm -f "/etc/rkmsiem/config/rules/$old.yaml" && echo "  - rules/$old.yaml (이름 변경)"
done

echo "==> 코드·서비스 갱신"
ACCOUNT_OPT=""
[ -x /usr/local/lib/rkmsiem/rkmsiem-account ] || ACCOUNT_OPT="--no-account-lock"   # 처음 설치 때 선택 유지
SSH_CLIENT="${SSH_CLIENT:-}" "$SRC/deploy/install.sh" $ACCOUNT_OPT

echo
echo "업데이트 완료. 문제가 있으면 아래 명령으로 이전 버전으로 되돌릴 수 있습니다:"
echo "  sudo systemctl stop rkmsiem rkmsiem-staff && sudo rm -rf /opt/rkmsiem /etc/rkmsiem && \\"
echo "  sudo cp -a $BK/opt-rkmsiem /opt/rkmsiem && sudo cp -a $BK/etc-rkmsiem /etc/rkmsiem && \\"
echo "  sudo cp -a $BK/rkmsiem.db* /var/lib/rkmsiem/ && sudo systemctl start rkmsiem"
[ -d "$BK/staff" ] && echo "  (담당자 관리 앱 DB: sudo rm -rf /var/lib/rkmsiem/staff && sudo cp -a $BK/staff /var/lib/rkmsiem/staff && sudo systemctl start rkmsiem-staff)"
true
