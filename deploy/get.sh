#!/bin/bash
# RKMSIEM 한 줄 설치 — 최신 .deb 를 받아 설치하고 설치·점검 화면을 띄운다:
#   curl -fsSL https://raw.githubusercontent.com/tsunat10101steam-cyber/RKMSIEM/main/deploy/get.sh | sudo bash
# 이후 새 버전은:  sudo rkmsiem-setup → 업데이트  (GitHub 에서 알아서 받아 옴)
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요:  curl -fsSL <이 주소> | sudo bash" >&2; exit 1; }
URL=https://github.com/tsunat10101steam-cyber/RKMSIEM/releases/latest/download/rkmsiem_all.deb
DEB=/tmp/rkmsiem_all.deb
echo "==> RKMSIEM 최신 버전 내려받기"
curl -fSL --retry 3 -o "$DEB" "$URL"
echo "==> 패키지 설치 (필요한 패키지도 함께)"
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=600 update -qq || echo "  ! 패키지 목록 갱신 실패 — 받아 둔 목록으로 계속"
apt-get -o DPkg::Lock::Timeout=600 install -y "$DEB"
rm -f "$DEB"
if [ -e /dev/tty ]; then
	exec rkmsiem-setup </dev/tty            # 파이프로 실행돼도 화면은 키보드로 조작
else
	echo "설치·점검 화면:  sudo rkmsiem-setup"
fi
