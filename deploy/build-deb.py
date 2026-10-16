"""배포 묶음 만들기 — dpkg 없이도(윈도우 포함) 동작:  python deploy/build-deb.py [버전]

만드는 것 (dist/):
  rkmsiem_<버전>_all.deb   Ubuntu:  sudo apt install ./rkmsiem_<버전>_all.deb  →  sudo rkmsiem-setup
  rkmsiem-v<버전>.tgz      압축 파일 (예전 방식:  sudo ./deploy/install.sh)

허용 목록에 있는 파일만 담는다 — .env · data/ · DB · secret.key · 캐시 · 로컬 로그는 절대 들어가지 않음.
.deb 는 /usr/share/rkmsiem 에 원본을 풀고 rkmsiem-setup(설치·점검 화면)/smoketest/update/uninstall 명령만 만든다.
설치(install.sh)는 내부에서 apt 를 쓰므로 패키지 설치 중(dpkg 잠금)에는 돌릴 수 없어 사용자가 이어서 실행한다.
"""
import gzip
import io
import os
import shutil
import sys
import tarfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INCLUDE = ["rkmsiem", "staffdir", "web", "config", "deploy", "docs", "samples", "tests",
           "README.md", "requirements.txt", ".env.example", ".gitattributes", ".gitignore",
           "Dockerfile", "docker-compose.yml", "gen_log.py"]
SKIP_DIRS = {"__pycache__", ".pytest_cache", "dist"}
SKIP_EXT = (".pyc", ".db", ".db-wal", ".db-shm", ".key", ".mmdb")
EXEC_EXT = (".sh",)
EXEC_NAMES = {"rkmsiem-account", "rkmsiem-ship-eve.py", "build-deb.py"}
DEPENDS = "python3 (>= 3.10), python3-venv, python3-pip, nftables, sudo | sudo-rs, curl, rsyslog, fonts-nanum, openssh-client, whiptail"


def files():
    for top in INCLUDE:
        p = os.path.join(ROOT, top)
        if os.path.isfile(p):
            yield top
            continue
        for d, dirs, fs in os.walk(p):
            dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
            for f in sorted(fs):
                if f.endswith(SKIP_EXT):
                    continue
                yield os.path.relpath(os.path.join(d, f), ROOT).replace(os.sep, "/")


def mode_of(rel):
    name = rel.rsplit("/", 1)[-1]
    return 0o755 if name.endswith(EXEC_EXT) or name in EXEC_NAMES else 0o644


def add_bytes(tar, name, data, mode=0o644, mtime=None):
    ti = tarfile.TarInfo(name)
    ti.size, ti.mode, ti.mtime = len(data), mode, mtime or int(time.time())
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    tar.addfile(ti, io.BytesIO(data))


def add_dir(tar, name, mtime):
    ti = tarfile.TarInfo(name)
    ti.type, ti.mode, ti.mtime = tarfile.DIRTYPE, 0o755, mtime
    ti.uid = ti.gid = 0
    ti.uname = ti.gname = "root"
    tar.addfile(ti)


def read(rel):
    with open(os.path.join(ROOT, rel), "rb") as fh:
        data = fh.read()
    if rel.endswith((".sh", ".py", ".service", ".timer", ".conf", ".nft")) or rel.rsplit("/", 1)[-1] in EXEC_NAMES:
        data = data.replace(b"\r\n", b"\n")              # 윈도우에서 만들어도 줄바꿈은 리눅스용
    return data


def tgz(paths, out, prefix, now):
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as t:
        for rel in paths:
            add_bytes(t, prefix + rel, read(rel), mode_of(rel), now)


def ar(members):
    out = io.BytesIO()
    out.write(b"!<arch>\n")
    for name, data in members:
        hdr = f"{name:<16}{int(time.time()):<12}{0:<6}{0:<6}{'100644':<8}{len(data):<10}`\n".encode()
        out.write(hdr + data + (b"\n" if len(data) % 2 else b""))
    return out.getvalue()


def deb(paths, out, version, now):
    share = "./usr/share/rkmsiem/"
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz", format=tarfile.GNU_FORMAT) as t:
        dirs = {"./usr", "./usr/share", "./usr/sbin", share.rstrip("/")}
        for rel in paths:
            parts = (share + rel).split("/")[:-1]
            for i in range(2, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        for d in sorted(dirs):
            add_dir(t, d, now)
        for rel in paths:
            add_bytes(t, share + rel, read(rel), mode_of(rel), now)
        dep = "/usr/share/rkmsiem/deploy"
        cmds = {   # rkmsiem-setup: 인자 없으면 설치·점검 화면(whiptail), 인자가 있으면 예전처럼 install.sh 옵션
            "setup": f'#!/bin/sh\n[ $# -eq 0 ] && exec {dep}/setup-tui.sh\nexec {dep}/install.sh "$@"\n',
            "smoketest": f'#!/bin/sh\nexec {dep}/smoketest.sh "$@"\n',
            "update": f'#!/bin/sh\nexec {dep}/update.sh "$@"\n',
            "uninstall": f'#!/bin/sh\nexec {dep}/uninstall.sh "$@"\n',
            "grafana": f'#!/bin/sh\nexec {dep}/grafana-embed.sh "$@"\n',
        }
        for cmd, body in cmds.items():
            add_bytes(t, f"./usr/sbin/rkmsiem-{cmd}", body.encode(), 0o755, now)
    size_kb = sum(len(read(r)) for r in paths) // 1024 + 1
    control = f"""Package: rkmsiem
Version: {version}
Architecture: all
Maintainer: RKMSIEM <rkmsiem@localhost>
Depends: {DEPENDS}
Installed-Size: {size_kb}
Section: admin
Priority: optional
Description: RKMSIEM - Ubuntu 인증 로그 SIEM/SOAR
 SSH 무차별 대입·계정 탈취·권한 상승을 탐지하고 nftables 차단·계정 잠금으로 대응합니다.
 설치 후 'sudo rkmsiem-setup' 화면에서 설치·자체 점검을 진행하세요.
""".encode()
    postinst = """#!/bin/sh
set -e
if [ "$1" = configure ]; then
	if [ -f /etc/rkmsiem/config/settings.yaml ]; then
		echo "RKMSIEM 새 버전을 받았습니다. 적용:  sudo rkmsiem-setup  ->  업데이트"
	else
		echo "RKMSIEM 를 받았습니다. 설치·점검 화면:  sudo rkmsiem-setup"
		echo "  첫 로그인 admin / admin -> 로그인 후 바로 'passwd' 로 바꾸세요"
	fi
fi
exit 0
""".encode()
    ctrl = io.BytesIO()
    with tarfile.open(fileobj=ctrl, mode="w:gz", format=tarfile.GNU_FORMAT) as t:
        add_bytes(t, "./control", control, 0o644, now)
        add_bytes(t, "./postinst", postinst, 0o755, now)
    with open(out, "wb") as fh:
        fh.write(ar([("debian-binary", b"2.0\n"), ("control.tar.gz", ctrl.getvalue()), ("data.tar.gz", data.getvalue())]))


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else "29"
    os.makedirs(os.path.join(ROOT, "dist"), exist_ok=True)
    paths = list(files())
    bad = [p for p in paths if p.split("/")[0] in {".env", "data"} or p.endswith(SKIP_EXT)]
    assert not bad, bad
    now = int(time.time())
    d = os.path.join(ROOT, "dist", f"rkmsiem_{version}_all.deb")
    z = os.path.join(ROOT, "dist", f"rkmsiem-v{version}.tgz")
    deb(paths, d, version, now)
    tgz(paths, z, "./", now)
    latest = os.path.join(ROOT, "dist", "rkmsiem_all.deb")      # 버전 없는 이름 — releases/latest/download/ 주소가 늘 같게
    shutil.copyfile(d, latest)
    for p in (d, latest, z):
        print(f"{p}  ({os.path.getsize(p) // 1024} KB, 파일 {len(paths)}개)")


if __name__ == "__main__":
    main()
