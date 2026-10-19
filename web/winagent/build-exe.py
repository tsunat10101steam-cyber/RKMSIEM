#!/usr/bin/env python3
"""윈도우에서 실행 — RKMSIEM 윈도우 클라이언트를 단일 exe 로 빌드.

사전 준비 (윈도우, 관리자 PowerShell):
    py -m pip install --upgrade pyinstaller
빌드:
    py build-exe.py
결과:
    dist\\rkmsiem-winagent.exe   (파이썬 설치 없이 돌아가는 단일 실행 파일)

표준 라이브러리만 쓰므로 추가 의존성은 없다. 서비스로 등록하려면 README 참고.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "rkmsiem-winagent.py")


def main():
    if sys.platform != "win32":
        sys.stderr.write("Run this on Windows (the exe is built for the OS it runs on).\n")
    cmd = [sys.executable, "-m", "PyInstaller", "--onefile", "--console",
           "--name", "rkmsiem-winagent",
           "--distpath", os.path.join(HERE, "dist"),
           "--workpath", os.path.join(HERE, "build"),
           "--specpath", HERE, SRC]
    print("running:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    sys.exit(main())
