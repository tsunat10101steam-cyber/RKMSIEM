"""python -m hsoar            서비스 (systemd rkmsiem-hsoar)
python -m hsoar check      설정·RKMSIEM·Slack 연결 확인

설정:
  $ADDON_ENV  (/etc/rkmsiem/addons/hsoar/addon.env — 핵심이 만듦)  RKMSIEM_URL · RKMSIEM_TOKEN
  $ADDON_DIR/hsoar.env   SLACK_BOT_TOKEN(xoxb-) · SLACK_APP_TOKEN(xapp-) · SLACK_CHANNEL(C…) · ALLOWED_USERS(U…,U…) · CONSOLE_URL
  $ADDON_DIR/policy.json 자동 대응 등급 (없으면 기본값 — policy.py)
  $ADDON_DIR/state.json  피드 위치 · 올린 메시지 · 일시 정지 (HSOAR 가 씀)
"""
import json
import logging
import os
import signal
import sys
import threading
import time

from . import VERSION, policy as pol
from .core import Engine
from .rk import RK, RKError
from .store import Store

log = logging.getLogger("hsoar")
ADDON_DIR = os.environ.get("ADDON_DIR", "/etc/rkmsiem/addons/hsoar")
ADDON_ENV = os.environ.get("ADDON_ENV", os.path.join(ADDON_DIR, "addon.env"))
STATE_DIR = os.environ.get("HSOAR_STATE", "/var/lib/rkmsiem-hsoar")


def read_env(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def config():
    c = dict(read_env(ADDON_ENV), **read_env(os.path.join(ADDON_DIR, "hsoar.env")))
    c["ALLOWED"] = [u.strip() for u in c.get("ALLOWED_USERS", "").split(",") if u.strip()]
    missing = [k for k in ("RKMSIEM_URL", "RKMSIEM_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_CHANNEL") if not c.get(k)]
    return c, missing


def build(c):
    from slack_sdk import WebClient
    from .slackio import SlackChat
    web = WebClient(token=c["SLACK_BOT_TOKEN"])
    rk = RK(c["RKMSIEM_URL"], c["RKMSIEM_TOKEN"])
    os.makedirs(STATE_DIR, exist_ok=True)
    eng = Engine(rk, SlackChat(web, c["SLACK_CHANNEL"]), pol.load(os.path.join(ADDON_DIR, "policy.json")),
                 Store(os.path.join(STATE_DIR, "state.json")), c["ALLOWED"], c.get("CONSOLE_URL", ""))
    return eng, web


def check():
    c, missing = config()
    ok = True
    print(f"HSOAR v{VERSION} · 설정 {ADDON_DIR}")
    if missing:
        print(f"✘ 빠진 설정: {', '.join(missing)} — sudo rkmsiem-setup → 추가 기능 → HSOAR → 설정")
        return 1
    try:
        print(f"✔ RKMSIEM 피드 위치 {RK(c['RKMSIEM_URL'], c['RKMSIEM_TOKEN']).feed()['last_seq']} ({c['RKMSIEM_URL']})")
    except (RKError, OSError) as e:
        ok = False
        print(f"✘ RKMSIEM: {e}")
    try:
        pol.load(os.path.join(ADDON_DIR, "policy.json"))
        print("✔ policy.json")
    except (pol.PolicyError, ValueError) as e:
        ok = False
        print(f"✘ policy.json: {e}")
    try:
        from slack_sdk import WebClient
        w = WebClient(token=c["SLACK_BOT_TOKEN"])
        a = w.auth_test()
        print(f"✔ Slack 봇 {a['user']} @ {a['team']}")
        w.conversations_info(channel=c["SLACK_CHANNEL"])
        print(f"✔ 채널 {c['SLACK_CHANNEL']} (봇을 채널에 초대했는지: /invite @{a['user']})")
    except Exception as e:                                  # noqa: BLE001
        ok = False
        print(f"✘ Slack: {e}")
    print(f"허용된 사람 (ALLOWED_USERS): {', '.join(c['ALLOWED']) or '없음 — 버튼·조치 명령을 아무도 못 씀'}")
    return 0 if ok else 1


def main():
    logging.basicConfig(level=os.environ.get("HSOAR_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    if len(sys.argv) > 1 and sys.argv[1] == "check":
        sys.exit(check())
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    while not stop.is_set():
        c, missing = config()
        if not missing:
            break
        log.warning("설정이 아직 없습니다 (%s) — sudo rkmsiem-setup → 추가 기능 → HSOAR → 설정. 60초 뒤 다시 확인", ", ".join(missing))
        stop.wait(60)
    if stop.is_set():
        return
    eng, web = build(c)
    from .slackio import serve
    client = serve(eng, c["SLACK_APP_TOKEN"], web)
    log.info("시작 — 자동 모드 %s · 허용된 사람 %d명", eng.mode(), len(c["ALLOWED"]))
    backoff = 2
    while not stop.is_set():
        try:
            eng.poll(wait=25)
            backoff = 2
        except (RKError, OSError) as e:
            log.warning("RKMSIEM 피드: %s — %d초 뒤 다시", e, backoff)
            stop.wait(backoff)
            backoff = min(backoff * 2, 60)
    client.close()


if __name__ == "__main__":
    main()
