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
    except FileNotFoundError:
        pass
    except OSError as e:                                    # 권한 문제는 '빠진 설정'으로 숨기지 않고 그대로 알림
        log.error("설정 파일을 읽을 수 없습니다: %s — %s (서비스 계정 rkmsiem-hsoar 의 권한 · /etc/rkmsiem 은 0751 이어야 함)", path, e)
        out["_unreadable"] = f"{path}: {e.strerror}"
    return out


def config():
    a, h = read_env(ADDON_ENV), read_env(os.path.join(ADDON_DIR, "hsoar.env"))
    c = dict(a, **h)
    c["_unreadable"] = [x.get("_unreadable") for x in (a, h) if x.get("_unreadable")]
    c["ALLOWED"] = [u.strip() for u in c.get("ALLOWED_USERS", "").split(",") if u.strip()]
    missing = [k for k in ("RKMSIEM_URL", "RKMSIEM_TOKEN", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN", "SLACK_CHANNEL") if not c.get(k)]
    return c, missing


HINTS = {
    "invalid_auth": "토큰이 틀렸거나 폐기됨",
    "not_authed": "토큰이 비어 있음",
    "token_revoked": "토큰이 폐기됨 — 새로 발급",
    "account_inactive": "앱이 삭제되었거나 워크스페이스에서 제거됨",
    "not_allowed_token_type": "토큰 종류가 다름 — 봇 토큰(xoxb-)과 앱 토큰(xapp-)이 서로 바뀌지 않았는지",
}
APP_TOKEN_HELP = ("api.slack.com/apps → HSOAR → Basic Information → App-Level Tokens → Generate (scope connections:write), "
                  "Socket Mode 켜짐 확인 → sudo rkmsiem-setup → 추가 기능 → HSOAR → 설정 의 앱 토큰(xapp-)에 입력")


def slack_err(e):
    """SlackApiError → 'invalid_auth (토큰이 틀렸거나 폐기됨)'"""
    code = getattr(getattr(e, "response", None), "get", lambda *_: None)("error")
    if not code:
        return str(e)
    return f"{code} ({HINTS[code]})" if code in HINTS else code


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
    for u in c["_unreadable"]:
        print(f"✘ 읽을 수 없음: {u} — sudo chmod 0751 /etc/rkmsiem 후 sudo systemctl restart rkmsiem-hsoar")
    if c["_unreadable"]:
        return 1
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
        from slack_sdk.errors import SlackApiError
    except ImportError as e:
        print(f"✘ slack_sdk 없음: {e} — HSOAR 를 다시 설치")
        return 1
    w = WebClient(token=c["SLACK_BOT_TOKEN"])
    bot = "hsoar"
    try:
        a = w.auth_test()
        bot = a["user"]
        print(f"✔ Slack 봇 토큰: {a['user']} @ {a['team']}")
    except SlackApiError as e:
        ok = False
        print(f"✘ Slack 봇 토큰(xoxb-): {slack_err(e)} — Slack 앱 → OAuth & Permissions → Bot User OAuth Token")
    except Exception as e:                                  # noqa: BLE001
        ok = False
        print(f"✘ Slack 연결: {e}")
    try:                                                    # Socket Mode 연결 주소만 받아 봄 (실제 연결은 안 함)
        WebClient().apps_connections_open(app_token=c["SLACK_APP_TOKEN"])
        print("✔ Slack 앱 토큰 (Socket Mode)")
    except SlackApiError as e:
        ok = False
        print(f"✘ Slack 앱 토큰(xapp-): {slack_err(e)} — {APP_TOKEN_HELP}")
    except Exception as e:                                  # noqa: BLE001
        ok = False
        print(f"✘ Slack 연결: {e}")
    try:                                                    # 채널 확인은 channels:read 권한이 있을 때만 — 없어도 동작에는 지장 없음
        ch = w.conversations_info(channel=c["SLACK_CHANNEL"])["channel"]
        if ch.get("is_member") is False:
            ok = False
            print(f"✘ 채널 {c['SLACK_CHANNEL']}: 봇이 채널에 없음 — 그 채널에서 /invite @{bot}")
        else:
            print(f"✔ 채널 {c['SLACK_CHANNEL']}")
    except SlackApiError as e:
        code = e.response.get("error")
        if code == "missing_scope":
            print(f"· 채널 {c['SLACK_CHANNEL']}: 확인 생략 (권한 없음 — 정상) · 그 채널에서 /invite @{bot} 했는지 확인")
        elif code == "channel_not_found":
            ok = False
            print(f"✘ 채널 {c['SLACK_CHANNEL']}: 찾을 수 없음 — 채널 ID(C…) 확인, 비공개 채널이면 먼저 /invite @{bot}")
        elif code not in ("invalid_auth", "not_authed", "token_revoked", "account_inactive"):   # 봇 토큰 문제는 위에서 이미 표시
            print(f"· 채널 {c['SLACK_CHANNEL']}: 확인 못 함 ({slack_err(e)})")
    except Exception:                                       # noqa: BLE001
        pass
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
    from slack_sdk.errors import SlackApiError
    from .slackio import serve
    wait = 30
    while True:                                             # 토큰이 틀려도 재시작을 반복하지 않고 천천히 다시 시도
        try:
            client = serve(eng, c["SLACK_APP_TOKEN"], web)
            break
        except SlackApiError as e:
            log.error("Slack 연결 실패: %s — 앱 토큰(xapp-) 확인: %s · %d초 뒤 다시", slack_err(e), APP_TOKEN_HELP, wait)
        except Exception as e:                              # noqa: BLE001  (네트워크 등)
            log.error("Slack 연결 실패: %s — %d초 뒤 다시", e, wait)
        if stop.wait(wait):
            return
        wait = min(wait * 2, 300)
        c, _ = config()                                     # 그동안 설정을 고쳤으면 새 토큰으로
        if c.get("SLACK_BOT_TOKEN") != web.token:
            eng, web = build(c)
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
