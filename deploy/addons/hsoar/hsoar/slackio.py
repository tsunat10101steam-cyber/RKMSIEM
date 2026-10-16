"""Slack 전송 — Socket Mode (서버가 Slack 으로 나가는 웹소켓 하나 · 공개 주소·포트 불필요) + Web API.
버튼·명령은 3초 안에 바로 응답(ack)하고, 실제 처리는 작업 스레드에서 (RKMSIEM 조치는 수십 초 걸릴 수 있음)."""
import logging
from concurrent.futures import ThreadPoolExecutor

log = logging.getLogger("hsoar.slack")
PUBLIC_CMDS = {"block", "unblock", "pause", "resume", "auto"}      # 채널 모두에게 보임 (누가 했는지 남게)


class SlackChat:
    def __init__(self, web, channel):
        self.web, self.channel = web, channel

    def post(self, blocks, text, thread_ts=None):
        r = self.web.chat_postMessage(channel=self.channel, blocks=blocks, text=text, thread_ts=thread_ts, unfurl_links=False)
        return {"channel": r["channel"], "ts": r["ts"]}

    def update(self, channel, ts, blocks, text):
        self.web.chat_update(channel=channel, ts=ts, blocks=blocks, text=text)

    def ephemeral(self, channel, user, text):
        self.web.chat_postEphemeral(channel=channel, user=user, text=text)


def serve(engine, app_token, web):
    from slack_sdk.socket_mode import SocketModeClient
    from slack_sdk.socket_mode.response import SocketModeResponse
    from slack_sdk.webhook import WebhookClient

    pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="hsoar")
    client = SocketModeClient(app_token=app_token, web_client=web)

    def safe(fn, *a):
        try:
            fn(*a)
        except Exception:                                   # noqa: BLE001
            log.exception("처리 실패")

    def listener(c, req):
        if req.type == "interactive":
            c.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
            p = req.payload
            if p.get("type") == "block_actions":
                u, ch = p.get("user", {}), (p.get("channel") or {}).get("id") or (p.get("container") or {}).get("channel_id")
                for a in p.get("actions", []):
                    pool.submit(safe, engine.on_click, u.get("id"), u.get("username") or u.get("name"), a.get("value") or "{}", ch,
                                (p.get("container") or {}).get("message_ts"))
        elif req.type == "slash_commands":
            p = req.payload
            c.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
            cmd = (p.get("text") or "help").split()[0].lower() if (p.get("text") or "").strip() else "help"

            def run():
                text = engine.on_command(p["user_id"], p.get("user_name", ""), p.get("text", ""))
                WebhookClient(p["response_url"]).send(text=text, response_type="in_channel" if cmd in PUBLIC_CMDS else "ephemeral")
            pool.submit(safe, run)
        else:
            c.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))

    client.socket_mode_request_listeners.append(listener)
    client.connect()
    log.info("Slack Socket Mode 연결됨")
    return client
