"""HSOAR 핵심 — Slack 과 무관 (chat 객체만 바꾸면 시험 가능).

이벤트 피드 → Slack 메시지
  alert(new/escalate) · 심각도 ≥ notify.min_severity → 사건 카드 1번 (IP·계정 버튼) + 정책 제안 (auto 등급은 mode=on 이면 바로 실행)
  run(waiting_approval) → 승인 카드 [승인] [거절]          run(waiting_task) → 사람 할 일 알림
버튼 · /hsoar 명령 → RKMSIEM API (전용 토큰) — 누른 사람이 ALLOWED_USERS 에 있어야 조치. 사유에 Slack 이름이 남음
"""
import json
import logging
import time

from . import policy as pol
from .rk import RKError

log = logging.getLogger("hsoar")
SLACK_HINTS = {
    "not_in_channel": "봇이 채널에 없음 — 알림 채널에서 /invite @hsoar",
    "channel_not_found": "채널 ID 가 틀림 — 설정의 SLACK_CHANNEL 확인",
    "is_archived": "보관된 채널 — 다른 채널로 바꾸거나 보관 해제",
    "missing_scope": "봇 권한 부족 — 앱을 manifest 로 다시 설치",
}


def slack_hint(e):
    """SlackApiError → 'not_in_channel (봇이 채널에 없음 …)'. Slack 과 무관한 오류는 그대로."""
    r = getattr(e, "response", None)
    code = r.get("error") if r is not None and hasattr(r, "get") else None
    if not code:
        return str(e)
    return f"{code} ({SLACK_HINTS[code]})" if code in SLACK_HINTS else code


SEV_KO = {"low": "낮음", "medium": "주의", "high": "높음", "critical": "긴급"}
SEV_ICON = {"low": "⚪", "medium": "🟡", "high": "🟠", "critical": "🔴"}
DUR = {"1h": 3600, "1d": 86400, "7d": 604800, "forever": None}
HELP = """*HSOAR* — RKMSIEM 을 Slack 에서
`/hsoar status` 지금 상태 · `/hsoar incidents` 열린 사건
`/hsoar block <IP> [1h|1d|7d|forever] <사유>` · `/hsoar unblock <IP> <사유>`
`/hsoar pause` 자동 실행 멈춤(킬 스위치) · `/hsoar resume` · `/hsoar auto off|dry|on`
조치·승인 버튼과 block·unblock·pause·auto 는 허용된 사람(ALLOWED_USERS)만."""


def _btn(text, value, style=None):
    b = {"type": "button", "text": {"type": "plain_text", "text": text[:75]}, "value": json.dumps(value, separators=(",", ":"))[:2000],
         "action_id": f"hsoar:{value.get('k')}:{value.get('a', '')}:{abs(hash(json.dumps(value, sort_keys=True))) % 10**8}"}
    if style:
        b["style"] = style
    return b


def _section(md):
    return {"type": "section", "text": {"type": "mrkdwn", "text": md[:2900]}}


def _context(md):
    return {"type": "context", "elements": [{"type": "mrkdwn", "text": md[:2900]}]}


class Engine:
    def __init__(self, rk, chat, policy, store, allowed=(), console_url=""):
        self.rk, self.chat, self.policy, self.store = rk, chat, policy, store
        self.allowed, self.console = set(allowed), console_url.rstrip("/")

    # ---------------------------------------------------------------- 피드
    def mode(self):
        return self.store["auto_mode"] or self.policy.get("auto", {}).get("mode", "dry")

    def poll(self, wait=25):
        if self.store["seq"] is None:                           # 처음: 지금부터 (지난 것은 올리지 않음)
            self.store["seq"] = self.rk.feed()["last_seq"]
            self.store.save()
        r = self.rk.feed(self.store["seq"], wait=wait, types=["alert", "run"])
        for ev in r["items"]:
            try:
                self.handle(ev["type"], ev["data"])
            except RKError as e:
                log.warning("이벤트 #%s 처리 실패: %s", ev["seq"], e)
            except Exception as e:                              # noqa: BLE001  Slack 전송 오류 등 — 한 이벤트 때문에 서비스가 죽지 않게
                log.error("이벤트 #%s 건너뜀 — %s", ev["seq"], slack_hint(e))
            self.store["seq"] = ev["seq"]
        if r["items"]:
            self.store.save()
        return len(r["items"])

    def handle(self, kind, d):
        if kind == "alert" and d.get("op") in ("new", "escalate") and d.get("incident_id"):
            self.on_alert(d)
        elif kind == "run" and d.get("state") == "waiting_approval" and self.policy.get("notify", {}).get("approvals", True):
            self.on_approval(d)
        elif kind == "run" and d.get("state") == "waiting_task" and self.policy.get("notify", {}).get("tasks", True):
            self.on_task(d)

    def _posted(self, key):
        return key in self.store["posted"]

    def _post(self, key, blocks, text):
        ref = self.chat.post(blocks, text)
        self.store["posted"][key] = ref
        return ref

    # ---------------------------------------------------------------- 사건 · 자동 대응
    def on_alert(self, a):
        iid, sev = a["incident_id"], a.get("severity", "low")
        notify = pol.SEV[sev] >= pol.SEV[self.policy.get("notify", {}).get("min_severity", "high")]
        if notify and not self._posted(f"inc:{iid}"):
            self._incident_card(iid, a)
        for rule, target in pol.plan(self.policy, a):
            key = f"plan:{iid}:{rule['do']['action']}:{target}"
            if self._posted(key):
                continue
            self.suggest_or_run(iid, rule, target, key)

    def _incident_card(self, iid, a):
        t = self.rk.targets(iid)
        btns = []
        for x in t.get("ips", [])[:3]:
            if not x["blocked"] and not x.get("guard"):
                btns.append(_btn(f"IP 차단 1시간 {x['value']}", {"k": "act", "a": "block_ip", "i": iid, "t": x["value"], "d": 3600}, "danger"))
        for x in t.get("accounts", [])[:2]:
            if not x["locked"] and not x.get("guard"):
                btns.append(_btn(f"계정 잠금 {x['value']}", {"k": "act", "a": "disable_account", "i": iid, "t": x["value"]}, "danger"))
        ents = " · ".join([f"`{x['value']}`" for x in t.get("ips", [])[:3]] + [f"👤 `{x['value']}`" for x in t.get("accounts", [])[:3]])
        blocks = [_section(f"{SEV_ICON.get(a['severity'], '')} *사건 #{iid}* {a['title']}\n심각도 {SEV_KO.get(a['severity'], a['severity'])} · 규칙 `{a.get('rule_id')}`"
                           + (f"\n{ents}" if ents else "")),
                  _context(f"모드 {t.get('mode')} · RKMSIEM 콘솔에서 `incident {iid}`" + (f" · {self.console}" if self.console else ""))]
        if btns:
            blocks.insert(1, {"type": "actions", "elements": btns[:5]})
        self._post(f"inc:{iid}", blocks, f"사건 #{iid} {a['title']}")

    def suggest_or_run(self, iid, rule, target, key):
        act, name = rule["do"]["action"], pol.ACTIONS[rule["do"]["action"]]
        dur = rule["do"].get("duration_sec") if act == "block_ip" else None
        what = f"{name} `{target}`" + (f" ({self._dur_ko(dur)})" if act == "block_ip" else "")
        mode = self.mode()
        if mode == "off":
            return
        if rule.get("tier") == "auto" and mode == "on" and not self.store["paused"] and self._under_cap():
            try:
                out = self.rk.act(iid, act, target, f"HSOAR 자동: {rule['name']}", dur)
                self.store["auto_log"].append(time.time())
                undo = {"block_ip": ("unblock_ip", "차단 해제"), "disable_account": ("enable_account", "잠금 해제")}[act]
                sim = " _(simulate — 기록만)_" if (out.get("output") or {}).get("simulated") else ""
                self._post(key, [_section(f"🤖 *자동 조치* — {what}{sim}\n사건 #{iid} · 규칙: {rule['name']}"),
                                 {"type": "actions", "elements": [_btn(undo[1], {"k": "act", "a": undo[0], "i": iid, "t": target})]}],
                           f"자동 조치 {name} {target}")
            except RKError as e:
                self._post(key, [_section(f"⚠️ 자동 조치 실패 — {what}\n{e}")], f"자동 조치 실패 {target}")
            return
        why = ("자동 실행 멈춤(/hsoar pause)" if self.store["paused"] else "시간당 자동 상한" if rule.get("tier") == "auto" and not self._under_cap()
               else "dry 모드 — 제안만" if rule.get("tier") == "auto" else "사람 확인 등급")
        v = {"k": "act", "a": act, "i": iid, "t": target}
        if dur:
            v["d"] = dur
        self._post(key, [_section(f"💡 *제안* — {what}\n사건 #{iid} · 규칙: {rule['name']} · _{why}_"),
                         {"type": "actions", "elements": [_btn(f"실행: {name}", v, "danger"), _btn("무시", {"k": "dismiss"})]}],
                   f"제안 {name} {target}")

    def _under_cap(self):
        cap = int(self.policy.get("auto", {}).get("max_per_hour", 10))
        return len([t for t in self.store["auto_log"] if t > time.time() - 3600]) < cap

    @staticmethod
    def _dur_ko(d):
        return {3600: "1시간", 86400: "1일", 604800: "7일", None: "무기한"}.get(d, f"{d}초")

    # ---------------------------------------------------------------- 승인 · 사람 할 일
    def on_approval(self, d):
        r = self.rk.run(d["id"])
        for s in r["steps"]:
            if s["state"] != "waiting_approval" or self._posted(f"appr:{r['id']}:{s['step_id']}"):
                continue
            inp = s.get("input") or {}
            tgt = inp.get("ip") or inp.get("account") or inp.get("container") or inp.get("service") or json.dumps(inp, ensure_ascii=False)[:120]
            self._post(f"appr:{r['id']}:{s['step_id']}", [
                _section(f"🟨 *승인 요청* — 플레이북 `{r['playbook_id']}` 실행 #{r['id']}\n단계 `{s['step_id']}` · `{s['action']}` → `{tgt}`"
                         + (f"\n사건 #{r['incident_id']}" if r.get("incident_id") else "")),
                {"type": "actions", "elements": [_btn("승인", {"k": "appr", "r": r["id"], "s": s["step_id"], "ok": 1}, "primary"),
                                                 _btn("거절", {"k": "appr", "r": r["id"], "s": s["step_id"], "ok": 0}, "danger")]},
                _context(f"모드 {r.get('mode')} · 승인은 허용된 사람만")], f"승인 요청 실행 #{r['id']} {s['action']}")

    def on_task(self, d):
        r = self.rk.run(d["id"])
        for s in r["steps"]:
            t = s.get("task")
            if s["state"] != "waiting_task" or not t or self._posted(f"task:{r['id']}:{s['step_id']}"):
                continue
            items = "\n".join(f"☐ {c}" for c in t["checklist"])
            self._post(f"task:{r['id']}:{s['step_id']}", [
                _section(f"📋 *사람 할 일* — {t['title']}\n{t.get('instructions') or ''}\n{items}"),
                _context(f"실행 #{r['id']} `{r['playbook_id']}`" + (f" · 사건 #{r['incident_id']}" if r.get("incident_id") else "")
                         + " · 확인 목록 체크는 RKMSIEM 콘솔에서" + (f" · {self.console}" if self.console else ""))], f"사람 할 일 {t['title']}")

    # ---------------------------------------------------------------- 버튼
    def on_click(self, user_id, user_name, value, channel=None, ts=None):
        """버튼 → (결과 문구). 메시지가 있으면 버튼을 결과로 바꿈."""
        v = json.loads(value)
        if v.get("k") == "dismiss":
            if channel and ts:
                self.chat.update(channel, ts, [_section(f"~무시함~ — <@{user_id}>")], "무시함")
            return "무시함"
        if user_id not in self.allowed:
            msg = f"<@{user_id}> 은(는) HSOAR 조치 권한이 없습니다 (ALLOWED_USERS)"
            if channel:
                self.chat.ephemeral(channel, user_id, msg)          # 누른 사람에게만 보임
            return msg
        who = f"Slack @{user_name} ({user_id})"
        try:
            if v["k"] == "appr":
                ok = bool(v["ok"])
                self.rk.decide(v["r"], v["s"], ok, f"{'승인' if ok else '거절'} — {who}")
                msg = f"{'✅ 승인' if ok else '⛔ 거절'} — 실행 #{v['r']} `{v['s']}` · <@{user_id}>"
            elif v["k"] == "act":
                a = v["a"]
                out = self.rk.act(v["i"], a, v["t"], f"HSOAR 버튼 — {who}", v.get("d"))
                name = {"block_ip": "IP 차단", "unblock_ip": "차단 해제", "disable_account": "계정 잠금", "enable_account": "잠금 해제"}.get(a, a)
                sim = " _(simulate — 기록만)_" if (out.get("output") or {}).get("simulated") else ""
                msg = f"✔ {name} `{v['t']}`" + (f" ({self._dur_ko(v.get('d'))})" if a == "block_ip" else "") + f"{sim} — 사건 #{v['i']} · <@{user_id}>"
            else:
                return "알 수 없는 버튼"
        except RKError as e:
            msg = f"⚠️ 실패 — {e}"
            if channel and ts:
                self.chat.post([_section(msg)], msg, thread_ts=ts)
            return msg
        if channel and ts:
            self.chat.update(channel, ts, [_section(msg)], msg)
        return msg

    # ---------------------------------------------------------------- /hsoar
    def on_command(self, user_id, user_name, text):
        parts = (text or "").split()
        cmd, args = (parts[0].lower() if parts else "help"), parts[1:]
        who = f"Slack @{user_name} ({user_id})"
        try:
            if cmd == "status":
                o = self.rk.overview()
                pb = o.get("playbooks", {})
                return (f"*RKMSIEM* 위협 수준 *{o['threat']['current']['label']}* · 열린 경보 {o['totals']['open_alerts']} · "
                        f"승인 대기 {len(pb.get('pending_approvals', []))} · 사람 할 일 {len(pb.get('pending_tasks', []))}\n"
                        f"HSOAR 자동 모드 *{self.mode()}*{' · ⏸ *일시 정지*' if self.store['paused'] else ''} · 최근 1시간 자동 조치 "
                        f"{len([t for t in self.store['auto_log'] if t > time.time() - 3600])}/{self.policy.get('auto', {}).get('max_per_hour', 10)}")
            if cmd in ("incidents", "inc"):
                items = self.rk.incidents(5).get("items", [])
                return "\n".join(f"{SEV_ICON.get(i['severity'], '')} #{i['id']} {i['title']} · {i['state']}" + (f" · @{i['assignee']}" if i.get("assignee") else "")
                                 for i in items) or "열린 사건이 없습니다"
            if cmd in ("block", "unblock", "pause", "resume", "auto") and user_id not in self.allowed:
                return f"<@{user_id}> 은(는) 이 명령을 쓸 수 없습니다 (ALLOWED_USERS)"
            if cmd == "block":
                if not args:
                    return "사용법: `/hsoar block <IP> [1h|1d|7d|forever] <사유>`"
                ip, rest = args[0], args[1:]
                dur = DUR.get(rest[0]) if rest and rest[0] in DUR else 86400
                if rest and rest[0] in DUR:
                    rest = rest[1:]
                if not rest:
                    return "사유를 적어 주세요: `/hsoar block 1.2.3.4 1d 스캔 반복`"
                out = self.rk.block(ip, f"{' '.join(rest)} — {who}", dur)
                return f"✔ 차단 `{ip}` ({self._dur_ko(dur)})" + (" _(simulate — 기록만)_" if out.get("simulated") else "")
            if cmd == "unblock":
                if len(args) < 2:
                    return "사용법: `/hsoar unblock <IP> <사유>`"
                self.rk.unblock(args[0], f"{' '.join(args[1:])} — {who}")
                return f"✔ 차단 해제 `{args[0]}`"
            if cmd == "pause":
                self.store["paused"] = True
                self.store.save()
                return f"⏸ 자동 실행을 멈췄습니다 (제안은 계속 올림) — <@{user_id}>"
            if cmd == "resume":
                self.store["paused"] = False
                self.store.save()
                return f"▶ 자동 실행을 다시 켰습니다 (모드 {self.mode()}) — <@{user_id}>"
            if cmd == "auto":
                if not args or args[0] not in ("off", "dry", "on"):
                    return f"지금 모드 *{self.mode()}* — `/hsoar auto off|dry|on`"
                self.store["auto_mode"] = args[0]
                self.store.save()
                return f"자동 모드 → *{args[0]}* — <@{user_id}>"
        except RKError as e:
            return f"⚠️ 실패 — {e}"
        return HELP
