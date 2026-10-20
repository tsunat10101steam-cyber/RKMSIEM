"""내장 플레이북 액션. 액션 = fn(ctx, input) -> output(dict).

- destructive=True 액션은 승인 정책을 거치고, simulate 모드에서는 아무것도 바꾸지 않고 '했을 일'만 기록한다.
- live 모드: settings.response 의 백엔드에 따라 실제로 실행한다.
    firewall.backend=nftables → nft 세트에 추가/삭제 (시간 제한 자동 해제)
    accounts.backend=helper   → root 헬퍼로 usermod 잠금/해제
    backend=none              → 플랫폼 DB(차단 목록·계정 상태)에만 기록
- 일시적 오류는 TransientError(재시도), 그 외는 ActionError(즉시 실패).
"""
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request

from ..plugins import action
from ..response import ResponseError, local_account


class ActionError(Exception):
    pass


class TransientError(ActionError):
    pass


def _ip(v):
    try:
        return str(ipaddress.ip_address(str(v)))
    except ValueError:
        raise ActionError(f"잘못된 IP: {v!r}")


def _resp_err(e):
    return TransientError(str(e)) if getattr(e, "transient", False) else ActionError(str(e))


# ------------------------------------------------------------------ 조회(비파괴)
@action("ip_reputation", description="IP 평판 조회 (AbuseIPDB + 로컬 인텔 + 공개 차단 목록 피드)")
def ip_reputation(ctx, inp):
    ip = _ip(inp.get("ip"))
    if not ctx.response or ctx.response.intel is None:
        raise TransientError("위협 인텔 색인이 아직 준비되지 않음")
    from ..abuseipdb import lookup
    return lookup(ctx.response, ip)


@action("asset_lookup", description="계정 조회 (Linux 로컬 계정 + 인벤토리)")
def asset_lookup(ctx, inp):
    name = str(inp.get("account") or "")
    assets = ctx.config.get("assets") or {}
    inv = next((a for a in assets.get("accounts", []) if a["name"] == name), None)
    st = ctx.db.one("SELECT disabled FROM account_state WHERE account=?", (name,))
    out = {"account": name, "found": inv is not None, "owner": inv.get("owner") if inv else None,
           "criticality": inv.get("criticality") if inv else None, "privileged": bool(inv and inv.get("privileged")),
           "disabled": bool(st and st["disabled"]), "sample_data": bool(assets.get("sample")), "source": "inventory"}
    acfg = ctx.response.assets_cfg if ctx.response else {}
    if acfg.get("backend") == "linux_local":
        loc = local_account(name, acfg.get("privileged_groups", ["sudo", "adm", "wheel", "root"]))
        if loc is not None:
            out.update(source="linux_local" + ("+inventory" if inv else ""), found=loc["exists"] or out["found"], system=loc)
            if loc.get("exists"):
                out["privileged"] = out["privileged"] or loc["privileged"]
    return out


# ------------------------------------------------------------------ 사람 할 일 (엔진이 직접 처리 — 실행을 멈추고 사람이 끝내면 이어감)
@action("manual_task", description="사람 할 일: 제목·설명·확인 목록 → 모두 체크하고 '완료' 해야 다음 단계로 (대응 절차서)")
def manual_task(ctx, inp):
    raise ActionError("manual_task 는 플레이북 엔진이 처리합니다 (직접 실행 불가)")


# ------------------------------------------------------------------ 사건/기록(플랫폼 내부)
@action("set_incident_severity", description="사건 심각도 변경")
def set_incident_severity(ctx, inp):
    if not ctx.incident_id:
        raise ActionError("사건이 없는 실행")
    ctx.incidents.set_severity(ctx.incident_id, inp["severity"], ctx.actor, inp.get("reason"))
    return {"incident_id": ctx.incident_id, "severity": inp["severity"]}


@action("record_result", description="대응 결과를 사건 타임라인에 기록")
def record_result(ctx, inp):
    if ctx.incident_id:
        ctx.incidents.add_timeline(ctx.incident_id, "playbook_result", ctx.actor, {"run_id": ctx.run_id, "summary": inp.get("summary")})
    return {"recorded": True, "summary": inp.get("summary")}


def _webhook_allowed(url, allow):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or not u.hostname or u.hostname not in allow:
        return False, "https 이고 허용 목록에 있는 호스트만 전송합니다"
    try:                                           # SSRF: 사설/루프백으로 해석되면 거부
        for info in socket.getaddrinfo(u.hostname, u.port or 443):
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"내부 주소로 해석됨({ip})"
    except socket.gaierror as e:
        raise TransientError(f"DNS 실패: {e}")
    return True, None


@action("notify", description="알림 (플랫폼 알림함 · 허용된 웹훅)")
def notify(ctx, inp):
    msg = str(inp.get("message", ""))[:2000]
    url = inp.get("webhook_url")
    delivered = "internal"
    if url:
        ok, why = _webhook_allowed(url, (ctx.config.get("approval") or {}).get("webhook_allowlist", []))
        if not ok:
            raise ActionError(f"웹훅 거부: {why}")
        if ctx.mode == "simulate":
            delivered = "simulated"
        else:
            req = urllib.request.Request(url, data=json.dumps({"text": msg}).encode(), headers={"Content-Type": "application/json"})
            try:
                urllib.request.urlopen(req, timeout=5).close()
            except OSError as e:
                raise TransientError(f"웹훅 전송 실패: {e}")
            delivered = "webhook"
    ctx.db.execute("INSERT INTO notifications (ts, channel, message, incident_id, run_id, delivered) VALUES (?,?,?,?,?,?)",
                   (time.time(), str(inp.get("channel", "soc")), msg, ctx.incident_id, ctx.run_id, delivered))
    if ctx.bus:
        ctx.bus.publish("notification", {"channel": inp.get("channel", "soc"), "message": msg, "incident_id": ctx.incident_id})
    return {"delivered": delivered, "channel": inp.get("channel", "soc")}


@action("send_email", description="메일 보내기 (허용된 받는 사람만 · 사건 보고서 PDF 첨부 가능)")
def send_email(ctx, inp):
    from ..mailer import MailError, split_addrs
    from ..reports import ReportError
    m = ctx.response.mailer if ctx.response else None
    if not m or not m.configured:
        raise ActionError("메일 발송이 설정되지 않음 (settings.yaml 의 mail)")
    to = split_addrs(inp.get("to"))
    ref = f"{ctx.run_id}:{ctx.step_id}"
    if m.already_sent("playbook", ref):                         # 재시도·재개 때 같은 메일을 두 번 보내지 않음
        return {"to": to, "status": "already_sent"}
    try:
        m.check_recipients(to)
        att = []
        if str(inp.get("attach_report", "")).lower() in ("true", "1", "yes") and ctx.incident_id:
            att = [(f"rkmsiem-incident-{ctx.incident_id}.pdf", ctx.response.report_incident(ctx.incident_id), "application/pdf")]
        mid = m.send("playbook", to, str(inp.get("subject") or "RKMSIEM 알림")[:200], str(inp.get("body") or "")[:20000],
                     attachments=att, ref=ref, actor=ctx.actor, simulate=ctx.mode == "simulate")
    except (MailError, ReportError) as e:
        raise ActionError(str(e))
    return {"mail_id": mid, "to": to, "status": "simulated" if ctx.mode == "simulate" else "queued", "attached": bool(att)}


# ------------------------------------------------------------------ 파괴적 조치 (승인 필요)
def _guard_ip(ctx, ip):
    for name, why in (("internal_networks", "사내망"), ("allowlist", "허용 목록"), ("never_block", "차단 금지 목록(관리 접속 등)")):
        if ctx.lists.contains(name, ip):
            raise ActionError(f"{ip} 는 {why}이라 차단할 수 없습니다")
    a = ipaddress.ip_address(ip)
    if a.is_loopback or a.is_unspecified or a.is_multicast or a.is_link_local:
        raise ActionError(f"{ip} 는 차단할 수 없는 주소입니다")


def _block_hist(ctx, ip, act, reason=None, expires_at=None, simulated=False):
    """차단 관리 화면의 기록 (차단·해제·연장 — 만료는 Platform.sweep_blocks)."""
    ctx.db.execute("INSERT INTO block_history (ts, ip, action, actor, reason, expires_at, incident_id, run_id, simulated) VALUES (?,?,?,?,?,?,?,?,?)",
                   (time.time(), ip, act, ctx.actor, reason, expires_at, ctx.incident_id, ctx.run_id, int(simulated)))


@action("block_ip", destructive=True, description="IP 차단 (live: nftables 또는 플랫폼 차단 목록)")
def block_ip(ctx, inp):
    ip = _ip(inp.get("ip"))
    _guard_ip(ctx, ip)
    dur = int(inp.get("duration_sec") or 0) or None
    fw = ctx.response.firewall if ctx.response else None
    if ctx.mode == "simulate":
        _block_hist(ctx, ip, "block", inp.get("reason"), time.time() + dur if dur else None, simulated=True)
        return {"simulated": True, "would": f"block {ip} for {dur or '∞'}s", "ip": ip, "backend": "nftables" if fw else "platform"}
    out = {"ip": ip, "blocked": True, "duration_sec": dur}
    if fw:
        try:
            out["firewall"] = fw.block(ip, dur)               # 먼저 실제 차단 — 실패하면 DB 에 남기지 않음
        except ResponseError as e:
            raise _resp_err(e)
    exp = time.time() + dur if dur else None
    cur = ctx.db.execute("INSERT OR IGNORE INTO blocklist (ip, reason, run_id, added_at, expires_at, added_by, incident_id) VALUES (?,?,?,?,?,?,?)",
                         (ip, inp.get("reason"), ctx.run_id, time.time(), exp, ctx.actor, ctx.incident_id))
    out["already_blocked"] = cur.rowcount == 0                # 멱등: 두 번 실행해도 한 번만
    if not out["already_blocked"]:
        _block_hist(ctx, ip, "block", inp.get("reason"), exp)
    out["backend"] = "nftables" if fw else "platform"
    return out


@action("unblock_ip", description="IP 차단 해제 (보상 작업)")
def unblock_ip(ctx, inp):
    ip = _ip(inp.get("ip"))
    fw = ctx.response.firewall if ctx.response else None
    if ctx.mode == "simulate":
        _block_hist(ctx, ip, "unblock", inp.get("reason"), simulated=True)
        return {"simulated": True, "would": f"unblock {ip}"}
    out = {"ip": ip}
    if fw:
        try:
            out["firewall"] = fw.unblock(ip)
        except ResponseError as e:
            raise _resp_err(e)
    cur = ctx.db.execute("DELETE FROM blocklist WHERE ip=?", (ip,))
    out["unblocked"] = cur.rowcount > 0 or bool(out.get("firewall", {}).get("was_present"))
    if out["unblocked"]:
        _block_hist(ctx, ip, "unblock", inp.get("reason"))
    return out


@action("extend_block", destructive=True, description="차단 기간 바꾸기 (지금부터 N초 · 무기한)")
def extend_block(ctx, inp):
    ip = _ip(inp.get("ip"))
    dur = int(inp.get("duration_sec") or 0) or None
    exp = time.time() + dur if dur else None
    if ctx.mode == "simulate":
        _block_hist(ctx, ip, "extend", inp.get("reason"), exp, simulated=True)
        return {"simulated": True, "would": f"extend {ip} to {dur or '∞'}s"}
    if not ctx.db.one("SELECT 1 FROM blocklist WHERE ip=?", (ip,)):
        raise ActionError(f"{ip} 는 차단 목록에 없습니다")
    _guard_ip(ctx, ip)
    fw = ctx.response.firewall if ctx.response else None
    out = {"ip": ip, "duration_sec": dur, "expires_at": exp}
    if fw:                                                    # nft 세트 원소의 timeout 은 바꿀 수 없어 지우고 다시 넣음
        try:
            fw.unblock(ip)
            out["firewall"] = fw.block(ip, dur)
        except ResponseError as e:
            raise _resp_err(e)
    ctx.db.execute("UPDATE blocklist SET expires_at=? WHERE ip=?", (exp, ip))
    _block_hist(ctx, ip, "extend", inp.get("reason"), exp)
    return out


@action("disable_account", destructive=True, description="계정 잠금 (live: usermod 헬퍼 또는 플랫폼 상태)")
def disable_account(ctx, inp):
    name = str(inp.get("account") or "")
    if not name:
        raise ActionError("account 가 없습니다")
    if ctx.lists.contains("protected_accounts", name):
        raise ActionError(f"{name} 은 보호 계정이라 잠글 수 없습니다")
    helper = ctx.response.accounts if ctx.response else None
    if ctx.mode == "simulate":
        return {"simulated": True, "would": f"lock account {name}", "account": name, "backend": "helper" if helper else "platform"}
    out = {"account": name, "disabled": True}
    if helper:
        try:
            out["system"] = helper.lock(name)
        except ResponseError as e:
            raise _resp_err(e)
    ctx.db.execute("INSERT INTO account_state (account, disabled, reason, run_id, updated_at) VALUES (?,1,?,?,?) "
                   "ON CONFLICT(account) DO UPDATE SET disabled=1, reason=excluded.reason, run_id=excluded.run_id, updated_at=excluded.updated_at",
                   (name, inp.get("reason"), ctx.run_id, time.time()))
    out["backend"] = "helper" if helper else "platform"
    return out


@action("enable_account", description="계정 잠금 해제 (보상 작업)")
def enable_account(ctx, inp):
    name = str(inp.get("account") or "")
    helper = ctx.response.accounts if ctx.response else None
    if ctx.mode == "simulate":
        return {"simulated": True, "would": f"unlock account {name}"}
    out = {"account": name, "disabled": False}
    if helper:
        try:
            out["system"] = helper.unlock(name)
        except ResponseError as e:
            raise _resp_err(e)
    ctx.db.execute("UPDATE account_state SET disabled=0, updated_at=? WHERE account=?", (time.time(), name))
    return out


# ------------------------------------------------------------------ 원격 조치 (대상 서버의 rkmsiem-agent 가 실행)
def _remote(ctx, action, inp, keys):
    from ..agents import ACTIONS as RA, AgentError
    if not ctx.agents:
        raise ActionError("원격 조치 에이전트 기능이 없습니다")
    agent = str(inp.get("agent") or "")
    params = {k: inp.get(k) for k in keys if inp.get(k) not in (None, "")}
    what = f"{RA[action][0]} {agent}:{' '.join(str(v) for v in params.values())}"
    if ctx.mode == "simulate":
        a = ctx.agents.get(agent, detail=False)
        if not a:
            raise ActionError(f"에이전트 '{agent}' 이 없습니다")
        if action not in a["allow"]:
            raise ActionError(f"'{agent}' 서버의 에이전트 설정(ALLOW)에서 '{RA[action][0]}' 을 허용하지 않았습니다")
        return {"simulated": True, "would": what, "agent": agent}
    try:
        jid = ctx.agents.submit(agent, action, params, ctx.actor, inp.get("reason"), ctx.incident_id)
    except AgentError as e:
        raise ActionError(str(e))
    r = ctx.agents.wait(jid, float(inp.get("timeout_sec") or 45))
    if r["state"] == "succeeded":
        return dict(json.loads(r["result"] or "{}"), job_id=jid, agent=agent)
    if r["state"] == "failed":
        raise ActionError(f"{what} 실패: {r['error']}")
    raise TransientError(f"{what}: 에이전트 응답 없음 (작업 #{jid} {r['state']})")


@action("container_stop", destructive=True, description="원격: 컨테이너 중지 (rkmsiem-agent)")
def container_stop(ctx, inp):
    return _remote(ctx, "container_stop", inp, ("container",))


@action("container_restart", destructive=True, description="원격: 컨테이너 재시작 (rkmsiem-agent)")
def container_restart(ctx, inp):
    return _remote(ctx, "container_restart", inp, ("container",))


@action("process_kill", destructive=True, description="원격: 프로세스 종료 (rkmsiem-agent · PID 재사용 확인)")
def process_kill(ctx, inp):
    return _remote(ctx, "process_kill", inp, ("pid", "start", "expect"))


@action("service_restart", destructive=True, description="원격: 서비스 재시작 (rkmsiem-agent)")
def service_restart(ctx, inp):
    return _remote(ctx, "service_restart", inp, ("service",))


@action("scan", description="원격: 악성코드 검사 (윈도우 클라이언트 · Defender 빠른 검사 — 결과는 작업 기록에)")
def scan(ctx, inp):
    return _remote(ctx, "scan", inp, ())


@action("message", description="원격: 클라이언트 화면에 메시지 표시 (윈도우 트레이 알림)")
def message(ctx, inp):
    return _remote(ctx, "message", inp, ("message",))
