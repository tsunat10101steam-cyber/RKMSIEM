"""내장 파서. 파서 = fn(raw: str, options: dict) -> 부분 ECS 문서(dict). 실패 시 ParseError.

시각은 timezone 옵션 기준으로 해석해 UTC 로 바꾼다. 공통 필드(event.created 등)는 normalize 가 채운다.
"""
import ipaddress
import json
import re
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from ..conditions import value_of
from ..plugins import parser


class ParseError(ValueError):
    pass


def _set(doc, dotted, value):
    if value is None or value == "":
        return
    cur = doc
    parts = dotted.split(".")
    for p in parts[:-1]:
        cur = cur.setdefault(p, {})
    cur[parts[-1]] = value


_FRAC = re.compile(r"\.(\d+)")
_OFFSET = re.compile(r"([+-])(\d{2}):?(\d{2})$")


def to_utc(ts, tz_name):
    """문자열/숫자 시각 → aware UTC datetime."""
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts / 1000 if ts > 1e12 else ts, timezone.utc)
    if not isinstance(ts, str) or not ts:
        raise ParseError("timestamp missing")
    s = ts.strip().replace("Z", "+00:00").replace("z", "+00:00")
    # Python 3.10 호환: 소수 초는 6자리로, 시간대는 +HH:MM 으로 맞춘다
    s = _FRAC.sub(lambda m: "." + (m.group(1) + "000000")[:6], s)
    s = _OFFSET.sub(lambda m: f"{m.group(1)}{m.group(2)}:{m.group(3)}", s)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError as e:
        raise ParseError(f"bad timestamp: {ts!r}") from e
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo(tz_name or "UTC"))
    return dt.astimezone(timezone.utc)


def clean_ip(v, warnings):
    if v is None:
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError:
        warnings.append(f"invalid ip: {str(v)[:64]}")
        return None


# ---------------------------------------------------------------- authlog
_AUTH = re.compile(r"^(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})\s+(\S+)\s*(.*)$")
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")
_AUTH_KV_DEFAULT = {"user": "user.name", "ip": "source.ip", "host": "host.name"}


@parser("authlog")
def parse_authlog(raw, opt):
    """'YYYY-MM-DD HH:MM:SS STATUS key=value ...' 형식 (기존 auth.log)."""
    m = _AUTH.match(raw.strip())
    if not m:
        raise ParseError("line does not match authlog format")
    ts, status, rest = m.groups()
    warnings = []
    outcome_map = opt.get("outcome_map", {})
    doc = {"@timestamp": to_utc(ts, opt.get("timezone")).isoformat(),
           "event": {"category": [opt.get("category", "authentication")], "action": status.lower(),
                     "outcome": outcome_map.get(status, "unknown")},
           "message": raw.strip()}
    kv_map = opt.get("kv_map", _AUTH_KV_DEFAULT)
    for k, v in _KV.findall(rest):
        v = v.strip('"')
        if k in kv_map:
            tgt = kv_map[k]
            _set(doc, tgt, clean_ip(v, warnings) if tgt.endswith(".ip") else v)
    if warnings:
        doc.setdefault("labels", {})["parse_warnings"] = warnings
    return doc


# ---------------------------------------------------------------- json
@parser("json")
def parse_json(raw, opt):
    """JSON 객체 1개. options.field_map 으로 정규화 필드 ← 입력 경로 매핑."""
    try:
        src = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError as e:
        raise ParseError(f"invalid json: {e}") from e
    if not isinstance(src, dict):
        raise ParseError("json event must be an object")
    warnings, doc = [], {"event": {}}
    for tgt, path in (opt.get("field_map") or {}).items():
        v = value_of(src, path)
        if v is None:
            continue
        if tgt == "@timestamp":
            doc["@timestamp"] = to_utc(v, opt.get("timezone")).isoformat()
        elif tgt.endswith(".ip"):
            _set(doc, tgt, clean_ip(v, warnings))
        elif tgt == "event.category":
            _set(doc, tgt, v if isinstance(v, list) else [str(v)])
        elif tgt == "event.outcome":
            v = str(v).lower()
            _set(doc, tgt, (opt.get("outcome_map") or {}).get(v, v if v in ("success", "failure") else "unknown"))
        else:
            _set(doc, tgt, v if isinstance(v, (int, float, bool, list, dict)) else str(v)[:4096])
    for tgt, v in (opt.get("static") or {}).items():        # 고정 값 (예: event.module: prometheus) — 매핑 값이 있으면 그쪽 우선
        if value_of(doc, tgt) is None:
            _set(doc, tgt, [v] if tgt == "event.category" and not isinstance(v, list) else v)
    if "@timestamp" not in doc:
        if opt.get("default_now"):                               # 시각이 없는 항목(현재 상태 목록 등)은 가져온 시각
            from datetime import datetime as _dt, timezone as _tz
            doc["@timestamp"] = _dt.now(_tz.utc).isoformat()
        else:
            raise ParseError("timestamp missing")
    doc["event"].setdefault("category", [opt.get("default_category", "event")])
    if warnings:
        doc.setdefault("labels", {})["parse_warnings"] = warnings
    return doc


# ---------------------------------------------------------------- syslog 계열 공통
class Skip(Exception):
    """수집은 했지만 저장할 필요가 없는 줄(설정 drop_unmatched) — 오류가 아님."""


_PRI = re.compile(r"^<(\d{1,3})>")
_5424 = re.compile(r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|\[.*?\])\s?(.*)$")
_3164 = re.compile(r"^([A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$")
# Ubuntu 23.10+ rsyslog 기본(고정밀 RFC3339): 2024-10-13T16:47:05.123456+09:00 host sshd[1]: msg
_RFC3339_LINE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) (\S+) ([^:\[\s]+)(?:\[(\d+)\])?: ?(.*)$")
_SEV = ["critical", "critical", "critical", "high", "medium", "low", "info", "info"]
_rx_cache = {}


def _rx(p):
    r = _rx_cache.get(p)
    if r is None:
        r = _rx_cache[p] = re.compile(p)
    return r


def _rfc3164_time(ts, tz, now=None):
    """연도가 없는 'Oct 13 16:47:05' → UTC. 미래로 하루 넘게 앞서면 작년으로(연말 경계)."""
    now = now or datetime.now(ZoneInfo(tz or "UTC"))
    try:
        dt = datetime.strptime(f"{now.year} {' '.join(ts.split())}", "%Y %b %d %H:%M:%S").replace(tzinfo=ZoneInfo(tz or "UTC"))
    except ValueError as e:
        raise ParseError(f"bad rfc3164 time {ts!r}") from e
    if (dt - now).total_seconds() > 86400:
        dt = dt.replace(year=now.year - 1)
    return dt.astimezone(timezone.utc)


def _base_doc(when, host, app, pid, msg, pri=None):
    doc = {"@timestamp": when.isoformat(), "message": msg,
           "event": {"category": ["host"], "outcome": "unknown"},
           "host": {"name": host}, "process": {"name": app, "pid": pid if pid not in (None, "-", "") else None}}
    if pri is not None:
        doc["event"]["severity"] = 7 - (pri & 7)
        doc["log"] = {"syslog": {"priority": pri, "severity": {"name": _SEV[pri & 7]}}}
    return doc


def _apply_extract(doc, app, msg, opt):
    """options.extract: [{program | program_regex, pattern, category, outcome, action, enabled}] — 처음 맞는 규칙 적용."""
    warnings = []
    matched = False
    for ex in opt.get("extract", []):
        if ex.get("enabled") is False:
            continue
        if ex.get("program") and ex["program"] != app:
            continue
        if ex.get("program_regex") and not _rx(ex["program_regex"]).search(app or ""):
            continue
        mm = _rx(ex["pattern"]).search(msg or "")
        if not mm:
            continue
        g = mm.groupdict()
        doc["event"].update({"category": [ex.get("category", "host")], "outcome": ex.get("outcome", "unknown"),
                             "action": ex.get("action")})
        if g.get("user"):
            _set(doc, "user.name", g["user"])
        if g.get("ip"):
            _set(doc, "source.ip", clean_ip(g["ip"], warnings))
        if g.get("target_user"):
            _set(doc, "user.target.name", g["target_user"])
        matched = True
        break
    if not matched and opt.get("drop_unmatched"):
        raise Skip()
    if warnings:
        doc.setdefault("labels", {})["parse_warnings"] = warnings
    return doc


@parser("syslog")
def parse_syslog(raw, opt, _now=None):
    """네트워크 syslog (<PRI> 포함, RFC5424 / RFC3164)."""
    s = raw.strip()
    m = _PRI.match(s)
    if not m:
        raise ParseError("missing <PRI>")
    pri = int(m.group(1))
    s = s[m.end():]
    tz = opt.get("timezone")
    if (m5 := _5424.match(s)):
        ts, host, app, pid, _msgid, _sd, msg = m5.groups()
        when = to_utc(ts, tz)
    elif (m3 := _3164.match(s)):
        ts, host, app, pid, msg = m3.groups()
        when = _rfc3164_time(ts, tz, _now)
    else:
        raise ParseError("not RFC5424/RFC3164")
    return _apply_extract(_base_doc(when, host, app, pid, msg, pri), app, msg, opt)


@parser("linux_syslog")
def parse_linux_syslog(raw, opt, _now=None):
    """rsyslog 가 파일로 쓴 줄 (/var/log/auth.log 등). 전통 형식과 Ubuntu 23.10+ RFC3339 형식 모두."""
    s = raw.rstrip("\r\n")
    if (m := _RFC3339_LINE.match(s)):
        ts, host, app, pid, msg = m.groups()
        when = to_utc(ts, opt.get("timezone"))
    elif (m := _3164.match(s)):
        ts, host, app, pid, msg = m.groups()
        when = _rfc3164_time(ts, opt.get("timezone"), _now)
    else:
        raise ParseError("not a syslog file line")
    return _apply_extract(_base_doc(when, host, app, pid, msg), app, msg, opt)


@parser("journald")
def parse_journald(raw, opt):
    """journalctl -o json 한 줄."""
    try:
        j = json.loads(raw)
    except ValueError as e:
        raise ParseError(f"invalid journald json: {e}") from e
    msg = j.get("MESSAGE")
    if isinstance(msg, list):                      # 바이트 배열로 오는 비 UTF-8 메시지
        msg = bytes(x for x in msg if isinstance(x, int)).decode("utf-8", "replace")
    try:
        when = datetime.fromtimestamp(int(j["__REALTIME_TIMESTAMP"]) / 1e6, timezone.utc)
    except (KeyError, ValueError) as e:
        raise ParseError("missing __REALTIME_TIMESTAMP") from e
    app = j.get("SYSLOG_IDENTIFIER") or j.get("_COMM") or ""
    pri = int(j["PRIORITY"]) if str(j.get("PRIORITY", "")).isdigit() else None
    doc = _base_doc(when, j.get("_HOSTNAME"), app, j.get("_PID") or j.get("SYSLOG_PID"), msg or "", pri)
    if j.get("_SYSTEMD_UNIT"):
        doc["process"]["unit"] = j["_SYSTEMD_UNIT"]
    return _apply_extract(doc, app, msg or "", opt)


# ---------------------------------------------------------------- suricata (EVE JSON)
_SURI_SEV = {1: "high", 2: "medium", 3: "low", 4: "info"}


@parser("suricata_eve")
def parse_suricata_eve(raw, opt):
    """Suricata eve.json 한 줄 → 정규화. 기본은 alert·anomaly 만 저장 (options.event_types 로 변경).

    alert: 출발/목적 IP·포트, 시그니처(rule.name/id), 분류(rule.category), 심각도(1 높음 … 3 낮음 → event.severity)
    """
    try:
        e = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError as x:
        raise ParseError(f"invalid eve json: {x}") from x
    if not isinstance(e, dict) or "event_type" not in e:
        raise ParseError("not a suricata eve record")
    et = e["event_type"]
    if et not in (opt.get("event_types") or ["alert", "anomaly"]):
        raise Skip()
    warnings = []
    doc = {"@timestamp": to_utc(e.get("timestamp"), opt.get("timezone")).isoformat(),
           "event": {"category": ["intrusion_detection", "network"], "kind": "alert" if et == "alert" else "event",
                     "action": f"ids_{et}", "outcome": "unknown", "module": "suricata"},
           "network": {"transport": (e.get("proto") or "").lower() or None, "protocol": e.get("app_proto")},
           "observer": {"type": "ids", "product": "suricata", "name": e.get("host") or e.get("sensor_name")}}
    for side, ip_k, port_k in (("source", "src_ip", "src_port"), ("destination", "dest_ip", "dest_port")):
        ip = clean_ip(e.get(ip_k), warnings) if e.get(ip_k) else None
        if ip:
            doc[side] = {"ip": ip, **({"port": int(e[port_k])} if e.get(port_k) is not None else {})}
    if et == "alert":
        a = e.get("alert") or {}
        sev = int(a.get("severity") or 3)
        doc["event"]["severity"] = sev
        doc["rule"] = {"id": str(a.get("signature_id", "")), "name": a.get("signature") or "", "category": a.get("category") or "",
                       "ruleset": "suricata", "severity_label": _SURI_SEV.get(sev, "low"), "action": a.get("action")}
        doc["message"] = f"[IDS] {a.get('signature', '')} ({a.get('category', '')}) {e.get('src_ip')}:{e.get('src_port')} → {e.get('dest_ip')}:{e.get('dest_port')}"
        if (a.get("action") or "") == "blocked":
            doc["event"]["outcome"] = "failure"                 # IPS 모드에서 막은 경우
    else:
        an = e.get("anomaly") or {}
        doc["rule"] = {"name": an.get("event") or an.get("type") or "anomaly", "category": "anomaly", "ruleset": "suricata"}
        doc["message"] = f"[IDS anomaly] {doc['rule']['name']} {e.get('src_ip')} → {e.get('dest_ip')}"
    doc["network"] = {k: v for k, v in doc["network"].items() if v}
    if e.get("flow_id"):
        doc["network"]["flow_id"] = str(e["flow_id"])
    if warnings:
        doc.setdefault("labels", {})["parse_warnings"] = warnings
    return doc
