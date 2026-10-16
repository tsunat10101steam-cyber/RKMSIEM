"""의미 검증(스키마로 못 잡는 것): 참조하는 목록·액션의 존재, 정규식, 단계 정의 등."""
import re

from . import conditions
from .plugins import ACTIONS
from .schemas import SchemaError


def _lists(store):
    return set((store.get("lists") or {}).keys())


def _check_conds(conds, known, where, errs):
    for name in conditions.referenced_lists(conds):
        if name not in known:
            errs.append(f"{where}: 목록 '{name}' 이 lists 에 없습니다")
    try:
        conditions.validate_regexes(conds)
    except Exception as e:
        errs.append(f"{where}: 정규식 오류 {e}")


def rule(content, store):
    errs, known = [], _lists(store)
    _check_conds(content.get("where"), known, "where", errs)
    _check_conds(content.get("exceptions"), known, "exceptions", errs)
    for part in ("first", "then"):
        if content.get(part):
            _check_conds(content[part]["where"], known, part, errs)
    for m in content.get("modifiers") or []:
        _check_conds(m["when"], known, "modifiers", errs)
    ids = [l["id"] for l in content["levels"]]
    if len(ids) != len(set(ids)):
        errs.append("levels: id 중복")
    mins = [l["min"] for l in content["levels"]]
    if mins != sorted(set(mins)):
        errs.append("levels: min 은 서로 다르고 오름차순이어야 합니다")
    if errs:
        raise SchemaError(errs)


def detection(content, store):
    errs, known = [], _lists(store)
    _check_conds(content.get("global_exceptions"), known, "global_exceptions", errs)
    for m in content.get("global_modifiers") or []:
        _check_conds(m["when"], known, "global_modifiers", errs)
    if errs:
        raise SchemaError(errs)


def playbook(content, store):
    errs, known = [], _lists(store)
    _check_conds((content.get("trigger") or {}).get("where"), known, "trigger", errs)
    ids = set()
    for s in content["steps"]:
        if s["id"] in ids:
            errs.append(f"steps: id '{s['id']}' 중복")
        ids.add(s["id"])
        if s["action"] not in ACTIONS:
            errs.append(f"steps.{s['id']}: 등록되지 않은 액션 '{s['action']}'")
        if s.get("compensate") and s["compensate"]["action"] not in ACTIONS:
            errs.append(f"steps.{s['id']}.compensate: 등록되지 않은 액션 '{s['compensate']['action']}'")
        _check_conds(s.get("when"), known, f"steps.{s['id']}.when", errs)
    if errs:
        raise SchemaError(errs)


def workflow(content, store):
    states = {s["id"] for s in content["states"]}
    errs = [] if content["initial"] in states else [f"initial '{content['initial']}' 이 states 에 없습니다"]
    for t in content["transitions"]:
        for x in [t["from"], *t["to"]]:
            if x not in states:
                errs.append(f"transitions: 알 수 없는 상태 '{x}'")
    if errs:
        raise SchemaError(errs)


def _pull_errors(s):
    from urllib.parse import urlsplit
    from .collectors.http_pull import ENV_PREFIX
    o, e, sid = s.get("options") or {}, [], s["id"]
    u = urlsplit(str(o.get("url", "")).replace("{cursor}", ""))
    if u.scheme not in ("http", "https") or not u.hostname:
        e.append(f"{sid}: url 은 http:// 또는 https:// 주소")
    try:
        if float(o.get("interval_sec", 60)) < 5:
            e.append(f"{sid}: interval_sec 는 5초 이상")
    except (TypeError, ValueError):
        e.append(f"{sid}: interval_sec 는 숫자")
    env = (o.get("auth") or {}).get("token_env") or o.get("token_env")
    if env and not str(env).startswith(ENV_PREFIX):
        e.append(f"{sid}: token_env 는 {ENV_PREFIX} 로 시작해야 함 (다른 비밀 값이 새지 않게)")
    if (o.get("auth") or {}).get("type", "bearer") not in ("bearer", "basic", "header"):
        e.append(f"{sid}: auth.type 은 bearer · basic · header")
    for h in (o.get("headers") or {}):
        if str(h).lower() in ("authorization", "cookie", "x-api-key"):
            e.append(f"{sid}: 비밀 헤더 '{h}' 는 headers 에 적지 말고 auth(웹에서 암호화 저장)로")
    fp = str((o.get("tls") or {}).get("fingerprint", "")).replace(":", "").lower()
    if fp and not re.fullmatch(r"[0-9a-f]{64}", fp):
        e.append(f"{sid}: tls.fingerprint 는 SHA-256 (16진수 64자)")
    if u.scheme == "http" and (o.get("auth") or o.get("token_env")) and u.hostname not in ("127.0.0.1", "::1", "localhost"):
        e.append(f"{sid}: 인증 정보를 http(암호화 없음)로 망에 보낼 수 없음 — https 주소를 쓰세요 (이 서버 안 127.0.0.1 은 허용)")
    return e


def sources(content, store):
    import re
    from .plugins import COLLECTORS, PARSERS
    errs, ids = [], set()
    for s in content["sources"]:
        if s["id"] in ids:
            errs.append(f"sources: id '{s['id']}' 중복")
        ids.add(s["id"])
        if s["type"] not in COLLECTORS:
            errs.append(f"{s['id']}: 등록되지 않은 수집기 '{s['type']}'")
        if s["parser"] not in PARSERS:
            errs.append(f"{s['id']}: 등록되지 않은 파서 '{s['parser']}'")
        for i, ex in enumerate((s.get("options") or {}).get("extract", [])):
            for k in ("pattern", "program_regex"):
                if ex.get(k):
                    try:
                        re.compile(ex[k])
                    except re.error as e:
                        errs.append(f"{s['id']}.extract[{i}].{k}: 정규식 오류 {e}")
            if "pattern" not in ex:
                errs.append(f"{s['id']}.extract[{i}]: pattern 없음")
        if s["type"] == "file" and not (s.get("options") or {}).get("path"):
            errs.append(f"{s['id']}: file 수집기는 options.path 필요")
        if s["type"] == "http_pull":
            errs += _pull_errors(s)
        if "view" in s:
            from .connect import view_errors
            errs += view_errors(s["id"], s["view"])
    if errs:
        raise SchemaError(errs)


_EMAIL = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
_DOMAIN = re.compile(r"^@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _emails(vals, where, errs, domains=False):
    for v in vals or []:
        if not (_EMAIL.match(v) or (domains and _DOMAIN.match(v))):
            errs.append(f"{where}: 메일 주소 형식 오류 '{v}'" + (" (주소 또는 @도메인)" if domains else ""))


def lists(content, store):
    import ipaddress
    errs = []
    for name, lst in content.items():
        if lst["kind"] == "cidr":
            for v in lst["values"]:
                try:
                    ipaddress.ip_network(v, strict=False)
                except ValueError:
                    errs.append(f"{name}: IP/CIDR 형식 오류 '{v}'")
    if errs:
        raise SchemaError(errs)


def mail(content, store):
    from email.utils import parseaddr
    errs = []
    if content.get("enabled"):
        if not content.get("host"):
            errs.append("메일을 켜려면 SMTP 서버(host)가 필요합니다")
        if not _EMAIL.match(parseaddr(content.get("from") or "")[1] or ""):
            errs.append("보낸 사람(from) 메일 주소가 올바르지 않습니다")
    _emails(content.get("allowed_recipients"), "허용 목록", errs, domains=True)
    _emails((content.get("alerts") or {}).get("to"), "경보 알림 받는 사람", errs)
    if errs:
        raise SchemaError(errs)


def reports(content, store):
    errs = []
    _emails((content.get("incident_on_close") or {}).get("to"), "사건 보고서 받는 사람", errs)
    names = [s["name"] for s in content.get("schedule") or []]
    if len(names) != len(set(names)):
        errs.append("보고서 일정 이름이 중복됩니다")
    for s in content.get("schedule") or []:
        _emails(s.get("to"), f"{s['name']} 받는 사람", errs)
    if errs:
        raise SchemaError(errs)


def reputation(content, store):
    a = content.get("abuseipdb") or {}
    if a.get("suspicious_score", 25) >= a.get("malicious_score", 75):
        raise SchemaError(["의심 점수 기준은 악성 기준보다 낮아야 합니다"])


def embeds(content, store):
    from .connect import _path_ok, view_of
    errs, seen = [], set()
    srcs = {x["id"]: x for x in (store.get("sources") or {}).get("sources", [])}
    for i, x in enumerate(content.get("slots") or []):
        if x.get("mode", "replace") == "replace":
            if x["slot"] in seen:
                errs.append(f"'{x['slot']}' 칸을 바꾸는 화면이 둘입니다 — 하나만 (나머지는 '뒤에 추가')")
            seen.add(x["slot"])
        if not view_of(srcs.get(x["source"])):
            errs.append(f"{i + 1}번째: 연동 '{x['source']}' 에 화면(view)이 없습니다")
        if not _path_ok(x["path"].replace("{from}", "0").replace("{to}", "0")):
            errs.append(f"{i + 1}번째: 경로는 / 로 시작 (.. 금지)")
    if errs:
        raise SchemaError(errs)


def register(store):
    from .plugins import load_builtin
    load_builtin()                       # 참조 검증 전에 내장 수집기·파서·액션 등록
    store.add_validator("sources", sources)
    store.add_validator("rule", rule)
    store.add_validator("detection", detection)
    store.add_validator("playbook", playbook)
    store.add_validator("workflow", workflow)
    store.add_validator("lists", lists)
    store.add_validator("mail", mail)
    store.add_validator("reports", reports)
    store.add_validator("reputation", reputation)
    store.add_validator("embeds", embeds)
    from .topology import validate as topology
    store.add_validator("topology", topology)
