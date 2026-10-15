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
    from .topology import validate as topology
    store.add_validator("topology", topology)
