"""조건식 DSL: 규칙(where/exceptions/modifiers)과 플레이북(trigger/when)이 함께 쓴다.

조건 = {field: 점 경로, op: 연산자, value: 값}. 목록 안 조건은 모두 참이어야 참(AND).
코드에서 eval 을 쓰지 않는다 — 정해진 연산자만 해석한다.
"""
import ipaddress
import re

_MISSING = object()


def get_path(doc, path):
    """'source.ip' 같은 점 경로로 값 찾기. 키 자체에 점이 있는 경우(alert.group 의 'source.ip')도 처리."""
    parts = path.split(".")
    cur = doc
    i = 0
    while i < len(parts):
        if isinstance(cur, dict):
            for j in range(len(parts), i, -1):          # 가장 긴 키부터 시도
                k = ".".join(parts[i:j])
                if k in cur:
                    cur, i = cur[k], j
                    break
            else:
                return _MISSING
        elif isinstance(cur, list) and parts[i].isdigit() and int(parts[i]) < len(cur):
            cur, i = cur[int(parts[i])], i + 1
        else:
            return _MISSING
    return cur


def value_of(doc, path, default=None):
    v = get_path(doc, path)
    return default if v is _MISSING else v


class Lists:
    """이름 있는 목록(config/lists.yaml) 조회 — CIDR 은 미리 컴파일."""

    def __init__(self, lists_cfg):
        self._lists = {}
        for name, spec in (lists_cfg or {}).items():
            if spec["kind"] == "cidr":
                self._lists[name] = ("cidr", [ipaddress.ip_network(v, strict=False) for v in spec["values"]])
            else:
                self._lists[name] = ("value", set(spec["values"]))

    def names(self):
        return set(self._lists)

    def contains(self, name, value):
        if name not in self._lists or value is None:
            return False
        kind, vals = self._lists[name]
        if kind == "value":
            return str(value) in vals
        try:
            ip = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        return any(ip in n for n in vals)


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def check(cond, doc, lists=None):
    v = get_path(doc, cond["field"])
    op, target = cond["op"], cond.get("value")
    if op == "exists":
        return v is not _MISSING and v is not None and v != ""
    if op == "not_exists":
        return v is _MISSING or v is None or v == ""
    if v is _MISSING:
        return op in ("ne", "not_in", "not_in_list")
    if op == "eq":
        return v == target
    if op == "ne":
        return v != target
    if op == "in":
        return v in (target or [])
    if op == "not_in":
        return v not in (target or [])
    if op == "contains":
        return target in v if isinstance(v, (list, str)) else False
    if op == "regex":
        return isinstance(v, str) and re.search(target, v) is not None
    if op in ("gt", "gte", "lt", "lte"):
        a, b = _num(v), _num(target)
        if a is None or b is None:
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "in_list":
        return bool(lists and lists.contains(target, v))
    if op == "not_in_list":
        return not (lists and lists.contains(target, v))
    raise ValueError(f"unknown op {op}")


def check_all(conds, doc, lists=None):
    return all(check(c, doc, lists) for c in (conds or []))


def referenced_lists(conds):
    return {c["value"] for c in (conds or []) if c["op"] in ("in_list", "not_in_list")}


def validate_regexes(conds):
    for c in conds or []:
        if c["op"] == "regex":
            re.compile(c["value"])


_TPL = re.compile(r"\{\{\s*([A-Za-z0-9_.@-]+)\s*\}\}")


def render(obj, ctx):
    """플레이북 입력 템플릿 {{ path }} 치환. 문자열 전체가 템플릿 하나면 원래 타입 유지."""
    if isinstance(obj, dict):
        return {k: render(v, ctx) for k, v in obj.items()}
    if isinstance(obj, list):
        return [render(v, ctx) for v in obj]
    if isinstance(obj, str):
        m = _TPL.fullmatch(obj.strip())
        if m:
            return value_of(ctx, m.group(1))
        return _TPL.sub(lambda mm: "" if value_of(ctx, mm.group(1)) is None else str(value_of(ctx, mm.group(1))), obj)
    return obj
