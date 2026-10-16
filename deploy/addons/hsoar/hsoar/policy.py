"""자동 대응 등급 — policy.json

{"notify": {"min_severity": "high", "approvals": true, "tasks": true},
 "auto":   {"mode": "dry", "max_per_hour": 10},            mode: off(제안도 안 함) · dry(Slack 에 제안만, 사람이 [실행]) · on(auto 등급은 바로 실행)
 "rules":  [{"name": "...", "when": {"rule": ["auth_bruteforce"], "min_severity": "critical"},
             "do": {"action": "block_ip", "target": "source.ip", "duration_sec": 3600}, "tier": "auto"}]}
tier: auto(자동 — mode=on 일 때만) · confirm(항상 Slack 버튼으로 사람 확인) · never(제안하지 않음)
action: block_ip · disable_account (보호 목록·차단 금지는 핵심이 거부)
"""
import json

SEV = {"low": 0, "medium": 1, "high": 2, "critical": 3}
ACTIONS = {"block_ip": "IP 차단", "disable_account": "계정 잠금"}
DEFAULT = {
    "notify": {"min_severity": "high", "approvals": True, "tasks": True},
    "auto": {"mode": "dry", "max_per_hour": 10},
    "rules": [
        {"name": "무차별 대입(심각) → 공격 IP 1시간 차단", "when": {"rule": ["auth_bruteforce", "distributed_attack"], "min_severity": "critical"},
         "do": {"action": "block_ip", "target": "source.ip", "duration_sec": 3600}, "tier": "auto"},
        {"name": "실패 뒤 로그인 성공 → 계정 잠금 (사람 확인)", "when": {"rule": ["compromise_after_failures", "spray_success", "ids_then_login"]},
         "do": {"action": "disable_account", "target": "user.name"}, "tier": "confirm"},
        {"name": "IDS 경보 후 로그인 → 공격 IP 차단 (사람 확인)", "when": {"rule": ["ids_then_login"]},
         "do": {"action": "block_ip", "target": "source.ip", "duration_sec": 86400}, "tier": "confirm"},
    ],
}


class PolicyError(ValueError):
    pass


def load(path):
    try:
        with open(path) as f:
            p = json.load(f)
    except FileNotFoundError:
        p = json.loads(json.dumps(DEFAULT))
    validate(p)
    return p


def validate(p):
    errs = []
    if p.get("auto", {}).get("mode", "dry") not in ("off", "dry", "on"):
        errs.append("auto.mode 는 off · dry · on")
    if p.get("notify", {}).get("min_severity", "high") not in SEV:
        errs.append("notify.min_severity 는 low · medium · high · critical")
    for i, r in enumerate(p.get("rules") or []):
        d = r.get("do") or {}
        if d.get("action") not in ACTIONS:
            errs.append(f"rules[{i}].do.action 은 {', '.join(ACTIONS)}")
        if r.get("tier", "confirm") not in ("auto", "confirm", "never"):
            errs.append(f"rules[{i}].tier 는 auto · confirm · never")
        if (r.get("when") or {}).get("min_severity", "low") not in SEV:
            errs.append(f"rules[{i}].when.min_severity 이상")
    if errs:
        raise PolicyError("; ".join(errs))


def matches(rule, alert):
    w = rule.get("when") or {}
    if w.get("rule") and alert.get("rule_id") not in w["rule"]:
        return False
    return SEV.get(alert.get("severity"), 0) >= SEV.get(w.get("min_severity", "low"), 0)


def plan(policy, alert):
    """이 경보에 대한 제안 목록 [(규칙, 대상 값)] — 대상 값이 경보에 없으면 뺌, 같은 (조치, 대상)은 한 번."""
    out, seen = [], set()
    for r in policy.get("rules") or []:
        if r.get("tier") == "never" or not matches(r, alert):
            continue
        v = (alert.get("group") or {}).get(r["do"].get("target") or ("source.ip" if r["do"]["action"] == "block_ip" else "user.name"))
        key = (r["do"]["action"], v)
        if v and key not in seen:
            seen.add(key)
            out.append((r, str(v)))
    return out
