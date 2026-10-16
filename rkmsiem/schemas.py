"""데이터 계약: 설정·규칙·플레이북·정규화 이벤트의 JSON Schema.

모든 설정은 이 스키마로 검증된 뒤에만 적용된다(잘못된 설정은 거부되고 기존 버전이 유지됨).
"""
from jsonschema import Draft202012Validator

SEVERITIES = ["info", "low", "medium", "high", "critical"]

_condition = {
    "type": "object",
    "required": ["field", "op"],
    "additionalProperties": False,
    "properties": {
        "field": {"type": "string", "minLength": 1},
        "op": {"enum": ["eq", "ne", "in", "not_in", "contains", "regex", "gt", "gte", "lt", "lte",
                        "exists", "not_exists", "in_list", "not_in_list"]},
        "value": {},
    },
}
_conditions = {"type": "array", "items": _condition}
_level = {
    "type": "object",
    "required": ["id", "min", "severity", "title"],
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "pattern": "^[A-Z][A-Z0-9_]*$"},
        "min": {"type": "integer", "minimum": 1},
        "severity": {"enum": SEVERITIES},
        "title": {"type": "string"},
        "basis": {"type": "string"},
    },
}
_modifier = {
    "type": "object",
    "required": ["when", "severity_delta"],
    "additionalProperties": False,
    "properties": {"when": _conditions, "severity_delta": {"type": "integer", "minimum": -4, "maximum": 4},
                   "note": {"type": "string"}},
}

RULE = {
    "type": "object",
    "required": ["id", "name", "type", "where", "group_by", "levels"],
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "enabled": {"type": "boolean"},
        "type": {"enum": ["match", "threshold", "distinct_count", "sequence"]},
        "where": _conditions,                       # 규칙에 들어오는 이벤트 조건 (sequence 는 first/then 이 따로 가짐)
        "group_by": {"type": "array", "items": {"type": "string"}, "minItems": 0},
        "window_sec": {"type": "integer", "minimum": 1},
        "distinct_field": {"type": "string"},
        "first": {
            "type": "object", "additionalProperties": False, "required": ["where"],
            "properties": {"where": _conditions, "window_sec": {"type": ["integer", "null"], "minimum": 1},
                           "distinct_field": {"type": "string"}},
        },
        "then": {
            "type": "object", "additionalProperties": False, "required": ["where"],
            "properties": {"where": _conditions, "within_sec": {"type": ["integer", "null"], "minimum": 1},
                           "lookback_sec": {"type": ["integer", "null"], "minimum": 1}},
        },
        "reset_on_then": {"type": "boolean"},
        "levels": {"type": "array", "items": _level, "minItems": 1},
        "unless_rules": {"type": "array", "items": {"type": "string"}},
        "unless_match_fields": {"type": "array", "items": {"type": "string"}},
        "unless_lookback_sec": {"type": "integer", "minimum": 1},
        "suppress_sec": {"type": "integer", "minimum": 0},
        "exceptions": _conditions,
        "modifiers": {"type": "array", "items": _modifier},
        "incident_key": {"type": "array", "items": {"type": "string"}},
        "risk": {"type": "object"},
        "tags": {"type": "array", "items": {"type": "string"}},
    },
    "allOf": [
        {"if": {"properties": {"type": {"const": "threshold"}}}, "then": {"required": ["window_sec"]}},
        {"if": {"properties": {"type": {"const": "distinct_count"}}}, "then": {"required": ["window_sec", "distinct_field"]}},
        {"if": {"properties": {"type": {"const": "sequence"}}}, "then": {"required": ["first", "then"]}},
    ],
}

DETECTION_POLICY = {
    "type": "object",
    "required": ["severity_risk", "default_suppress_sec"],
    "additionalProperties": False,
    "properties": {
        "severity_risk": {"type": "object", "properties": {s: {"type": "number"} for s in SEVERITIES},
                          "required": SEVERITIES},
        "risk_per_event": {"type": "number", "minimum": 0},
        "risk_max": {"type": "number", "minimum": 0},
        "default_suppress_sec": {"type": "integer", "minimum": 0},
        "evidence_cap": {"type": "integer", "minimum": 1},
        "global_exceptions": _conditions,
        "global_modifiers": {"type": "array", "items": _modifier},
        "threat_levels": {"type": "array"},
    },
}

LISTS = {
    "type": "object",
    "additionalProperties": {
        "type": "object", "required": ["kind", "values"], "additionalProperties": False,
        "properties": {"kind": {"enum": ["cidr", "value"]}, "values": {"type": "array", "items": {"type": "string"}},
                       "description": {"type": "string"}, "sample": {"type": "boolean"}},
    },
}

SOURCES = {
    "type": "object",
    "required": ["sources"],
    "properties": {"sources": {"type": "array", "items": {
        "type": "object", "required": ["id", "type", "parser"],
        "properties": {
            "id": {"type": "string", "pattern": "^[a-z][a-z0-9_-]*$"},
            "type": {"type": "string"},
            "parser": {"type": "string"},
            "enabled": {"type": "boolean"},
            "sample": {"type": "boolean"},
            "dataset": {"type": "string"},
            "options": {"type": "object"},
        }}}},
}

WORKFLOW = {
    "type": "object",
    "required": ["states", "initial", "transitions"],
    "properties": {
        "states": {"type": "array", "items": {"type": "object", "required": ["id", "label"],
                                               "properties": {"id": {"type": "string"}, "label": {"type": "string"},
                                                              "terminal": {"type": "boolean"}}}},
        "initial": {"type": "string"},
        "transitions": {"type": "array", "items": {"type": "object", "required": ["from", "to"],
                                                    "properties": {"from": {"type": "string"},
                                                                   "to": {"type": "array", "items": {"type": "string"}},
                                                                   "require_reason": {"type": "boolean"}}}},
        "grouping": {"type": "object"},
    },
}

RBAC = {
    "type": "object",
    "required": ["roles"],
    "properties": {"roles": {"type": "object", "additionalProperties": {
        "type": "object", "required": ["permissions"],
        "properties": {"label": {"type": "string"}, "permissions": {"type": "array", "items": {"type": "string"}}}}}},
}

APPROVAL = {
    "type": "object",
    "required": ["require_approval_for", "approver_roles"],
    "properties": {
        "require_approval_for": {"enum": ["destructive", "all", "none"]},
        "approver_roles": {"type": "array", "items": {"type": "string"}},
        "forbid_self_approval": {"type": "boolean"},
        "timeout_sec": {"type": "integer", "minimum": 1},
        "webhook_allowlist": {"type": "array", "items": {"type": "string"}},
    },
}

PLAYBOOK = {
    "type": "object",
    "required": ["id", "name", "trigger", "steps"],
    "additionalProperties": False,
    "properties": {
        "id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
        "name": {"type": "string"},
        "description": {"type": "string"},
        "enabled": {"type": "boolean"},
        "trigger": {"type": "object", "required": ["on"], "additionalProperties": False,
                    "properties": {"on": {"enum": ["alert", "incident", "manual"]}, "where": _conditions,
                                   "once_per": {"enum": ["alert", "incident"]}}},
        "steps": {"type": "array", "minItems": 1, "items": {
            "type": "object", "required": ["id", "action"], "additionalProperties": False,
            "properties": {
                "id": {"type": "string", "pattern": "^[a-z][a-z0-9_]*$"},
                "action": {"type": "string"},
                "input": {"type": "object"},
                "when": _conditions,
                "timeout_sec": {"type": "number", "minimum": 0.1},
                "retries": {"type": "integer", "minimum": 0, "maximum": 10},
                "retry_backoff_sec": {"type": "number", "minimum": 0},
                "on_failure": {"enum": ["abort", "continue", "compensate"]},
                "approval": {"enum": ["policy", "required", "none"]},
                "compensate": {"type": "object", "required": ["action"],
                               "properties": {"action": {"type": "string"}, "input": {"type": "object"}}},
            }}},
    },
}

_addrs = {"type": "array", "items": {"type": "string", "maxLength": 254}, "maxItems": 200}
MAIL = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "enabled": {"type": "boolean"},
        "host": {"type": "string", "maxLength": 253},
        "port": {"type": "integer", "minimum": 1, "maximum": 65535},
        "security": {"enum": ["starttls", "ssl", "none"]},
        "username": {"type": "string", "maxLength": 254},
        "from": {"type": "string", "maxLength": 300},
        "subject_prefix": {"type": "string", "maxLength": 50},
        "console_url": {"type": "string", "maxLength": 300},
        "timeout_sec": {"type": "number", "minimum": 1, "maximum": 120},
        "retries": {"type": "integer", "minimum": 0, "maximum": 10},
        "retry_backoff_sec": {"type": "number", "minimum": 0, "maximum": 300},
        "max_per_hour": {"type": "integer", "minimum": 1, "maximum": 10000},
        "max_size_mb": {"type": "number", "minimum": 1, "maximum": 50},
        "allowed_recipients": _addrs,
        "alerts": {"type": "object", "additionalProperties": False, "properties": {
            "enabled": {"type": "boolean"}, "to": _addrs, "min_severity": {"enum": SEVERITIES},
            "batch_sec": {"type": "integer", "minimum": 0, "maximum": 3600}, "approvals": {"type": "boolean"}}},
    },
}
REPORTS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "font": {"type": "string"},
        "incident_on_close": {"type": "object", "additionalProperties": False, "properties": {"enabled": {"type": "boolean"}, "to": _addrs}},
        "schedule": {"type": "array", "maxItems": 20, "items": {
            "type": "object", "required": ["name", "every", "at"], "additionalProperties": False,
            "properties": {"name": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,30}$"},
                           "every": {"enum": ["day", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]},
                           "at": {"type": "string", "pattern": "^([01][0-9]|2[0-3]):[0-5][0-9]$"},
                           "period_hours": {"type": "number", "minimum": 1, "maximum": 8760}, "to": _addrs, "enabled": {"type": "boolean"}}}},
    },
}
REPUTATION = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"abuseipdb": {"type": "object", "additionalProperties": False, "properties": {
        "enabled": {"type": "boolean"}, "max_age_days": {"type": "integer", "minimum": 1, "maximum": 365},
        "timeout_sec": {"type": "number", "minimum": 1, "maximum": 60}, "cache_ttl_sec": {"type": "integer", "minimum": 0, "maximum": 604800},
        "malicious_score": {"type": "integer", "minimum": 1, "maximum": 100}, "suspicious_score": {"type": "integer", "minimum": 0, "maximum": 100}}}},
}

# 대시보드(dashboard all) 칸에 끼우는 Grafana 단일 패널 (d-solo) — 콘솔 settings 'API 토큰 · Grafana' 탭에서 편집
GRAFANA_SLOTS = ["threat", "kpi", "alerts", "hourly", "top", "targets", "map", "timeline", "incidents", "runs", "ips", "collectors"]
GRAFANA_PANELS = {
    "type": "object",
    "additionalProperties": False,
    "properties": {"slots": {"type": "array", "maxItems": 12, "items": {
        "type": "object", "required": ["slot", "uid", "panel_id"], "additionalProperties": False,
        "properties": {"slot": {"enum": GRAFANA_SLOTS}, "mode": {"enum": ["replace", "after"]},
                       "uid": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,64}$"}, "panel_id": {"type": "integer", "minimum": 1, "maximum": 100000},
                       "title": {"type": "string", "maxLength": 64}, "span": {"type": "integer", "minimum": 3, "maximum": 12},
                       "height": {"type": "integer", "minimum": 120, "maximum": 1200}}}}},
}

TOPOLOGY = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "nodes": {"type": "array", "maxItems": 500, "items": {
            "type": "object", "required": ["id", "type", "x", "y"], "additionalProperties": False,
            "properties": {"id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$"}, "label": {"type": "string", "maxLength": 64},
                           "type": {"enum": ["siem", "server", "router", "switch", "firewall", "ids", "pc", "attacker", "cloud", "other"]},
                           "ip": {"type": "string", "maxLength": 45}, "note": {"type": "string", "maxLength": 200},
                           "interfaces": {"type": "array", "maxItems": 64, "items": {          # 라우터·방화벽·SIEM 처럼 IP 가 여러 개인 기기
                               "type": "object", "additionalProperties": False,
                               "properties": {"name": {"type": "string", "maxLength": 32}, "ip": {"type": "string", "maxLength": 45},
                                              "prefix": {"type": "integer", "minimum": 0, "maximum": 128}}}},
                           "x": {"type": "number"}, "y": {"type": "number"}}}},
        "links": {"type": "array", "maxItems": 2000, "items": {
            "type": "object", "required": ["id", "from", "to"], "additionalProperties": False,
            "properties": {"id": {"type": "string", "pattern": "^[A-Za-z0-9_-]{1,40}$"}, "from": {"type": "string"}, "to": {"type": "string"},
                           "label": {"type": "string", "maxLength": 40},
                           "from_if": {"type": "string", "maxLength": 32}, "to_if": {"type": "string", "maxLength": 32}}}},
    },
}

ASSETS = {"type": "object", "properties": {"accounts": {"type": "array"}, "hosts": {"type": "array"}, "sample": {"type": "boolean"}}}
INTEL = {"type": "object", "properties": {"entries": {"type": "array"}, "sample": {"type": "boolean"}}}

SETTINGS = {
    "type": "object",
    "required": ["database", "pipeline", "retention", "soar", "api"],
    "properties": {
        "env": {"type": "string"},
        "timezone": {"type": "string"},
        "plugins": {"type": "array", "items": {"type": "string"}},
        "database": {"type": "object", "required": ["path"]},
        "pipeline": {"type": "object", "required": ["queue_size", "batch_size"]},
        "retention": {"type": "object"},
        "soar": {"type": "object", "required": ["mode"], "properties": {"mode": {"enum": ["simulate", "live"]}}},
        "api": {"type": "object", "required": ["host", "port"]},
        "incidents": {"type": "object"},
    },
}

# 정규화 이벤트 (ECS 부분집합)
EVENT = {
    "type": "object",
    "required": ["@timestamp", "event"],
    "properties": {
        "@timestamp": {"type": "string"},
        "event": {"type": "object", "required": ["created", "dataset"],
                  "properties": {"category": {"type": "array", "items": {"type": "string"}},
                                 "outcome": {"enum": ["success", "failure", "unknown"]},
                                 "severity": {"type": "integer"}}},
        "source": {"type": "object", "properties": {"ip": {"type": "string"}}},
        "user": {"type": "object", "properties": {"name": {"type": "string"}}},
        "host": {"type": "object"},
        "labels": {"type": "object"},
    },
}

KINDS = {
    "rule": RULE, "playbook": PLAYBOOK, "detection": DETECTION_POLICY, "lists": LISTS, "sources": SOURCES,
    "workflow": WORKFLOW, "rbac": RBAC, "approval": APPROVAL, "assets": ASSETS, "intel": INTEL,
    "mail": MAIL, "reports": REPORTS, "reputation": REPUTATION, "topology": TOPOLOGY, "grafana_panels": GRAFANA_PANELS,
}


class SchemaError(ValueError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("; ".join(errors))


def validate(kind_or_schema, doc):
    schema = KINDS[kind_or_schema] if isinstance(kind_or_schema, str) else kind_or_schema
    errs = sorted(Draft202012Validator(schema).iter_errors(doc), key=lambda e: list(e.path))
    if errs:
        raise SchemaError([f"{'/'.join(map(str, e.path)) or '(root)'}: {e.message}" for e in errs[:20]])
    return doc
