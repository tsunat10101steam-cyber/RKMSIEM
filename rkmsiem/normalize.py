"""정규화: 파서 결과 + 공통 필드 → ECS 부분집합 문서. 잘못된 이벤트는 예외로 DLQ 에 보낸다."""
import getpass
import re
from datetime import datetime, timezone

from . import schemas
from .plugins import PARSERS


class NormalizeError(ValueError):
    pass


# RKMSIEM 자신의 정상 동작 (서비스 계정이 승인된 헬퍼를 sudo 로 실행 — 계정 잠금 대응·자가 점검)은
# 권한 상승으로 보지 않도록 event.action 을 service_helper 로 바꾼다. 그 밖의 sudo 사용은 그대로 감시.
_SELF = {"user": None, "commands": ["/usr/local/lib/rkmsiem/rkmsiem-account"]}


def configure_self(user=None, commands=None):
    try:
        _SELF["user"] = user or getpass.getuser()
    except Exception:     # noqa: BLE001
        _SELF["user"] = None
    if commands:
        _SELF["commands"] = [c for c in commands if c]


def _is_self_helper(doc):
    ev, msg = doc.get("event") or {}, doc.get("message") or ""
    if ev.get("action") != "privilege_use" or not _SELF["user"] or (doc.get("user") or {}).get("name") != _SELF["user"]:
        return False
    return any(re.search(r"(?:^|;\s*)COMMAND=" + re.escape(c) + r"(?:\s|$)", msg) for c in _SELF["commands"])


def normalize(rec, source_cfg):
    parser = PARSERS.get(source_cfg["parser"])
    if parser is None:
        raise NormalizeError(f"unknown parser {source_cfg['parser']}")
    doc = parser(rec["raw"], source_cfg.get("options") or {})
    ev = doc.setdefault("event", {})
    ev["created"] = datetime.fromtimestamp(rec["received_at"], timezone.utc).isoformat()
    ev["dataset"] = source_cfg.get("dataset", source_cfg["id"])
    ev.setdefault("outcome", "unknown")
    if rec.get("event_id"):
        ev["id"] = rec["event_id"]
    labels = doc.setdefault("labels", {})
    labels["source_id"] = source_cfg["id"]
    labels["sample"] = bool(source_cfg.get("sample"))
    if _is_self_helper(doc):
        ev["action"] = "service_helper"
        labels["self_activity"] = True
    doc["trace"] = {"id": rec["trace_id"]}
    doc["rkmsiem"] = {"raw_ref": rec["idem_key"]}
    try:
        schemas.validate(schemas.EVENT, doc)
    except schemas.SchemaError as e:
        raise NormalizeError(str(e)) from e
    ts = datetime.fromisoformat(doc["@timestamp"]).timestamp()
    return doc, ts


def columns(doc):
    """검색용 컬럼 (전체 문서는 doc 에 JSON 으로 보관)."""
    ev = doc.get("event", {})
    return {
        "dataset": ev.get("dataset"), "category": ",".join(ev.get("category") or []), "action": ev.get("action"),
        "outcome": ev.get("outcome"), "severity": ev.get("severity"),
        "user_name": (doc.get("user") or {}).get("name"), "source_ip": (doc.get("source") or {}).get("ip"),
        "host_name": (doc.get("host") or {}).get("name"), "message": (doc.get("message") or "")[:2000],
    }
