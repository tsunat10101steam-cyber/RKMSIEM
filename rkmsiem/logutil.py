"""구조화 로그(JSON) + 민감 정보 마스킹."""
import json
import logging
import re
import sys
import time

_SECRET_KEYS = re.compile(r"(pass(word|wd)?|secret|token|api[_-]?key|authorization|cookie|ticket)", re.I)
_SECRET_INLINE = re.compile(
    r"(?i)((?:pass(?:word|wd)?|secret|token|api[_-]?key|authorization|ticket)\s*[\"']?\s*[:=]\s*[\"']?)(Bearer\s+)?([^\s\"'&,}]+)")


def mask_text(s):
    if not isinstance(s, str):
        return s
    return _SECRET_INLINE.sub(lambda m: m.group(1) + (m.group(2) or "") + "***", s)


def mask(obj):
    """dict/list 안의 민감한 키 값을 *** 로."""
    if isinstance(obj, dict):
        return {k: ("***" if _SECRET_KEYS.search(str(k)) else mask(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [mask(v) for v in obj]
    return mask_text(obj)


class _JsonFormatter(logging.Formatter):
    def format(self, r):
        d = {"ts": round(time.time(), 3), "level": r.levelname, "logger": r.name, "msg": mask_text(r.getMessage())}
        for k in ("trace_id", "source_id", "rule_id", "run_id", "incident_id"):
            if hasattr(r, k):
                d[k] = getattr(r, k)
        if r.exc_info:
            d["exc"] = mask_text(self.formatException(r.exc_info))
        return json.dumps(d, ensure_ascii=False)


def setup(level="INFO"):
    root = logging.getLogger()
    if any(isinstance(h.formatter, _JsonFormatter) for h in root.handlers):
        return
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(_JsonFormatter())
    root.handlers[:] = [h]
    root.setLevel(level)
    logging.getLogger("werkzeug").setLevel("WARNING")   # 요청 URL(쿼리 포함) 로그 억제
