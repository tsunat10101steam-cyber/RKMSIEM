"""HTTP 수집기: POST /api/ingest/<source_id> 가 이 수집기로 들어온다 (스레드 없음, 수동형)."""
import json

from ..pipeline import make_record
from ..plugins import collector
from . import Collector


@collector("http")
class HttpCollector(Collector):
    def start(self):
        self.state = "passive"

    def stop(self, timeout=5):
        self.state = "stopped"

    def records_from_body(self, body, content_type):
        """JSON 객체 / JSON 배열 / NDJSON 을 레코드 목록으로. 잘못된 줄도 원본 보존을 위해 레코드로 넘김(파서가 실패 처리)."""
        text = body.decode("utf-8", "replace")
        items = []
        stripped = text.strip()
        if stripped.startswith("["):
            try:
                items = [json.dumps(x, ensure_ascii=False) if not isinstance(x, str) else x for x in json.loads(stripped)]
            except ValueError:
                items = [stripped]
        elif "ndjson" in (content_type or "") or "\n" in stripped:
            items = [l for l in stripped.splitlines() if l.strip()]
        elif stripped:
            items = [stripped]
        recs = []
        for raw in items:
            ev_id = None
            try:
                obj = json.loads(raw)
                if isinstance(obj, dict):
                    ev_id = obj.get(self.opt.get("id_field", "id"))
            except ValueError:
                pass
            recs.append(make_record(self.id, raw, event_id=str(ev_id) if ev_id else None))
        self.mark(len(recs))
        return recs
