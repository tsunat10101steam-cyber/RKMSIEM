"""수집기 공통 인터페이스. 새 수집기는 Collector 를 상속하고 @plugins.collector("이름") 으로 등록."""
import threading
import time


class Collector:
    type_name = "base"

    def __init__(self, cfg, pipeline, db, metrics):
        self.cfg, self.pipeline, self.db, self.metrics = cfg, pipeline, db, metrics
        self.id = cfg["id"]
        self.opt = cfg.get("options") or {}
        self._stop = threading.Event()
        self._thread = None
        self.state = "stopped"             # stopped | running | backpressure | error | passive
        self.last_error = None
        self.last_event_at = None
        self.received = 0

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._safe_run, name=f"collector:{self.id}", daemon=True)
        self._thread.start()

    def _safe_run(self):
        while not self._stop.is_set():
            try:
                self.state = "running"
                self.run()
                return
            except Exception as e:           # 수집기 하나가 죽어도 재시작 (다른 수집기와 격리)
                self.state, self.last_error = "error", f"{type(e).__name__}: {e}"
                self.metrics.inc("collector_errors_total", source=self.id)
                self._stop.wait(5)

    def run(self):
        raise NotImplementedError

    def stop(self, timeout=5):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)
        self.state = "stopped"

    def mark(self, n=1):
        self.received += n
        self.last_event_at = time.time()

    def status(self):
        return {"id": self.id, "type": self.type_name, "parser": self.cfg["parser"], "state": self.state,
                "sample": bool(self.cfg.get("sample")), "received": self.received,
                "last_event_at": self.last_event_at, "last_error": self.last_error,
                "alive": self.state == "passive" or bool(self._thread and self._thread.is_alive())}
