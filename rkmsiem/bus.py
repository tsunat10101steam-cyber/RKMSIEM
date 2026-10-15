"""실시간 이벤트 버스 (SSE 구독자에게 전달). 느린 구독자는 버퍼가 차면 끊어 서버 전체를 막지 않는다."""
import itertools
import queue
import threading
import time


class Bus:
    def __init__(self, buffer=500):
        self._subs = set()
        self._lock = threading.Lock()
        self._buffer = buffer
        self._seq = itertools.count(1)

    def subscribe(self):
        q = queue.Queue(self._buffer)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def publish(self, kind, data):
        msg = {"id": next(self._seq), "type": kind, "ts": time.time(), "data": data}
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(msg)
            except queue.Full:                 # 따라오지 못하는 구독자 → 끊기 신호
                with self._lock:
                    self._subs.discard(q)
                try:
                    q.get_nowait()
                    q.put_nowait({"type": "_overflow"})
                except (queue.Empty, queue.Full):
                    pass

    def count(self):
        with self._lock:
            return len(self._subs)
