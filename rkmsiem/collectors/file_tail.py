"""파일 tail 수집기: 줄 단위로 따라 읽기 · 체크포인트 · 회전/잘림 감지 · 백프레셔."""
import hashlib
import os
import threading
import time

from ..pipeline import make_record
from ..plugins import collector
from ..settings import BASE_DIR
from . import Collector


@collector("file")
class FileTailCollector(Collector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        p = self.opt["path"]
        self.path = p if os.path.isabs(p) else os.path.join(BASE_DIR, p)
        self._acked = None
        self._lock = threading.Lock()

    def _file_id(self, st):
        return f"{getattr(st, 'st_ino', 0)}:{getattr(st, 'st_dev', 0)}"

    def _checkpoint(self, offset, fid):
        self.db.execute("INSERT INTO collector_offsets (source_id, path, offset, file_id, updated_at) VALUES (?,?,?,?,?) "
                        "ON CONFLICT(source_id) DO UPDATE SET path=excluded.path, offset=excluded.offset, "
                        "file_id=excluded.file_id, updated_at=excluded.updated_at",
                        (self.id, self.path, offset, fid, time.time()))

    def _ack(self, offset, fid):
        def done():
            with self._lock:
                if self._acked is None or offset > self._acked:
                    self._acked = offset
                    self._checkpoint(offset, fid)
        return done

    def run(self):
        poll = float(self.opt.get("poll_sec", 1.0))
        cp = self.db.one("SELECT offset, file_id FROM collector_offsets WHERE source_id=?", (self.id,))
        while not self._stop.is_set():
            if not os.path.exists(self.path):
                self.state, self.last_error = "waiting", f"file not found: {self.path}"
                self._stop.wait(poll)
                continue
            st = os.stat(self.path)
            fid = self._file_id(st)
            if cp and cp["file_id"] == fid and cp["offset"] <= st.st_size:
                offset = cp["offset"]
            elif cp and cp["file_id"] == fid:          # 잘림(truncate) → 처음부터
                offset = 0
            elif cp:                                    # 회전(rotate) → 새 파일 처음부터
                offset = 0
            else:
                offset = 0 if self.opt.get("from_beginning", True) else st.st_size
            cp = {"offset": offset, "file_id": fid}
            self.state, self.last_error = "running", None
            with open(self.path, "rb") as f:
                f.seek(offset)
                buf = b""
                while not self._stop.is_set():
                    chunk = f.read(65536)
                    if not chunk:
                        try:
                            st2 = os.stat(self.path)
                        except FileNotFoundError:
                            break
                        if self._file_id(st2) != fid or st2.st_size < f.tell():
                            break                       # 회전/잘림 → 바깥 루프에서 다시 열기
                        self._stop.wait(poll)
                        continue
                    buf += chunk
                    *lines, buf = buf.split(b"\n")
                    for line in lines:
                        start = offset
                        offset += len(line) + 1
                        text = line.decode("utf-8", "replace").rstrip("\r")
                        if not text.strip():
                            continue
                        # 키 = 파일·위치·내용 해시: 재시작 후 다시 읽은 줄은 중복으로 걸러지고, 잘린 뒤 같은 위치의 새 줄은 살아남음
                        key = f"{self.id}:{fid}:{start}:{hashlib.sha1(line).hexdigest()[:16]}"
                        rec = make_record(self.id, text, idem_key=key, ack=self._ack(offset, fid))
                        while not self.pipeline.submit(rec, timeout=1):     # 큐가 가득 → 대기(백프레셔)
                            self.state = "backpressure"
                            self.metrics.inc("backpressure_waits_total", source=self.id)
                            if self._stop.is_set():
                                return
                        self.state = "running"
                        self.mark()
                    cp = {"offset": offset - len(buf), "file_id": fid}
            cp = self.db.one("SELECT offset, file_id FROM collector_offsets WHERE source_id=?", (self.id,)) or cp
