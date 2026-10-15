"""journald 수집기 (Linux): `journalctl -f -o json` 을 따라 읽고 커서를 체크포인트한다.

- 처리(저장) 완료된 이벤트의 __CURSOR 만 저장 → 재시작 시 --after-cursor 로 이어 읽기 (최소 1회)
- 멱등성 키 = 커서 (journald 가 엔트리마다 고유하게 부여)
- 권한: 서비스 계정이 systemd-journal (또는 adm) 그룹에 속해야 시스템 저널을 읽을 수 있다
options:
  units: [ssh.service]            # 비우면 전체 저널 (권장하지 않음 — 양이 많음)
  identifiers: [sshd, sudo, su]   # SYSLOG_IDENTIFIER 필터 (-t)
  since: "-1h"                    # 체크포인트가 없을 때 시작 지점 (journalctl --since 형식, 기본 now)
  journalctl: /usr/bin/journalctl
"""
import json
import shutil
import subprocess
import threading
import time

from ..pipeline import make_record
from ..plugins import collector
from . import Collector


@collector("journald")
class JournaldCollector(Collector):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.proc = None
        self._lock = threading.Lock()
        self._acked = None

    def _argv(self, cursor):
        exe = self.opt.get("journalctl") or shutil.which("journalctl") or "/usr/bin/journalctl"
        argv = (list(exe) if isinstance(exe, list) else [exe]) + ["--follow", "--output=json", "--no-pager", "--all"]
        for u in self.opt.get("units", []):
            argv += ["--unit", str(u)]
        for t in self.opt.get("identifiers", []):
            argv += ["--identifier", str(t)]
        if cursor:
            argv += ["--after-cursor", cursor]
        else:
            argv += ["--since", str(self.opt.get("since", "now"))]
        return argv

    def _ack(self, cursor):
        def done():
            with self._lock:
                self._acked = cursor
                self.db.execute("INSERT INTO collector_offsets (source_id, path, offset, file_id, updated_at) VALUES (?,?,?,?,?) "
                                "ON CONFLICT(source_id) DO UPDATE SET file_id=excluded.file_id, updated_at=excluded.updated_at",
                                (self.id, "journald", 0, cursor, time.time()))
        return done

    def run(self):
        while not self._stop.is_set():
            row = self.db.one("SELECT file_id FROM collector_offsets WHERE source_id=?", (self.id,))
            cursor = row["file_id"] if row else None
            try:
                self.proc = subprocess.Popen(self._argv(cursor), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                self.state, self.last_error = "error", "journalctl 을 찾을 수 없습니다 (Linux/systemd 전용)"
                self._stop.wait(30)
                continue
            self.state, self.last_error = "running", None
            for line in self.proc.stdout:
                if self._stop.is_set():
                    break
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    cur = json.loads(text).get("__CURSOR")
                except ValueError:
                    cur = None
                rec = make_record(self.id, text, idem_key=f"{self.id}:{cur}" if cur else None, ack=self._ack(cur) if cur else None)
                while not self.pipeline.submit(rec, timeout=1):
                    self.state = "backpressure"
                    if self._stop.is_set():
                        break
                self.state = "running"
                self.mark()
            if self.proc.poll() is None:
                self.proc.terminate()
            err = self.proc.stderr.read().decode("utf-8", "replace")[-500:] if self.proc.stderr else ""
            if not self._stop.is_set():
                self.state, self.last_error = "error", f"journalctl 종료 (rc={self.proc.wait()}): {err.strip()}"
                self._stop.wait(5)                      # 잠시 후 재시작

    def stop(self, timeout=5):
        self._stop.set()
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        super().stop(timeout)
