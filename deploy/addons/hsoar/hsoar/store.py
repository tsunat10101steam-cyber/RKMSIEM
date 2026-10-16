"""상태 파일 (JSON, 원자적 저장) — 피드 위치 · 이미 올린 메시지 · 일시 정지 · 자동 모드 · 자동 실행 시각."""
import json
import os
import threading
import time


class Store:
    def __init__(self, path):
        self.path, self._lock = path, threading.RLock()
        try:
            with open(path) as f:
                self.d = json.load(f)
        except (OSError, ValueError):
            self.d = {}
        self.d.setdefault("seq", None)
        self.d.setdefault("posted", {})          # 키(inc:12 · appr:5:block · task:5:identify) → {channel, ts}
        self.d.setdefault("paused", False)
        self.d.setdefault("auto_mode", None)     # None = policy.json 값
        self.d.setdefault("auto_log", [])        # 자동 실행 시각 (시간당 상한)

    def save(self):
        with self._lock:
            if len(self.d["posted"]) > 2000:     # 오래된 것부터 정리
                for k in list(self.d["posted"])[:-1500]:
                    del self.d["posted"][k]
            cut = time.time() - 3600
            self.d["auto_log"] = [t for t in self.d["auto_log"] if t > cut]
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.d, f, ensure_ascii=False)
            os.replace(tmp, self.path)

    def __getitem__(self, k):
        return self.d[k]

    def __setitem__(self, k, v):
        with self._lock:
            self.d[k] = v
