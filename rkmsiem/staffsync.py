"""담당자 명단 연동 — 별도 '담당자 관리' 앱(staffdir)에서 명단을 가져와 staff_directory 에 보관.

- 가져오기: GET <staff.url>/api/sync/people (헤더 X-Sync-Key = 환경 변수 RKMSIEM_STAFF_SYNC_KEY)
- 주기: staff.sync_interval_sec (기본 60초) + 담당자 앱이 변경을 알리면(POST /api/staff/hook) 바로
- 명단은 담당자 앱이 기준: 받은 명단으로 통째로 바꾼다(없어진 사람은 빠짐). 실패하면 마지막 명단을 그대로 쓴다.
- 지난 사건의 담당 기록(아이디)은 명단과 상관없이 그대로 남는다.
"""
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request

log = logging.getLogger("rkmsiem.staff")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
COLS = ("username", "display_name", "team", "email", "phone", "notify_assign", "active", "updated_at")


class StaffSyncError(RuntimeError):
    pass


class StaffSync:
    def __init__(self, platform):
        self.p = platform
        s = platform.settings
        self.url = (s.get("staff.url") or "").rstrip("/")
        self.public_url = s.get("staff.public_url") or ""
        self.interval = max(10, int(s.get("staff.sync_interval_sec", 60)))
        self.timeout = int(s.get("staff.timeout_sec", 5))
        self.key = s.secret("RKMSIEM_STAFF_SYNC_KEY") or ""
        self.fetch = self._http_fetch                 # 테스트에서 바꿔 끼움
        self.state = {"last_ok": None, "last_try": None, "last_error": None, "version": None, "count": None, "changed_at": None}
        self._kick, self._stop = threading.Event(), threading.Event()
        self._lock = threading.Lock()

    @property
    def configured(self):
        return bool(self.url and self.key)

    def _http_fetch(self):
        req = urllib.request.Request(f"{self.url}/api/sync/people", headers={"X-Sync-Key": self.key, "X-Client": "rkmsiem",
                                                                              "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise StaffSyncError("연동 키가 맞지 않습니다" if e.code == 401 else f"담당자 앱 응답 오류 {e.code}") from None
        except (urllib.error.URLError, OSError) as e:
            raise StaffSyncError(f"담당자 앱에 연결할 수 없습니다 ({getattr(e, 'reason', e)})") from None

    @staticmethod
    def _clean(items):
        out = {}
        for it in items if isinstance(items, list) else []:
            if not isinstance(it, dict) or not USERNAME_RE.match(str(it.get("username") or "")):
                continue
            row = {"username": it["username"]}
            for k, n in (("display_name", 64), ("team", 64), ("email", 254), ("phone", 32)):
                v = it.get(k)
                row[k] = str(v)[:n] if isinstance(v, str) and v.strip() else None
            row["notify_assign"] = int(bool(it.get("notify_assign", 1)))
            row["active"] = int(bool(it.get("active", 1)))
            row["updated_at"] = it.get("updated_at") if isinstance(it.get("updated_at"), (int, float)) else None
            out[row["username"]] = row
        return out

    def sync(self, actor="system", force=False):
        """담당자 앱에서 명단을 가져와 바꾼다. 결과: {"ok", "changed", "added", "removed", "updated", "count"}."""
        if not self.configured:
            raise StaffSyncError("담당자 앱 연동이 설정되지 않았습니다 (staff.url · RKMSIEM_STAFF_SYNC_KEY)")
        with self._lock:
            self.state["last_try"] = time.time()
            try:
                data = self.fetch()
                if not isinstance(data, dict) or not isinstance(data.get("items"), list):
                    raise StaffSyncError("담당자 앱 응답 형식이 올바르지 않습니다")
            except StaffSyncError as e:
                self.state["last_error"] = str(e)
                self.p.metrics.inc("staff_sync_errors_total")
                raise
            rows = self._clean(data["items"])
            now = time.time()
            self.state.update(last_ok=now, last_error=None, count=sum(r["active"] for r in rows.values()))
            if not force and data.get("version") and data["version"] == self.state["version"]:
                return {"ok": True, "changed": False, "count": self.state["count"]}
            with self.p.db.tx() as c:
                old = {r["username"]: dict(r) for r in c.execute(f"SELECT {', '.join(COLS)} FROM staff_directory")}
                added = sorted(set(rows) - set(old))
                removed = sorted(set(old) - set(rows))
                updated = sorted(u for u in set(rows) & set(old) if any(rows[u][k] != old[u][k] for k in COLS))
                if removed:
                    c.execute(f"DELETE FROM staff_directory WHERE username IN ({','.join('?' * len(removed))})", removed)
                for u in added + updated:
                    r = rows[u]
                    c.execute(f"INSERT OR REPLACE INTO staff_directory ({', '.join(COLS)}, synced_at) VALUES ({','.join('?' * (len(COLS) + 1))})",
                              [r[k] for k in COLS] + [now])
                c.execute("UPDATE staff_directory SET synced_at=?", (now,))
                changed = bool(added or removed or updated)
                if changed:
                    self.p.audit.record(actor, "staff.sync", "staff", None, None,
                                        {"added": added, "removed": removed, "updated": updated}, conn=c)   # 아이디만 (연락처 값은 남기지 않음)
            self.state["version"] = data.get("version")
            if changed:
                self.state["changed_at"] = now
                self.p.bus.publish("staff", {"added": len(added), "removed": len(removed), "updated": len(updated)})
            return {"ok": True, "changed": changed, "added": added, "removed": removed, "updated": updated, "count": self.state["count"]}

    def kick(self):
        self._kick.set()

    def loop(self):
        if not self.configured:
            return
        fails = 0
        while not self._stop.is_set():
            try:
                self.sync()
                fails = 0
            except StaffSyncError as e:
                fails += 1
                if fails == 1 or fails % 10 == 0:
                    log.warning("staff sync: %s (마지막 명단으로 계속)", e)
            except Exception:              # noqa: BLE001
                fails += 1
                log.exception("staff sync")
            # 실패하면 10·20·40초… 로 빨리 다시 시도 (담당자 앱이 늦게 뜨는 설치·재시작 직후 대비), 최대 주기까지
            self._kick.wait(min(self.interval, 10 * 2 ** (fails - 1)) if fails else self.interval)
            self._kick.clear()

    def stop(self):
        self._stop.set()
        self._kick.set()

    def status(self):
        return dict(self.state, configured=self.configured, public_url=self.public_url, interval_sec=self.interval,
                    directory=self.p.db.scalar("SELECT COUNT(*) FROM staff_directory WHERE active=1"))

    # ------------------------------------------------------------ 조회
    def person(self, username, active_only=True):
        return self.p.db.one("SELECT * FROM staff_directory WHERE username=?" + (" AND active=1" if active_only else ""), (username,))

    def roster(self):
        return self.p.db.all("SELECT * FROM staff_directory WHERE active=1 ORDER BY team IS NULL, team, display_name, username")
