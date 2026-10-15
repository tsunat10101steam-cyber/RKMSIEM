"""수집 파이프라인: 제한된 큐 → 정규화 → 저장(멱등) → 처리기(탐지 등).

데이터 유실/재처리 정책
- 파일 수집기: 처리(저장) 완료된 위치까지만 체크포인트 → 재시작 시 이어 읽기(최소 1회). 중복은 멱등성 키로 제거.
- HTTP 수집: 큐에 넣으면 202. ?wait=1 이면 저장·탐지까지 기다려 200 (최소 1회 보장 필요 시 사용).
  202 응답 후 프로세스가 비정상 종료되면 큐에 있던 이벤트는 유실될 수 있다 → 송신 측 재전송 + 멱등성 키 권장.
- UDP syslog: 프로토콜 특성상 큐가 가득 차면 드롭하고 dropped 지표로 계수.
- 파싱/정규화 실패: 원본은 raw_events(status=failed)에 보존하고 DLQ 에 격리 → 설정 수정 후 재처리 가능.
- 저장 실패(일시적 잠금 등): 재시도 → 계속 실패하면 DLQ(stage=store), 해당 배치는 체크포인트하지 않음.
"""
import hashlib
import logging
import queue
import sqlite3
import threading
import time
import uuid

from . import normalize as norm
from .db import dumps
from .parsers import Skip

SKIP = "__skip__"

log = logging.getLogger("rkmsiem.pipeline")


def make_record(source_id, raw, idem_key=None, ack=None, event_id=None, received_at=None):
    raw = raw if isinstance(raw, str) else dumps(raw)
    key = idem_key or (f"{source_id}:id:{event_id}" if event_id else
                       f"{source_id}:sha:{hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()}")
    return {"source_id": source_id, "raw": raw, "idem_key": key, "ack": ack, "event_id": event_id,
            "received_at": received_at or time.time(), "trace_id": uuid.uuid4().hex[:16]}


class Pipeline:
    def __init__(self, db, settings, metrics, bus, sources_provider):
        self.db, self.metrics, self.bus = db, metrics, bus
        self.sources = sources_provider               # () -> {source_id: cfg}
        p = settings.get("pipeline")
        self.q = queue.Queue(maxsize=p["queue_size"])
        self.batch_size = p["batch_size"]
        self.batch_wait = p.get("batch_wait_ms", 100) / 1000
        self.enqueue_timeout = p.get("enqueue_timeout_sec", 2)
        self.max_attempts = p.get("retry", {}).get("max_attempts", 3)
        self.backoff = p.get("retry", {}).get("backoff_ms", 200) / 1000
        self.handlers = []
        self._stop = threading.Event()
        self._thread = None
        self._waiters = {}
        self._wl = threading.Lock()
        self.last_batch_at = None

    # ---------- 입구 ----------
    def submit(self, rec, block=True, timeout=None):
        try:
            self.q.put(rec, block=block, timeout=self.enqueue_timeout if timeout is None else timeout)
        except queue.Full:
            self.metrics.inc("ingest_rejected_total", source=rec["source_id"])
            return False
        self.metrics.inc("ingest_received_total", source=rec["source_id"])
        return True

    def submit_and_wait(self, recs, timeout=10):
        """HTTP ?wait=1: 저장 완료까지 대기. 반환: (stored, duplicates, failed)."""
        ev = threading.Event()
        result = {"left": len(recs), "stored": 0, "dup": 0, "failed": 0}
        with self._wl:
            for r in recs:
                self._waiters[r["trace_id"]] = (ev, result)
        for r in recs:
            if not self.submit(r):
                self._finish_wait(r["trace_id"], "failed")
        ev.wait(timeout)
        return result

    def _finish_wait(self, trace_id, kind):
        with self._wl:
            w = self._waiters.pop(trace_id, None)
        if w:
            ev, res = w
            res[{"stored": "stored", "dup": "dup", "skipped": "skipped"}.get(kind, "failed")] = \
                res.get({"stored": "stored", "dup": "dup", "skipped": "skipped"}.get(kind, "failed"), 0) + 1
            res["left"] -= 1
            if res["left"] <= 0:
                ev.set()

    def add_handler(self, fn):
        self.handlers.append(fn)

    # ---------- 작업자 ----------
    def start(self):
        self._thread = threading.Thread(target=self._run, name="pipeline", daemon=True)
        self._thread.start()

    def stop(self, drain=True, timeout=10):
        if drain:
            end = time.time() + timeout
            while not self.q.empty() and time.time() < end:
                time.sleep(.05)
        self._stop.set()
        if self._thread:
            self._thread.join(timeout)

    def alive(self):
        return bool(self._thread and self._thread.is_alive())

    def _run(self):
        while not self._stop.is_set():
            try:
                first = self.q.get(timeout=.3)
            except queue.Empty:
                self.metrics.set("queue_depth", 0)
                continue
            batch, deadline = [first], time.time() + self.batch_wait
            while len(batch) < self.batch_size and time.time() < deadline:
                try:
                    batch.append(self.q.get(timeout=max(0, deadline - time.time())))
                except queue.Empty:
                    break
            self.metrics.set("queue_depth", self.q.qsize())
            try:
                self.process_batch(batch)
            except Exception:                    # 작업자는 절대 죽지 않게
                log.exception("batch failed")

    def process_batch(self, batch):
        t0 = time.time()
        sources = self.sources()
        prepared = []                            # (rec, doc, ts, error)
        for rec in batch:
            src = sources.get(rec["source_id"])
            try:
                if src is None:
                    raise norm.NormalizeError(f"unknown source {rec['source_id']}")
                doc, ts = norm.normalize(rec, src)
                prepared.append((rec, doc, ts, None, bool(src.get("sample"))))
            except Skip:                         # 설정상 버리는 줄(drop_unmatched) — 저장 안 함, 오류 아님
                self.metrics.inc("skipped_total", source=rec["source_id"])
                prepared.append((rec, None, None, SKIP, False))
            except Exception as e:
                self.metrics.inc("parse_errors_total", source=rec["source_id"])
                prepared.append((rec, None, None, str(e)[:500], bool(src and src.get("sample"))))

        stored = self._store(prepared)
        if stored is None:                       # 저장 실패 → DLQ, 체크포인트 안 함
            return
        new_events, dups = stored
        # 처리기(탐지 → 사건 → 플레이북): 한 배치 안에서는 발생 시각 순으로 정렬해 소스 간 작은 순서 뒤바뀜을 보정
        # (배치 경계를 넘는 큰 지연 도착은 보정하지 않음 — README '한계' 참고, 규칙 재생 API 로 재평가 가능)
        new_events.sort(key=lambda e: (e["ts"], e["id"]))
        for fn in self.handlers:
            try:
                fn(new_events)
            except Exception as e:
                log.exception("handler failed")
                self._dlq(None, "detect", dumps([e_["id"] for e_ in new_events][:200]), str(e), None)
        # ?wait=1 응답은 탐지·사건 처리까지 끝난 뒤
        for rec, doc, ts, err, _ in prepared:
            kind = "skipped" if err is SKIP else "failed" if err else ("dup" if rec["trace_id"] in dups else "stored")
            self._finish_wait(rec["trace_id"], kind)
        for rec, *_ in prepared:
            if rec.get("ack"):
                try:
                    rec["ack"]()
                except Exception:
                    log.exception("ack failed")
        now = time.time()
        self.last_batch_at = now
        for ev in new_events:
            self.metrics.observe("ingest_latency_ms", (now - ev["received_at"]) * 1000)
        self.metrics.observe("batch_ms", (now - t0) * 1000)
        if new_events:
            per = {}
            for e in new_events:
                per[e["source_id"]] = per.get(e["source_id"], 0) + 1
            self.bus.publish("ingest", {"stored": len(new_events), "by_source": per, "duplicates": len(dups)})

    def _store(self, prepared):
        for attempt in range(1, self.max_attempts + 1):
            try:
                new_events, dups = [], set()
                with self.db.tx() as c:
                    for rec, doc, ts, err, sample in prepared:
                        if err is SKIP:
                            continue
                        cur = c.execute("INSERT OR IGNORE INTO raw_events (source_id, received_at, raw, idem_key, status, error, trace_id, sample) "
                                        "VALUES (?,?,?,?,?,?,?,?)",
                                        (rec["source_id"], rec["received_at"], rec["raw"][:65536], rec["idem_key"],
                                         "failed" if err else "ok", err, rec["trace_id"], int(sample)))
                        if cur.rowcount == 0:
                            dups.add(rec["trace_id"])
                            continue
                        raw_id = cur.lastrowid
                        if err:
                            c.execute("INSERT INTO dlq (source_id, stage, raw, error, created_at, trace_id) VALUES (?,?,?,?,?,?)",
                                      (rec["source_id"], "parse", rec["raw"][:65536], err, time.time(), rec["trace_id"]))
                            continue
                        cols = norm.columns(doc)
                        now = time.time()
                        cur = c.execute(
                            "INSERT INTO events (raw_id, ts, ingested_at, source_id, dataset, category, action, outcome, severity, "
                            "user_name, source_ip, host_name, message, doc, sample, trace_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (raw_id, ts, now, rec["source_id"], cols["dataset"], cols["category"], cols["action"], cols["outcome"],
                             cols["severity"], cols["user_name"], cols["source_ip"], cols["host_name"], cols["message"],
                             dumps(doc), int(sample), rec["trace_id"]))
                        new_events.append({"id": cur.lastrowid, "ts": ts, "doc": doc, "source_id": rec["source_id"],
                                           "sample": sample, "received_at": rec["received_at"], "trace_id": rec["trace_id"]})
                self.metrics.inc("events_stored_total", len(new_events))
                if dups:
                    self.metrics.inc("duplicates_total", len(dups))
                return new_events, dups
            except sqlite3.OperationalError as e:      # 일시적 오류(잠금 등) → 재시도
                log.warning("store retry %d/%d: %s", attempt, self.max_attempts, e)
                self.metrics.inc("store_retries_total")
                time.sleep(self.backoff * attempt)
            except Exception as e:                     # 영구 오류 → 즉시 격리
                log.exception("store failed")
                return self._store_failed(prepared, str(e))
        return self._store_failed(prepared, "store retries exhausted")

    def _store_failed(self, prepared, err):
        for rec, *_ in prepared:
            self._dlq(rec["source_id"], "store", rec["raw"], err, rec["trace_id"])
            self._finish_wait(rec["trace_id"], "failed")
        self.metrics.inc("store_failures_total", len(prepared))
        return None

    def _dlq(self, source_id, stage, raw, err, trace_id):
        try:
            self.db.execute("INSERT INTO dlq (source_id, stage, raw, error, created_at, trace_id) VALUES (?,?,?,?,?,?)",
                            (source_id, stage, (raw or "")[:65536], err[:1000], time.time(), trace_id))
        except Exception:
            log.exception("dlq write failed")

    # ---------- DLQ 재처리 ----------
    def replay_dlq(self, ids=None):
        """파싱 실패 건을 현재 설정으로 다시 처리. 성공하면 replayed=1."""
        sql = "SELECT d.*, r.id AS raw_id, r.received_at, r.idem_key FROM dlq d JOIN raw_events r ON r.trace_id = d.trace_id " \
              "WHERE d.replayed = 0 AND d.stage = 'parse'"
        rows = self.db.all(sql)
        if ids:
            rows = [r for r in rows if r["id"] in set(ids)]
        sources, ok, failed, new_events = self.sources(), 0, 0, []
        for r in rows:
            src = sources.get(r["source_id"])
            rec = {"raw": r["raw"], "received_at": r["received_at"], "trace_id": r["trace_id"], "idem_key": r["idem_key"]}
            try:
                doc, ts = norm.normalize(rec, src)
            except Exception as e:
                failed += 1
                self.db.execute("UPDATE dlq SET attempts = attempts + 1, error = ? WHERE id = ?", (str(e)[:1000], r["id"]))
                continue
            cols = norm.columns(doc)
            with self.db.tx() as c:
                cur = c.execute(
                    "INSERT INTO events (raw_id, ts, ingested_at, source_id, dataset, category, action, outcome, severity, "
                    "user_name, source_ip, host_name, message, doc, sample, trace_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (r["raw_id"], ts, time.time(), r["source_id"], cols["dataset"], cols["category"], cols["action"], cols["outcome"],
                     cols["severity"], cols["user_name"], cols["source_ip"], cols["host_name"], cols["message"], dumps(doc),
                     int(bool(src.get("sample"))), r["trace_id"]))
                c.execute("UPDATE raw_events SET status='ok', error=NULL WHERE id=?", (r["raw_id"],))
                c.execute("UPDATE dlq SET replayed=1 WHERE id=?", (r["id"],))
            new_events.append({"id": cur.lastrowid, "ts": ts, "doc": doc, "source_id": r["source_id"],
                               "sample": bool(src.get("sample")), "received_at": r["received_at"], "trace_id": r["trace_id"]})
            ok += 1
        for fn in self.handlers:
            fn(new_events)
        return {"replayed": ok, "failed": failed}
