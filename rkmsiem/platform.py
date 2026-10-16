"""플랫폼 조립: 수집 → 정규화/저장 → 탐지 → 경보/사건 → 플레이북, 그리고 설정 변경 반영·보존 정책·상태 점검."""
import gzip
import json
import logging
import os
import threading
import time

from . import plugins, validators
from .alerts import AlertStore
from .audit import AuditLog
from .bus import Bus
from .configstore import ConfigStore
from .db import Database
from .detect import Engine
from .incidents import IncidentService
from .intel import FeedUpdater, IntelIndex
from .logutil import mask
from .metrics import Metrics
from .pipeline import Pipeline
from .response import Response
from .soar.engine import PlaybookEngine

log = logging.getLogger("rkmsiem.platform")


class Platform:
    def __init__(self, settings):
        self.settings = settings
        self.db = Database(settings.path("database.path") if settings.get("database.path") != ":memory:" else ":memory:")
        self.db.migrate()
        self.metrics, self.bus = Metrics(), Bus()
        self.audit = AuditLog(self.db, mask=mask)
        plugins.load_builtin()
        plugins.load_external(settings.get("plugins"))
        self.config = ConfigStore(self.db, settings.config_dir, self.audit)
        validators.register(self.config)
        self.config_report = self.config.bootstrap()
        self._seed_web_settings()
        self._ensure_builtin_sources()
        self._retire_renamed_rules()
        self._ensure_terminal_permission()
        from .vault import Vault
        self.vault = Vault(self.db, self.audit)
        self.alerts = AlertStore(self.db, self.metrics)
        self.incidents = IncidentService(self.db, self.config, self.audit, self.bus, self.metrics)
        self.soar = PlaybookEngine(self.db, self.config, self.audit, self.incidents, settings, self.bus, self.metrics)
        from .agents import Agents
        self.agents = self.soar.agents = Agents(self.db, self.audit, self.bus)
        from .feed import Feed
        self.feed = Feed(self.db)
        self.bus.listen(self.feed.on_publish)
        self.response = Response(settings)
        from . import normalize
        normalize.configure_self(commands=[((settings.get("response") or {}).get("accounts") or {}).get("helper") or "/usr/local/lib/rkmsiem/rkmsiem-account"])
        self.soar.response = self.response
        self.rebuild_reputation()
        from . import reports
        from .mailer import MailNotifier, Mailer
        self.mailer = Mailer(settings, self.db, self.audit, self.metrics, config=self.config, vault=self.vault)
        self.notifier = MailNotifier(self)
        from .staffsync import StaffSync
        self.staff = StaffSync(self)                 # 담당자 명단 (별도 담당자 관리 앱과 연동)
        self.response.mailer = self.mailer
        self.response.report_incident = lambda iid: reports.incident_pdf(self, iid)
        self.feed_dir = settings.path("intel_feed_dir") if settings.get("intel_feed_dir") else os.path.join(os.path.dirname(self.db.path), "feeds")
        self.feeds = FeedUpdater(self.config, self.feed_dir, self.rebuild_intel)
        self.rebuild_intel()
        self.pipeline = Pipeline(self.db, settings, self.metrics, self.bus, self.sources)
        self.pipeline.add_handler(self.on_events)
        self._engine_lock = threading.RLock()
        self.engine = None
        self.rebuild_engine()
        self.collectors = {}
        from .terminal import TerminalManager
        self.terminal = TerminalManager(self)          # 웹 터미널 (토폴로지에서 SIEM 과 와이어로 이어진 기기에 SSH)
        self.config.on_change(self._on_config_change)
        self._stop = threading.Event()
        self._threads = []

    # ------------------------------------------------------------------ 설정
    def sources(self):
        return {s["id"]: s for s in (self.config.get("sources") or {}).get("sources", [])}

    def rebuild_engine(self):
        """규칙/정책 변경 시 엔진을 새로 만들고 최근 이벤트로 창 상태를 복원한다."""
        rules = self.config.all("rule")
        eng = Engine(rules, self.config.get("detection"), self.config.get("lists"), self.metrics)
        latest = self.db.scalar("SELECT MAX(ts) FROM events") or 0
        since = latest - eng.max_window()
        rows = self.db.all("SELECT id, ts, doc, sample, source_id FROM events WHERE ts >= ? ORDER BY ts, id", (since,))
        evs = [{"id": r["id"], "ts": r["ts"], "doc": json.loads(r["doc"]), "sample": bool(r["sample"]), "source_id": r["source_id"]} for r in rows]
        eng.warmup(evs, self.alerts.open_for_warmup(since))
        with self._engine_lock:
            self.engine = eng
        log.info("detection engine ready: %d rules, warmup %d events", len(eng.rules), len(evs))

    def rebuild_intel(self):
        try:
            self.response.intel = IntelIndex(self.config.get("intel"), self.feed_dir)
            self.metrics.set("intel_entries", sum(self.response.intel.feed_counts.values()))
        except Exception:
            log.exception("intel index build failed — 이전 색인 유지")

    # 웹 설정 화면에서 바꾸는 항목(메일·보고서·평판)의 첫 값: settings.yaml 에 적혀 있던 값 + 기본값
    WEB_SETTINGS_DEFAULTS = {
        "mail": {"enabled": False, "host": "", "port": 587, "security": "starttls", "username": "", "from": "", "subject_prefix": "[RKMSIEM]",
                 "console_url": "", "timeout_sec": 15, "retries": 3, "max_per_hour": 60, "max_size_mb": 15, "allowed_recipients": [],
                 "alerts": {"enabled": True, "to": [], "min_severity": "high", "batch_sec": 60, "approvals": True}},
        "reports": {"incident_on_close": {"enabled": False, "to": []},
                    "schedule": [{"name": "daily", "every": "day", "at": "09:00", "period_hours": 24, "to": [], "enabled": False},
                                 {"name": "weekly", "every": "monday", "at": "09:00", "period_hours": 168, "to": [], "enabled": False}]},
        "topology": {"nodes": [], "links": []},
        "embeds": {"slots": []},
        "reputation": {"abuseipdb": {"enabled": True, "max_age_days": 90, "timeout_sec": 5, "cache_ttl_sec": 21600,
                                     "malicious_score": 75, "suspicious_score": 25}},
    }

    def _seed_web_settings(self):
        from .schemas import SchemaError

        def merge(base, over):
            out = dict(base)
            for k, v in (over or {}).items():
                out[k] = merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
            return out
        for kind, dflt in self.WEB_SETTINGS_DEFAULTS.items():
            if self.config.get(kind) is not None:
                continue
            content = merge(dflt, self.settings.get(kind))
            try:
                self.config.put(kind, "default", content, "system", "settings.yaml 에서 가져옴 (이후 콘솔 settings 에서 변경)")
            except SchemaError as e:
                log.error("settings.yaml 의 %s 값이 올바르지 않아 기본값으로 시작: %s", kind, e)
                self.config.put(kind, "default", dflt, "system", "기본값")

    SURICATA_SOURCE = {"id": "suricata-eve", "type": "http", "parser": "suricata_eve", "enabled": True, "dataset": "suricata.eve",
                       "options": {"timezone": "UTC", "event_types": ["alert", "anomaly"]}}

    def _ensure_builtin_sources(self):
        """기존 설치(설정 파일을 덮어쓰지 않는 업데이트)에도 Suricata 수신 소스를 한 번만 추가. 지운 뒤에는 다시 넣지 않음."""
        cur = self.config.get("sources")
        if not cur or any(s["id"] == self.SURICATA_SOURCE["id"] for s in cur.get("sources", [])):
            return
        marker = "IDS 수신 소스 자동 추가"
        for v in self.config.versions("sources", "default"):              # 예전에 있었는데 지운 거라면 다시 넣지 않음
            old = self.config.content_at("sources", "default", v["version"]) or {}
            if any(s.get("id") == self.SURICATA_SOURCE["id"] for s in old.get("sources", [])):
                return
        new = dict(cur, sources=cur["sources"] + [dict(self.SURICATA_SOURCE)])
        try:
            self.config.put("sources", "default", new, "system", f"{marker} (IDS 연동, 수동형 HTTP — 보내는 쪽이 없으면 아무 일도 안 함)")
        except Exception:     # noqa: BLE001
            log.exception("suricata source add failed")

    NEW_PERMISSIONS = {"terminal:use": ["admin"]}                   # 업데이트로 생긴 권한 → 기본으로 받을 역할

    def _ensure_terminal_permission(self):
        """기존 설치(권한 표가 DB 에 있음)에도 새 권한을 한 번만 추가. 관리자가 뺀 뒤에는 다시 넣지 않음."""
        cur = self.config.get("rbac")
        if not cur:
            return
        for perm, roles in self.NEW_PERMISSIONS.items():
            if any(perm in (r.get("permissions") or []) for r in cur.get("roles", {}).values()):
                continue
            if any(perm in str(self.config.content_at("rbac", "default", v["version"]) or {}) for v in self.config.versions("rbac", "default")):
                continue
            new = {"roles": {k: dict(v, permissions=list(v.get("permissions", [])) + ([perm] if k in roles else [])) for k, v in cur["roles"].items()}}
            new = dict(cur, **new)
            try:
                self.config.put("rbac", "default", new, "system", f"새 권한 {perm} 추가 ({', '.join(roles)})")
                cur = new
            except Exception:     # noqa: BLE001
                log.exception("rbac permission add failed")

    RETIRED_RULES = {"ids_suricata_alert": "ids_alert"}             # 예전 id → 새 id (이름 정리로 바뀐 규칙)

    def _retire_renamed_rules(self):
        """업데이트로 id 가 바뀐 규칙: 새 규칙이 있으면 예전 규칙은 꺼서 같은 경보가 두 번 나지 않게."""
        rules = self.config.all("rule")
        for old, new in self.RETIRED_RULES.items():
            if old not in rules or new not in rules:
                continue
            label = f"(사용 안 함) {rules[new]['name']} — 예전 규칙"
            if rules[old].get("enabled", True) or rules[old].get("name") != label:
                cur = self.config.get("rule", old)
                cur.update(enabled=False, name=label)
                cur.pop("description", None)
                self.config.put("rule", old, cur, "system", f"'{new}' 로 이름이 바뀌어 사용 중지")

    def rebuild_reputation(self):
        from .abuseipdb import AbuseIPDB
        self.response.abuseipdb = AbuseIPDB((self.config.get("reputation") or {}).get("abuseipdb"), self.vault.get("abuseipdb_key"))

    def _on_config_change(self, kind, name):
        if kind == "intel":
            self.rebuild_intel()
        if kind == "reputation":
            self.rebuild_reputation()
        if kind in ("rule", "detection", "lists"):
            self.rebuild_engine()
        if kind == "sources" and self.collectors:
            self.stop_collectors()
            self.start_collectors()
        self.bus.publish("config", {"kind": kind, "name": name, "version": self.config.version(kind, name)})

    # ------------------------------------------------------------------ 처리기
    def on_events(self, events):
        if not events:
            return
        changes = []
        with self._engine_lock:
            for ev in events:
                changes += self.engine.process(ev)
        if not changes:
            return
        with self.db.tx() as c:
            self.alerts.apply(changes, conn=c)
            results = self.incidents.on_alerts(changes, c)
        for ch in changes:
            if ch["op"] in ("new", "escalate"):
                a = ch["alert"]
                self.bus.publish("alert", {"op": ch["op"], "id": a["id"], "rule_id": a["rule_id"], "level_id": a["level_id"],
                                           "title": a["title"], "severity": a["severity"], "group": a["group"],
                                           "incident_id": a.get("incident_id")})
        for op, inc_id, a in results:
            if op == "created":
                self.bus.publish("incident", {"id": inc_id, "op": "created", "severity": a["severity"], "title": a["title"]})
        self.soar.on_incident_results(results)

    # ------------------------------------------------------------------ 수명 주기
    def start_collectors(self):
        from .plugins import COLLECTORS
        for sid, cfg in self.sources().items():
            if not cfg.get("enabled", True):
                continue
            cls = COLLECTORS.get(cfg["type"])
            if cls is None:
                log.error("unknown collector type %s", cfg["type"])
                continue
            c = cls(cfg, self.pipeline, self.db, self.metrics)
            if hasattr(c, "vault"):
                c.vault = self.vault                   # 당겨오기: 웹에서 넣은 토큰 (암호화 보관)
            c.start()
            self.collectors[sid] = c

    def stop_collectors(self):
        for c in self.collectors.values():
            c.stop()
        self.collectors = {}

    def start(self, collectors=True, feeds=True):
        if self.response.firewall:
            log.info("firewall reconcile: %s", self.response.reconcile(self.db))
        self.pipeline.start()
        self.soar.start()
        if collectors:
            self.start_collectors()
        loops = [self._retention_loop, self._ticker_loop, self.mailer.loop, self.notifier.loop, self.staff.loop] + ([self.feeds.loop] if feeds else [])
        for fn in loops:
            t = threading.Thread(target=fn, daemon=True, name=fn.__name__)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        self.terminal.stop()
        self.feeds.stop()
        self.staff.stop()
        self.notifier.stop()
        self.mailer.stop()
        self.stop_collectors()
        self.pipeline.stop()
        self.soar.stop()

    def sweep_blocks(self, now=None):
        """기간이 지난 차단을 목록에서 빼고 기록 (방화벽 쪽은 nft 원소 timeout 으로 이미 풀림)."""
        now = now or time.time()
        rows = self.db.all("SELECT ip, reason, incident_id, run_id FROM blocklist WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,))
        for r in rows:
            with self.db.tx() as c:
                if c.execute("DELETE FROM blocklist WHERE ip=? AND expires_at IS NOT NULL AND expires_at <= ?", (r["ip"], now)).rowcount:
                    c.execute("INSERT INTO block_history (ts, ip, action, actor, reason, incident_id, run_id) VALUES (?,?,?,?,?,?,?)",
                              (now, r["ip"], "expire", "system", r["reason"], r["incident_id"], r["run_id"]))
        if rows:
            self.bus.publish("config", {"kind": "blocklist", "name": "expired"})
        return [r["ip"] for r in rows]

    def _ticker_loop(self):
        n = 0
        while not self._stop.wait(5):
            n += 1
            if n % 12 == 0:                                   # 1분마다 만료된 차단 정리
                try:
                    self.sweep_blocks()
                    if n % 720 == 0:                          # 1시간마다 7일 지난 피드 정리
                        self.feed.prune()
                except Exception:
                    log.exception("block sweep")
            try:
                self.metrics.set("queue_depth", self.pipeline.q.qsize())
                self.bus.publish("metrics", {"queue_depth": self.pipeline.q.qsize(), "events_stored": self.metrics.total("events_stored_total"),
                                             "subscribers": self.bus.count()})
            except Exception:
                log.exception("ticker")

    # ------------------------------------------------------------------ 보존 정책
    def _retention_loop(self):
        every = self.settings.get("retention.check_interval_sec", 3600)
        while not self._stop.wait(every):
            try:
                self.apply_retention()
            except Exception:
                log.exception("retention")

    def apply_retention(self, now=None):
        """보존 기간이 지난 원본/이벤트를 gzip JSONL 로 보관 후 삭제. 감사 로그는 삭제하지 않는다."""
        now = now or time.time()
        r = self.settings.get("retention") or {}
        arch = self.settings.path("retention.archive_dir") if r.get("archive_dir") else None
        report = {}
        for table, col, days in (("events", "ingested_at", r.get("events_days")), ("raw_events", "received_at", r.get("raw_days"))):
            if not days:
                continue
            cutoff = now - days * 86400
            rows = self.db.all(f"SELECT * FROM {table} WHERE {col} < ? LIMIT 50000", (cutoff,))   # 테이블·열 이름은 위 상수
            if not rows:
                continue
            if arch:
                os.makedirs(arch, exist_ok=True)
                with gzip.open(os.path.join(arch, f"{table}-{int(now)}.jsonl.gz"), "at", encoding="utf-8") as f:
                    for row in rows:
                        f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
            with self.db.tx() as c:
                if table == "raw_events":
                    c.execute("UPDATE events SET raw_id=NULL WHERE raw_id IN (SELECT id FROM raw_events WHERE received_at < ?)", (cutoff,))
                c.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
            report[table] = len(rows)
        if report:
            self.audit.record("system", "retention.apply", None, None, None, report)
        return report

    # ------------------------------------------------------------------ 상태
    def health(self):
        return {"status": "ok", "uptime_sec": round(time.time() - self.metrics.started, 1)}

    def readiness(self):
        checks = {}
        try:
            checks["database"] = self.db.ping()
        except Exception as e:                       # noqa: BLE001
            checks["database"] = False
            checks["database_error"] = str(e)
        checks["pipeline_worker"] = self.pipeline.alive()
        checks["soar_worker"] = self.soar.alive()
        depth, cap = self.pipeline.q.qsize(), self.pipeline.q.maxsize
        checks["queue_ok"] = depth < cap * 0.9
        checks["collectors"] = {sid: c.status()["state"] for sid, c in self.collectors.items()}
        checks["collectors_ok"] = all(s in ("running", "passive", "waiting") for s in checks["collectors"].values())
        checks["config_rejected"] = self.config_report.get("rejected", [])
        ready = checks["database"] and checks["pipeline_worker"] and checks["soar_worker"] and checks["queue_ok"]
        return ready, checks
