"""메일 발송 (SMTP) · 경보/승인 알림 메일 · 보고서 정기 발송.

- 서버 주소·포트·보안 방식·보내는 사람은 settings.yaml 의 mail, 비밀번호는 환경 변수 RKMSIEM_SMTP_PASSWORD 에만
- 받는 사람은 허용 목록(mail.allowed_recipients + 설정에 적힌 수신자)에 있어야 한다 — 플레이북 템플릿 등으로
  임의 주소에 사건 정보를 보내는 것을 막음
- 발송은 별도 작업자 스레드에서 (탐지·대응을 막지 않음), 일시 오류는 재시도, 모든 발송은 mail_log 와 감사 로그에 남김
- 시간당 상한(max_per_hour)으로 폭주 방지. 경보 알림은 batch_sec 동안 모아 한 통으로 보냄
"""
import logging
import queue
import re
import smtplib
import ssl
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.utils import formatdate, getaddresses, make_msgid
from zoneinfo import ZoneInfo

log = logging.getLogger("rkmsiem.mail")
PASSWORD_ENV = "RKMSIEM_SMTP_PASSWORD"
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"]


class MailError(Exception):
    pass


def split_addrs(v):
    """'a@x, b@y' · ['a@x'] · 'Name <a@x>' → 주소 목록 (소문자·중복 제거)."""
    items = v if isinstance(v, (list, tuple)) else [v or ""]
    out = []
    for _, addr in getaddresses([str(x) for x in items]):
        a = addr.strip().lower()
        if a and a not in out:
            out.append(a)
    return out


class Mailer:
    def __init__(self, settings, db, audit=None, metrics=None, smtp_factory=None, environ=None, config=None, vault=None):
        import os
        self.settings, self.db, self.audit, self.metrics = settings, db, audit, metrics
        self.config, self.vault = config, vault                 # 웹에서 바꾼 설정이 바로 반영되도록 매번 읽음
        self.env = os.environ if environ is None else environ
        self.smtp_factory = smtp_factory
        self.q = queue.Queue(1000)
        self._stop = threading.Event()
        self.last_error = None
        self.db.execute("UPDATE mail_log SET status='failed', error='서버 재시작으로 발송 취소' WHERE status='queued'")

    # ---------------------------------------------------------------- 설정
    @property
    def cfg(self):
        c = self.config.get("mail") if self.config else None
        return c if c is not None else (self.settings.get("mail") or {})

    def reports_cfg(self):
        c = self.config.get("reports") if self.config else None
        return c if c is not None else (self.settings.get("reports") or {})

    @property
    def password(self):
        return (self.vault.get("smtp_password") if self.vault else self.env.get(PASSWORD_ENV)) or ""

    @staticmethod
    def is_configured(c):
        return bool(c.get("enabled") and c.get("host") and c.get("from"))

    @property
    def configured(self):
        return self.is_configured(self.cfg)

    def _configured_recipients(self, cfg=None):
        cfg = cfg or self.cfg
        r = list(cfg.get("allowed_recipients") or [])
        r += split_addrs((cfg.get("alerts") or {}).get("to"))
        rep = self.reports_cfg()
        r += split_addrs((rep.get("incident_on_close") or {}).get("to"))
        for s in rep.get("schedule") or []:
            r += split_addrs(s.get("to"))
        try:                                         # 담당자 명단(담당자 관리 앱)의 활성 담당자 메일도 허용
            r += [u["email"] for u in self.db.all("SELECT email FROM staff_directory WHERE active=1 AND email IS NOT NULL AND email <> ''")]
        except Exception:     # noqa: BLE001 — 마이그레이션 전
            pass
        return [x.strip().lower() for x in r if x]

    def allowed(self, addr, cfg=None):
        a = addr.lower()
        for rule in self._configured_recipients(cfg):
            if rule.startswith("@") and a.endswith(rule):
                return True
            if rule == a:
                return True
        return False

    def check_recipients(self, to, cfg=None):
        addrs = split_addrs(to)
        if not addrs:
            raise MailError("받는 사람이 없습니다")
        bad = [a for a in addrs if not EMAIL_RE.match(a)]
        if bad:
            raise MailError(f"메일 주소 형식 오류: {', '.join(bad)}")
        denied = [a for a in addrs if not self.allowed(a, cfg)]
        if denied:
            raise MailError(f"허용 목록에 없는 받는 사람: {', '.join(denied)} (settings.yaml mail.allowed_recipients)")
        if len(addrs) > 20:
            raise MailError("받는 사람은 20명까지")
        return addrs

    # ---------------------------------------------------------------- 발송 요청
    def already_sent(self, kind, ref):
        return bool(self.db.scalar("SELECT 1 FROM mail_log WHERE kind=? AND ref=? AND status IN ('queued','sent','simulated')", (kind, str(ref))))

    def send(self, kind, to, subject, text, html=None, attachments=None, ref=None, actor="system", wait=False, simulate=False,
             cfg=None, password=None):
        """메일 발송 요청 → mail_log id. wait=True 면 결과까지 기다림(테스트 메일·수동 발송).
        cfg/password 를 주면 그 설정으로 보냄 (웹 설정 화면의 '저장 전 테스트')."""
        c = cfg or self.cfg
        if not self.is_configured(c):
            raise MailError("메일 발송이 꺼져 있습니다 — 콘솔 settings 의 메일에서 켜기 · SMTP 서버 · 보낸 사람 설정")
        addrs = self.check_recipients(to, c)
        subject = re.sub(r"[\r\n]+", " ", f"{c.get('subject_prefix', '[RKMSIEM]')} {subject}".strip())[:200]
        limit = int(c.get("max_per_hour", 60))
        sent_hour = self.db.scalar("SELECT COUNT(*) FROM mail_log WHERE ts > ? AND status IN ('queued','sent')", (time.time() - 3600,))
        if not simulate and sent_hour >= limit:
            raise MailError(f"시간당 발송 한도({limit}통) 초과 — 잠시 뒤 다시")
        size = len(text or "") + sum(len(a[1]) for a in attachments or [])
        if size > int(c.get("max_size_mb", 15)) * 1024 * 1024:
            raise MailError("첨부 포함 메일 크기 초과")
        mid = self.db.execute("INSERT INTO mail_log (ts, kind, ref, recipients, subject, status, actor, size) VALUES (?,?,?,?,?,?,?,?)",
                              (time.time(), kind, None if ref is None else str(ref), ", ".join(addrs), subject,
                               "simulated" if simulate else "queued", actor, size)).lastrowid
        if self.audit:
            self.audit.record(actor, "mail.send" if not simulate else "mail.simulate", "mail", mid, None,
                              {"kind": kind, "to": addrs, "subject": subject, "attachments": [a[0] for a in attachments or []]})
        if simulate:
            return mid
        item = {"id": mid, "to": addrs, "subject": subject, "text": text, "html": html, "attachments": attachments or [], "done": threading.Event(),
                "cfg": c, "password": password}
        if wait:
            self._deliver(item)
        else:
            try:
                self.q.put_nowait(item)
            except queue.Full:
                self.db.execute("UPDATE mail_log SET status='failed', error='발송 대기열 가득 참' WHERE id=?", (mid,))
                raise MailError("발송 대기열이 가득 찼습니다")
        return mid

    def result(self, mid):
        return self.db.one("SELECT * FROM mail_log WHERE id=?", (mid,))

    # ---------------------------------------------------------------- SMTP
    def _connect(self, c, password):
        host, port, sec, timeout = c["host"], int(c.get("port", 587)), c.get("security", "starttls"), float(c.get("timeout_sec", 15))
        ctx = ssl.create_default_context()
        if self.smtp_factory:                           # 테스트용 가짜 SMTP
            s = self.smtp_factory(host, port, sec, timeout)
        elif sec == "ssl":
            s = smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx)
        else:
            s = smtplib.SMTP(host, port, timeout=timeout)
            s.ehlo()
            if sec == "starttls":
                s.starttls(context=ctx)
                s.ehlo()
        if c.get("username"):
            s.login(c["username"], password)
        return s

    def _build(self, item):
        c = item["cfg"]
        m = EmailMessage()
        m["From"] = c["from"]
        m["To"] = ", ".join(item["to"])
        m["Subject"] = item["subject"]
        m["Date"] = formatdate(localtime=True)
        m["Message-ID"] = make_msgid(domain=(c["from"].rsplit("@", 1)[-1].strip(" >") or "rkmsiem.local"))
        m["Auto-Submitted"] = "auto-generated"
        m.set_content(item["text"] or "")
        if item.get("html"):
            m.add_alternative(item["html"], subtype="html")
        for name, data, mime in item["attachments"]:
            maintype, subtype = (mime or "application/octet-stream").split("/", 1)
            m.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
        return m

    def _deliver(self, item):
        c = item.get("cfg") or self.cfg
        password = item["password"] if item.get("password") is not None else self.password
        retries, backoff = int(c.get("retries", 3)), float(c.get("retry_backoff_sec", 5))
        err = None
        for attempt in range(1, retries + 2):
            try:
                s = self._connect(c, password)
                try:
                    s.send_message(self._build(item))
                finally:
                    try:
                        s.quit()
                    except Exception:   # noqa: BLE001
                        pass
                self.db.execute("UPDATE mail_log SET status='sent', attempts=?, sent_at=?, error=NULL WHERE id=?", (attempt, time.time(), item["id"]))
                self.last_error = None
                if self.metrics:
                    self.metrics.inc("mail_sent_total")
                item["done"].set()
                return True
            except smtplib.SMTPAuthenticationError as e:
                err, permanent = f"SMTP 로그인 실패 ({e.smtp_code}) — 계정·앱 비밀번호 확인", True
            except smtplib.SMTPRecipientsRefused as e:
                err, permanent = f"받는 사람 거부: {', '.join(e.recipients)}", True
            except smtplib.SMTPResponseException as e:
                err, permanent = f"SMTP {e.smtp_code} {str(e.smtp_error)[:200]}", 500 <= e.smtp_code < 600
            except (smtplib.SMTPException, OSError) as e:
                err, permanent = f"연결 실패: {e}", False
            self.db.execute("UPDATE mail_log SET attempts=?, error=? WHERE id=?", (attempt, err, item["id"]))
            if permanent or attempt > retries or self._stop.is_set():
                break
            time.sleep(backoff * attempt)
        self.db.execute("UPDATE mail_log SET status='failed', error=? WHERE id=?", (err, item["id"]))
        self.last_error = err
        log.warning("mail %s failed: %s", item["id"], err)
        if self.metrics:
            self.metrics.inc("mail_failed_total")
        item["done"].set()
        return False

    def loop(self):
        while not self._stop.is_set():
            try:
                item = self.q.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._deliver(item)
            except Exception:     # noqa: BLE001
                log.exception("mail worker")

    def stop(self):
        self._stop.set()

    def status(self):
        c = self.cfg
        last = self.db.one("SELECT status, error, ts FROM mail_log WHERE status IN ('sent','failed') ORDER BY id DESC LIMIT 1")
        return {"configured": self.configured, "host": c.get("host"), "port": c.get("port"), "security": c.get("security", "starttls"),
                "from": c.get("from"), "username": c.get("username") or None, "password_set": bool(self.password),
                "allowed_recipients": self._configured_recipients(), "max_per_hour": c.get("max_per_hour", 60),
                "queue": self.q.qsize(), "last": last, "last_error": self.last_error,
                "alerts": c.get("alerts") or {}, "reports": self.reports_cfg()}


# ==================================================================== 실시간 알림 · 정기 보고서
class MailNotifier:
    """이벤트 버스를 구독해 경보는 모아서, 승인 요청은 바로, 사건 종결 시 보고서를 메일로 보낸다. 정기 보고서 일정도 처리."""

    def __init__(self, platform):
        self.p = platform
        self._stop = threading.Event()
        self.buf, self.buf_since = [], None
        self.seen_approvals = set()

    @property
    def mailer(self):
        return self.p.mailer

    def _cfg(self):
        return self.mailer.cfg.get("alerts") or {}

    def loop(self):
        q = self.p.bus.subscribe()
        last_sched = 0
        while not self._stop.is_set():
            try:
                msg = q.get(timeout=1)
                if msg.get("type") == "_overflow":
                    self.p.bus.unsubscribe(q)
                    q = self.p.bus.subscribe()
                else:
                    self.on_message(msg)
            except queue.Empty:
                pass
            except Exception:     # noqa: BLE001
                log.exception("mail notifier")
            try:
                self.flush()
                if time.time() - last_sched >= 30:
                    last_sched = time.time()
                    self.run_schedule()
            except Exception:     # noqa: BLE001
                log.exception("mail notifier flush/schedule")
        self.p.bus.unsubscribe(q)

    def stop(self):
        self._stop.set()

    def on_message(self, msg):
        if not self.mailer.configured:
            return
        t, d = msg["type"], msg.get("data") or {}
        cfg = self._cfg()
        if t == "alert" and d.get("op") in ("new", "escalate") and cfg.get("enabled") and cfg.get("to"):
            if SEV_RANK.get(d.get("severity"), 0) >= SEV_RANK.get(cfg.get("min_severity", "high"), 3):
                if not self.buf:
                    self.buf_since = time.time()
                self.buf.append(d)
        elif t == "run" and d and d.get("state") == "waiting_approval" and cfg.get("approvals", True) and cfg.get("to"):
            self.approval_mail(d)
        elif t == "incident" and d.get("state") in self.p.incidents.terminal_states():
            rc = self.mailer.reports_cfg().get("incident_on_close") or {}
            if rc.get("enabled") and rc.get("to"):
                self.send_incident_report(d["id"], rc["to"], actor="system", ref=f"{d['id']}:{d['state']}")

    def flush(self, force=False):
        if not self.buf:
            return
        if not force and time.time() - self.buf_since < float(self._cfg().get("batch_sec", 60)):
            return
        items, self.buf = self.buf, []
        top = max(items, key=lambda a: SEV_RANK.get(a["severity"], 0))
        subj = f"{'긴급' if top['severity'] == 'critical' else '경보'} {len(items)}건 — {top['title']}"
        lines = [f"새 보안 경보 {len(items)}건 ({self._now()})", ""]
        for a in items[:50]:
            grp = " · ".join(f"{k}={v}" for k, v in (a.get("group") or {}).items())
            lines.append(f"[{a['severity'].upper()}] {a['title']}  {grp}  사건 #{a.get('incident_id') or '-'}  ({'단계 상향' if a['op'] == 'escalate' else '신규'})")
        if len(items) > 50:
            lines.append(f"… 외 {len(items) - 50}건")
        lines += ["", self._console_hint("incident <번호>")]
        try:
            self.mailer.send("alert", self._cfg()["to"], subj, "\n".join(lines))
        except MailError as e:
            log.warning("alert mail skipped: %s", e)

    def approval_mail(self, run):
        rows = self.p.db.all("SELECT a.id, a.step_id, a.expires_at, s.action, s.input FROM approvals a JOIN step_runs s "
                             "ON s.run_id=a.run_id AND s.step_id=a.step_id WHERE a.run_id=? AND a.state='pending'", (run["id"],))
        for r in rows:
            if r["id"] in self.seen_approvals or self.mailer.already_sent("approval", r["id"]):
                continue
            self.seen_approvals.add(r["id"])
            text = "\n".join([f"플레이북 {run['playbook_id']} (실행 #{run['id']}) 이 승인을 기다립니다.", "",
                              f"단계: {r['step_id']} ({r['action']})", f"입력: {r['input']}", f"사건: #{run.get('incident_id') or '-'}",
                              f"만료: {self._fmt(r['expires_at'])}", f"실행 모드: {run.get('mode')}", "",
                              self._console_hint(f"run {run['id']}"), "승인/거절은 콘솔에서 사유와 함께 합니다 (메일로는 승인되지 않음)."])
            try:
                self.mailer.send("approval", self._cfg()["to"], f"승인 요청 — {r['action']} (실행 #{run['id']})", text, ref=r["id"])
            except MailError as e:
                log.warning("approval mail skipped: %s", e)

    def assignment_mail(self, inc, username, actor):
        """사건 배정 알림 — 담당자 명단(담당자 관리 앱)에 메일이 있고 '배정 알림 받기'가 켜져 있을 때만."""
        u = self.p.staff.person(username)
        if not (u and u["email"] and u["notify_assign"] and self.mailer.configured):
            return None
        text = "\n".join([f"{u['display_name'] or username} 님에게 사건이 배정되었습니다.", "",
                          f"사건: #{inc['id']} {inc['title']}", f"심각도: {inc['severity']} · 상태: {inc.get('state_label') or inc['state']}",
                          f"배정한 사람: {actor}", "", self._console_hint(f"incident {inc['id']}")])
        try:
            return self.mailer.send("assign", u["email"], f"사건 #{inc['id']} 배정 — {inc['title']}", text,
                                    ref=f"{inc['id']}:{username}:{int(time.time() // 60)}", actor=actor)
        except MailError as e:
            log.warning("assignment mail skipped: %s", e)
            return None

    def send_incident_report(self, iid, to, actor, ref=None, wait=False):
        from . import reports
        if ref and self.mailer.already_sent("report:incident", ref):
            return None
        inc = self.p.incidents.get(iid)
        pdf = reports.incident_pdf(self.p, iid)
        text = "\n".join([f"사건 #{iid} 보고서를 첨부합니다.", "", f"제목: {inc['title']}", f"심각도: {inc['severity']} · 상태: {inc['state_label']}",
                          f"담당: {inc.get('assignee') or '미지정'}", "", self._console_hint(f"incident {iid}")])
        return self.mailer.send("report:incident", to, f"사건 #{iid} 보고서 — {inc['title']}", text,
                                attachments=[(f"rkmsiem-incident-{iid}.pdf", pdf, "application/pdf")], ref=ref or iid, actor=actor, wait=wait)

    def send_summary(self, frm, to_ts, recipients, actor, kind="report:manual", ref=None, label=None, wait=False):
        from . import reports
        pdf = reports.summary_pdf(self.p, frm, to_ts)
        span = f"{self._fmt(frm)} ~ {self._fmt(to_ts)}"
        text = "\n".join([f"{label or '기간'} 보안 관제 요약 보고서를 첨부합니다.", f"범위: {span}", "", self._console_hint("dashboard all")])
        day = datetime.fromtimestamp(to_ts, self._tz()).strftime("%Y%m%d")
        return self.mailer.send(kind, recipients, f"{label or '요약'} 보고서 ({span})", text,
                                attachments=[(f"rkmsiem-summary-{day}.pdf", pdf, "application/pdf")], ref=ref, actor=actor, wait=wait)

    def run_schedule(self, now=None):
        """reports.schedule: [{name, every: day|monday..sunday, at: 'HH:MM', period_hours, to, enabled}]"""
        if not self.mailer.configured:
            return []
        done = []
        now_l = datetime.fromtimestamp(now or time.time(), self._tz())
        for s in self.mailer.reports_cfg().get("schedule") or []:
            if not s.get("enabled") or not s.get("to"):
                continue
            every = s.get("every", "day")
            if every != "day" and WEEKDAYS[now_l.weekday()] != every:
                continue
            hh, mm = (int(x) for x in str(s.get("at", "09:00")).split(":"))
            due = now_l.replace(hour=hh, minute=mm, second=0, microsecond=0)
            if now_l < due or now_l - due > timedelta(hours=12):          # 늦게 켜져도 12시간 안이면 보냄
                continue
            ref = due.strftime("%Y-%m-%d")
            kind = f"report:{s['name']}"
            if self.mailer.already_sent(kind, ref):
                continue
            to_ts = due.timestamp()
            try:
                self.send_summary(to_ts - float(s.get("period_hours", 24)) * 3600, to_ts, s["to"], "system", kind=kind, ref=ref,
                                  label={"day": "일간", "monday": "주간"}.get(every, s["name"]))
                done.append(kind)
            except MailError as e:
                log.warning("scheduled report %s skipped: %s", s["name"], e)
        return done

    # ---------------------------------------------------------------- 도구
    def _tz(self):
        return ZoneInfo(self.p.settings.get("timezone", "UTC"))

    def _fmt(self, ts):
        return datetime.fromtimestamp(ts, self._tz()).strftime("%Y-%m-%d %H:%M") if ts else "-"

    def _now(self):
        return self._fmt(time.time())

    def _console_hint(self, cmd):
        url = self.mailer.cfg.get("console_url")
        return f"콘솔: {url}  →  {cmd}" if url else f"콘솔에서: {cmd}"
