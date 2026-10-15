"""PDF 보고서 (reportlab): 사건 보고서 · 기간 요약 보고서.

- 모든 수치는 DB·분석 함수(analytics.overview) 결과를 그대로 쓴다 (콘솔 화면과 같은 값)
- 한글 폰트: settings.reports.font → NanumGothic(apt fonts-nanum) → Noto CJK → 맑은 고딕(Windows) 순으로 찾음
- 사건 보고서 끝에 감사 로그 해시 체인 검증 결과와 보고서 생성 정보를 넣어 증빙으로 쓸 수 있게 함
"""
import io
import json
import os
import time
from datetime import datetime
from xml.sax.saxutils import escape
from zoneinfo import ZoneInfo

from . import analytics
from .alerts import row_to_alert
from .conditions import Lists

FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/nanum/NanumGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf", None),
    ("/usr/share/fonts/truetype/nanum/NanumBarunGothic.ttf", "/usr/share/fonts/truetype/nanum/NanumBarunGothicBold.ttf", None),
    ("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/opentype/noto/NotoSansCJK-Bold.ttc", 1),
    ("C:/Windows/Fonts/malgun.ttf", "C:/Windows/Fonts/malgunbd.ttf", None),
    ("/Library/Fonts/AppleGothic.ttf", None, None),
]
SEV_KO = {"critical": "긴급", "high": "높음", "medium": "주의", "low": "낮음", "info": "정보"}
SEV_HEX = {"critical": "#d93636", "high": "#e07b17", "medium": "#c9a000", "low": "#6b7685", "info": "#8a94a3"}
STATE_KO = {"succeeded": "성공", "failed": "실패", "skipped": "건너뜀", "waiting_approval": "승인 대기", "pending": "대기", "running": "실행 중",
            "cancelled": "취소", "compensated": "되돌림", "timed_out": "시간 초과", "rejected": "거절", "queued": "대기", "approved": "승인",
            "expired": "만료"}
TL_KO = {"created": "사건 생성", "alert_linked": "경보 연결", "alert_escalated": "경보 상향", "severity_changed": "심각도 변경", "state_changed": "상태 변경",
         "assigned": "담당자 배정", "comment": "메모", "approval_requested": "승인 요청", "approval_approved": "승인", "approval_rejected": "거절",
         "playbook_result": "대응 결과", "playbook_finished": "플레이북 종료"}


class ReportError(Exception):
    pass


class M(str):
    """reportlab 마크업으로 그대로 쓸 문자열. 그 밖의 문자열은 모두 escape (로그 원문의 '<' 등으로 깨지지 않게)."""


_FONT = {}


def _fonts(settings):
    if _FONT:
        return _FONT["r"], _FONT["b"]
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    want = (settings.get("reports") or {}).get("font")
    cands = ([(want, None, None)] if want else []) + FONT_CANDIDATES
    for reg, bold, sub in cands:
        if reg and os.path.exists(reg):
            kw = {"subfontIndex": sub} if sub is not None else {}
            pdfmetrics.registerFont(TTFont("KR", reg, **kw))
            if bold and os.path.exists(bold):
                pdfmetrics.registerFont(TTFont("KR-B", bold, **kw))
            else:
                pdfmetrics.registerFont(TTFont("KR-B", reg, **kw))
            _FONT.update(r="KR", b="KR-B", path=reg)
            return "KR", "KR-B"
    raise ReportError("한글 폰트가 없습니다 — Ubuntu: sudo apt install fonts-nanum (또는 settings.yaml reports.font 에 .ttf 경로)")


def font_status(settings):
    try:
        _fonts(settings)
        return True, _FONT["path"]
    except ReportError as e:
        return False, str(e)
    except ImportError:
        return False, "reportlab 패키지 없음 — pip install reportlab"


# ==================================================================== 공통 틀
class _Doc:
    def __init__(self, p, title, subtitle):
        try:
            from reportlab.lib import colors
            from reportlab.lib.enums import TA_LEFT
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle
            from reportlab.lib.units import mm
        except ImportError:
            raise ReportError("reportlab 패키지 없음 — pip install reportlab")
        self.p, self.colors, self.mm = p, colors, mm
        self.tz = ZoneInfo(p.settings.get("timezone", "UTC"))
        r, b = _fonts(p.settings)
        self.r, self.b = r, b
        base = dict(fontName=r, fontSize=9, leading=13, wordWrap="CJK", alignment=TA_LEFT)
        self.st = {"body": ParagraphStyle("body", **base),
                   "small": ParagraphStyle("small", **dict(base, fontSize=7.5, leading=10, textColor=colors.HexColor("#555b66"))),
                   "cell": ParagraphStyle("cell", **dict(base, fontSize=8, leading=10.5)),
                   "cellb": ParagraphStyle("cellb", **dict(base, fontName=b, fontSize=8, leading=10.5)),
                   "h1": ParagraphStyle("h1", **dict(base, fontName=b, fontSize=17, leading=22, spaceAfter=2)),
                   "sub": ParagraphStyle("sub", **dict(base, fontSize=9, textColor=colors.HexColor("#555b66"), spaceAfter=8)),
                   "h2": ParagraphStyle("h2", **dict(base, fontName=b, fontSize=11.5, leading=15, spaceBefore=12, spaceAfter=5,
                                                      textColor=colors.HexColor("#14532d")))}
        self.title, self.subtitle, self.flow = title, subtitle, []
        self.A4 = A4
        self.generated = time.time()

    def t(self, ts, sec=False):
        return datetime.fromtimestamp(ts, self.tz).strftime("%Y-%m-%d %H:%M" + (":%S" if sec else "")) if ts else "-"

    def P(self, text, style="body"):
        from reportlab.platypus import Paragraph
        return Paragraph(text if isinstance(text, M) else escape(str(text if text is not None else "")).replace("\n", "<br/>"), self.st[style])

    def h1(self):
        self.flow += [self.P(M(f"<b>{escape(self.title)}</b>"), "h1"), self.P(self.subtitle, "sub")]

    def h2(self, text):
        self.flow.append(self.P(text, "h2"))

    def para(self, text, style="body"):
        self.flow.append(self.P(text, style))

    def mpara(self, markup, style="body"):          # 값은 호출하는 쪽에서 escape 한 마크업
        self.flow.append(self.P(M(markup), style))

    def sev(self, s):
        return M(f'<font color="{SEV_HEX.get(s, "#333")}"><b>{SEV_KO.get(s, escape(str(s)))}</b></font>')

    def table(self, head, rows, widths, zebra=True):
        from reportlab.platypus import Table, TableStyle
        c = self.colors
        data = [[self.P(h, "cellb") for h in head]] + [[x if hasattr(x, "wrap") else self.P(x, "cell") for x in r] for r in rows]
        tw = self.A4[0] - 30 * self.mm
        t = Table(data, colWidths=[w * tw for w in widths], repeatRows=1)
        st = [("BACKGROUND", (0, 0), (-1, 0), c.HexColor("#e8efe9")), ("LINEBELOW", (0, 0), (-1, 0), .8, c.HexColor("#14532d")),
              ("VALIGN", (0, 0), (-1, -1), "TOP"), ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
              ("LINEBELOW", (0, 1), (-1, -1), .25, c.HexColor("#d5d9de"))]
        if zebra:
            st += [("BACKGROUND", (0, i), (-1, i), c.HexColor("#f6f7f9")) for i in range(2, len(data), 2)]
        t.setStyle(TableStyle(st))
        self.flow.append(t)

    def kv(self, pairs, cols=2):
        rows, cur = [], []
        for k, v in pairs:
            cur += [self.P(k, "cellb"), self.P(v, "cell")]
            if len(cur) == cols * 2:
                rows.append(cur)
                cur = []
        if cur:
            rows.append(cur + [""] * (cols * 2 - len(cur)))
        from reportlab.platypus import Table, TableStyle
        tw = self.A4[0] - 30 * self.mm
        w = [.16, .34] * cols if cols == 2 else [.2, .8]
        t = Table(rows, colWidths=[x * tw for x in w])
        t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), .5, self.colors.HexColor("#c9ced5")),
                               ("INNERGRID", (0, 0), (-1, -1), .25, self.colors.HexColor("#e1e4e8")),
                               ("BACKGROUND", (0, 0), (0, -1), self.colors.HexColor("#f2f4f6"))] +
                              ([("BACKGROUND", (2, 0), (2, -1), self.colors.HexColor("#f2f4f6"))] if cols == 2 else [])))
        self.flow.append(t)

    def spacer(self, h=4):
        from reportlab.platypus import Spacer
        self.flow.append(Spacer(1, h * self.mm))

    def build(self):
        from reportlab.platypus import SimpleDocTemplate
        buf = io.BytesIO()
        mm, gen = self.mm, self.t(self.generated, True)

        def deco(canvas, doc):
            canvas.saveState()
            canvas.setFont(self.r, 7.5)
            canvas.setFillColor(self.colors.HexColor("#7a828e"))
            canvas.drawString(15 * mm, 10 * mm, f"RKMSIEM · {self.title} · 생성 {gen} ({self.tz.key}) · 대외비")
            canvas.drawRightString(self.A4[0] - 15 * mm, 10 * mm, f"{doc.page} 쪽")
            canvas.setStrokeColor(self.colors.HexColor("#14532d"))
            canvas.setLineWidth(1.2)
            canvas.line(15 * mm, self.A4[1] - 12 * mm, self.A4[0] - 15 * mm, self.A4[1] - 12 * mm)
            canvas.restoreState()

        doc = SimpleDocTemplate(buf, pagesize=self.A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=17 * mm, bottomMargin=17 * mm,
                                title=self.title, author="RKMSIEM", subject=self.subtitle)
        doc.build(self.flow, onFirstPage=deco, onLaterPages=deco)
        return buf.getvalue()


def _short(v, n=160):
    s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False, default=str)
    return s if len(s) <= n else s[:n - 1] + "…"


def _out_text(action, o, err):
    """단계 출력 → 사람이 읽는 한 줄."""
    if not o:
        return err or "-"
    if o.get("simulated"):
        return f"시뮬레이션 — {o.get('would', '')} (실제 변경 없음)"
    yn = lambda v: "예" if v else "아니오"   # noqa: E731
    if action == "ip_reputation":
        ab = o.get("abuseipdb") or {}
        return (f"판정 {o.get('verdict')} · 출처 {o.get('source') or '-'}"
                + (f" · AbuseIPDB {ab['score']}점 신고 {ab.get('total_reports')}건" if "score" in ab else "")
                + (f" · AbuseIPDB 오류: {ab['error']}" if ab.get("error") else ""))
    if action == "asset_lookup":
        return f"계정 {o.get('account')} · 존재 {yn(o.get('found'))} · 권한 계정 {yn(o.get('privileged'))} · 소유 {o.get('owner') or '-'}"
    if action == "notify":
        return f"알림 전달 ({o.get('delivered')}, 채널 {o.get('channel')})"
    if action == "record_result":
        return o.get("summary") or "-"
    if action == "block_ip":
        return f"{o.get('ip')} 차단 ({o.get('backend')}" + (f", {o['duration_sec']}초" if o.get("duration_sec") else ", 무기한") + ")" + \
            (" · 이미 차단돼 있었음" if o.get("already_blocked") else "")
    if action == "disable_account":
        return f"계정 {o.get('account')} 잠금 ({o.get('backend')})"
    if action == "set_incident_severity":
        return f"사건 심각도 → {SEV_KO.get(o.get('severity'), o.get('severity'))}"
    if action == "send_email":
        return f"메일 {o.get('status')} → {', '.join(o.get('to') or [])}"
    return _short(o, 140)


# ==================================================================== 사건 보고서
def incident_pdf(p, iid):
    inc = p.incidents.detail(iid)
    if not inc:
        raise KeyError(f"incident {iid}")
    alerts = [row_to_alert(r) for r in p.db.all("SELECT * FROM alerts WHERE incident_id=? ORDER BY first_ts", (iid,))]
    runs = [p.soar.detail(r["id"]) for r in p.db.all("SELECT id FROM playbook_runs WHERE incident_id=? ORDER BY id", (iid,))]
    d = _Doc(p, f"사건 보고서 #{iid}", inc["title"])
    d.h1()

    ips = sorted({a["group"].get("source.ip") for a in alerts if a["group"].get("source.ip")})
    users = sorted({a["group"].get("user.name") for a in alerts if a["group"].get("user.name")})
    first = min((a["first_ts"] for a in alerts), default=inc["created_at"])
    last = max((a["last_ts"] for a in alerts), default=inc["updated_at"])
    d.kv([("심각도", d.sev(inc["severity"])), ("상태", inc["state_label"]), ("담당자", inc.get("assignee") or "미지정"),
          ("위험 점수", f"{inc.get('risk_score') or 0:.0f}"), ("사건 생성", d.t(inc["created_at"])), ("종결", d.t(inc.get("closed_at"))),
          ("공격 기간", f"{d.t(first)} ~ {d.t(last)}"), ("경보", f"{len(alerts)}건"), ("출발 IP", ", ".join(ips) or "-"),
          ("대상 계정", ", ".join(users) or "-"), ("상관 키", inc["correlation_key"]), ("샘플 데이터", "예 (가상)" if inc.get("sample") else "아니오")])

    # 1. 요약 (자동 문장)
    d.h2("1. 요약")
    top = max(alerts, key=lambda a: (a["severity_rank"], a["risk_score"]), default=None)
    acts = []
    for r in runs:
        for s in r["steps"]:
            o = s.get("output") or {}
            if s["action"] == "block_ip" and s["state"] == "succeeded":
                acts.append(f"IP {o.get('ip')} 차단" + (" (시뮬레이션)" if o.get("simulated") else ""))
            if s["action"] == "disable_account" and s["state"] == "succeeded":
                acts.append(f"계정 {o.get('account')} 잠금" + (" (시뮬레이션)" if o.get("simulated") else ""))
    summary = (f"{d.t(first)}부터 {d.t(last)}까지 {', '.join(ips) or '알 수 없는 출발지'}에서 "
               f"{', '.join(users) or '여러 계정'}을(를) 대상으로 한 활동이 탐지되었다. "
               + (f"가장 높은 경보는 「{top['title']}」({SEV_KO.get(top['severity'])}, {top['event_count']}회)이다. " if top else "")
               + (f"대응 조치: {', '.join(acts)}. " if acts else "실제 차단·잠금 조치는 실행되지 않았다. ")
               + f"현재 상태는 '{inc['state_label']}'이다.")
    d.para(summary)

    # 2. 탐지 근거
    d.h2("2. 탐지 근거 (경보)")
    if alerts:
        d.table(["심각도", "경보 · 규칙", "횟수", "기간", "기준 · 위험 점수"],
                [[d.sev(a["severity"]), f"{a['title']}\n{a['rule_id']} v{a['rule_version']} · {a['level_id']}", a["event_count"],
                  f"{d.t(a['first_ts'])}\n~ {d.t(a['last_ts'])}",
                  f"{a.get('basis') or a['risk_basis'].get('_extra', {}).get('basis', '') or '-'}\n위험 {a['risk_score']:.0f} = 기본 {a['risk_basis'].get('severity_base', '-')} + "
                  f"{a['risk_basis'].get('event_count', '-')}×{a['risk_basis'].get('per_event', '-')}"] for a in alerts],
                [.09, .33, .07, .2, .31])
    else:
        d.para("연결된 경보 없음")

    # 3. 공격 정보 · 평판
    rep = [(s.get("output") or {}) for r in runs for s in r["steps"] if s["action"] == "ip_reputation" and s.get("output")]
    d.h2("3. 공격 출발지 평판")
    if rep:
        rows = []
        for o in {x.get("ip"): x for x in rep}.values():
            ab = o.get("abuseipdb") or {}
            rows.append([o.get("ip"), o.get("verdict"), o.get("source") or "-",
                         (f"점수 {ab['score']} · 신고 {ab.get('total_reports')}건 · {ab.get('country') or '?'} · {ab.get('isp') or ''}"
                          + (" · Tor" if ab.get("is_tor") else "")) if "score" in ab else (ab.get("error") or "조회 안 함")])
        d.table(["IP", "판정", "출처", "AbuseIPDB"], rows, [.17, .13, .22, .48])
    else:
        d.para("평판 조회 기록 없음 (ip_reputation 단계가 실행되지 않음)")

    # 4. 대응 조치
    d.h2("4. 대응 조치 (플레이북)")
    if runs:
        for r in runs:
            d.mpara(f"<b>실행 #{r['id']} · {escape(r['playbook_id'])} v{r['playbook_version']}</b> — {STATE_KO.get(r['state'], escape(r['state']))} · 모드 {escape(r['mode'])} · "
                   f"요청 {escape(r['requested_by'])} · {d.t(r['created_at'])}{(' · 오류 ' + escape(r['error'])) if r.get('error') else ''}")
            appr = {a["step_id"]: a for a in r.get("approvals") or []}
            rows = []
            for s in r["steps"]:
                a = appr.get(s["step_id"])
                rows.append([s["step_id"], s["action"], STATE_KO.get(s["state"], s["state"]),
                             _out_text(s["action"], s.get("output"), s.get("error")),
                             (f"{STATE_KO.get(a['state'], a['state'])} · {a.get('decided_by') or '시간 초과'}" + (f"\n{a['reason']}" if a.get("reason") else "")) if a else "-"])
            d.table(["단계", "액션", "결과", "출력", "승인 (결정자 · 사유)"], rows, [.13, .15, .09, .41, .22])
            d.spacer(2)
    else:
        d.para("실행된 플레이북 없음")

    # 5. 타임라인
    d.h2("5. 처리 타임라인")
    tl = []
    for t in inc["timeline"]:
        x = t.get("detail") or {}
        what = x.get("title") or x.get("summary") or x.get("text") or \
            (f"{x.get('from')} → {x.get('to')}" if x.get("from") else "") or \
            (f"{x['action']} (실행 #{x.get('run_id')}) {_short(x.get('input') or {}, 90)}" if x.get("action") else "") or \
            (f"{x.get('playbook', '')} {STATE_KO.get(x.get('state'), x.get('state') or '')}".strip()) or _short(x, 120)
        tl.append([d.t(t["ts"], True), TL_KO.get(t["kind"], t["kind"]), t["actor"].replace("playbook:", "플레이북 "),
                   what + (f" ({x['reason']})" if x.get("reason") else "")])
    d.table(["시각", "구분", "주체", "내용"], tl, [.18, .12, .2, .5])

    # 6. 근거 이벤트
    ev_ids = [i for a in alerts for i in a["evidence"]][-200:]
    evs = p.db.all("SELECT ts, source_id, outcome, user_name, source_ip, message FROM events WHERE id IN (SELECT value FROM json_each(?)) "
                   "ORDER BY ts LIMIT 25", (json.dumps(ev_ids),)) if ev_ids else []
    d.h2(f"6. 근거 로그 (최대 25건 / 근거 이벤트 {len(ev_ids)}건)")
    if evs:
        d.table(["시각", "결과", "계정 · IP", "원문"], [[d.t(e["ts"], True), e["outcome"], f"{e['user_name'] or '-'} @ {e['source_ip'] or '-'}",
                                                    _short(e["message"] or "", 150)] for e in evs], [.18, .09, .23, .5])
    else:
        d.para("근거 이벤트 없음")

    # 7. 무결성
    v = p.audit.verify()
    d.h2("7. 기록 무결성")
    d.mpara(f"감사 로그 해시 체인 검증: <b>{'정상' if v.get('ok') else '훼손 감지 #' + str(v.get('broken_at'))}</b> "
           f"({v.get('checked', 0)}건 검증, {d.t(time.time(), True)}). 이 보고서의 모든 조치·승인 기록은 수정·삭제할 수 없는 감사 로그에서 가져왔다.")
    return d.build()


# ==================================================================== 기간 요약 보고서
def summary_pdf(p, frm=None, to=None):
    from .geoip import Locator
    tz = p.settings.get("timezone", "UTC")
    ov = analytics.overview(p.db, p.config, Locator(p.settings, Lists(p.config.get("lists"))), frm, to, tz)
    m, t = ov["meta"], ov["totals"]
    d = _Doc(p, "보안 관제 요약 보고서", "")
    d.subtitle = f"범위 {d.t(m['from'])} ~ {d.t(m['to'])} ({tz}) · {m['aggregation']}" + (" · 샘플(가상) 데이터 포함" if m["has_sample"] else "")
    d.h1()

    d.h2("1. 위협 수준")
    d.mpara(f"현재 판정: <b>{escape(ov['threat']['current']['label'])}</b> ({escape(ov['threat']['current']['en'])}) — "
           f"침해 의심 IP {ov['threat']['reasons']['severe_ips']}개 · 계정 단위 공격 {ov['threat']['reasons']['account_alerts']}건 · "
           f"긴급 경보 {ov['threat']['reasons']['critical_alerts']}건")
    inc = ov["incidents"]
    open_inc = sum(n for s, n in inc.items() if s not in ("resolved", "false_positive"))
    pb = ov["playbooks"]
    d.spacer(2)
    d.kv([("전체 이벤트", f"{t['events']:,}"), ("로그인 실패", f"{t['fail']:,} ({(t['fail'] / t['events'] * 100 if t['events'] else 0):.1f}%)"),
          ("출발 IP", f"{t['unique_ips']:,} (실패 {t['fail_ips']:,})"), ("경보", f"{t['alerts']:,} (미처리 {t['open_alerts']:,})"),
          ("긴급·높음 IP", f"{t['critical_high_ips']:,}"), ("침해 의심 IP", f"{t['severe_ips']:,}"),
          ("열린 사건", f"{open_inc:,}"), ("대응 성공률", "-" if pb["success_rate"] is None else f"{pb['success_rate'] * 100:.0f}% ({pb['finished']}건)"),
          ("승인 대기", f"{len(pb['pending_approvals'])}건"), ("경보 심각도", " · ".join(f"{SEV_KO[k]} {v}" for k, v in ov["alerts_by_severity"].items() if v) or "-")])

    d.h2("2. 로그인 실패 추이")
    d.flow.append(_bar_chart(d, ov["series"], m["bucket_sec"]))

    d.h2("3. 위험 IP 상위 15")
    if ov["offenders"]:
        d.table(["IP", "심각도", "위험", "실패", "성공", "대표 탐지", "계정", "사건"],
                [[o["ip"], d.sev(o["severity"]), f"{o['risk']:.0f}", f"{o['fails']:,}", o["success"], o["rules"][0]["title"],
                  ", ".join(o["users"][:4]) + (f" 외 {len(o['users']) - 4}" if len(o["users"]) > 4 else ""), f"#{o['incident_id']}" if o["incident_id"] else "-"]
                 for o in ov["offenders"][:15]], [.15, .08, .06, .08, .06, .3, .19, .08])
    else:
        d.para("경보가 걸린 IP 없음")

    d.h2("4. 표적 계정 · 출발 국가")
    from reportlab.platypus import Table
    left = [[x["user"], f"{x['fails']:,}", x["ips"], "계정 단위 경보" if x["account_alert"] else ""] for x in ov["targets"][:10]]
    right = [[f"{c['name']} ({c['cc']})", f"{c['fails']:,}", c["ips"], SEV_KO.get(c["level"], "") if c["level"] else ""] for c in ov["geo"]["countries"][:10]]
    keep = d.flow
    d.flow = []
    d.table(["계정", "실패", "IP", ""], left or [["-", "", "", ""]], [.17, .1, .07, .14])
    d.table(["국가", "실패", "IP", "최고"], right or [["위치 정보 없음", "", "", ""]], [.2, .1, .07, .1])
    lt, rt = d.flow
    d.flow = keep
    tw = d.A4[0] - 30 * d.mm
    d.flow.append(Table([[lt, rt]], colWidths=[tw * .49, tw * .51], style=[("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0)]))
    if ov["geo"]["source"] != "GeoLite2":
        d.para("※ 국가는 위치 DB 가 없으면 표시되지 않거나 샘플 추정입니다.", "small")
    elif "dbip" in (ov["geo"].get("db") or "").lower():
        d.para("※ 위치: IP Geolocation by DB-IP (https://db-ip.com, CC BY 4.0)", "small")

    d.h2("5. 탐지 규칙별 경보 · 오탐")
    rows = p.db.all("SELECT a.rule_id, COUNT(*) n, SUM(i.state='false_positive') fp FROM alerts a LEFT JOIN incidents i ON i.id=a.incident_id "
                    "WHERE a.last_ts >= ? AND a.first_ts < ? GROUP BY a.rule_id ORDER BY n DESC", (m["from"], m["to"]))
    rules = p.config.all("rule")
    d.table(["규칙", "이름", "경보", "오탐 처리", "오탐률"], [[r["rule_id"], (rules.get(r["rule_id"]) or {}).get("name", "-"), r["n"], r["fp"] or 0,
                                                     f"{(r['fp'] or 0) / r['n'] * 100:.1f}%"] for r in rows] or [["-", "범위 안 경보 없음", "", "", ""]],
            [.22, .38, .12, .14, .14])

    d.h2("6. 대응 현황")
    blocks = p.db.all("SELECT ip, reason, added_at, expires_at FROM blocklist ORDER BY added_at DESC LIMIT 20")
    d.para(f"플레이북 실행 상태: {', '.join(f'{STATE_KO.get(k, k)} {v}' for k, v in pb['by_state'].items()) or '없음'} · 현재 차단 IP {len(blocks)}개")
    if blocks:
        d.table(["차단 IP", "사유", "추가", "만료"], [[b["ip"], b["reason"] or "-", d.t(b["added_at"]), d.t(b["expires_at"]) if b["expires_at"] else "무기한"]
                                               for b in blocks], [.18, .46, .18, .18])
    v = p.audit.verify()
    d.h2("7. 기록 무결성")
    d.mpara(f"감사 로그 해시 체인: <b>{'정상' if v.get('ok') else '훼손 감지'}</b> ({v.get('checked', 0)}건 검증)")
    return d.build()


def _bar_chart(d, series, bucket):
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from reportlab.graphics.shapes import Drawing, String
    c = d.colors
    tw = d.A4[0] - 30 * d.mm
    dr = Drawing(tw, 150)
    if not any(x["fail"] or x["success"] for x in series):
        dr.add(String(10, 70, "범위 안 로그인 이벤트 없음", fontName=d.r, fontSize=9))
        return dr
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 34, 22, tw - 44, 112
    ch.data = [[x["fail"] for x in series], [x["success"] for x in series]]
    ch.groupSpacing, ch.barSpacing = 1, 0
    ch.bars[0].fillColor, ch.bars[1].fillColor = c.HexColor("#d93636"), c.HexColor("#4caf6d")
    ch.bars.strokeWidth = 0
    ch.valueAxis.valueMin = 0
    ch.valueAxis.labels.fontName, ch.valueAxis.labels.fontSize = d.r, 7
    every = max(1, len(series) // 12)
    fmt = "%m-%d" if bucket >= 86400 else "%d일 %H시"
    ch.categoryAxis.categoryNames = [datetime.fromtimestamp(x["t"], d.tz).strftime(fmt) if i % every == 0 else "" for i, x in enumerate(series)]
    ch.categoryAxis.labels.fontName, ch.categoryAxis.labels.fontSize = d.r, 6.5
    ch.categoryAxis.labels.angle, ch.categoryAxis.labels.dy, ch.categoryAxis.labels.boxAnchor = 30, -2, "ne"
    dr.add(ch)
    dr.add(String(tw - 150, 140, "■ 실패", fontName=d.r, fontSize=8, fillColor=c.HexColor("#d93636")))
    dr.add(String(tw - 100, 140, "■ 성공", fontName=d.r, fontSize=8, fillColor=c.HexColor("#4caf6d")))
    return dr
