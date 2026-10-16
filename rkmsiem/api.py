"""HTTP API (Flask) — 인증 · RBAC · 입력 검증 · SSE · 상태 점검 · 지표 · UI 서빙.

권한 검사는 전부 여기(백엔드)에서 한다. UI 의 버튼 숨김은 편의일 뿐 보안 통제가 아니다.
SQL 은 매개변수 바인딩만, 정렬/필터 필드는 허용 목록으로만 받는다.
"""
import functools
import hmac
import json
import logging
import os
import queue
import time
import urllib.parse
from datetime import datetime

from flask import Flask, Response, g, jsonify, request, send_from_directory, stream_with_context
from jsonschema import Draft202012Validator

from . import analytics, yamlio
from .alerts import row_to_alert
from .auth import AuthError, AuthService
from .db import loads
from .detect import compare, simulate
from .geoip import Locator
from .conditions import Lists
from .incidents import WorkflowError
from .logutil import mask
from .schemas import SchemaError
from .settings import BASE_DIR
from .soar.engine import ApprovalError

log = logging.getLogger("rkmsiem.api")
WEB_DIR = os.path.join(BASE_DIR, "web")


class ApiError(Exception):
    def __init__(self, status, msg, details=None):
        super().__init__(msg)
        self.status, self.msg, self.details = status, msg, details


def _validate(body, schema):
    errs = list(Draft202012Validator(schema).iter_errors(body))
    if errs:
        raise ApiError(400, "invalid_request", [f"{'/'.join(map(str, e.path)) or '(body)'}: {e.message}" for e in errs[:10]])
    return body


def _ts(v):
    """시각 파라미터: epoch 초 또는 ISO8601."""
    if v in (None, ""):
        return None
    try:
        return float(v)
    except ValueError:
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            raise ApiError(400, f"bad time: {v}")


def _int(name, default, lo, hi):
    try:
        v = int(request.args.get(name, default))
    except ValueError:
        raise ApiError(400, f"bad {name}")
    return max(lo, min(hi, v))


def create_app(platform):
    p = platform
    s = p.settings
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = s.get("api.max_body_kb", 1024) * 1024
    auth = AuthService(p.db, p.config, p.audit, s, vault=p.vault)
    app.extensions["rkmsiem_auth"] = auth
    locator_cache = {}

    def locator():
        key = p.config.version("lists")
        if key not in locator_cache:
            locator_cache.clear()
            locator_cache[key] = Locator(s, Lists(p.config.get("lists")))
        return locator_cache[key]

    # ------------------------------------------------------------ 공통
    @app.errorhandler(ApiError)
    def _api_err(e):
        return jsonify({"error": e.msg, "details": e.details}), e.status

    @app.errorhandler(SchemaError)
    def _schema_err(e):
        return jsonify({"error": "validation_failed", "details": e.errors}), 400

    @app.errorhandler(KeyError)
    def _nf(e):
        return jsonify({"error": "not_found", "details": str(e)}), 404

    @app.errorhandler(WorkflowError)
    def _wf(e):
        return jsonify({"error": "workflow", "details": str(e)}), 409

    @app.errorhandler(ApprovalError)
    def _ap(e):
        return jsonify({"error": "approval", "details": str(e)}), 403

    @app.errorhandler(413)
    def _big(e):
        return jsonify({"error": "payload_too_large"}), 413

    @app.errorhandler(404)
    def _404(e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(Exception)
    def _500(e):
        if hasattr(e, "code") and isinstance(getattr(e, "code"), int):
            return jsonify({"error": getattr(e, "name", "error")}), e.code
        log.exception("unhandled")
        return jsonify({"error": "internal_error"}), 500

    def _cx_frame():                                     # 콘솔이 연동 화면(다른 포트) iframe 을 열 수 있게
        pub = (s.get("connect.public_origin") or "").rstrip("/")
        if pub:
            return pub
        hn = request.host[:request.host.rindex("]") + 1] if request.host.startswith("[") else request.host.split(":")[0]
        return f"https://{hn}:{int(s.get('connect.port', 8445) or 8445)}"

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        if request.path.startswith("/connect/"):         # 연동 제품의 페이지 — 제품 자체 정책 그대로, 콘솔(같은 호스트)에서만 프레임 허용
            hn = request.host[:request.host.rindex("]") + 1] if request.host.startswith("[") else request.host.split(":")[0]
            resp.headers["Content-Security-Policy"] = f"frame-ancestors https://{hn}:*"
            resp.headers["Referrer-Policy"] = "same-origin"
            return resp
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; "
            f"connect-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:; frame-src 'self' {_cx_frame()}; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        elif request.path == "/" or request.path.startswith("/static/"):
            # 업데이트 뒤에도 브라우저가 예전 app.js 를 쓰지 않게 — 매번 확인(바뀌지 않았으면 304)
            resp.headers["Cache-Control"] = "no-cache"
        return resp

    MUST_CHANGE_OK = {"/api/me", "/api/me/password", "/api/auth/logout"}     # 비밀번호를 바꾸기 전에 쓸 수 있는 것

    def require(perm):
        def deco(fn):
            @functools.wraps(fn)
            def wrapper(*a, **kw):
                h = request.headers.get("Authorization", "")
                user = auth.resolve(h[7:] if h.startswith("Bearer ") else None, client=request.remote_addr)
                if not user and request.headers.get("X-RKMSIEM-Local"):
                    user = auth.local_user(request.headers["X-RKMSIEM-Local"], request.remote_addr)
                if not user:
                    return jsonify({"error": "unauthorized"}), 401
                if user["id"] is None and request.path.startswith(("/api/me/", "/api/stream")):     # root 점검 키는 개인 설정 없음
                    return jsonify({"error": "forbidden", "details": "점검 키로는 쓸 수 없는 기능"}), 403
                if user.get("must_change") and request.path not in MUST_CHANGE_OK:
                    return jsonify({"error": "password_change_required",
                                    "details": "처음 받은 비밀번호입니다 — passwd 로 새 비밀번호(12자 이상)를 정한 뒤 다시 로그인하세요"}), 403
                if perm and perm not in user["permissions"]:
                    p.audit.record(user["username"], "auth.forbidden", "api", request.path, None, {"perm": perm, "method": request.method})
                    return jsonify({"error": "forbidden", "required": perm}), 403
                g.user = user
                return fn(*a, **kw)
            return wrapper
        return deco

    def body(schema=None):
        try:
            b = request.get_json(force=True, silent=False) if request.data else {}
        except Exception:
            raise ApiError(400, "invalid_json")
        if not isinstance(b, dict):
            raise ApiError(400, "body must be an object")
        return _validate(b, schema) if schema else b

    def actor():
        return g.user["username"]

    def client():
        return request.remote_addr or "?"

    # ------------------------------------------------------------ UI · 상태
    @app.get("/")
    def index():
        return send_from_directory(WEB_DIR, "index.html")

    @app.get("/favicon.ico")
    def favicon():                                           # 링크 태그를 안 읽는 클라이언트용
        return send_from_directory(WEB_DIR, "favicon.svg", mimetype="image/svg+xml")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(WEB_DIR, name)            # send_from_directory 가 경로 탈출을 막음

    @app.get("/healthz")
    def healthz():
        return jsonify(p.health())

    @app.get("/readyz")
    def readyz():
        ok, checks = p.readiness()
        public = {k: v for k, v in checks.items() if k in ("database", "pipeline_worker", "soar_worker", "queue_ok", "collectors_ok")}
        return jsonify({"ready": ok, "checks": public}), (200 if ok else 503)

    @app.get("/metrics")
    @require("metrics:read")
    def prom():
        from .promsec import security_metrics
        return Response(p.metrics.prometheus() + "\n" + security_metrics(p), mimetype="text/plain; version=0.0.4")

    # ------------------------------------------------------------ 인증
    @app.post("/api/auth/login")
    def login():
        b = body({"type": "object", "required": ["username", "password"], "additionalProperties": False,
                  "properties": {"username": {"type": "string", "maxLength": 64}, "password": {"type": "string", "maxLength": 256}}})
        try:
            token, info = auth.login(b["username"], b["password"], client())
        except AuthError as e:
            return jsonify({"error": str(e)}), (429 if str(e) == "rate_limited" else 401)
        return jsonify(dict(info, token=token) if token else info)     # 2단계 인증: mfa_ticket → /api/auth/mfa

    @app.post("/api/auth/mfa")
    def login_mfa():
        b = body({"type": "object", "required": ["ticket", "code"], "additionalProperties": False,
                  "properties": {"ticket": {"type": "string", "maxLength": 128}, "code": {"type": "string", "maxLength": 16}}})
        try:
            token, info = auth.login_mfa(b["ticket"], b["code"], client())
        except AuthError as e:
            return jsonify({"error": str(e)}), (429 if str(e) == "rate_limited" else 401)
        return jsonify(dict(info, token=token))

    @app.post("/api/auth/logout")
    @require(None)
    def logout():
        auth.logout(request.headers["Authorization"][7:])
        p.audit.record(actor(), "auth.logout", "user", actor())
        return jsonify({"ok": True})

    @app.get("/api/me")
    @require(None)
    def me():
        return jsonify({"username": g.user["username"], "role": g.user["role"], "permissions": sorted(g.user["permissions"]),
                        "must_change_password": g.user["must_change"], "mfa_enabled": g.user["mfa"],
                        "mode": s.get("soar.mode"), "env": s.get("env")})

    # ------------------------------------------------------------ 실시간
    @app.post("/api/stream/ticket")
    @require("alerts:read")
    def ticket():
        return jsonify({"ticket": auth.stream_ticket(g.user)})

    @app.get("/api/stream")
    def stream():
        user = auth.resolve(request.args.get("ticket"), kind="stream")
        if not user:
            return jsonify({"error": "unauthorized"}), 401
        q = p.bus.subscribe()
        hb = s.get("api.stream_heartbeat_sec", 15)

        @stream_with_context
        def gen():
            try:
                yield "retry: 3000\n\n"
                yield f"event: hello\ndata: {json.dumps({'user': user['username'], 'ts': time.time()})}\n\n"
                while True:
                    try:
                        m = q.get(timeout=hb)
                    except queue.Empty:
                        yield f": ping {int(time.time())}\n\n"
                        continue
                    if m.get("type") == "_overflow":
                        yield "event: overflow\ndata: {}\n\n"
                        return
                    yield f"id: {m['id']}\nevent: {m['type']}\ndata: {json.dumps(m, ensure_ascii=False, default=str)}\n\n"
            finally:
                p.bus.unsubscribe(q)
        return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------ 수집
    @app.post("/api/ingest/<source_id>")
    def ingest(source_id):
        if not auth.check_ingest_key(request.headers.get("X-API-Key")):
            return jsonify({"error": "unauthorized"}), 401
        coll = p.collectors.get(source_id)
        if coll is None or coll.type_name != "http":
            return jsonify({"error": "unknown_source"}), 404
        recs = coll.records_from_body(request.get_data(cache=False), request.content_type)
        if not recs:
            return jsonify({"error": "empty"}), 400
        if request.args.get("wait") in ("1", "true"):
            res = p.pipeline.submit_and_wait(recs, timeout=10)
            code = 200 if res["left"] <= 0 else 202
            return jsonify({"accepted": len(recs), "stored": res["stored"], "duplicates": res["dup"], "failed": res["failed"]}), code
        accepted = 0
        for r in recs:
            if not p.pipeline.submit(r):
                break
            accepted += 1
        if accepted < len(recs):                                   # 큐 포화 → 백프레셔
            return jsonify({"error": "queue_full", "accepted": accepted, "rejected": len(recs) - accepted}), 429, {"Retry-After": "2"}
        return jsonify({"accepted": accepted}), 202

    # ------------------------------------------------------------ 대시보드 · 검색
    @app.get("/api/overview")
    @require("alerts:read")
    def overview():
        frm, to = _ts(request.args.get("from")), _ts(request.args.get("to"))
        return jsonify(analytics.overview(p.db, p.config, locator(), frm, to, s.get("timezone", "UTC")))

    EVENT_FILTERS = {"ip": "source_ip", "user": "user_name", "outcome": "outcome", "source": "source_id", "dataset": "dataset", "action": "action"}

    @app.get("/api/events")
    @require("events:read")
    def events():
        where, params = [], []
        frm, to = _ts(request.args.get("from")), _ts(request.args.get("to"))
        if frm is not None:
            where.append("ts >= ?"); params.append(frm)
        if to is not None:
            where.append("ts < ?"); params.append(to)
        for k, col in EVENT_FILTERS.items():
            if request.args.get(k):
                where.append(f"{col} = ?"); params.append(request.args[k])
        if request.args.get("q"):
            q = request.args["q"][:200].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            where.append("message LIKE ? ESCAPE '\\'"); params.append(f"%{q}%")
        if request.args.get("alert_id"):
            a = p.db.one("SELECT evidence FROM alerts WHERE id=?", (_int("alert_id", 0, 0, 1 << 62),))
            ids = loads(a["evidence"], []) if a else []
            where.append("id IN (SELECT value FROM json_each(?))"); params.append(json.dumps(ids))
        order = {"ts": "ts ASC, id ASC", "-ts": "ts DESC, id DESC"}.get(request.args.get("sort", "-ts"))
        if order is None:
            raise ApiError(400, "sort must be ts or -ts")
        size, page = _int("size", 50, 1, 500), _int("page", 1, 1, 100000)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = p.db.scalar(f"SELECT COUNT(*) FROM events{w}", params)
        rows = p.db.all(f"SELECT id, ts, ingested_at, source_id, dataset, category, action, outcome, user_name, source_ip, host_name, "
                        f"message, sample, trace_id FROM events{w} ORDER BY {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
        return jsonify({"total": total, "page": page, "size": size, "items": rows})

    @app.get("/api/events/<int:eid>")
    @require("events:read")
    def event(eid):
        r = p.db.one("SELECT e.*, r.raw, r.received_at FROM events e LEFT JOIN raw_events r ON r.id = e.raw_id WHERE e.id=?", (eid,))
        if not r:
            raise KeyError(eid)
        r["doc"] = loads(r["doc"])
        r["raw"] = mask(r["raw"])
        return jsonify(r)

    ALERT_SORT = {"-created": "created_at DESC", "created": "created_at ASC", "-severity": "severity_rank DESC, risk_score DESC",
                  "-risk": "risk_score DESC", "-last": "last_ts DESC"}

    @app.get("/api/alerts")
    @require("alerts:read")
    def alerts():
        where, params = [], []
        for k in ("rule_id", "severity", "status", "level_id"):
            if request.args.get(k):
                where.append(f"{k} = ?"); params.append(request.args[k])
        if request.args.get("incident_id"):
            where.append("incident_id = ?"); params.append(_int("incident_id", 0, 0, 1 << 62))
        if request.args.get("ip"):
            where.append("json_extract(group_fields, '$.\"source.ip\"') = ?"); params.append(request.args["ip"])
        frm, to = _ts(request.args.get("from")), _ts(request.args.get("to"))
        if frm is not None:
            where.append("last_ts >= ?"); params.append(frm)
        if to is not None:
            where.append("first_ts < ?"); params.append(to)
        order = ALERT_SORT.get(request.args.get("sort", "-severity"))
        if not order:
            raise ApiError(400, f"sort must be one of {list(ALERT_SORT)}")
        size, page = _int("size", 50, 1, 500), _int("page", 1, 1, 100000)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = p.db.scalar(f"SELECT COUNT(*) FROM alerts{w}", params)
        rows = [row_to_alert(r) for r in p.db.all(f"SELECT * FROM alerts{w} ORDER BY {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])]
        return jsonify({"total": total, "page": page, "size": size, "items": rows})

    @app.get("/api/alerts/<int:aid>")
    @require("alerts:read")
    def alert(aid):
        a = p.alerts.get(aid)
        if not a:
            raise KeyError(aid)
        a["evidence_events"] = p.db.all("SELECT id, ts, source_id, outcome, user_name, source_ip, message FROM events "
                                        "WHERE id IN (SELECT value FROM json_each(?)) ORDER BY ts", (json.dumps(a["evidence"]),))
        a["runs"] = p.db.all("SELECT id, playbook_id, state, mode, created_at FROM playbook_runs WHERE alert_id=?", (aid,))
        a["rule"] = p.config.content_at("rule", a["rule_id"], a["rule_version"])
        return jsonify(a)

    @app.post("/api/alerts/<int:aid>/status")
    @require("alerts:write")
    def alert_status(aid):
        b = body({"type": "object", "required": ["status"], "properties": {"status": {"enum": ["open", "acknowledged", "closed"]},
                                                                        "reason": {"type": "string", "maxLength": 1000}}})
        cur = p.db.execute("UPDATE alerts SET status=?, updated_at=? WHERE id=?", (b["status"], time.time(), aid))
        if cur.rowcount == 0:
            raise KeyError(aid)
        p.audit.record(actor(), "alert.status", "alert", aid, b.get("reason"), {"status": b["status"]})
        p.bus.publish("alert", {"op": "status", "id": aid, "status": b["status"]})
        return jsonify({"ok": True})

    # ------------------------------------------------------------ 사건
    INC_SORT = {"-updated": "updated_at DESC", "-severity": "severity_rank DESC, updated_at DESC", "-created": "created_at DESC"}

    @app.get("/api/incidents")
    @require("incidents:read")
    def incidents():
        where, params = [], []
        for k in ("state", "severity", "assignee"):
            if request.args.get(k):
                where.append(f"{k} = ?"); params.append(request.args[k])
        if request.args.get("unassigned") in ("1", "true"):
            where.append("assignee IS NULL")
        if request.args.get("open") in ("1", "true"):
            term = sorted(p.incidents.terminal_states())
            where.append(f"state NOT IN ({','.join('?' * len(term))})"); params += term
        order = INC_SORT.get(request.args.get("sort", "-severity"))
        if not order:
            raise ApiError(400, "bad sort")
        size, page = _int("size", 50, 1, 500), _int("page", 1, 1, 100000)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = p.db.scalar(f"SELECT COUNT(*) FROM incidents{w}", params)
        rows = p.db.all(f"SELECT i.*, (SELECT COUNT(*) FROM alerts a WHERE a.incident_id=i.id) alert_count FROM incidents i{w} "
                        f"ORDER BY {order} LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
        return jsonify({"total": total, "page": page, "size": size, "items": rows, "workflow": p.incidents.workflow()})

    @app.get("/api/incidents/<int:iid>")
    @require("incidents:read")
    def incident(iid):
        d = p.incidents.detail(iid)
        if not d:
            raise KeyError(iid)
        d["alerts"] = [row_to_alert(r) for r in p.db.all("SELECT * FROM alerts WHERE incident_id=? ORDER BY first_ts", (iid,))]
        d["runs"] = [p.soar.detail(r["id"]) for r in p.db.all("SELECT id FROM playbook_runs WHERE incident_id=? ORDER BY id", (iid,))]
        d["notifications"] = p.db.all("SELECT * FROM notifications WHERE incident_id=? ORDER BY ts", (iid,))
        if "audit:read" in g.user["permissions"]:
            run_ids = [str(r["id"]) for r in d["runs"]]
            since = d["created_at"] - 5                    # 예전에 같은 번호를 썼던(초기화로 지운) 사건의 기록은 제외
            d["audit"] = [a for a in p.audit.list(500) if a["ts"] >= since and ((a["target_type"] == "incident" and a["target_id"] == str(iid))
                          or (a["target_type"] == "run" and a["target_id"] in run_ids))]
        return jsonify(d)

    @app.post("/api/incidents/<int:iid>/transition")
    @require("incidents:write")
    def transition(iid):
        b = body({"type": "object", "required": ["to"], "properties": {"to": {"type": "string", "maxLength": 64},
                                                                    "reason": {"type": "string", "maxLength": 2000}}})
        return jsonify(p.incidents.transition(iid, b["to"], actor(), b.get("reason")))

    @app.post("/api/incidents/<int:iid>/assign")
    @require("incidents:assign")
    def assign(iid):
        b = body({"type": "object", "required": ["assignee"], "properties": {"assignee": {"type": ["string", "null"], "maxLength": 64}}})
        if b["assignee"] and not p.staff.person(b["assignee"]):           # 담당자 명단(담당자 관리 앱)의 활성 담당자만
            raise ApiError(400, "담당자 명단에 없는 아이디입니다")
        inc = p.incidents.assign(iid, b["assignee"], actor())
        if b["assignee"] and b["assignee"] != actor():
            p.notifier.assignment_mail(inc, b["assignee"], actor())       # 담당자에게 메일 (설정·동의한 경우만)
        return jsonify(inc)

    @app.post("/api/incidents/<int:iid>/comment")
    @require("incidents:write")
    def comment(iid):
        b = body({"type": "object", "required": ["text"], "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 4000}}})
        p.incidents.comment(iid, b["text"], actor())
        return jsonify({"ok": True})

    # ------------------------------------------------------------ 규칙
    @app.get("/api/rules")
    @require("rules:read")
    def rules():
        st = p.engine.stats
        fp = {k.split("=", 1)[1]: v for k, v in (p.metrics.snapshot()["counters"].get("false_positive_total") or {}).items()}
        out = []
        for rid, r in sorted(p.config.all("rule").items()):
            n_alerts = p.db.scalar("SELECT COUNT(*) FROM alerts WHERE rule_id=?", (rid,))
            out.append({"id": rid, "name": r["name"], "type": r["type"], "enabled": r.get("enabled", True), "version": r["_version"],
                        "levels": r["levels"], "stats": dict(st.get(rid, {})), "alerts_total": n_alerts,
                        "false_positives": fp.get(rid, 0), "fp_rate": round(fp.get(rid, 0) / n_alerts, 3) if n_alerts else None})
        return jsonify({"items": out})

    @app.get("/api/rules/<rid>")
    @require("rules:read")
    def rule(rid):
        r = p.config.get("rule", rid)
        if r is None:
            raise KeyError(rid)
        return jsonify({"rule": r, "version": p.config.version("rule", rid), "versions": p.config.versions("rule", rid),
                        "yaml": yamlio.dumps(r)})

    def _content():
        if (request.content_type or "").startswith(("text/yaml", "application/yaml", "application/x-yaml")):
            try:
                c = yamlio.loads(request.get_data(as_text=True))
            except Exception as e:
                raise ApiError(400, f"yaml: {e}")
        else:
            c = body()
        if not isinstance(c, dict):
            raise ApiError(400, "object expected")
        return c

    @app.put("/api/rules/<rid>")
    @require("rules:write")
    def put_rule(rid):
        v = p.config.put("rule", rid, _content(), actor(), request.args.get("comment"))
        return jsonify({"id": rid, "version": v})

    @app.post("/api/rules/<rid>/enabled")
    @require("rules:write")
    def rule_enabled(rid):
        b = body({"type": "object", "required": ["enabled"], "properties": {"enabled": {"type": "boolean"}, "reason": {"type": "string"}}})
        return jsonify({"id": rid, "version": p.config.set_enabled("rule", rid, b["enabled"], actor(), b.get("reason"))})

    @app.post("/api/rules/<rid>/rollback")
    @require("rules:write")
    def rule_rollback(rid):
        b = body({"type": "object", "required": ["version"], "properties": {"version": {"type": "integer", "minimum": 1}, "reason": {"type": "string"}}})
        return jsonify({"id": rid, "version": p.config.rollback("rule", rid, b["version"], actor(), b.get("reason"))})

    @app.post("/api/rules/simulate")
    @require("rules:simulate")
    def rules_simulate():
        """후보 규칙(rule) 또는 비활성/삭제(disable_rule_id)를 저장된 이벤트에 재생해 현재 규칙과 결과를 비교. 저장하지 않음."""
        b = body({"type": "object", "properties": {"rule": {"type": "object"}, "disable_rule_id": {"type": "string"},
                                                   "from": {}, "to": {}, "max_events": {"type": "integer", "minimum": 1, "maximum": 500000}}})
        current = p.config.all("rule")
        candidate = dict(current)
        if b.get("rule"):
            p.config.validate("rule", b["rule"])
            candidate[b["rule"]["id"]] = dict(b["rule"], _version=0)
        if b.get("disable_rule_id"):
            candidate.pop(b["disable_rule_id"], None)
        frm, to = _ts(b.get("from")), _ts(b.get("to"))
        where, params = [], []
        if frm is not None:
            where.append("ts >= ?"); params.append(frm)
        if to is not None:
            where.append("ts < ?"); params.append(to)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        limit = b.get("max_events", 200000)
        rows = p.db.all(f"SELECT id, ts, doc, sample FROM events{w} ORDER BY ts, id LIMIT ?", params + [limit])
        evs = [{"id": r["id"], "ts": r["ts"], "doc": json.loads(r["doc"]), "sample": bool(r["sample"])} for r in rows]
        pol, lists = p.config.get("detection"), p.config.get("lists")
        t0 = time.time()
        before, _ = simulate(current, pol, lists, evs)
        after, stats = simulate(candidate, pol, lists, evs)
        p.audit.record(actor(), "rule.simulate", "rule", (b.get("rule") or {}).get("id") or b.get("disable_rule_id"), None, {"events": len(evs)})
        return jsonify({"events": len(evs), "elapsed_ms": round((time.time() - t0) * 1000, 1), "diff": compare(before, after),
                        "stats": {k: dict(v) for k, v in stats.items()}})

    # ------------------------------------------------------------ 플레이북 · 실행
    @app.get("/api/playbooks")
    @require("playbooks:read")
    def playbooks():
        from .plugins import ACTIONS
        return jsonify({"items": [dict(v, id=k) for k, v in sorted(p.config.all("playbook").items())],
                        "actions": {k: {"destructive": getattr(f, "destructive", False), "description": getattr(f, "description", "")}
                                    for k, f in sorted(ACTIONS.items())}, "mode": s.get("soar.mode")})

    @app.put("/api/playbooks/<pid>")
    @require("playbooks:write")
    def put_playbook(pid):
        return jsonify({"id": pid, "version": p.config.put("playbook", pid, _content(), actor(), request.args.get("comment"))})

    @app.get("/api/playbooks/<pid>")
    @require("playbooks:read")
    def playbook(pid):
        pb = p.config.get("playbook", pid)
        if pb is None:
            raise KeyError(pid)
        return jsonify({"playbook": pb, "version": p.config.version("playbook", pid), "versions": p.config.versions("playbook", pid),
                        "yaml": yamlio.dumps(pb)})

    @app.post("/api/playbooks/<pid>/enabled")
    @require("playbooks:write")
    def playbook_enabled(pid):
        b = body({"type": "object", "required": ["enabled"], "properties": {"enabled": {"type": "boolean"}, "reason": {"type": "string"}}})
        return jsonify({"id": pid, "version": p.config.set_enabled("playbook", pid, b["enabled"], actor(), b.get("reason"))})

    @app.post("/api/playbooks/<pid>/rollback")
    @require("playbooks:write")
    def playbook_rollback(pid):
        b = body({"type": "object", "required": ["version"], "properties": {"version": {"type": "integer", "minimum": 1}, "reason": {"type": "string"}}})
        return jsonify({"id": pid, "version": p.config.rollback("playbook", pid, b["version"], actor(), b.get("reason"))})

    @app.post("/api/playbooks/validate")
    @require("playbooks:read")
    def playbook_validate():
        """편집 중인 플레이북을 저장하지 않고 검증 + 최근 경보에 트리거를 대입해 '몇 건에 실행됐을지' 미리 보기."""
        b = body({"type": "object", "required": ["playbook"], "properties": {"playbook": {"type": "object"},
                                                                              "max_alerts": {"type": "integer", "minimum": 1, "maximum": 5000}}})
        pb = b["playbook"]
        try:
            p.config.validate("playbook", pb)
        except SchemaError as e:
            return jsonify({"ok": False, "errors": e.errors})
        from .conditions import check_all, render
        trig, lists = pb["trigger"], Lists(p.config.get("lists"))
        preview = {"trigger": trig["on"], "checked": 0, "matched": 0, "samples": []}
        if trig["on"] != "manual":
            rows = p.db.all("SELECT a.*, i.title AS i_title, i.severity AS i_severity, i.state AS i_state, i.correlation_key AS i_key "
                            "FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id ORDER BY a.id DESC LIMIT ?", (b.get("max_alerts", 500),))
            for r in rows:
                ctx = {"alert": row_to_alert(r), "incident": {"id": r["incident_id"], "title": r["i_title"], "severity": r["i_severity"],
                                                              "state": r["i_state"], "correlation_key": r["i_key"]}}
                preview["checked"] += 1
                if not check_all(trig.get("where"), ctx, lists):
                    continue
                preview["matched"] += 1
                if len(preview["samples"]) < 5:
                    preview["samples"].append({"alert_id": r["id"], "title": ctx["alert"]["title"], "severity": ctx["alert"]["severity"],
                                               "incident_id": r["incident_id"], "ts": ctx["alert"].get("last_ts"),
                                               "inputs": {s["id"]: render(s.get("input") or {}, dict(ctx, steps={})) for s in pb["steps"]}})
        return jsonify({"ok": True, "errors": [], "yaml": yamlio.dumps(pb), "preview": preview})

    @app.post("/api/playbooks/<pid>/run")
    @require("playbooks:run")
    def run_playbook(pid):
        b = body({"type": "object", "required": ["incident_id"], "properties": {"incident_id": {"type": "integer"}}})
        return jsonify({"run_id": p.soar.run_manual(pid, b["incident_id"], actor())}), 201

    @app.get("/api/runs")
    @require("runs:read")
    def runs():
        where, params = [], []
        for k in ("state", "playbook_id"):
            if request.args.get(k):
                where.append(f"{k} = ?"); params.append(request.args[k])
        if request.args.get("incident_id"):
            where.append("incident_id = ?"); params.append(_int("incident_id", 0, 0, 1 << 62))
        size, page = _int("size", 50, 1, 500), _int("page", 1, 1, 100000)
        w = (" WHERE " + " AND ".join(where)) if where else ""
        total = p.db.scalar(f"SELECT COUNT(*) FROM playbook_runs{w}", params)
        rows = p.db.all(f"SELECT id, playbook_id, playbook_version, incident_id, alert_id, state, mode, error, requested_by, created_at, "
                        f"started_at, finished_at FROM playbook_runs{w} ORDER BY id DESC LIMIT ? OFFSET ?", params + [size, (page - 1) * size])
        return jsonify({"total": total, "items": rows})

    @app.get("/api/runs/<int:rid>")
    @require("runs:read")
    def run(rid):
        d = p.soar.detail(rid)
        if not d:
            raise KeyError(rid)
        return jsonify(d)

    @app.post("/api/runs/<int:rid>/steps/<sid>/decision")
    @require("runs:approve")
    def decision(rid, sid):
        b = body({"type": "object", "required": ["approve", "reason"], "properties": {"approve": {"type": "boolean"},
                                                                                     "reason": {"type": "string", "minLength": 1, "maxLength": 2000}}})
        p.soar.decide(rid, sid, actor(), g.user["role"], b["approve"], b["reason"])
        return jsonify(p.soar.detail(rid))

    @app.post("/api/runs/<int:rid>/cancel")
    @require("runs:cancel")
    def cancel(rid):
        b = body({"type": "object", "required": ["reason"], "properties": {"reason": {"type": "string", "minLength": 1},
                                                                        "compensate": {"type": "boolean"}}})
        p.soar.cancel(rid, actor(), b["reason"], b.get("compensate", True))
        return jsonify(p.soar.detail(rid))

    # ------------------------------------------------------------ 운영
    @app.get("/api/collectors")
    @require("collectors:read")
    def collectors():
        return jsonify({"collectors": [c.status() for c in p.collectors.values()],
                        "pipeline": {"queue_depth": p.pipeline.q.qsize(), "queue_size": p.pipeline.q.maxsize, "alive": p.pipeline.alive(),
                                     "last_batch_at": p.pipeline.last_batch_at,
                                     "dlq_pending": p.db.scalar("SELECT COUNT(*) FROM dlq WHERE replayed=0"),
                                     "received": p.metrics.total("ingest_received_total"), "stored": p.metrics.total("events_stored_total"),
                                     "rejected": p.metrics.total("ingest_rejected_total"), "duplicates": p.metrics.total("duplicates_total"),
                                     "parse_errors": p.metrics.total("parse_errors_total"),
                                     "latency": p.metrics.hist_summary("ingest_latency_ms")}})

    # ------------------------------------------------------------ 장기 API 토큰 (Prometheus · Grafana · 외부 도구, 읽기 전용)
    @app.get("/api/tokens")
    @require("users:write")
    def tokens():
        return jsonify({"items": auth.list_api_tokens(), "scopes": auth.TOKEN_SCOPES})

    @app.post("/api/tokens")
    @require("users:write")
    def token_create():
        b = body({"type": "object", "required": ["name", "scopes"], "additionalProperties": False,
                  "properties": {"name": {"type": "string", "maxLength": 64}, "scopes": {"type": "array", "items": {"type": "string"}, "maxItems": 10},
                                 "expires_days": {"type": ["integer", "null"], "minimum": 1, "maximum": 3650}}})
        if g.user["id"] is None:
            raise ApiError(403, "forbidden", "API 토큰으로는 토큰을 만들 수 없습니다")
        try:
            return jsonify(auth.create_api_token(b["name"], b["scopes"], actor(), b.get("expires_days"))), 201
        except ValueError as e:
            raise ApiError(400, str(e))

    @app.delete("/api/tokens/<int:tid>")
    @require("users:write")
    def token_revoke(tid):
        try:
            auth.revoke_api_token(tid, actor())
        except KeyError:
            raise ApiError(404, "not_found")
        return jsonify({"ok": True})

    # ------------------------------------------------------------ 연동 화면 (connect) — rkmsiem/connect.py
    from . import connect as cx

    _cx_origin = _cx_frame

    def _cx_items():
        out = []
        for sid, src in p.sources().items():
            v = cx.view_of(src)
            if not v and src["type"] != "http_pull":
                continue
            c = p.collectors.get(sid)
            st = c.status() if c else {}
            out.append({"id": sid, "type": src["type"], "dataset": src.get("dataset"), "enabled": src.get("enabled", True),
                        "title": (v or {}).get("title") or sid, "kind": (v or {}).get("kind"),
                        "view": {"home": v.get("home", "/"), "dashboards": v.get("dashboards") or [], "sso": bool(v.get("sso"))} if v else None,
                        "status": {k: st.get(k) for k in ("state", "alive", "received", "last_event_at", "last_error", "last_poll_at", "last_count")} if st else None})
        return out

    @app.get("/api/connect")
    @require("metrics:read")
    def connect_list():
        return jsonify({"origin": _cx_origin(), "items": _cx_items(), "slots": (p.config.get("embeds") or {}).get("slots", [])})

    @app.post("/api/connect/session")
    @require("metrics:read")
    def connect_session():
        """연동 화면 iframe 은 Authorization 헤더를 못 보내므로 /connect/ 경로 전용 HttpOnly 쿠키를 준다 (세션 토큰과 별개)."""
        if g.user["id"] is None:
            raise ApiError(403, "forbidden", "사람 계정으로만 열 수 있습니다")
        t, ttl = auth.connect_ticket(g.user)
        resp = jsonify({"ok": True, "origin": _cx_origin(), "expires_in": ttl})
        resp.set_cookie(cx.COOKIE, t, max_age=ttl, path="/connect/", httponly=True, samesite="Strict",
                        secure=request.headers.get("X-Forwarded-Proto") == "https" or request.is_secure)
        return resp

    @app.get("/api/connect/<sid>/fetch")
    @require("config:write")
    def connect_fetch(sid):
        """설정 화면 도우미 (예: Grafana 대시보드·패널 고르기) — 제품의 JSON 을 서버가 대신 읽음. GET 만, 2MB 까지."""
        v = cx.view_of(p.sources().get(sid))
        path = request.args.get("path", "/")
        if not v:
            raise ApiError(404, "not_found", "화면(view)이 없는 연동입니다")
        if not cx._path_ok(path):
            raise ApiError(400, "bad_path")
        base, target = cx.upstream_target(v, sid, path.lstrip("/").split("?")[0], urllib.parse.urlsplit(path).query)
        hdr = cx.build_headers([("Accept", "application/json")], v, g.user, client(), request.host, sid)
        try:
            conn, r = cx.fetch(v, "GET", target, hdr, timeout=10)
            data = r.read(2 * 1024 * 1024 + 1)
            conn.close()
        except OSError as e:
            raise ApiError(502, "upstream_error", f"연동 제품({urllib.parse.urlsplit(v['url']).netloc})에 접속 실패: {e} — '화면 주소' 확인")
        if r.status >= 400 or len(data) > 2 * 1024 * 1024:
            raise ApiError(502, "upstream_error", f"연동 제품 응답 {r.status}")
        try:
            return jsonify({"data": json.loads(data)})
        except ValueError:
            raise ApiError(502, "upstream_error", "JSON 이 아닌 응답")

    @app.route("/connect/<sid>/", defaults={"rest": ""}, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    @app.route("/connect/<sid>/<path:rest>", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
    def connect_proxy(sid, rest):
        # nginx 의 연동 화면 포트(8445)를 거친 요청만 — 콘솔과 같은 출처에서 제품 페이지가 열리지 않게
        if request.headers.get("X-RKMSIEM-Connect") != "1":
            return Response("연동 화면은 https://<서버>:8445 에서만 열립니다", status=404, mimetype="text/plain")
        user = auth.resolve(request.cookies.get(cx.COOKIE), kind="connect")
        if not user or user["must_change"] or "metrics:read" not in user["permissions"]:
            return Response("<!doctype html><meta charset=utf-8><body style='background:#111;color:#ccc;font:14px sans-serif;padding:24px'>"
                            "RKMSIEM 로그인이 필요합니다 — 콘솔에서 <b>connect</b> 로 여세요.</body>", status=401, mimetype="text/html")
        v = cx.view_of(p.sources().get(sid))
        if not v:
            return Response("연동 화면이 없습니다", status=404, mimetype="text/plain")
        if (request.content_length or 0) > cx.MAX_BODY:
            return Response("요청이 너무 큽니다", status=413)
        base, target = cx.upstream_target(v, sid, rest, request.query_string.decode("latin-1"))
        hdr = cx.build_headers(list(request.headers.items()), v, user, client(), request.host, sid)
        body = request.get_data() if request.method not in ("GET", "HEAD") else None
        try:
            conn, r = cx.fetch(v, request.method, target, hdr, body)
        except OSError as e:
            return Response(f"연동 제품({urllib.parse.urlsplit(v['url']).netloc})에 접속하지 못했습니다: {e}\n"
                            f"→ settings → 당겨오기 → {sid} 편집 → '화면 주소' 확인 (제품이 켜져 있는지 · 이 서버에서 닿는지)", status=502, mimetype="text/plain; charset=utf-8")
        origin = _cx_origin()
        headers = []
        for k, val in r.getheaders():
            lk = k.lower()
            if lk in cx.HOP or lk == "x-frame-options":
                continue
            if lk == "location":
                val = cx.rewrite_location(val, v, sid, origin)
            headers.append((k, val))

        def stream():
            try:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    yield chunk
            finally:
                conn.close()
        resp = Response(stream() if request.method != "HEAD" else b"", status=r.status, headers=headers, direct_passthrough=True)
        cl = r.getheader("Content-Length")
        if cl and request.method != "HEAD":
            resp.headers["Content-Length"] = cl
        return resp

    # ------------------------------------------------------------ 당겨오기 (다른 시스템 API 를 주기적으로 조회)
    @app.get("/api/pull")
    @require("collectors:read")
    def pull_list():
        from .collectors.http_pull import vault_name
        set_names = {r["name"] for r in p.db.all("SELECT name FROM secrets WHERE name LIKE 'pull:%'")}
        out = []
        for sid, cfg in p.sources().items():
            if cfg["type"] != "http_pull":
                continue
            c = p.collectors.get(sid)
            cur = p.db.one("SELECT value, updated_at FROM collector_state WHERE source_id=? AND key='cursor'", (sid,))
            out.append({"source": cfg, "secret_set": vault_name(sid) in set_names, "status": c.status() if c else None,
                        "cursor": json.loads(cur["value"]) if cur else None})
        return jsonify({"items": out, "version": p.config.version("sources")})

    @app.post("/api/pull/test")
    @require("config:write")
    def pull_test():
        """저장 전에 한 번 조회해 보기 — 받은 항목 앞부분과 변환(정규화) 결과. 저장·탐지는 하지 않음."""
        from . import normalize as norm
        from .collectors.http_pull import PullError, pull_once, secret_for
        from .pipeline import make_record
        from .validators import _pull_errors
        b = body({"type": "object", "required": ["source"], "additionalProperties": False,
                  "properties": {"source": {"type": "object"}, "secret": {"type": "string", "maxLength": 4096}}})
        src = dict(b["source"], type="http_pull")
        src.setdefault("id", "test")
        src.setdefault("parser", "json")
        errs = _pull_errors(src)
        if errs:
            raise ApiError(400, "invalid_source", errs)
        opt = dict(src.get("options") or {}, max_pages=1, max_items=50)
        try:
            secret = b.get("secret") or secret_for(opt, src["id"], p.vault)
            t0 = time.time()
            items, cursor = pull_once(opt, secret, None)
        except (PullError, OSError, ValueError) as e:
            p.audit.record(actor(), "pull.test", "source", src["id"], None, {"ok": False, "error": str(e)[:200]})
            return jsonify({"ok": False, "error": str(e)[:500]}), 200
        parsed = []
        for it in items[:5]:
            try:
                doc, _ = norm.normalize(make_record(src["id"], json.dumps(it, ensure_ascii=False)), src)
                parsed.append({"doc": doc})
            except Exception as e:                       # noqa: BLE001
                parsed.append({"error": str(e)[:300]})
        p.audit.record(actor(), "pull.test", "source", src["id"], None, {"ok": True, "items": len(items)})
        return jsonify({"ok": True, "count": len(items), "ms": round((time.time() - t0) * 1000), "cursor": cursor,
                        "items": [json.dumps(x, ensure_ascii=False)[:2000] for x in items[:3]], "parsed": parsed})

    @app.post("/api/pull/<sid>/secret")
    @require("config:write")
    def pull_secret(sid):
        from .collectors.http_pull import vault_name
        from .vault import VaultError
        b = body({"type": "object", "required": ["value"], "additionalProperties": False, "properties": {"value": {"type": "string", "maxLength": 4096}}})
        try:
            p.vault.set(vault_name(sid), b["value"], actor())
        except VaultError as e:
            raise ApiError(400, str(e))
        return jsonify({"ok": True})

    @app.delete("/api/pull/<sid>/secret")
    @require("config:write")
    def pull_secret_clear(sid):
        from .collectors.http_pull import vault_name
        from .vault import VaultError
        try:
            p.vault.clear(vault_name(sid), actor())
        except VaultError as e:
            raise ApiError(400, str(e))
        return jsonify({"ok": True})

    @app.post("/api/pull/<sid>/cursor/reset")
    @require("config:write")
    def pull_cursor_reset(sid):
        p.db.execute("DELETE FROM collector_state WHERE source_id=? AND key='cursor'", (sid,))
        p.audit.record(actor(), "pull.cursor_reset", "source", sid)
        return jsonify({"ok": True})

    @app.get("/api/dlq")
    @require("dlq:read")
    def dlq():
        rows = p.db.all("SELECT id, source_id, stage, error, attempts, created_at, replayed, substr(raw, 1, 500) raw FROM dlq ORDER BY id DESC LIMIT ?",
                        (_int("size", 100, 1, 500),))
        for r in rows:
            r["raw"] = mask(r["raw"])
        return jsonify({"items": rows})

    @app.post("/api/dlq/replay")
    @require("dlq:replay")
    def dlq_replay():
        b = body({"type": "object", "properties": {"ids": {"type": "array", "items": {"type": "integer"}, "maxItems": 10000}}})
        res = p.pipeline.replay_dlq(b.get("ids"))
        p.audit.record(actor(), "dlq.replay", "dlq", None, None, res)
        return jsonify(res)

    @app.get("/api/audit")
    @require("audit:read")
    def audit():
        rows = p.audit.list(_int("size", 100, 1, 1000), (_int("page", 1, 1, 100000) - 1) * _int("size", 100, 1, 1000),
                            request.args.get("target_type"), request.args.get("target_id"))
        for r in rows:
            r["detail"] = loads(r["detail"], None)
        return jsonify({"items": rows})

    @app.get("/api/audit/verify")
    @require("audit:read")
    def audit_verify():
        return jsonify(p.audit.verify())

    CONFIG_KINDS = ("detection", "lists", "sources", "workflow", "rbac", "approval", "assets", "intel", "mail", "reports", "reputation", "topology", "embeds")

    @app.get("/api/config/<kind>")
    @require("config:read")
    def config_get(kind):
        if kind not in CONFIG_KINDS:
            raise KeyError(kind)
        return jsonify({"kind": kind, "content": p.config.get(kind), "version": p.config.version(kind), "versions": p.config.versions(kind, "default")})

    @app.put("/api/config/<kind>")
    @require("config:write")
    def config_put(kind):
        if kind not in CONFIG_KINDS:
            raise KeyError(kind)
        return jsonify({"kind": kind, "version": p.config.put(kind, "default", _content(), actor(), request.args.get("comment"))})

    @app.post("/api/config/<kind>/rollback")
    @require("config:write")
    def config_rollback(kind):
        if kind not in CONFIG_KINDS:
            raise KeyError(kind)
        b = body({"type": "object", "required": ["version"], "properties": {"version": {"type": "integer", "minimum": 1}}})
        return jsonify({"kind": kind, "version": p.config.rollback(kind, "default", b["version"], actor())})

    # ------------------------------------------------------------ 담당자 명단 (별도 담당자 관리 앱) · 로그인 계정
    def _workload():
        term = sorted(p.incidents.terminal_states())
        rows = p.db.all(f"SELECT assignee, COUNT(*) n, MAX(severity_rank) top FROM incidents WHERE assignee IS NOT NULL "
                        f"AND state NOT IN ({','.join('?' * len(term))}) GROUP BY assignee", term)
        return {r["assignee"]: {"open": r["n"], "top_rank": r["top"]} for r in rows}

    @app.get("/api/users")
    @require("users:write")
    def users():
        """로그인 계정 (역할·활성). 이름·팀·연락처는 담당자 관리 앱에서 관리."""
        wl = _workload()
        roster = {r["username"] for r in p.staff.roster()}
        items = [dict(u, open_incidents=wl.get(u["username"], {}).get("open", 0), in_roster=u["username"] in roster) for u in auth.list_users()]
        return jsonify({"items": items, "roles": {k: v.get("label", k) for k, v in auth.roles().items()}})

    @app.get("/api/assignees")
    @require("incidents:read")
    def assignees():
        """사건 배정 목록용 — 담당자 명단의 활성 담당자와 맡은 열린 사건 수 (연락처는 내보내지 않음)."""
        wl, roles = _workload(), auth.roles()
        acct = {u["username"]: u for u in auth.list_users() if u["active"]}
        items = []
        for r in p.staff.roster():
            a = acct.get(r["username"])
            items.append({"username": r["username"], "display_name": r["display_name"] or r["username"], "team": r["team"],
                          "has_email": bool(r["email"]), "has_account": bool(a), "role": a["role"] if a else None,
                          "role_label": (roles.get(a["role"]) or {}).get("label", a["role"]) if a else None,
                          "open_incidents": wl.get(r["username"], {}).get("open", 0)})
        return jsonify({"items": items, "me": actor()})

    @app.get("/api/staff/status")
    @require("incidents:read")
    def staff_status():
        return jsonify(p.staff.status())

    @app.post("/api/staff/sync")
    @require("users:write")
    def staff_sync():
        from .staffsync import StaffSyncError
        try:
            r = p.staff.sync(actor(), force=True)
        except StaffSyncError as e:
            raise ApiError(502, str(e))
        return jsonify(dict(r, status=p.staff.status()))

    @app.post("/api/staff/hook")
    def staff_hook():
        """담당자 앱이 '명단이 바뀌었다'고 알림 → 바로 다시 가져감 (본문은 쓰지 않음)."""
        k = request.headers.get("X-Sync-Key", "")
        if not (p.staff.configured and k and hmac.compare_digest(k.encode(), p.staff.key.encode())):
            return jsonify({"error": "unauthorized"}), 401
        p.staff.kick()
        return jsonify({"ok": True}), 202

    @app.post("/api/users")
    @require("users:write")
    def create_user():
        b = body({"type": "object", "required": ["username", "password", "role"], "additionalProperties": False,
                  "properties": {"username": {"type": "string"}, "password": {"type": "string"}, "role": {"type": "string"}}})
        try:
            auth.create_user(b["username"], b["password"], b["role"], actor(), must_change=True)    # 임시 비밀번호 → 첫 로그인 때 본인이 바꿈
        except ValueError as e:
            raise ApiError(400, str(e))
        except Exception as e:
            if "UNIQUE" in str(e):
                raise ApiError(409, "이미 있는 사용자 이름입니다")
            raise
        return jsonify({"ok": True}), 201

    @app.patch("/api/users/<name>")
    @require("users:write")
    def update_user(name):
        b = body({"type": "object", "additionalProperties": False, "required": ["role"], "properties": {"role": {"type": "string"}}})
        try:
            auth.update_user(name, b, actor())
        except ValueError as e:
            raise ApiError(400, str(e))
        return jsonify({"ok": True})

    @app.post("/api/users/<name>/password")
    @require("users:write")
    def user_password(name):
        """관리자가 임시 비밀번호로 재설정 (그 사용자의 모든 세션 로그아웃)."""
        b = body({"type": "object", "required": ["password"], "properties": {"password": {"type": "string", "maxLength": 256}}})
        try:
            auth.change_password(name, None, b["password"], actor(), require_current=False)
        except ValueError as e:
            raise ApiError(400, str(e))
        return jsonify({"ok": True})

    @app.post("/api/users/<name>/active")
    @require("users:write")
    def user_active(name):
        b = body({"type": "object", "required": ["active"], "properties": {"active": {"type": "boolean"}}})
        if not b["active"]:
            if name == actor():
                raise ApiError(400, "자기 자신은 비활성화할 수 없습니다")
            try:
                auth.guard_deactivate(name)
            except ValueError as e:
                raise ApiError(400, str(e))
        auth.set_active(name, b["active"], actor())
        return jsonify({"ok": True})

    @app.get("/api/metrics")
    @require("metrics:read")
    def metrics_json():
        snap = p.metrics.snapshot()
        snap["latency"] = {k: p.metrics.hist_summary(k) for k in ("ingest_latency_ms", "e2e_event_to_alert_ms", "batch_ms", "step_ms", "run_ms")}
        snap["rules"] = {k: dict(v) for k, v in p.engine.stats.items()}
        snap["sse_subscribers"] = p.bus.count()
        return jsonify(snap)

    @app.get("/api/notifications")
    @require("alerts:read")
    def notifications():
        return jsonify({"items": p.db.all("SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (_int("size", 50, 1, 500),))})

    # ------------------------------------------------------------ 계정 · 차단 목록 · 점검
    @app.post("/api/me/password")
    @require(None)
    def change_password():
        b = body({"type": "object", "required": ["current", "new"], "additionalProperties": False,
                  "properties": {"current": {"type": "string", "maxLength": 256}, "new": {"type": "string", "maxLength": 256}}})
        try:
            auth.change_password(actor(), b["current"], b["new"], actor())
        except AuthError:
            return jsonify({"error": "invalid_credentials"}), 401
        except ValueError as e:
            raise ApiError(400, str(e))
        return jsonify({"ok": True, "note": "모든 세션이 로그아웃되었습니다. 다시 로그인하세요."})

    # 2단계 인증 (본인)
    @app.get("/api/me/mfa")
    @require(None)
    def mfa_status():
        return jsonify(dict(auth.totp_status(g.user), required_for_terminal=p.terminal.require_mfa))

    @app.post("/api/me/mfa/setup")
    @require(None)
    def mfa_setup():
        try:
            return jsonify(auth.totp_begin(g.user))
        except ValueError as e:
            raise ApiError(409, str(e))

    @app.post("/api/me/mfa/enable")
    @require(None)
    def mfa_enable():
        b = body({"type": "object", "required": ["code"], "additionalProperties": False, "properties": {"code": {"type": "string", "maxLength": 16}}})
        try:
            auth.totp_enable(g.user, b["code"])
        except AuthError:
            return jsonify({"error": "invalid_code", "details": "코드가 맞지 않습니다 — 휴대폰 시간이 맞는지 확인하세요"}), 400
        except ValueError as e:
            raise ApiError(409, str(e))
        return jsonify({"ok": True})

    @app.post("/api/me/mfa/disable")
    @require(None)
    def mfa_disable():
        b = body({"type": "object", "required": ["password", "code"], "additionalProperties": False,
                  "properties": {"password": {"type": "string", "maxLength": 256}, "code": {"type": "string", "maxLength": 16}}})
        try:
            auth.totp_disable(g.user, b["password"], b["code"])
        except AuthError:
            return jsonify({"error": "invalid_credentials", "details": "비밀번호 또는 코드가 맞지 않습니다"}), 400
        except ValueError as e:
            raise ApiError(409, str(e))
        return jsonify({"ok": True})

    @app.post("/api/users/<name>/mfa/reset")
    @require("users:write")
    def user_mfa_reset(name):
        auth.totp_reset(name, actor())
        return jsonify({"ok": True})

    @app.get("/api/blocklist")
    @require("runs:read")
    def blocklist():
        rows = p.db.all("SELECT * FROM blocklist ORDER BY added_at DESC LIMIT 1000")
        return jsonify({"items": rows, "backend": "nftables" if p.response.firewall else "platform", "mode": s.get("soar.mode")})

    @app.post("/api/blocklist")
    @require("runs:approve")
    def block_manual():
        b = body({"type": "object", "required": ["ip", "reason"], "additionalProperties": False,
                  "properties": {"ip": {"type": "string", "maxLength": 64}, "reason": {"type": "string", "minLength": 1, "maxLength": 500},
                                 "duration_sec": {"type": "integer", "minimum": 60, "maximum": 31536000}}})
        out = p.soar.manual_action("block_ip", {"ip": b["ip"], "duration_sec": b.get("duration_sec"), "reason": b["reason"]}, actor(), b["reason"])
        p.bus.publish("config", {"kind": "blocklist", "name": b["ip"]})
        return jsonify(out), 201

    @app.delete("/api/blocklist/<ip>")
    @require("runs:cancel")
    def unblock_manual(ip):
        reason = request.args.get("reason") or "manual unblock"
        out = p.soar.manual_action("unblock_ip", {"ip": ip}, actor(), reason)
        p.bus.publish("config", {"kind": "blocklist", "name": ip})
        return jsonify(out)

    # ------------------------------------------------------------ 보고서 · 메일
    from .mailer import MailError, split_addrs
    from .reports import ReportError

    def _pdf(data, name):
        return Response(data, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="{name}"',
                                                                   "Cache-Control": "no-store"})

    @app.errorhandler(MailError)
    def _mail_err(e):
        return jsonify({"error": "mail", "details": str(e)}), 400

    @app.errorhandler(ReportError)
    def _report_err(e):
        return jsonify({"error": "report", "details": str(e)}), 503

    @app.get("/api/reports/incident/<int:iid>.pdf")
    @require("incidents:read")
    def report_incident(iid):
        from . import reports
        data = reports.incident_pdf(p, iid)
        p.audit.record(actor(), "report.download", "incident", iid, None, {"bytes": len(data)})
        return _pdf(data, f"rkmsiem-incident-{iid}.pdf")

    @app.get("/api/reports/summary.pdf")
    @require("alerts:read")
    def report_summary():
        from . import reports
        data = reports.summary_pdf(p, _ts(request.args.get("from")), _ts(request.args.get("to")))
        p.audit.record(actor(), "report.download", "summary", None, None, {"from": request.args.get("from"), "to": request.args.get("to")})
        return _pdf(data, f"rkmsiem-summary-{datetime.now().strftime('%Y%m%d-%H%M')}.pdf")

    _mail_to = {"type": "object", "properties": {"to": {"type": ["string", "array"]}, "from": {}, "to_ts": {}}}

    def _recipients(b, default):
        if not p.mailer.configured:
            raise MailError("메일 발송이 꺼져 있습니다 — settings.yaml 의 mail (enabled · host · from) 설정 후 서비스 재시작")
        to = split_addrs(b.get("to")) or split_addrs(default)
        if not to:
            raise ApiError(400, "받는 사람이 없습니다 (to 또는 설정의 기본 수신자)")
        return to

    @app.post("/api/reports/incident/<int:iid>/email")
    @require("incidents:write")
    def report_incident_email(iid):
        b = body(_mail_to)
        if not p.incidents.get(iid):
            raise KeyError(iid)
        dflt = ((s.get("reports") or {}).get("incident_on_close") or {}).get("to") or ((s.get("mail") or {}).get("alerts") or {}).get("to")
        mid = p.notifier.send_incident_report(iid, _recipients(b, dflt), actor=actor(), wait=True)
        return jsonify(p.mailer.result(mid))

    @app.post("/api/reports/summary/email")
    @require("incidents:write")
    def report_summary_email():
        b = body(_mail_to)
        frm, to_ts = _ts(b.get("from")), _ts(b.get("to_ts"))
        if frm is None:                                            # 기본: 콘솔과 같은 '최근 데이터 24시간'
            from .analytics import resolve_range
            frm, to_ts, _ = resolve_range(p.db, None, None)
        to = _recipients(b, ((s.get("mail") or {}).get("alerts") or {}).get("to"))
        return jsonify(p.mailer.result(p.notifier.send_summary(frm, to_ts or time.time(), to, actor(), wait=True)))

    @app.get("/api/mail")
    @require("config:read")
    def mail_status():
        from .reports import font_status
        ok, font = font_status(s)
        return jsonify({"status": p.mailer.status(), "pdf_font": {"ok": ok, "detail": font},
                        "log": p.db.all("SELECT id, ts, kind, ref, recipients, subject, status, attempts, error, actor, size, sent_at "
                                        "FROM mail_log ORDER BY id DESC LIMIT ?", (_int("size", 50, 1, 500),))})

    @app.post("/api/mail/test")
    @require("config:write")
    def mail_test():
        """테스트 메일. mail(저장 전 설정)·password(저장 전 비밀번호)를 주면 그 값으로 보내 본다 — 저장은 하지 않음."""
        b = body({"type": "object", "required": ["to"], "properties": {"to": {"type": ["string", "array"]}, "mail": {"type": "object"},
                                                                        "password": {"type": "string", "maxLength": 4096}}})
        cfg = b.get("mail")
        if cfg is not None:
            p.config.validate("mail", cfg)
            cfg = dict(cfg, enabled=True)                    # 꺼 둔 상태에서도 시험은 가능
        c = cfg or p.mailer.cfg
        mid = p.mailer.send("test", b["to"], "테스트 메일", "RKMSIEM 메일 설정이 정상입니다.\n\n"
                            f"요청: {actor()} · 서버 {c.get('host')}:{c.get('port')} ({c.get('security', 'starttls')})"
                            + (" · 저장 전 설정으로 시험" if cfg else ""),
                            actor=actor(), wait=True, cfg=cfg, password=b.get("password") or None)
        return jsonify(p.mailer.result(mid))

    # ------------------------------------------------------------ 비밀 값 (웹 입력 · 암호화 저장 · 다시 읽기 불가)
    from .vault import VaultError

    @app.errorhandler(VaultError)
    def _vault_err(e):
        return jsonify({"error": "secret", "details": str(e)}), 400

    @app.get("/api/secrets")
    @require("config:read")
    def secrets_status():
        return jsonify(p.vault.status())

    @app.put("/api/secrets/<name>")
    @require("config:write")
    def secret_set(name):
        b = body({"type": "object", "required": ["value"], "properties": {"value": {"type": "string", "minLength": 1, "maxLength": 4096}}})
        p.vault.set(name, b["value"], actor())
        if name == "abuseipdb_key":
            p.rebuild_reputation()
        return jsonify(p.vault.status())

    @app.delete("/api/secrets/<name>")
    @require("config:write")
    def secret_clear(name):
        p.vault.clear(name, actor())
        if name == "abuseipdb_key":
            p.rebuild_reputation()
        return jsonify(p.vault.status())

    # ------------------------------------------------------------ 네트워크 토폴로지
    @app.get("/api/topology")
    @require("alerts:read")
    def topology_get():
        from . import topology as topo
        layout = p.config.get("topology") or {"nodes": [], "links": []}
        ips = topo.layout_ips(layout) | {x.strip() for x in request.args.get("ips", "").split(",")[:400] if x.strip()}   # 아직 저장 안 한 기기도
        return jsonify({"layout": layout, "version": p.config.version("topology"), "types": topo.TYPES,
                        "status": topo.status(p, ips), "can_edit": "config:write" in g.user["permissions"]})

    @app.get("/api/topology/discover")
    @require("config:read")
    def topology_discover():
        from . import topology as topo
        return jsonify({"items": topo.discover(p, _int("days", 7, 1, 90))})

    # ------------------------------------------------------------ 웹 터미널 (SIEM 과 와이어로 이어진 기기에 SSH)
    from .terminal import TerminalError, targets as term_targets

    @app.errorhandler(TerminalError)
    def _term_err(e):
        return jsonify({"error": "terminal", "details": str(e)}), e.status

    @app.get("/api/terminal")
    @require("terminal:use")
    def terminal_list():
        return jsonify({"enabled": p.terminal.enabled, "targets": term_targets(p.terminal.layout()),
                        "ports": sorted(p.terminal.ports), "sessions": p.terminal.list(actor())})

    @app.post("/api/terminal")
    @require("terminal:use")
    def terminal_open():
        b = body({"type": "object", "required": ["ip", "login"], "additionalProperties": False,
                  "properties": {"ip": {"type": "string", "maxLength": 64}, "login": {"type": "string", "maxLength": 32},
                                 "port": {"type": "integer", "minimum": 1, "maximum": 65535},
                                 "cols": {"type": "integer", "minimum": 20, "maximum": 500}, "rows": {"type": "integer", "minimum": 5, "maximum": 300},
                                 "legacy": {"type": "boolean"}}})
        if p.terminal.require_mfa and not g.user["mfa"]:
            raise ApiError(403, "mfa_required", "웹 터미널은 2단계 인증을 켠 계정만 쓸 수 있습니다 — 콘솔에서 mfa setup")
        sess = p.terminal.open(actor(), b["ip"], b["login"], b.get("port", 22), b.get("cols", 100), b.get("rows", 30), b.get("legacy", False))
        return jsonify(sess.info()), 201

    @app.get("/api/terminal/<sid>")
    @require("terminal:use")
    def terminal_read(sid):
        import base64
        sess = p.terminal.get(sid, actor())
        data, end, closed, lost = p.terminal.read(sess, _int("since", 0, 0, 1 << 62), _int("wait", 20, 0, 25))
        return jsonify({"data": base64.b64encode(data).decode(), "next": end, "closed": closed, "truncated": lost,
                        "reason": sess.reason, "exit_code": sess.exit_code})

    @app.post("/api/terminal/<sid>/input")
    @require("terminal:use")
    def terminal_input(sid):
        b = body({"type": "object", "required": ["data"], "additionalProperties": False,
                  "properties": {"data": {"type": "string", "maxLength": 65536}}})
        p.terminal.write(p.terminal.get(sid, actor()), b["data"].encode("utf-8", "replace"))
        return jsonify({"ok": True})

    @app.post("/api/terminal/<sid>/resize")
    @require("terminal:use")
    def terminal_resize(sid):
        b = body({"type": "object", "required": ["cols", "rows"], "additionalProperties": False,
                  "properties": {"cols": {"type": "integer", "minimum": 20, "maximum": 500}, "rows": {"type": "integer", "minimum": 5, "maximum": 300}}})
        p.terminal.resize(p.terminal.get(sid, actor()), b["rows"], b["cols"])
        return jsonify({"ok": True})

    @app.delete("/api/terminal/<sid>")
    @require("terminal:use")
    def terminal_close(sid):
        p.terminal.close(p.terminal.get(sid, actor()))
        return jsonify({"ok": True})

    @app.get("/api/intel/lookup")
    @require("alerts:read")
    def intel_lookup():
        """IP 평판 직접 조회 (플레이북 ip_reputation 과 같은 결과: AbuseIPDB + 피드 + 로컬)."""
        import ipaddress
        from .abuseipdb import lookup
        try:
            ip = str(ipaddress.ip_address(request.args.get("ip", "").strip()))
        except ValueError:
            raise ApiError(400, "ip 가 올바르지 않습니다")
        if p.response.intel is None:
            raise ApiError(503, "위협 인텔 색인 준비 중")
        return jsonify(dict(lookup(p.response, ip), abuseipdb_status=p.response.abuseipdb.status()))

    @app.post("/api/system/reset")
    @require("config:write")
    def system_reset():
        """데이터 초기화. dry_run 이면 지울 개수만. 'all' 은 confirm='초기화' 가 있어야 실행."""
        from .maintenance import ResetError, reset
        b = body({"type": "object", "required": ["scope"], "properties": {
            "scope": {"enum": ["test", "all"]}, "dry_run": {"type": "boolean"}, "confirm": {"type": "string"},
            "reason": {"type": "string", "maxLength": 500}, "include_blocklist": {"type": "boolean"}}, "additionalProperties": False})
        if b["scope"] == "all" and not b.get("dry_run") and b.get("confirm") != "초기화":
            raise ApiError(400, "전체 초기화는 confirm 에 '초기화' 를 넣어야 실행됩니다")
        try:
            return jsonify(reset(p, b["scope"], actor(), b.get("reason"), bool(b.get("dry_run")), bool(b.get("include_blocklist"))))
        except ResetError as e:
            raise ApiError(400, str(e))

    @app.get("/api/system/doctor")
    @require("config:read")
    def system_doctor():
        from .doctor import run_checks
        res = run_checks(s, p)
        return jsonify({"checks": res, "ok": not any(c["status"] == "fail" for c in res)})

    @app.post("/api/system/feeds/refresh")
    @require("config:write")
    def feeds_refresh():
        st = p.feeds.refresh(force=True)
        p.audit.record(actor(), "intel.refresh", "intel", None, None, st)
        return jsonify({"status": st, "counts": p.response.intel.feed_counts if p.response.intel else {}})

    # 리버스 프록시(nginx) 뒤에서 실제 클라이언트 IP 사용 (로그인 속도 제한·감사용)
    n_proxy = int(s.get("api.trusted_proxies", 0) or 0)
    if n_proxy:
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n_proxy, x_proto=n_proxy)

    return app
