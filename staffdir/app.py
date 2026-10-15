"""담당자 앱 HTTP — 관리자 화면·API · RKMSIEM 연동 API.

설정은 환경 변수로만 받는다 (운영: /etc/rkmsiem/staff.env, 0600):
  STAFF_DB            DB 경로 (기본 data/staff.db)
  STAFF_HOST/PORT     기본 127.0.0.1:8090
  STAFF_SYNC_KEYS     연동 키 (쉼표 구분) — RKMSIEM 의 RKMSIEM_STAFF_SYNC_KEY 와 같은 값
  STAFF_NOTIFY_URL    (선택) 명단이 바뀌면 알릴 주소 — 예: http://127.0.0.1:8088/api/staff/hook (받는 쪽이 다시 가져감)
  STAFF_CONSOLE_URL   (선택) 화면의 'RKMSIEM 콘솔' 링크 (기본: 같은 호스트의 8088, https 면 8443)
  STAFF_TRUSTED_PROXIES  nginx(HTTPS) 뒤에서 운영하면 1 — X-Forwarded-For 로 접속 IP 를 알아냄 (로그인 횟수 제한용)
"""
import functools
import hmac
import logging
import os
import threading
import time
import urllib.request

from flask import Flask, g, jsonify, request, send_from_directory

from .store import FIELDS, StaffError, Store, sha

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger("staffdir")


def load_dotenv(path=None):
    """개발 편의: 프로젝트 루트 .env 에서 아직 없는 환경 변수만 채운다."""
    path = path or os.path.join(BASE_DIR, ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def env_config(environ=None):
    e = os.environ if environ is None else environ
    return {"db": e.get("STAFF_DB") or os.path.join(BASE_DIR, "data", "staff.db"),
            "host": e.get("STAFF_HOST", "127.0.0.1"), "port": int(e.get("STAFF_PORT", "8090")),
            "sync_keys": [k.strip() for k in (e.get("STAFF_SYNC_KEYS") or "").split(",") if k.strip()],
            "notify_url": e.get("STAFF_NOTIFY_URL", ""), "console_url": e.get("STAFF_CONSOLE_URL", ""),
            "token_ttl": int(e.get("STAFF_TOKEN_TTL_SEC", "28800")), "login_per_min": int(e.get("STAFF_LOGIN_RATE_PER_MIN", "10")),
            "trusted_proxies": int(e.get("STAFF_TRUSTED_PROXIES", "0") or 0)}


class _Limiter:
    def __init__(self, per_min):
        self.per_min, self.hits, self.lock = per_min, {}, threading.Lock()

    def allow(self, key):
        now = time.time()
        with self.lock:
            q = [t for t in self.hits.get(key, []) if t > now - 60]
            ok = len(q) < self.per_min
            if ok:
                q.append(now)
            self.hits[key] = q
            return ok


def create_app(cfg, store=None):
    st = store or Store(cfg["db"])
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    if cfg.get("trusted_proxies"):
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=cfg["trusted_proxies"], x_proto=cfg["trusted_proxies"])
    app.extensions["staff_store"] = st
    limiter = _Limiter(cfg["login_per_min"])
    sync_hashes = [sha(k) for k in cfg["sync_keys"]]

    def notify():
        """명단이 바뀌었다고 RKMSIEM 에 알림 (내용은 보내지 않음 — 받는 쪽이 연동 API 로 다시 가져감)."""
        if not (cfg["notify_url"] and cfg["sync_keys"]):
            return

        def go():
            try:
                req = urllib.request.Request(cfg["notify_url"], data=b"{}", method="POST",
                                             headers={"X-Sync-Key": cfg["sync_keys"][0], "Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5).close()
            except Exception as e:        # noqa: BLE001 — 알림 실패해도 받는 쪽이 주기적으로 가져감
                log.warning("notify failed: %s", e)
        threading.Thread(target=go, daemon=True).start()
    app.extensions["staff_notify"] = notify

    @app.errorhandler(StaffError)
    def _bad(e):
        return jsonify({"error": str(e)}), 400

    @app.errorhandler(KeyError)
    def _nf(e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(404)
    def _404(e):
        return jsonify({"error": "not_found"}), 404

    @app.errorhandler(413)
    def _big(e):
        return jsonify({"error": "payload_too_large"}), 413

    @app.errorhandler(Exception)
    def _500(e):
        if isinstance(getattr(e, "code", None), int):
            return jsonify({"error": getattr(e, "name", "error")}), e.code
        log.exception("unhandled")
        return jsonify({"error": "internal_error"}), 500

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        if request.path.startswith("/api/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def admin(fn):
        @functools.wraps(fn)
        def w(*a, **kw):
            h = request.headers.get("Authorization", "")
            who = st.resolve(h[7:] if h.startswith("Bearer ") else None)
            if not who:
                return jsonify({"error": "unauthorized"}), 401
            g.admin = who
            return fn(*a, **kw)
        return w

    def body():
        b = request.get_json(force=True, silent=True) if request.data else {}
        if not isinstance(b, dict):
            raise StaffError("요청 형식이 올바르지 않습니다")
        return b

    def public(p):
        return {k: p[k] for k in ("username", "display_name", "team", "email", "phone", "notify_assign", "active", "created_at", "updated_at")}

    # ------------------------------------------------------------ 화면
    @app.get("/")
    def index():
        return send_from_directory(WEB, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name):
        return send_from_directory(WEB, name)

    @app.get("/favicon.ico")
    def favicon():
        return send_from_directory(WEB, "favicon.svg", mimetype="image/svg+xml")

    @app.get("/healthz")
    def healthz():
        return jsonify({"status": "ok", "people": len(st.people(include_inactive=False)), "sync_key": bool(sync_hashes)})

    # ------------------------------------------------------------ 로그인
    @app.post("/api/login")
    def login():
        if not limiter.allow(request.remote_addr or "?"):
            return jsonify({"error": "rate_limited"}), 429
        b = body()
        t = st.login(b.get("username"), b.get("password"), cfg["token_ttl"])
        if not t:
            return jsonify({"error": "invalid_credentials"}), 401
        return jsonify({"token": t, "username": b["username"]})

    @app.post("/api/logout")
    @admin
    def logout():
        st.logout(request.headers.get("Authorization", "")[7:])
        return jsonify({"ok": True})

    @app.get("/api/me")
    @admin
    def me():
        return jsonify({"username": g.admin, "console_url": cfg["console_url"], "sync_key": bool(sync_hashes),
                        "notify": bool(cfg["notify_url"]), "sync_clients": st.sync_clients()})

    # ------------------------------------------------------------ 담당자
    @app.get("/api/people")
    @admin
    def people():
        return jsonify({"items": [public(p) for p in st.people()]})

    @app.post("/api/people")
    @admin
    def add_person():
        b = body()
        p = st.add(b.get("username"), {k: b[k] for k in FIELDS if k in b}, g.admin)
        notify()
        return jsonify(public(p)), 201

    @app.patch("/api/people/<username>")
    @admin
    def update_person(username):
        b = body()
        p = st.update(username, {k: b[k] for k in FIELDS if k in b}, g.admin)
        notify()
        return jsonify(public(p))

    @app.post("/api/people/<username>/active")
    @admin
    def person_active(username):
        b = body()
        if not isinstance(b.get("active"), bool):
            raise StaffError("active 는 true/false")
        st.set_active(username, b["active"], g.admin)
        notify()
        return jsonify({"ok": True})

    @app.delete("/api/people/<username>")
    @admin
    def delete_person(username):
        st.delete(username, g.admin)
        notify()
        return jsonify({"ok": True})

    @app.get("/api/changes")
    @admin
    def changes():
        return jsonify({"items": st.changes(int(request.args.get("limit", 50)))})

    # ------------------------------------------------------------ 연동 (RKMSIEM → 명단 읽기 전용)
    @app.get("/api/sync/people")
    def sync_people():
        k = request.headers.get("X-Sync-Key", "")
        if not (k and any(hmac.compare_digest(sha(k), h) for h in sync_hashes)):
            return jsonify({"error": "unauthorized"}), 401
        r = st.roster()
        st.note_sync(request.headers.get("X-Client", "rkmsiem")[:64] + "@" + (request.remote_addr or "?"), len(r["items"]))
        return jsonify(r)

    return app
