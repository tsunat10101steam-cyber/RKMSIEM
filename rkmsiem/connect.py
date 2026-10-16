"""연동 화면 (connect) — 당겨오기 등 연동 소스에 붙인 '화면(view)'을 콘솔 안에서 연다.

소스 설정의 view:
  url          연동 제품 주소 (예: http://127.0.0.1:3000) — 이 서버가 대신 접속(역방향 프록시)
  home         connect <id> 로 열 경로 (예: /d/abc/?kiosk)
  dashboards   이름 붙인 경로 [{name, title, path}] — connect <id> <이름>
  keep_prefix  true(기본): 제품이 /connect/<id>/ 아래에서 동작 (Grafana serve_from_sub_path 등) · false: 앞부분을 떼고 넘김
  sso          {user_header, role_header, prefix, roles}: RKMSIEM 로그인을 헤더로 넘김 (제품의 auth proxy 기능)
  tls          {insecure: true} 자체 서명 https 제품

보안: 연동 화면은 콘솔과 다른 출처(https://<서버>:8445)에서만 열린다 — 제품 페이지가 콘솔의 로그인 토큰(sessionStorage)에
닿지 못하게. nginx 가 8445 의 /connect/ 만 이 앱으로 넘기며 X-RKMSIEM-Connect 헤더를 붙이고, 8443 에서는 /connect/ 를 막는다.
출입증은 /connect/ 경로 전용 HttpOnly 쿠키(rk_cx, 세션 토큰과 별개 · 로그아웃 시 무효).
"""
import http.client
import re
import ssl
import urllib.parse

COOKIE = "rk_cx"
MAX_BODY = 10 * 1024 * 1024
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "trailers", "transfer-encoding", "upgrade",
       "host", "content-length"}
NEVER_FORWARD = ("x-forwarded-", "x-real-ip", "x-rkmsiem-", "forwarded")
_HEADER = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_PATH = re.compile(r"^/[^\s\\]{0,1000}$")
_KIND = re.compile(r"^[a-z0-9_-]{1,32}$")
_ROLE = re.compile(r"^[A-Za-z0-9 _-]{1,32}$")


def view_of(src):
    v = (src or {}).get("view")
    return v if isinstance(v, dict) and v.get("url") else None


def _path_ok(p):
    return isinstance(p, str) and bool(_PATH.match(p)) and not p.startswith("//") and ".." not in urllib.parse.unquote(p).split("?")[0]


def view_errors(sid, v):
    """소스 검증(validators.sources)에서 부름 — 오류 문구 목록."""
    e = []
    if not isinstance(v, dict):
        return [f"{sid}: view 는 객체"]
    unknown = set(v) - {"url", "home", "dashboards", "keep_prefix", "sso", "tls", "kind", "title"}
    if unknown:
        e.append(f"{sid}: view 에 알 수 없는 항목 {', '.join(sorted(unknown))}")
    u = urllib.parse.urlsplit(str(v.get("url", "")))
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or u.query or u.fragment:
        e.append(f"{sid}: view.url 은 http(s)://호스트[:포트][/경로] (계정·쿼리 없이)")
    if v.get("home") is not None and not _path_ok(v["home"]):
        e.append(f"{sid}: view.home 은 / 로 시작하는 경로 (.. 금지)")
    ds = v.get("dashboards") or []
    if not isinstance(ds, list) or len(ds) > 30:
        e.append(f"{sid}: view.dashboards 는 30개 이하 목록")
        ds = []
    names = set()
    for d in ds:
        if not isinstance(d, dict) or not re.match(r"^[a-z0-9_-]{1,32}$", str(d.get("name", ""))) or not _path_ok(d.get("path")):
            e.append(f"{sid}: view.dashboards 항목은 name(영문 소문자·숫자·-_) + path(/ 로 시작)")
        elif d["name"] in names:
            e.append(f"{sid}: view.dashboards 이름 '{d['name']}' 중복")
        else:
            names.add(d["name"])
        if isinstance(d, dict) and len(str(d.get("title", ""))) > 64:
            e.append(f"{sid}: view.dashboards 제목은 64자 이하")
    if v.get("kind") is not None and not _KIND.match(str(v["kind"])):
        e.append(f"{sid}: view.kind 는 영문 소문자·숫자")
    sso = v.get("sso")
    if sso is not None:
        if not isinstance(sso, dict):
            e.append(f"{sid}: view.sso 는 객체")
        else:
            for k in ("user_header", "role_header"):
                h = sso.get(k)
                if h is None:
                    continue
                if not _HEADER.match(str(h)) or str(h).lower() in HOP | {"cookie", "authorization"} or str(h).lower().startswith(NEVER_FORWARD):
                    e.append(f"{sid}: view.sso.{k} 로 쓸 수 없는 헤더 '{h}'")
            if not sso.get("user_header"):
                e.append(f"{sid}: view.sso.user_header 필요 (예: X-WEBAUTH-USER)")
            if not re.match(r"^[A-Za-z0-9._-]{0,16}$", str(sso.get("prefix", ""))):
                e.append(f"{sid}: view.sso.prefix 는 16자 이하 영문·숫자·._-")
            roles = sso.get("roles") or {}
            if not isinstance(roles, dict) or not all(isinstance(x, str) and _ROLE.match(x) for x in roles.values()):
                e.append(f"{sid}: view.sso.roles 는 {{RKMSIEM 역할: 제품 역할}}")
    return e


def upstream_target(v, sid, rest, query):
    base = urllib.parse.urlsplit(v["url"])
    prefix = base.path.rstrip("/")
    path = (f"{prefix}/connect/{sid}/{rest}" if v.get("keep_prefix", True) else f"{prefix}/{rest}")
    if query:
        path += "?" + query
    return base, path


def _filtered_cookie(raw):
    keep = [c.strip() for c in (raw or "").split(";") if c.strip() and not c.strip().startswith(COOKIE + "=")]
    return "; ".join(keep)


def build_headers(req_headers, v, user, client_ip, public_host, sid, settings_roles=None):
    sso = v.get("sso") or {}
    drop = {h.lower() for h in (sso.get("user_header"), sso.get("role_header")) if h}
    out = {}
    for k, val in req_headers:
        lk = k.lower()
        if lk in HOP or lk in drop or lk.startswith(NEVER_FORWARD) or lk == "cookie":
            continue
        out[k] = val
    ck = _filtered_cookie(dict((k.lower(), x) for k, x in req_headers).get("cookie"))
    if ck:
        out["Cookie"] = ck
    out["X-Forwarded-For"] = client_ip or ""
    out["X-Forwarded-Proto"] = "https"
    out["X-Forwarded-Host"] = public_host or ""
    out["X-Forwarded-Prefix"] = f"/connect/{sid}"
    if sso.get("user_header"):
        out[sso["user_header"]] = f"{sso.get('prefix', 'rk-')}{user['username']}"
        if sso.get("role_header"):
            roles = sso.get("roles") or {}
            out[sso["role_header"]] = roles.get(user["role"]) or roles.get("default") or "Viewer"
    return out


def fetch(v, method, path, headers, body=None, timeout=60):
    """제품에 요청 — http.client 로 직접 (리다이렉트는 따라가지 않고 그대로 브라우저에 돌려줌)."""
    base = urllib.parse.urlsplit(v["url"])
    port = base.port or (443 if base.scheme == "https" else 80)
    if base.scheme == "https":
        ctx = ssl.create_default_context()
        if (v.get("tls") or {}).get("insecure"):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(base.hostname, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(base.hostname, port, timeout=timeout)
    host = base.hostname if base.port is None else f"{base.hostname}:{base.port}"
    conn.request(method, path, body=body, headers=dict(headers, Host=host))
    return conn, conn.getresponse()


def rewrite_location(loc, v, sid, public_origin):
    """제품이 자기 내부 주소로 보낸 리다이렉트 → 연동 화면 주소로."""
    if not loc:
        return loc
    base = v["url"].rstrip("/")
    if loc.startswith(base):
        rest = loc[len(base):]
        if not v.get("keep_prefix", True):
            rest = f"/connect/{sid}" + (rest if rest.startswith("/") else "/" + rest)
        return public_origin + rest
    return loc
