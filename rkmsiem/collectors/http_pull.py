"""당겨오기(HTTP pull) 수집기: 다른 시스템의 API 를 주기적으로 조회해 이벤트로 가져온다.

예: Prometheus 경보(/api/v1/alerts), Kubernetes 이벤트(/api/v1/events), 사내 시스템의 JSON API.

options:
  url            조회 주소 (http/https). '{cursor}' 를 넣으면 그 자리에 커서 값
  interval_sec   조회 간격 (기본 60, 최소 5)
  timeout_sec    응답 대기 (기본 15)
  headers        추가 헤더 (비밀 값은 넣지 말 것 — 아래 auth)
  auth           {type: bearer|basic|header, user: (basic), header: (header 이름)}
                 비밀 값: 웹 설정에서 넣으면 암호화 저장(vault 'pull:<id>'), 또는 token_env: RKMSIEM_PULL_* 환경 변수
  tls            {verify: true, ca_file: 경로, fingerprint: SHA-256 지문(자체 서명 인증서 고정)}
  items_path     응답에서 목록 위치 (예: data.alerts · items). 비우면 응답 전체(배열/객체/NDJSON)
  only_if        {경로: [허용 값...]} — 이 조건에 맞는 항목만 (예: {type: [Warning]})
  id_fields      항목을 구별하는 경로 목록 → 같은 항목은 한 번만 저장 (없으면 내용 전체로 구별)
  cursor         {field: 항목의 커서 경로, param: 쿼리 이름(또는 url 의 {cursor}), start: now|beginning}
                 → 마지막으로 받은 값 이후만 요청, 저장이 끝난 뒤에만 앞으로 옮김
  next_path      응답에서 다음 쪽 위치 (URL 이면 그대로, 아니면 next_param 쿼리로) · max_pages (기본 10)
  max_items      한 번에 가져올 최대 항목 (기본 5000) · max_bytes 응답 크기 상한 (기본 10MB)
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import ssl
import threading
import time
import urllib.parse
from datetime import datetime, timezone

from ..conditions import value_of
from ..pipeline import make_record
from ..plugins import collector
from . import Collector

ENV_PREFIX = "RKMSIEM_PULL_"            # 비밀 값을 읽을 수 있는 환경 변수 — 이 접두어만 (암호화 키 등 다른 비밀이 새지 않게)


class PullError(Exception):
    pass


def vault_name(source_id):
    return f"pull:{source_id}"


def secret_for(opt, source_id, vault):
    env = (opt.get("auth") or {}).get("token_env") or opt.get("token_env")
    if env:
        if not env.startswith(ENV_PREFIX):
            raise PullError(f"token_env 는 {ENV_PREFIX} 로 시작해야 합니다")
        return os.environ.get(env)
    return vault.get(vault_name(source_id)) if vault else None


def _target(url):
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise PullError("url 은 http:// 또는 https:// 주소여야 합니다")
    return u


def fetch(opt, secret=None, url=None):
    """한 번 요청 → (상태 코드, 응답 바이트). 리다이렉트는 따라가지 않음(다른 곳으로 비밀 값이 새지 않게)."""
    u = _target(url or opt["url"])
    tls = opt.get("tls") or {}
    headers = {"Accept": "application/json", "User-Agent": "rkmsiem-pull/1"}
    headers.update({str(k): str(v) for k, v in (opt.get("headers") or {}).items()})
    auth = opt.get("auth") or {}
    if secret:
        t = auth.get("type", "bearer")
        if t == "basic":
            headers["Authorization"] = "Basic " + base64.b64encode(f"{auth.get('user', '')}:{secret}".encode()).decode()
        elif t == "header":
            headers[auth.get("header") or "X-API-Key"] = secret
        else:
            headers["Authorization"] = f"Bearer {secret}"
    timeout = float(opt.get("timeout_sec", 15))
    if u.scheme == "https":
        ctx = ssl.create_default_context(cafile=tls.get("ca_file") or None)
        fp = (tls.get("fingerprint") or "").replace(":", "").strip().lower()
        if fp or tls.get("verify") is False:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=timeout, context=ctx)
        conn.connect()
        if fp and not hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(), fp):
            conn.close()
            raise PullError("인증서 지문이 설정과 다릅니다 (가로채기 또는 인증서 교체)")
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        body = json.dumps(opt["body"]).encode() if opt.get("body") is not None else None
        if body:
            headers["Content-Type"] = "application/json"
        conn.request(opt.get("method", "GET").upper(), (u.path or "/") + (f"?{u.query}" if u.query else ""), body=body, headers=headers)
        r = conn.getresponse()
        limit = int(opt.get("max_bytes", 10 * 1024 * 1024))
        data = r.read(limit + 1)
        if len(data) > limit:
            raise PullError(f"응답이 너무 큼 (> {limit // 1024 // 1024}MB) — max_bytes 또는 조회 범위 조정")
        return r.status, data
    finally:
        conn.close()


def extract_items(opt, data):
    """응답 → 항목 목록 (dict). items_path · NDJSON · 단일 객체 지원."""
    text = data.decode("utf-8", "replace").strip()
    if not text:
        return [], None
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            return [json.loads(l) for l in text.splitlines() if l.strip()], None
        except ValueError as e:
            raise PullError(f"JSON 이 아닌 응답: {e}")
    nxt = value_of(doc, opt["next_path"]) if opt.get("next_path") and isinstance(doc, dict) else None
    items = value_of(doc, opt["items_path"]) if opt.get("items_path") else doc
    if items is None:
        raise PullError(f"응답에 '{opt.get('items_path')}' 가 없습니다")
    if isinstance(items, dict):
        items = [items]
    if not isinstance(items, list):
        raise PullError(f"'{opt.get('items_path') or '(응답)'}' 가 목록이 아닙니다")
    return [x for x in items if isinstance(x, dict)], nxt


def keep(opt, item):
    for path, allowed in (opt.get("only_if") or {}).items():
        allowed = allowed if isinstance(allowed, list) else [allowed]
        if value_of(item, path) not in allowed:
            return False
    return True


def item_id(opt, item):
    fields = opt.get("id_fields") or []
    if not fields:
        return None
    vals = [value_of(item, f) for f in fields]
    if all(v is None for v in vals):
        return None
    return hashlib.sha256(json.dumps(vals, sort_keys=True, default=str).encode()).hexdigest()[:32]


def _cursor_key(v):
    """커서 값 비교용: 숫자는 숫자로, 시각 문자열은 시각으로, 그 밖은 문자열로."""
    if isinstance(v, (int, float)):
        return (0, float(v), "")
    s = str(v)
    try:
        return (0, datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp(), "")
    except ValueError:
        return (1, 0.0, s)


def with_cursor(opt, url, cursor):
    if cursor is None:
        return url
    q = urllib.parse.quote(str(cursor), safe="")
    if "{cursor}" in url:
        return url.replace("{cursor}", q)
    param = (opt.get("cursor") or {}).get("param")
    if not param:
        return url
    return url + ("&" if "?" in url else "?") + f"{urllib.parse.quote(param)}={q}"


def pull_once(opt, secret, cursor=None):
    """한 번 조회(여러 쪽): → (항목들, 새 커서 후보). 저장하지 않음 — 시험 조회에도 씀."""
    base = opt["url"]
    url = with_cursor(opt, base.replace("{cursor}", "") if cursor is None and "{cursor}" in base else base, cursor)
    items, pages, max_items = [], 0, int(opt.get("max_items", 5000))
    max_pages = int(opt.get("max_pages", 10))
    while url and pages < max_pages and len(items) < max_items:
        status, data = fetch(opt, secret, url)
        if status in (301, 302, 303, 307, 308):
            raise PullError(f"주소가 옮겨졌습니다 (HTTP {status}) — url 을 새 주소로 바꾸세요")
        if status == 401 or status == 403:
            raise PullError(f"인증 실패 (HTTP {status}) — 토큰·권한 확인")
        if status >= 400:
            raise PullError(f"HTTP {status}: {data[:200].decode('utf-8', 'replace')}")
        got, nxt = extract_items(opt, data)
        items += [x for x in got if keep(opt, x)]
        pages += 1
        if not nxt:
            break
        if str(nxt).startswith(("http://", "https://")):
            if urllib.parse.urlsplit(str(nxt)).hostname != urllib.parse.urlsplit(base).hostname:
                break                                  # 다른 호스트로는 비밀 값을 들고 가지 않음
            url = str(nxt)
        else:
            p = opt.get("next_param", "continue")
            sep = "&" if "?" in base else "?"
            url = with_cursor(opt, base, cursor) + f"{sep}{urllib.parse.quote(p)}={urllib.parse.quote(str(nxt), safe='')}"
    items = items[:max_items]
    new = cursor
    field = (opt.get("cursor") or {}).get("field")
    if field:
        for x in items:
            v = value_of(x, field)
            if v is not None and (new is None or _cursor_key(v) > _cursor_key(new)):
                new = v
    return items, new


def now_cursor(opt):
    fmt = (opt.get("cursor") or {}).get("format", "iso")
    t = time.time()
    return int(t) if fmt == "epoch" else int(t * 1000) if fmt == "epoch_ms" else datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@collector("http_pull")
class HttpPullCollector(Collector):
    vault = None                                       # Platform 이 넣어 줌 (웹에서 넣은 토큰)

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.last_poll_at = self.next_poll_at = None
        self.last_count = 0
        self._pending = 0
        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)

    # 커서는 저장이 끝난 뒤에만 앞으로 (중간에 꺼져도 다음에 그 자리부터 — 겹친 것은 id 로 걸러짐)
    def _load_cursor(self):
        r = self.db.one("SELECT value FROM collector_state WHERE source_id=? AND key='cursor'", (self.id,))
        return json.loads(r["value"]) if r else None

    def _save_cursor(self, v):
        self.db.execute("INSERT INTO collector_state (source_id, key, value, updated_at) VALUES (?, 'cursor', ?, ?) "
                        "ON CONFLICT(source_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                        (self.id, json.dumps(v), time.time()))

    def _acked(self):
        with self._cv:
            self._pending -= 1
            self._cv.notify_all()

    def poll(self):
        secret = secret_for(self.opt, self.id, self.vault)
        cur = self._load_cursor()
        if cur is None and (self.opt.get("cursor") or {}).get("field") and (self.opt.get("cursor") or {}).get("start", "now") == "now":
            cur = now_cursor(self.opt)                 # 처음엔 지금부터 (과거 전체를 한꺼번에 당기지 않게)
            self._save_cursor(cur)
        items, new = pull_once(self.opt, secret, cur)
        with self._cv:
            self._pending = len(items)
        for it in items:
            iid = item_id(self.opt, it)
            rec = make_record(self.id, json.dumps(it, ensure_ascii=False),
                              idem_key=f"{self.id}:pull:{iid}" if iid else None, ack=self._acked)
            while not self.pipeline.submit(rec, timeout=1):
                self.state = "backpressure"
                if self._stop.is_set():
                    return
            self.state = "running"
        self.mark(len(items))
        self.last_count = len(items)
        with self._cv:                                 # 저장 완료(또는 중복 판정)까지 기다린 뒤 커서 이동
            self._cv.wait_for(lambda: self._pending <= 0 or self._stop.is_set(), timeout=60)
            done = self._pending <= 0
        if done and new is not None and new != cur:
            self._save_cursor(new)

    def run(self):
        interval = max(5.0, float(self.opt.get("interval_sec", 60)))
        fails = 0
        while not self._stop.is_set():
            self.last_poll_at = time.time()
            try:
                self.poll()
                self.last_error, fails = None, 0
                self.state = "running"
            except Exception as e:                     # noqa: BLE001 — 실패해도 수집기는 살아 있고 간격을 늘려 재시도
                fails += 1
                self.state, self.last_error = "error", f"{e}"[:300]
                self.metrics.inc("collector_errors_total", source=self.id)
            wait = interval if not fails else min(600.0, interval * 2 ** min(fails, 6))
            self.next_poll_at = time.time() + wait
            self._stop.wait(wait)

    def status(self):
        s = super().status()
        u = urllib.parse.urlsplit(self.opt.get("url", ""))
        s.update(listen=f"{u.scheme}://{u.hostname}{':' + str(u.port) if u.port else ''}{u.path} · {int(float(self.opt.get('interval_sec', 60)))}초마다",
                 last_poll_at=self.last_poll_at, next_poll_at=self.next_poll_at, last_count=self.last_count)
        return s
