"""운영 자가 점검 — 설치 직후·장애 시 '실제로 동작할 조건'이 갖춰졌는지 확인한다.

서비스 프로세스 안에서(/api/system/doctor) 돌리면 CAP_NET_ADMIN 등 실제 권한으로 확인된다.
"""
import importlib
import os
import shutil
import sys

from .conditions import Lists
from .settings import BASE_DIR


def _c(name, status, detail=""):
    return {"check": name, "status": status, "detail": detail}


def run_checks(settings, platform=None):
    out = []
    v = sys.version_info
    out.append(_c("python", "ok" if v >= (3, 10) else "fail", f"{v.major}.{v.minor}.{v.micro}"))
    for mod, need in (("flask", True), ("ruamel.yaml", True), ("jsonschema", True), ("waitress", False), ("maxminddb", False)):
        try:
            importlib.import_module(mod)
            out.append(_c(f"package:{mod}", "ok"))
        except ImportError:
            out.append(_c(f"package:{mod}", "fail" if need else "warn", "설치 필요" if need else "선택 — 운영 권장"))

    dbp = settings.path("database.path")
    d = os.path.dirname(dbp)
    out.append(_c("database_dir", "ok" if os.path.isdir(d) and os.access(d, os.W_OK) else "fail", d))
    if platform is None:
        return out

    p = platform
    rej = p.config_report.get("rejected", [])
    out.append(_c("config", "fail" if rej else "ok", "; ".join(f"{r['file']}: {r['error']}" for r in rej)[:500] or "모든 설정 유효"))
    out.append(_c("users", "ok" if p.db.scalar("SELECT COUNT(*) FROM users WHERE active=1") else "fail", "활성 사용자 수"))

    for sid, src in p.sources().items():
        if not src.get("enabled", True):
            continue
        opt = src.get("options") or {}
        if src["type"] == "file":
            path = opt["path"] if os.path.isabs(opt["path"]) else os.path.join(BASE_DIR, opt["path"])
            ok = os.path.exists(path) and os.access(path, os.R_OK)
            out.append(_c(f"source:{sid}", "ok" if ok else "fail", f"{path} {'읽기 가능' if ok else '없음/권한 없음 (adm 그룹?)'}"))
        elif src["type"] == "journald":
            j = opt.get("journalctl") or shutil.which("journalctl")
            out.append(_c(f"source:{sid}", "ok" if j else "fail", j or "journalctl 없음"))
        else:
            out.append(_c(f"source:{sid}", "ok", src["type"]))
        c = p.collectors.get(sid)
        if c:
            st = c.status()
            out.append(_c(f"collector:{sid}", "ok" if st["state"] in ("running", "passive", "backpressure") else "warn",
                          f"{st['state']} {st.get('last_error') or ''}".strip()))

    fw = p.response.firewall
    if fw is None:
        out.append(_c("firewall", "warn", "backend none — 차단은 플랫폼 기록만 (실제 차단 안 함)"))
    else:
        ok, msg = fw.check()
        out.append(_c("firewall", "ok" if ok else "fail", "nft 세트 접근 가능" if ok else f"nft 실패: {msg} (CAP_NET_ADMIN·테이블 확인)"))
    acc = p.response.accounts
    if acc is None:
        out.append(_c("account_lock", "warn", "backend none — 계정 잠금은 플랫폼 기록만"))
    else:
        ok, msg = acc.check()
        out.append(_c("account_lock", "ok" if ok else "fail", msg if ok else f"헬퍼 실행 실패: {msg} (sudoers·헬퍼 경로 확인)"))

    idx = p.response.intel
    counts = idx.feed_counts if idx else {}
    if counts:
        empty = [k for k, n in counts.items() if not n]
        out.append(_c("intel_feeds", "warn" if empty else "ok",
                      ", ".join(f"{k}={n}" for k, n in counts.items()) + (" (아직 안 받은 피드 있음 — 몇 분 뒤 재확인)" if empty else "")))
    else:
        out.append(_c("intel_feeds", "warn", "피드 없음 — IP 평판은 로컬 항목만"))
    ab = p.response.abuseipdb
    if not ab.enabled:
        out.append(_c("abuseipdb", "warn", "키 없음 — IP 평판은 공개 피드·로컬 항목만 (콘솔 dashboard settings rep 에서 입력)"))
    else:
        from .abuseipdb import AbuseError
        try:                                            # 키 확인 (결과는 캐시돼 반복 점검은 한도를 쓰지 않음)
            ab.check("1.1.1.1")
            st = ab.status()
            out.append(_c("abuseipdb", "ok", "API 키 정상" + (f" · 오늘 남은 조회 {st['remaining']}/{st['limit']}" if st["remaining"] is not None else "")
                          + f" · 캐시 {st['cached_ips']}개"))
        except AbuseError as e:
            out.append(_c("abuseipdb", "fail" if "키" in str(e) else "warn", f"{e} — 평판은 공개 피드로 계속"))
    vs = p.vault.status()
    out.append(_c("secrets", "fail" if not vs["ready"] else ("ok" if vs["key_source"] == "env" else "warn"),
                  vs["error"] or ("웹 입력 비밀 값 암호화 키: 환경 변수 RKMSIEM_SECRET_KEY" if vs["key_source"] == "env"
                                  else "암호화 키가 DB 옆 secret.key 파일 — 운영은 rkmsiem.env 에 RKMSIEM_SECRET_KEY (install.sh 가 생성)")))
    m = p.mailer
    if not m.configured:
        out.append(_c("mail", "warn", "메일 발송 꺼짐 — 콘솔 dashboard settings 에서 켜기 (알림·보고서 메일 안 보냄)"))
    else:
        st = m.status()
        last = st["last"]
        bad = last and last["status"] == "failed"
        out.append(_c("mail", "warn" if bad else "ok", f"{st['host']}:{st['port']} ({st['security']}) · 보낸 사람 {st['from']}"
                      + (" · 비밀번호 없음" if st["username"] and not st["password_set"] else "")
                      + (f" · 마지막 발송 실패: {last['error']}" if bad else (" · 마지막 발송 성공" if last else " · 아직 보낸 메일 없음 (콘솔 mail 에서 테스트)"))))
    sf = p.staff
    if not sf.configured:
        out.append(_c("staff_sync", "warn", "담당자 앱 연동 안 됨 — 마지막 명단을 그대로 사용 (staff.url · RKMSIEM_STAFF_SYNC_KEY)"))
    else:
        from .staffsync import StaffSyncError
        try:
            r = sf.sync("doctor")
            out.append(_c("staff_sync", "ok" if r["count"] else "warn",
                          f"담당자 앱 {sf.url} · 활성 담당자 {r['count']}명" + ("" if r["count"] else " — 명단이 비어 사건을 배정할 수 없음")))
        except StaffSyncError as e:
            out.append(_c("staff_sync", "fail", f"{e} — 마지막 명단 {sf.status()['directory']}명으로 계속 (systemctl status rkmsiem-staff)"))
    from .reports import font_status
    fok, fdetail = font_status(settings)
    out.append(_c("pdf_report", "ok" if fok else "warn", f"한글 폰트 {fdetail}" if fok else fdetail))
    from .geoip import Locator
    loc = Locator(settings, Lists(p.config.get("lists")))
    out.append(_c("geoip", "ok" if loc.source == "GeoLite2" else "warn",
                  {"GeoLite2": f"위치 DB 사용 ({loc.db_name})", "sample": "샘플 추정 (실제 위치 아님)",
                   "none": "위치 DB 없음 — 지도 위치 표시 안 됨 (sudo /usr/local/lib/rkmsiem/geoip-update)"}[loc.source]))
    out.append(_c("soar_mode", "ok" if settings.get("soar.mode") == "live" else "warn",
                  settings.get("soar.mode") + (" — 승인돼도 실제 조치 안 함" if settings.get("soar.mode") != "live" else " — 승인된 조치가 실제 실행됨")))
    lists = p.config.get("lists") or {}
    nb = (lists.get("never_block") or {}).get("values", [])
    out.append(_c("never_block", "ok" if nb else "warn", ", ".join(nb) or "비어 있음 — 관리자 접속 IP 를 넣어 자기 차단을 막으세요"))
    try:
        import grp
        admins = set(grp.getgrnam("sudo").gr_mem)
        allowed = set((lists.get("privileged_users") or {}).get("values", []))
        miss = sorted(admins - allowed)
        out.append(_c("privileged_users", "warn" if miss else "ok", f"sudo 그룹인데 목록에 없음: {', '.join(miss)}" if miss else "sudo 그룹 반영됨"))
    except (ImportError, KeyError):
        pass
    tzf = "/etc/timezone"
    if os.path.exists(tzf):
        sys_tz = open(tzf, encoding="utf-8").read().strip()
        out.append(_c("timezone", "ok" if sys_tz == settings.get("timezone") else "warn",
                      f"서버 {sys_tz} / 설정 {settings.get('timezone')} (auth.log 전통 형식 해석 기준)"))
    ready, checks = p.readiness()
    out.append(_c("readiness", "ok" if ready else "fail", ", ".join(f"{k}={v}" for k, v in checks.items() if k in ("database", "pipeline_worker", "soar_worker", "queue_ok"))))
    return out
