"""RKMSIEM 명령줄.

  python -m rkmsiem serve [--no-collectors]      API + UI + 수집기 실행 (운영: waitress)
  python -m rkmsiem doctor                       설치·권한·수집 조건 자가 점검 (서비스 안에서의 점검은 /api/system/doctor)
  python -m rkmsiem check-config                 설정 전체 검증 (임시 DB 사용, 운영 DB 변경 없음)
  python -m rkmsiem user add <이름> <역할>       사용자 추가 (비밀번호: 입력 또는 RKMSIEM_NEW_PASSWORD)
  python -m rkmsiem user passwd <이름>           비밀번호 재설정 (관리자용, 모든 세션 로그아웃)
  python -m rkmsiem reset test|all [--dry-run]    데이터 초기화 (웹 콘솔 settings → 데이터 탭과 같음)
  python -m rkmsiem gen-sample                   samples/auth.log 예제(가상) 데이터 생성
  python -m rkmsiem verify-audit                 감사 로그 해시 체인 검증
"""
import argparse
import getpass
import json
import os
import signal
import sys
import tempfile

from . import logutil, settings as settings_mod


def main(argv=None):
    ap = argparse.ArgumentParser(prog="rkmsiem")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sv = sub.add_parser("serve")
    sv.add_argument("--no-collectors", action="store_true")
    sub.add_parser("doctor")
    sub.add_parser("check-config")
    us = sub.add_parser("user")
    us.add_argument("action", choices=["add", "passwd"])
    us.add_argument("username")
    us.add_argument("role", nargs="?")
    sub.add_parser("gen-sample")
    sub.add_parser("verify-audit")
    rs = sub.add_parser("reset", help="데이터 초기화 (test: 스모크테스트·샘플 기록만, all: 이벤트·경보·사건 전부)")
    rs.add_argument("scope", choices=["test", "all"])
    rs.add_argument("--dry-run", action="store_true", help="지울 개수만 보기")
    rs.add_argument("--yes", action="store_true", help="확인 질문 없이 실행")
    rs.add_argument("--include-blocklist", action="store_true", help="all 에서 차단 목록도 지움")
    a = ap.parse_args(argv)
    logutil.setup(os.environ.get("RKMSIEM_LOG_LEVEL", "INFO"))

    if a.cmd == "check-config":
        from .platform import Platform
        s = settings_mod.load(overrides={"database.path": os.path.join(tempfile.mkdtemp(), "check.db")})
        p = Platform(s)
        print(json.dumps(p.config_report, ensure_ascii=False, indent=1))
        return 1 if p.config_report["rejected"] else 0

    if a.cmd == "gen-sample":
        sys.path.insert(0, settings_mod.BASE_DIR)
        import gen_log
        out = os.path.join(settings_mod.BASE_DIR, "samples", "auth.log")
        n, ips = gen_log.write(out)
        print(f"{out}: {n} lines, {ips} IPs (SAMPLE DATA — 가상 데이터)")
        return 0

    s = settings_mod.load()

    if a.cmd == "doctor":
        from .doctor import run_checks
        from .platform import Platform
        p = Platform(s)                       # 수집기/작업자는 띄우지 않음
        res = run_checks(s, p)
        icon = {"ok": "✔", "warn": "!", "fail": "✘"}
        for c in res:
            print(f" {icon[c['status']]} {c['status']:4} {c['check']:22} {c['detail']}")
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("\n※ 방화벽 권한(CAP_NET_ADMIN)은 서비스에만 부여됩니다. 서비스 안에서의 결과는 웹 콘솔 'doctor' 또는 GET /api/system/doctor")
        return 1 if any(c["status"] == "fail" for c in res) else 0

    from .platform import Platform
    p = Platform(s)

    if a.cmd == "verify-audit":
        r = p.audit.verify()
        print(json.dumps(r))
        return 0 if r["ok"] else 2

    if a.cmd == "reset":
        from .maintenance import reset
        from .platform import Platform
        p = Platform(s)                       # 수집기/작업자는 띄우지 않음
        plan = reset(p, a.scope, "cli", dry_run=True)["counts"]
        print("지울 대상: " + ", ".join(f"{k} {v}" for k, v in plan.items()))
        if a.dry_run:
            return 0
        if not a.yes:
            want = "초기화" if a.scope == "all" else "y"
            if input(f"계속하려면 '{want}' 입력: ").strip() != want:
                print("취소했습니다.")
                return 1
        r = reset(p, a.scope, os.environ.get("SUDO_USER") or "cli", "CLI 초기화", include_blocklist=a.include_blocklist)
        print("완료: " + ", ".join(f"{k} {v}" for k, v in r["counts"].items()))
        print("서비스가 실행 중이면 메모리 상태를 맞추기 위해 재시작하세요: sudo systemctl restart rkmsiem")
        return 0

    if a.cmd == "user":
        from .auth import AuthService
        auth = AuthService(p.db, p.config, p.audit, s)
        pw = os.environ.get("RKMSIEM_NEW_PASSWORD") or getpass.getpass("new password (12자 이상): ")
        if a.action == "add":
            if not a.role:
                print("역할이 필요합니다: admin | analyst | responder | viewer")
                return 2
            auth.create_user(a.username, pw, a.role, "cli")
            print(f"user {a.username} ({a.role}) created")
        else:
            auth.change_password(a.username, None, pw, "cli", require_current=False)
            print(f"password reset: {a.username} (모든 세션 로그아웃)")
        return 0

    if a.cmd == "serve":
        from .api import create_app
        app = create_app(p)
        made = app.extensions["rkmsiem_auth"].bootstrap_admin()
        if made:
            print(f"bootstrap admin created: {made} — 로그인 후 비밀번호를 바꾸세요 (콘솔 'passwd')")
        elif not p.db.scalar("SELECT COUNT(*) FROM users"):
            print("⚠ 사용자가 없습니다. RKMSIEM_ADMIN_PASSWORD 를 설정하거나 'python -m rkmsiem user add <이름> admin' 을 실행하세요.")
        if p.config_report["rejected"]:
            print("⚠ 거부된 설정:", json.dumps(p.config_report["rejected"], ensure_ascii=False))
        p.start(collectors=not a.no_collectors)
        host, port = s.get("api.host"), s.get("api.port")
        print(f"RKMSIEM on http://{host}:{port}  (soar mode: {s.get('soar.mode')}, "
              f"firewall: {'nftables' if p.response.firewall else 'none'}, accounts: {'helper' if p.response.accounts else 'none'})")
        server = s.get("api.server", "flask")
        try:
            if server == "waitress":
                from waitress import create_server
                srv = create_server(app, host=host, port=port, threads=int(s.get("api.threads", 32)),
                                    channel_timeout=3600, send_bytes=1, ident="rkmsiem")
                signal.signal(signal.SIGTERM, lambda *_: srv.close())
                srv.run()
            else:
                signal.signal(signal.SIGTERM, lambda *_: (p.stop(), sys.exit(0)))
                app.run(host=host, port=port, threaded=True, use_reloader=False)
        finally:
            p.stop()
        return 0


if __name__ == "__main__":
    sys.exit(main())
