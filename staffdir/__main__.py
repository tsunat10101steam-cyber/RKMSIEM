"""담당자 앱 명령줄.

  python -m staffdir serve                          화면·API 실행 (기본 127.0.0.1:8090)
  python -m staffdir admin add <이름>               앱 관리자 추가 (비밀번호: 입력 또는 STAFF_NEW_PASSWORD)
  python -m staffdir admin passwd <이름>            앱 관리자 비밀번호 재설정
  python -m staffdir import-rkmsiem <rkmsiem.db>    예전 RKMSIEM 사용자 정보(이름·팀·연락처)를 담당자로 가져오기 (있는 아이디는 건너뜀)
"""
import argparse
import getpass
import logging
import os
import signal
import sqlite3
import sys

from .app import create_app, env_config, load_dotenv
from .store import StaffError, Store


def _password():
    pw = os.environ.get("STAFF_NEW_PASSWORD")
    if pw:
        return pw
    pw = getpass.getpass("새 비밀번호 (12자 이상): ")
    if getpass.getpass("한 번 더: ") != pw:
        raise StaffError("두 비밀번호가 다릅니다")
    return pw


def read_rkmsiem_users(path):
    """RKMSIEM DB 를 읽기 전용으로 열어 사용자 프로필을 꺼낸다 (0007 마이그레이션 이후 열이 있을 때만)."""
    c = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    c.row_factory = sqlite3.Row
    try:
        cols = {r[1] for r in c.execute("PRAGMA table_info(users)")}
        want = [k for k in ("display_name", "team", "email", "phone", "notify_assign") if k in cols]
        return [dict(r) for r in c.execute(f"SELECT username, active{''.join(', ' + k for k in want)} FROM users ORDER BY id")]
    finally:
        c.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="staffdir")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    ad = sub.add_parser("admin")
    ad.add_argument("action", choices=["add", "passwd"])
    ad.add_argument("username")
    im = sub.add_parser("import-rkmsiem")
    im.add_argument("db")
    im.add_argument("--if-empty", action="store_true", help="담당자가 한 명도 없을 때만 가져오기")
    a = ap.parse_args(argv)
    logging.basicConfig(level=os.environ.get("STAFF_LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s %(message)s")
    load_dotenv()
    cfg = env_config()
    st = Store(cfg["db"])

    try:
        if a.cmd == "admin":
            if a.action == "add":
                st.add_admin(a.username, _password())
                print(f"앱 관리자 {a.username} 추가")
            else:
                st.set_admin_password(a.username, _password())
                print(f"앱 관리자 {a.username} 비밀번호 재설정 (모든 세션 로그아웃)")
            return 0
        if a.cmd == "import-rkmsiem":
            if a.if_empty and st.people():
                print("담당자가 이미 있어 가져오기를 건너뜁니다")
                return 0
            if not os.path.exists(a.db):
                print(f"RKMSIEM DB 없음: {a.db} — 건너뜀")
                return 0
            added = st.import_rows(read_rkmsiem_users(a.db), "import")
            print(f"담당자 {len(added)}명 가져옴" + (f": {', '.join(added)}" if added else ""))
            return 0
    except (StaffError, KeyError) as e:
        print(f"실패: {e}", file=sys.stderr)
        return 2

    app = create_app(cfg, st)
    if not st.admin_count():
        print("⚠ 앱 관리자가 없습니다. 'python -m staffdir admin add <이름>' 으로 먼저 만드세요 (연동 API 는 동작)")
    if not cfg["sync_keys"]:
        print("⚠ STAFF_SYNC_KEYS 가 없어 RKMSIEM 이 명단을 가져갈 수 없습니다")
    print(f"담당자 앱 http://{cfg['host']}:{cfg['port']}  (DB {cfg['db']})")
    try:
        from waitress import create_server
    except ImportError:
        app.run(host=cfg["host"], port=cfg["port"], threaded=True, use_reloader=False)
        return 0
    srv = create_server(app, host=cfg["host"], port=cfg["port"], threads=8, ident="staffdir")
    signal.signal(signal.SIGTERM, lambda *_: srv.close())
    srv.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
