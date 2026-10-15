"""SQLite 저장소: 스레드별 연결, WAL, 자동 마이그레이션.

모든 쿼리는 매개변수 바인딩만 사용한다(문자열로 SQL 을 조립하지 않음).
"""
import contextlib
import glob
import json
import os
import sqlite3
import threading
import time

MIGRATIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "migrations")


class Database:
    def __init__(self, path):
        self.path = path
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._local = threading.local()
        self.write_lock = threading.RLock()   # 쓰기 직렬화 (SQLite 는 단일 쓰기)

    def conn(self):
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(self.path, timeout=10, check_same_thread=False, isolation_level=None)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA synchronous=NORMAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA busy_timeout=10000")
            self._local.conn = c
        return c

    def close(self):
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

    # ---- 조회 ----
    def all(self, sql, params=()):
        return [dict(r) for r in self.conn().execute(sql, params).fetchall()]

    def one(self, sql, params=()):
        r = self.conn().execute(sql, params).fetchone()
        return dict(r) if r else None

    def scalar(self, sql, params=()):
        r = self.conn().execute(sql, params).fetchone()
        return r[0] if r else None

    # ---- 쓰기 ----
    def execute(self, sql, params=()):
        with self.write_lock:
            return self.conn().execute(sql, params)

    @contextlib.contextmanager
    def tx(self):
        with self.write_lock:
            c = self.conn()
            c.execute("BEGIN IMMEDIATE")
            try:
                yield c
                c.execute("COMMIT")
            except BaseException:
                c.execute("ROLLBACK")
                raise

    def migrate(self):
        c = self.conn()
        c.execute("CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at REAL NOT NULL)")
        done = {r[0] for r in c.execute("SELECT version FROM schema_migrations")}
        applied = []
        files = sorted(glob.glob(os.path.join(MIGRATIONS_DIR, "*.sql")) + glob.glob(os.path.join(MIGRATIONS_DIR, "[0-9]*.py")))
        for f in files:
            v = os.path.basename(f).split("_")[0]
            if v in done:
                continue
            with self.write_lock:
                if f.endswith(".py"):                  # 표 재구성처럼 트랜잭션 밖 설정(PRAGMA)이 필요한 마이그레이션
                    import importlib.util
                    spec = importlib.util.spec_from_file_location(f"rkmsiem_migration_{v}", f)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    mod.migrate(c)
                else:
                    with open(f, encoding="utf-8") as fh:
                        c.executescript("BEGIN;" + fh.read() + ";COMMIT;")
                c.execute("INSERT INTO schema_migrations VALUES (?, ?)", (v, time.time()))
            applied.append(v)
        return applied

    def ping(self):
        return self.scalar("SELECT 1") == 1


def dumps(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), default=str)


def loads(s, default=None):
    if s is None:
        return default
    return json.loads(s)
