"""사건·경보·실행·이벤트 번호를 다시 쓰지 않게 (AUTOINCREMENT).

배경: SQLite 의 기본 정수 키는 '현재 최대값 + 1' 이라, 데이터 초기화로 마지막 번호들을 지우면 같은 번호가 다시 나온다.
     그러면 예전 사건 #2 의 감사 기록이 새 사건 #2 에 섞여 보인다(증거 혼선).
방법: 표를 AUTOINCREMENT 로 다시 만들고(내용·색인 그대로), 다음 번호를 '지금 최대값'과 '감사 로그에 남은 적 있는 번호' 중 큰 값 뒤로 맞춘다.
"""
import re

TABLES = {"incidents": "incident", "alerts": "alert", "playbook_runs": "run", "events": None}   # 표 → 감사 로그 target_type


def migrate(c):
    c.execute("PRAGMA foreign_keys=OFF")                   # 표 재구성 동안만 (트랜잭션 밖에서만 바꿀 수 있음)
    c.execute("BEGIN IMMEDIATE")
    try:
        for t, audit_type in TABLES.items():
            row = c.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()
            if not row:
                continue
            sql = row[0]
            if "AUTOINCREMENT" not in sql.upper():
                indexes = [r[0] for r in c.execute("SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL", (t,))]
                cols = ",".join(r[1] for r in c.execute(f"PRAGMA table_info({t})"))
                new_sql = re.sub(r"\bid(\s+)INTEGER PRIMARY KEY\b", r"id\1INTEGER PRIMARY KEY AUTOINCREMENT", sql, count=1)
                new_sql = re.sub(rf"^CREATE TABLE {t}\b", f"CREATE TABLE {t}__new", new_sql, count=1)
                if "AUTOINCREMENT" not in new_sql:
                    raise RuntimeError(f"{t}: id 열을 찾지 못함")
                c.execute(new_sql)
                c.execute(f"INSERT INTO {t}__new ({cols}) SELECT {cols} FROM {t}")
                c.execute(f"DROP TABLE {t}")
                c.execute(f"ALTER TABLE {t}__new RENAME TO {t}")
                for s in indexes:
                    c.execute(s)
            top = c.execute(f"SELECT COALESCE(MAX(id), 0) FROM {t}").fetchone()[0]
            if audit_type:                                  # 지워졌어도 감사 로그에 남은 번호는 다시 쓰지 않음
                used = c.execute("SELECT MAX(CAST(target_id AS INTEGER)) FROM audit_log WHERE target_type=? AND target_id GLOB '[0-9]*'",
                                 (audit_type,)).fetchone()[0]
                top = max(top, used or 0)
            c.execute("DELETE FROM sqlite_sequence WHERE name=?", (t,))
            c.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (t, top))
        bad = c.execute("PRAGMA foreign_key_check").fetchall()
        if bad:
            raise RuntimeError(f"외래 키 검사 실패: {bad[:5]}")
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
    finally:
        c.execute("PRAGMA foreign_keys=ON")
