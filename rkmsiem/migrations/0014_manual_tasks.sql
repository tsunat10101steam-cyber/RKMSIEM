-- 플레이북의 사람 할 일 단계 (manual_task) — 확인 목록을 다 체크하고 '완료' 해야 다음 단계로
CREATE TABLE IF NOT EXISTS manual_tasks (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id       INTEGER NOT NULL,
  step_id      TEXT NOT NULL,
  incident_id  INTEGER,
  state        TEXT NOT NULL,          -- pending | done | skipped | failed
  title        TEXT NOT NULL,
  instructions TEXT,
  checklist    TEXT NOT NULL,          -- JSON [항목]
  checked      TEXT,                   -- JSON [번호]
  note         TEXT,
  requested_at REAL NOT NULL,
  done_at      REAL,
  done_by      TEXT,
  UNIQUE (run_id, step_id)
);
CREATE INDEX IF NOT EXISTS manual_tasks_state ON manual_tasks(state);
