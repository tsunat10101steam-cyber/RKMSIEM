-- 차단 관리: 누가·어느 사건에서 차단했는지 + 차단/해제/연장/만료 기록
ALTER TABLE blocklist ADD COLUMN added_by TEXT;
ALTER TABLE blocklist ADD COLUMN incident_id INTEGER;
CREATE TABLE IF NOT EXISTS block_history (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts          REAL NOT NULL,
  ip          TEXT NOT NULL,
  action      TEXT NOT NULL,          -- block | unblock | extend | expire
  actor       TEXT,
  reason      TEXT,
  expires_at  REAL,
  incident_id INTEGER,
  run_id      INTEGER,
  simulated   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS block_history_ip ON block_history(ip, ts);
CREATE INDEX IF NOT EXISTS block_history_ts ON block_history(ts);
