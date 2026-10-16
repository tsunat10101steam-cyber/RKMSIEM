-- 추가 기능(HSOAR 등)이 읽는 이벤트 피드 — 순번(seq)으로 이어 읽기, 꺼져 있던 동안의 것도 받음 (7일 보관)
CREATE TABLE IF NOT EXISTS event_feed (
  seq   INTEGER PRIMARY KEY AUTOINCREMENT,
  ts    REAL NOT NULL,
  type  TEXT NOT NULL,
  data  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_feed_ts ON event_feed(ts);
