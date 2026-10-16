-- 수집기별 상태 값 (당겨오기 커서 등). 파일 수집기의 위치는 기존 collector_offsets
CREATE TABLE IF NOT EXISTS collector_state (
  source_id  TEXT NOT NULL,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  updated_at REAL NOT NULL,
  PRIMARY KEY (source_id, key)
);
