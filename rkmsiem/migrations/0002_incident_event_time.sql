-- 사건 묶음 기준을 '이벤트 시각'으로 (재생·지연 수집에도 같은 결과)
ALTER TABLE incidents ADD COLUMN last_event_ts REAL;
ALTER TABLE incidents ADD COLUMN correlation_fields TEXT;
CREATE INDEX IF NOT EXISTS ix_incidents_state ON incidents(state, updated_at);
