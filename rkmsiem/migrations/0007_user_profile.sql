-- 담당자 정보: 표시 이름 · 팀 · 연락처 · 배정 알림 받기
ALTER TABLE users ADD COLUMN display_name TEXT;
ALTER TABLE users ADD COLUMN team TEXT;
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN phone TEXT;
ALTER TABLE users ADD COLUMN notify_assign INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN updated_at REAL;
CREATE INDEX IF NOT EXISTS ix_incidents_assignee ON incidents(assignee, state);
