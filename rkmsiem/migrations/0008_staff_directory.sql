-- 담당자 명단: 별도 '담당자 관리' 앱에서 가져온 사본 (앱이 꺼져 있어도 마지막 명단으로 배정·배정 메일).
-- 처음에는 기존 사용자 정보(0007)로 채운다 — 연동이 되면 담당자 앱의 명단으로 통째로 바뀜.
CREATE TABLE IF NOT EXISTS staff_directory (
  username TEXT PRIMARY KEY,
  display_name TEXT, team TEXT, email TEXT, phone TEXT,
  notify_assign INTEGER NOT NULL DEFAULT 1,
  active INTEGER NOT NULL DEFAULT 1,
  updated_at REAL,
  synced_at REAL
);
INSERT OR IGNORE INTO staff_directory (username, display_name, team, email, phone, notify_assign, active, updated_at, synced_at)
  SELECT username, display_name, team, email, phone, notify_assign, active, updated_at, NULL FROM users;
