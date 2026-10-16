-- 원격 조치 에이전트 (대상 서버에 설치 · SIEM 으로 나가서 할 일을 받아 감)
CREATE TABLE IF NOT EXISTS agents (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  name        TEXT NOT NULL UNIQUE,
  token_hash  TEXT UNIQUE,
  created_by  TEXT,
  created_at  REAL NOT NULL,
  enrolled_at REAL,
  last_seen   REAL,
  last_ip     TEXT,
  hostname    TEXT,
  version     TEXT,
  allow       TEXT,               -- 에이전트 쪽 정책이 허용한 조치 (JSON)
  info        TEXT,               -- 마지막 상태 보고 (JSON: 컨테이너·프로세스·서비스…)
  revoked_at  REAL
);
CREATE TABLE IF NOT EXISTS agent_enroll (
  code_hash   TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  created_by  TEXT,
  created_at  REAL NOT NULL,
  expires_at  REAL NOT NULL,
  used_at     REAL
);
CREATE TABLE IF NOT EXISTS agent_jobs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  agent_id     INTEGER NOT NULL,
  action       TEXT NOT NULL,
  params       TEXT NOT NULL,
  state        TEXT NOT NULL,      -- queued | sent | succeeded | failed | expired
  requested_by TEXT,
  reason       TEXT,
  incident_id  INTEGER,
  created_at   REAL NOT NULL,
  sent_at      REAL,
  finished_at  REAL,
  result       TEXT,
  error        TEXT
);
CREATE INDEX IF NOT EXISTS agent_jobs_agent ON agent_jobs(agent_id, state);
