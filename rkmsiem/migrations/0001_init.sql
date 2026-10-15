-- RKMSIEM 초기 스키마
CREATE TABLE IF NOT EXISTS raw_events (
  id          INTEGER PRIMARY KEY,
  source_id   TEXT NOT NULL,
  received_at REAL NOT NULL,
  raw         TEXT NOT NULL,
  idem_key    TEXT NOT NULL UNIQUE,         -- 중복 수신 방지
  status      TEXT NOT NULL DEFAULT 'ok',   -- ok | failed
  error       TEXT,
  trace_id    TEXT NOT NULL,
  sample      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_raw_received ON raw_events(received_at);

CREATE TABLE IF NOT EXISTS events (           -- 정규화 이벤트 (ECS 부분집합)
  id          INTEGER PRIMARY KEY,
  raw_id      INTEGER REFERENCES raw_events(id),
  ts          REAL NOT NULL,                  -- 발생 시각 (epoch, UTC)
  ingested_at REAL NOT NULL,                  -- 수집 시각
  source_id   TEXT NOT NULL,
  dataset     TEXT,
  category    TEXT,
  action      TEXT,
  outcome     TEXT,
  severity    INTEGER,
  user_name   TEXT,
  source_ip   TEXT,
  host_name   TEXT,
  message     TEXT,
  doc         TEXT NOT NULL,                  -- 전체 정규화 문서(JSON)
  sample      INTEGER NOT NULL DEFAULT 0,
  trace_id    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_ip ON events(source_ip, ts);
CREATE INDEX IF NOT EXISTS ix_events_user ON events(user_name, ts);
CREATE INDEX IF NOT EXISTS ix_events_source ON events(source_id, ts);

CREATE TABLE IF NOT EXISTS dlq (               -- 처리 실패 격리 (재처리 가능)
  id         INTEGER PRIMARY KEY,
  source_id  TEXT,
  stage      TEXT NOT NULL,                    -- parse | normalize | store | detect
  raw        TEXT,
  error      TEXT NOT NULL,
  attempts   INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL,
  trace_id   TEXT,
  replayed   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS collector_offsets (
  source_id TEXT PRIMARY KEY,
  path      TEXT,
  offset    INTEGER NOT NULL,
  file_id   TEXT,
  updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
  id            INTEGER PRIMARY KEY,
  rule_id       TEXT NOT NULL,
  rule_version  INTEGER NOT NULL,
  level_id      TEXT NOT NULL,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL,
  severity_rank INTEGER NOT NULL,
  risk_score    REAL NOT NULL,
  risk_basis    TEXT NOT NULL,                 -- 점수 산정 근거(JSON)
  group_key     TEXT NOT NULL,
  group_fields  TEXT NOT NULL,                 -- {"source.ip": "...", ...}
  dedup_key     TEXT NOT NULL,
  first_ts      REAL NOT NULL,
  last_ts       REAL NOT NULL,
  event_count   INTEGER NOT NULL,
  evidence      TEXT NOT NULL,                 -- 근거 이벤트 id 목록(JSON, 상한 있음)
  detail        TEXT,
  status        TEXT NOT NULL DEFAULT 'open',  -- open | acknowledged | closed
  incident_id   INTEGER,
  created_at    REAL NOT NULL,
  updated_at    REAL NOT NULL,
  sample        INTEGER NOT NULL DEFAULT 0,
  e2e_ms        REAL                           -- 수신 → 경보 생성 지연
);
CREATE INDEX IF NOT EXISTS ix_alerts_created ON alerts(created_at);
CREATE INDEX IF NOT EXISTS ix_alerts_dedup ON alerts(dedup_key, last_ts);
CREATE INDEX IF NOT EXISTS ix_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
  id              INTEGER PRIMARY KEY,
  title           TEXT NOT NULL,
  state           TEXT NOT NULL,
  severity        TEXT NOT NULL,
  severity_rank   INTEGER NOT NULL,
  risk_score      REAL NOT NULL DEFAULT 0,
  correlation_key TEXT NOT NULL,
  assignee        TEXT,
  created_at      REAL NOT NULL,
  updated_at      REAL NOT NULL,
  closed_at       REAL,
  sample          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_incidents_key ON incidents(correlation_key, state);

CREATE TABLE IF NOT EXISTS incident_timeline (
  id          INTEGER PRIMARY KEY,
  incident_id INTEGER NOT NULL REFERENCES incidents(id),
  ts          REAL NOT NULL,
  kind        TEXT NOT NULL,
  actor       TEXT NOT NULL,
  detail      TEXT
);
CREATE INDEX IF NOT EXISTS ix_timeline_incident ON incident_timeline(incident_id, ts);

CREATE TABLE IF NOT EXISTS playbook_runs (
  id               INTEGER PRIMARY KEY,
  playbook_id      TEXT NOT NULL,
  playbook_version INTEGER NOT NULL,
  incident_id      INTEGER,
  alert_id         INTEGER,
  state            TEXT NOT NULL,            -- queued|running|waiting_approval|succeeded|failed|cancelled|compensated
  mode             TEXT NOT NULL,            -- simulate | live
  context          TEXT NOT NULL,
  error            TEXT,
  requested_by     TEXT NOT NULL,
  dedup_key        TEXT UNIQUE,              -- 같은 경보에 같은 플레이북 중복 실행 방지
  created_at       REAL NOT NULL,
  updated_at       REAL NOT NULL,
  started_at       REAL,
  finished_at      REAL,
  sample           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_runs_state ON playbook_runs(state);

CREATE TABLE IF NOT EXISTS step_runs (
  id          INTEGER PRIMARY KEY,
  run_id      INTEGER NOT NULL REFERENCES playbook_runs(id),
  step_id     TEXT NOT NULL,
  idx         INTEGER NOT NULL,
  action      TEXT NOT NULL,
  state       TEXT NOT NULL,                 -- pending|skipped|waiting_approval|running|succeeded|failed|timed_out|rejected|compensated
  attempts    INTEGER NOT NULL DEFAULT 0,
  input       TEXT,
  output      TEXT,
  error       TEXT,
  idem_key    TEXT NOT NULL UNIQUE,
  started_at  REAL,
  finished_at REAL
);
CREATE INDEX IF NOT EXISTS ix_steps_run ON step_runs(run_id, idx);

CREATE TABLE IF NOT EXISTS approvals (
  id           INTEGER PRIMARY KEY,
  run_id       INTEGER NOT NULL,
  step_id      TEXT NOT NULL,
  state        TEXT NOT NULL,                -- pending|approved|rejected|expired
  requested_at REAL NOT NULL,
  expires_at   REAL NOT NULL,
  decided_at   REAL,
  decided_by   TEXT,
  reason       TEXT,
  UNIQUE(run_id, step_id)
);

CREATE TABLE IF NOT EXISTS audit_log (         -- 해시 체인 · 수정/삭제 불가
  id          INTEGER PRIMARY KEY,
  ts          REAL NOT NULL,
  actor       TEXT NOT NULL,
  action      TEXT NOT NULL,
  target_type TEXT,
  target_id   TEXT,
  reason      TEXT,
  detail      TEXT,
  prev_hash   TEXT NOT NULL,
  hash        TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE IF NOT EXISTS config_versions (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  name       TEXT NOT NULL,
  version    INTEGER NOT NULL,
  content    TEXT NOT NULL,                  -- 검증된 JSON
  sha        TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 0,
  created_at REAL NOT NULL,
  created_by TEXT NOT NULL,
  comment    TEXT,
  UNIQUE(kind, name, version)
);
CREATE INDEX IF NOT EXISTS ix_config_active ON config_versions(kind, name, active);

CREATE TABLE IF NOT EXISTS users (
  id         INTEGER PRIMARY KEY,
  username   TEXT NOT NULL UNIQUE,
  pw_hash    TEXT NOT NULL,
  role       TEXT NOT NULL,
  active     INTEGER NOT NULL DEFAULT 1,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES users(id),
  kind       TEXT NOT NULL,                  -- session | stream
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
  id          INTEGER PRIMARY KEY,
  ts          REAL NOT NULL,
  channel     TEXT NOT NULL,
  message     TEXT NOT NULL,
  incident_id INTEGER,
  run_id      INTEGER,
  delivered   TEXT NOT NULL                  -- internal | simulated | webhook
);

CREATE TABLE IF NOT EXISTS blocklist (         -- live 모드 IP 차단 어댑터(로컬)
  ip         TEXT PRIMARY KEY,
  reason     TEXT,
  run_id     INTEGER,
  added_at   REAL NOT NULL,
  expires_at REAL
);

CREATE TABLE IF NOT EXISTS account_state (     -- live 모드 계정 비활성화 어댑터(로컬)
  account    TEXT PRIMARY KEY,
  disabled   INTEGER NOT NULL,
  reason     TEXT,
  run_id     INTEGER,
  updated_at REAL NOT NULL
);
