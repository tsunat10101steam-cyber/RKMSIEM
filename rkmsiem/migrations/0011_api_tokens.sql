-- 장기 API 토큰 (Prometheus 수집 · Grafana · 외부 도구) — 권한을 좁게(scopes), 폐기 가능, 원문은 저장하지 않음
CREATE TABLE IF NOT EXISTS api_tokens (
  id           INTEGER PRIMARY KEY,
  name         TEXT NOT NULL UNIQUE,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,                -- 화면 표시용 앞 몇 글자
  scopes       TEXT NOT NULL,                -- JSON 배열
  created_by   TEXT NOT NULL,
  created_at   REAL NOT NULL,
  expires_at   REAL,
  last_used_at REAL,
  last_used_ip TEXT,
  revoked_at   REAL
);
