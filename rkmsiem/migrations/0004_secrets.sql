-- 웹에서 입력한 비밀 값 (SMTP 비밀번호 · AbuseIPDB 키). 값은 암호화(Fernet)해서만 저장 — 키는 환경 변수 RKMSIEM_SECRET_KEY
CREATE TABLE IF NOT EXISTS secrets (
  name        TEXT PRIMARY KEY,
  ciphertext  TEXT NOT NULL,
  hint        TEXT,                        -- 화면 표시용 끝 2자리 (예: '…9f')
  updated_at  REAL NOT NULL,
  updated_by  TEXT NOT NULL
);
