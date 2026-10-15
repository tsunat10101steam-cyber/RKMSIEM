-- 첫 로그인 비밀번호 변경 강제 · 2단계 인증(TOTP)
ALTER TABLE users ADD COLUMN must_change_pw INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_secret TEXT;          -- Fernet 암호문 (RKMSIEM_SECRET_KEY) — DB 만 유출돼도 못 씀
ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN totp_last_step INTEGER;   -- 같은 코드 재사용 방지
