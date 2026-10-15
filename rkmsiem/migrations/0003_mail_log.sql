-- 메일 발송 기록 (알림 · 보고서 · 플레이북) — 중복 발송 방지(kind+ref)와 발송 이력 확인용
CREATE TABLE IF NOT EXISTS mail_log (
  id          INTEGER PRIMARY KEY,
  ts          REAL NOT NULL,
  kind        TEXT NOT NULL,               -- alert | approval | report:incident | report:<일정 이름> | playbook | test | manual
  ref         TEXT,                        -- 같은 kind 안에서 중복 판단 키 (사건 번호, 날짜 등)
  recipients  TEXT NOT NULL,
  subject     TEXT NOT NULL,
  status      TEXT NOT NULL,               -- queued | sent | failed | simulated
  attempts    INTEGER NOT NULL DEFAULT 0,
  error       TEXT,
  actor       TEXT,
  size        INTEGER,
  sent_at     REAL
);
CREATE INDEX IF NOT EXISTS ix_mail_ts ON mail_log(ts);
CREATE INDEX IF NOT EXISTS ix_mail_ref ON mail_log(kind, ref);
