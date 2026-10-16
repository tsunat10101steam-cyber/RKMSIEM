"""HSOAR — RKMSIEM 추가 기능: Slack 으로 관리하는 자동 대응.

핵심(RKMSIEM)과는 전용 API 토큰 + 이벤트 피드(/api/feed)로만 이야기한다 (docs/ADDONS.md).
  rk.py      RKMSIEM API 클라이언트
  store.py   상태 파일 (피드 위치 · 올린 메시지 · 일시 정지 · 자동 실행 기록)
  policy.py  자동 대응 등급 (auto · confirm · never) — policy.json
  core.py    이벤트 → Slack 메시지 · 버튼/명령 → RKMSIEM 조치 (Slack 과 무관한 핵심 로직)
  slackio.py Slack 전송 (Socket Mode · Web API)
"""
VERSION = "1"
