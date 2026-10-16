# HSOAR — RKMSIEM 을 Slack 으로

RKMSIEM 의 **추가 기능**. 경보·승인 요청·사람 할 일을 Slack 채널에 올리고, 버튼과 `/hsoar` 명령으로 처리하며,
정책에 따라 자동 대응한다. 지우면 RKMSIEM 은 그대로 수동 운영.

```
Slack ⇄ (Socket Mode: 서버가 Slack 으로 나가는 연결만 — 공개 주소·포트 불필요) ⇄ rkmsiem-hsoar ⇄ (전용 토큰 · /api/feed) ⇄ RKMSIEM
```

## 설치

1. `sudo rkmsiem-setup` → **추가 기능** → **HSOAR** → 설치 (slack_sdk 를 받으므로 인터넷 필요)
2. 이어서 **설정** — 화면 안내대로:
   - https://api.slack.com/apps → **Create New App → From an app manifest** → 워크스페이스 → `/opt/rkmsiem-hsoar/slack-manifest.yaml` 붙여 넣기
   - **Install to Workspace** → Bot User OAuth Token (`xoxb-…`)
   - **Basic Information → App-Level Tokens → Generate** (scope `connections:write`) → `xapp-…`
   - 알림 채널에서 `/invite @hsoar`, 채널 ID (`C…`)
   - 버튼·조치를 쓸 사람의 Slack 멤버 ID (`U…`, 프로필 → ⋮ → 멤버 ID 복사)
3. 설정이 끝나면 **상태 확인** — RKMSIEM 피드 · policy.json · Slack 봇·채널을 점검

## Slack 에 올라오는 것

| 언제 | 메시지 | 버튼 |
|---|---|---|
| 경보 심각도 ≥ `notify.min_severity`(기본 high) | 🔴 사건 카드 (IP·계정) | IP 차단 1시간 · 계정 잠금 |
| 정책 규칙에 맞음 | 💡 제안 / 🤖 자동 조치 | 실행 · 무시 / 해제 |
| 플레이북 승인 대기 | 🟨 승인 요청 | 승인 · 거절 |
| 플레이북 사람 할 일 | 📋 할 일 (확인 목록) | — (체크는 콘솔에서) |

버튼은 **ALLOWED_USERS** 에 있는 사람만 (아니면 그 사람에게만 보이는 거절 메시지). 처리하면 메시지가 결과로 바뀜.
RKMSIEM 쪽에는 행위자 `token:addon-hsoar`, 사유에 `Slack @이름 (U…)` 가 남는다 (감사 로그 · 사건 타임라인 · 차단 목록).

## /hsoar

| 명령 | 누가 | |
|---|---|---|
| `status` · `incidents` · `help` | 누구나 (나에게만 보임) | 위협 수준·열린 경보·승인 대기·할 일·자동 모드 / 열린 사건 5개 |
| `block <IP> [1h\|1d\|7d\|forever] <사유>` · `unblock <IP> <사유>` | ALLOWED_USERS (채널에 보임) | 차단 금지·사내망은 RKMSIEM 이 거부 |
| `pause` · `resume` | ALLOWED_USERS | **킬 스위치** — 자동 실행만 멈춤 (제안·알림은 계속) |
| `auto off\|dry\|on` | ALLOWED_USERS | 자동 모드 (policy.json 보다 우선, 재시작해도 유지) |

## 자동 대응 등급 — `/etc/rkmsiem/addons/hsoar/policy.json`

```json
{"notify": {"min_severity": "high", "approvals": true, "tasks": true},
 "auto":   {"mode": "dry", "max_per_hour": 10},
 "rules": [
   {"name": "무차별 대입(심각) → 공격 IP 1시간 차단", "when": {"rule": ["auth_bruteforce", "distributed_attack"], "min_severity": "critical"},
    "do": {"action": "block_ip", "target": "source.ip", "duration_sec": 3600}, "tier": "auto"},
   {"name": "실패 뒤 로그인 성공 → 계정 잠금 (사람 확인)", "when": {"rule": ["compromise_after_failures", "spray_success", "ids_then_login"]},
    "do": {"action": "disable_account", "target": "user.name"}, "tier": "confirm"}]}
```

| mode | tier auto | tier confirm |
|---|---|---|
| `off` | 아무것도 안 함 | 아무것도 안 함 |
| `dry` (기본) | 제안 + [실행] 버튼 | 제안 + [실행] 버튼 |
| `on` | **바로 실행** + [해제] 버튼 | 제안 + [실행] 버튼 |

- 자동 실행은 시간당 `max_per_hour` 까지, 넘으면 제안으로 바뀜. `/hsoar pause` 동안도 제안만.
- `tier: never` 는 제안하지 않음. 같은 사건의 같은 (조치, 대상)은 한 번만.
- 보호 목록(차단 금지·사내망·보호 계정)과 simulate 모드는 RKMSIEM 이 그대로 적용 — HSOAR 가 넘을 수 없음.
- 바꾼 뒤 `sudo systemctl restart rkmsiem-hsoar`. 처음엔 **dry** 로 며칠 제안을 보고 `on` 으로.

## 파일

| 경로 | |
|---|---|
| `/etc/rkmsiem/addons/hsoar/addon.env` | RKMSIEM 이 만든 전용 토큰 (root:rkmsiem-hsoar 0640) |
| `/etc/rkmsiem/addons/hsoar/hsoar.env` | Slack 토큰·채널·ALLOWED_USERS·CONSOLE_URL |
| `/etc/rkmsiem/addons/hsoar/policy.json` | 자동 대응 등급 |
| `/var/lib/rkmsiem-hsoar/state.json` | 피드 위치 · 올린 메시지 · 일시 정지 · 자동 모드 |
| `/opt/rkmsiem-hsoar/` | 프로그램 (venv + slack_sdk) |
| `journalctl -u rkmsiem-hsoar -f` | 로그 |

## 문제 해결 — `sudo rkmsiem-setup → 추가 기능 → HSOAR → 상태 확인`

| 표시 | 원인 · 고치는 법 |
|---|---|
| `✘ Slack 앱 토큰(xapp-): invalid_auth` | 앱 레벨 토큰이 틀렸거나 폐기됨 (봇 토큰과 바뀌어 들어간 경우 포함). Slack 앱 → **Basic Information → App-Level Tokens → Generate** (scope `connections:write`), **Socket Mode** 켜짐 확인 → 설정에서 앱 토큰 다시 입력 |
| `✘ Slack 봇 토큰(xoxb-): invalid_auth` | **OAuth & Permissions → Bot User OAuth Token** 을 다시 복사 (앱을 재설치했으면 바뀜) |
| `· 채널 …: 확인 생략` | 정상 — 앱에 채널 읽기 권한을 주지 않으므로. 그 채널에서 `/invite @hsoar` 했는지만 확인 |
| 로그 `not_in_channel` | 봇이 알림 채널에 없음 — 그 채널에서 `/invite @hsoar` (서비스는 죽지 않고 계속 시도, 초대하면 다음 경보부터 올라옴) |
| 로그 `channel_not_found` | `SLACK_CHANNEL` 이 틀림 — 채널 ID(`C…`) 다시 확인 |
| 로그 `Slack 연결 실패 … 초 뒤 다시` | 서비스는 죽지 않고 30초→5분 간격으로 다시 시도. 설정을 고치면 `sudo systemctl restart rkmsiem-hsoar` 로 바로 |

토큰은 비밀번호와 같다 — 채팅·스크린샷에 올렸다면 Slack 에서 폐기하고 새로 발급.
