# 추가 기능 (add-on)

핵심(RKMSIEM)은 **사람이 운영**하는 SIEM·SOAR 이고, 자동화(HSOAR 등)는 **추가 기능**으로 붙였다 뗐다 한다.
추가 기능에 문제가 생겨도 지우면 핵심은 그대로 수동 운영으로 돌아간다.

```
sudo rkmsiem-setup → 추가 기능 → HSOAR → 설치 / 제거
sudo /usr/share/rkmsiem/deploy/addon.sh list | install <id> | uninstall <id>
```

## 약속 (핵심 ↔ 추가 기능)

| 무엇 | 내용 |
|---|---|
| 위치 | `deploy/addons/<id>/` — `addon.conf`(셸 변수) · `install.sh` · `uninstall.sh` |
| 설치 | `addon.sh install <id>` → 핵심이 **전용 API 토큰** `addon-<id>` 를 `SCOPES` 권한만으로 발급 → `/etc/rkmsiem/addons/<id>/addon.env` (root 0600: `RKMSIEM_URL=http://127.0.0.1:8088` · `RKMSIEM_TOKEN` · `RKMSIEM_ADDON`) → `ADDON_ENV=… install.sh` |
| 통신 | API 로만 (`Authorization: Bearer $RKMSIEM_TOKEN`). DB·설정 파일을 직접 건드리지 않음 |
| 기록 | 토큰으로 한 조치는 감사 로그·사건 타임라인·차단 목록에 `token:addon-<id>` 로 남음 — 사람이 한 것과 구분 |
| 제거 | `uninstall.sh` → 서비스 중지 → 토큰 폐기 → `/etc/rkmsiem/addons/<id>` 삭제 |
| 다시 설치 | 새 토큰 (예전 토큰은 자동 폐기) |

`addon.conf`:

```sh
ID=hsoar
NAME="HSOAR"
DESC="한 줄 설명 (setup 메뉴에 보임)"
VERSION=1
AVAILABLE=1                      # 0 이면 메뉴에 '준비 중'
SCOPES="feed:read incidents:read incidents:write runs:read playbooks:run runs:approve runs:cancel"
SERVICE=rkmsiem-hsoar            # 제거할 때 멈출 systemd 서비스
```

## 토큰 권한

| 권한 | 쓸 수 있는 API |
|---|---|
| `feed:read` | `GET /api/feed` (아래) |
| `alerts:read` · `incidents:read` · `events:read` · `runs:read` · `collectors:read` · `metrics:read` | 조회 |
| `incidents:write` | 사건 상태·메모 · 플레이북 사람 할 일 처리 `POST /api/runs/<id>/steps/<step>/task` |
| `playbooks:run` | `POST /api/playbooks/<id>/run` · 평판·계정 조회 |
| `runs:approve` | 사건 즉시 조치(차단·잠금) `POST /api/incidents/<id>/actions` · 원격 조치 `POST /api/agents/<name>/actions` · 차단 기간 변경 |
| `runs:cancel` | 해제 · 실행 취소 |

어떤 토큰으로도 안 되는 것: 설정 변경, 사용자·토큰 관리, 연동 화면 출입증, 에이전트 등록·해제.
보호 목록(차단 금지·보호 계정·대상 서버의 PROTECT_*)과 사유 필수 규칙은 토큰에도 똑같이 적용된다.

## 이벤트 피드 — `GET /api/feed`

꺼져 있던 동안의 이벤트도 놓치지 않게 순번(`seq`)으로 이어 읽는다 (7일 보관).

```
GET /api/feed                         → {"items": [], "last_seq": 1234}      처음: 지금 위치만
GET /api/feed?after=1234&wait=25      → 새 이벤트가 생길 때까지 최대 25초 기다림
GET /api/feed?after=1234&types=incident,run&limit=200
```

```json
{"items": [{"seq": 1235, "ts": 1760580000.1, "type": "incident", "data": {...}}], "last_seq": 1235}
```

종류: `alert` · `incident` · `run`(승인 대기·사람 할 일 포함 상태 변화) · `notification` · `blocklist` · `agents`.
추가 기능은 처리한 마지막 `seq` 를 자기 쪽에 저장해 두고 다음 요청의 `after` 로 넘기면 된다.

## HSOAR (준비 중)

Slack 으로 관리하는 자동 대응 — Socket Mode(서버가 Slack 으로 나가는 연결만, 공개 주소 불필요)로
경보·승인 요청·사람 할 일을 Slack 에 올리고 버튼으로 처리, `/hsoar` 명령, 자동 승인 등급(자동 · Slack 승인 · 금지)과 킬 스위치.
위 피드와 토큰 권한만으로 동작하도록 만든다.
