# RKMSIEM — 동적 SIEM/SOAR 플랫폼 (단일 노드)

로그 수집 → 정규화 → 저장 → 상관분석 탐지 → 경보 → 사건 → 플레이북(승인·자동 대응) → 실시간 UI · 감사 로그까지
**실제 데이터 흐름으로 연결된** 보안 관제 플랫폼입니다. 탐지 기준·플레이북·워크플로·권한·데이터 소스는 모두 설정(YAML)으로 관리됩니다.

> ⚠ `samples/` 의 auth.log, `config/assets.yaml`, `config/intel.yaml`, `samples/geoip_sample.json` 은 **예제(가상) 데이터**입니다.
> UI 에 `SAMPLE` 표시로 구분되며 운영 데이터처럼 다루지 마세요.

## 1. 아키텍처

```
 [수집기 플러그인]  file(tail) · http(POST /api/ingest/<source>) · syslog_udp      ← config/sources.yaml
        │ 멱등성 키(파일:위치+내용 해시 / 송신 id / 본문 해시) · 원본 보존(raw_events)
        ▼
 [제한된 큐] 가득 차면 HTTP 429 · 파일은 대기(백프레셔) · UDP 는 드롭 계수
        ▼
 [정규화] 파서 플러그인(authlog · json · syslog RFC3164/5424) → ECS 부분집합 → 스키마 검증 (실패 → DLQ, 재처리 가능)
        ▼
 [저장] SQLite(WAL) — events · raw_events · dlq · alerts · incidents · playbook_runs · audit_log(해시 체인) · config_versions
        ▼
 [탐지 엔진] 규칙 유형 match · threshold · distinct_count · sequence, 단계별 기준, 예외, 위험도 보정,
            unless(상위 규칙 우선), 중복 억제·단계 상향, 위험 점수 근거 기록                 ← config/rules/*.yaml
        ▼
 [사건 관리] 상관 키로 경보를 묶음 · 설정 워크플로 · 담당자 · 타임라인                         ← config/workflow.yaml
        ▼
 [SOAR] 플레이북(조건·승인·제한 시간·재시도·실패 처리·보상) · 액션 플러그인 · simulate/live   ← config/playbooks/*.yaml
        ▼
 [Flask API] 토큰 인증 · RBAC(백엔드 검사) · SSE 실시간 · /healthz · /readyz · /metrics      ← config/rbac.yaml
        ▼
 [웹 콘솔] web/ — 터미널형 UI. 모든 수치는 /api/overview 등 백엔드 계산값을 표시만 함
```

| 모듈 | 역할 |
|---|---|
| `rkmsiem/schemas.py` | 데이터 계약(규칙·플레이북·설정·이벤트 JSON Schema) |
| `rkmsiem/configstore.py` · `validators.py` | 설정 검증·버전·롤백·변경 알림 (잘못된 설정은 거부, 기존 버전 유지) |
| `rkmsiem/pipeline.py` · `collectors/` · `parsers/` · `normalize.py` | 수집 파이프라인 |
| `rkmsiem/detect.py` · `alerts.py` | 스트리밍 상관분석 엔진 · 시뮬레이션/비교 · 경보 저장 |
| `rkmsiem/incidents.py` | 사건·워크플로·타임라인 |
| `rkmsiem/soar/engine.py` · `soar/actions.py` | 플레이북 실행 엔진 · 액션 |
| `rkmsiem/auth.py` · `api.py` | 인증·RBAC·REST·SSE |
| `rkmsiem/staffsync.py` · `staffdir/` | 담당자 명단 연동 · 별도 담당자 관리 앱 (자체 DB·관리자·연동 API) |
| `rkmsiem/audit.py` | 해시 체인 감사 로그 (DB 트리거로 UPDATE/DELETE 차단) |
| `rkmsiem/platform.py` | 조립 · 설정 핫 리로드 · 재시작 복원 · 보존 정책 · 상태 점검 |
| `detector.py` · `app.py` · `dashboard.py` | **기존 기능 호환 계층** (같은 엔진·규칙 사용) |

## 2. 실행

```bash
python -m pip install -r requirements.txt     # Flask, ruamel.yaml, jsonschema, pytest
cp .env.example .env                          # RKMSIEM_ADMIN_PASSWORD(12자↑), RKMSIEM_INGEST_KEYS 채우기
python -m rkmsiem gen-sample                  # (선택) samples/auth.log 예제 데이터 생성
python -m rkmsiem check-config                # 설정 전체 검증
python -m rkmsiem serve                       # http://127.0.0.1:8088
python -m staffdir admin add admin           # (선택) 담당자 관리 앱 관리자 — 비밀번호 입력 또는 STAFF_NEW_PASSWORD
python -m staffdir serve                      # (선택) 담당자 관리 앱 http://127.0.0.1:8090 — 연동은 .env 의 STAFF_SYNC_KEYS·RKMSIEM_STAFF_SYNC_KEY·RKMSIEM_STAFF__URL
```

- 최초 기동 시 사용자가 없으면 `.env` 의 관리자 계정이 만들어집니다. 추가 사용자: `python -m rkmsiem user add <이름> <admin|analyst|responder|viewer>`
- 콘솔에서 `login` → `dashboard all` / `dashboard incidents` / `incident <번호>` / `help`
- HTTP 수집 예:
  ```bash
  curl -X POST "http://127.0.0.1:8088/api/ingest/http-json?wait=1" -H "X-API-Key: <키>" -H "Content-Type: application/json" -d '[{"id":"e1","timestamp":"2026-10-12T01:00:00Z","src_ip":"203.0.113.5","user":"admin","outcome":"failure","category":"authentication"}]'
  ```
- Syslog: `127.0.0.1:5514/udp` (RFC3164/5424, sshd 실패/성공 추출 규칙은 `config/sources.yaml`)
- 기존 스크립트: `python app.py [로그경로]` (콘솔 출력), `python dashboard.py` (오프라인 HTML 리포트)
- `Dockerfile` · `docker-compose.yml` 제공 — **이 개발 PC 에 Docker 가 없어 검증하지 못했습니다.**

## 2-1. Ubuntu 서버 운영 배포 (22.04 / 24.04 / 26.04)

**화면으로 설치·점검 (권장)** — 화살표·스페이스·엔터로 옵션 선택, 진행률 막대, 자체 점검 결과 정리:

```bash
# 처음 한 번 — 최신 버전을 받아 설치하고 화면을 띄움
curl -fsSL https://raw.githubusercontent.com/tsunat10101steam-cyber/RKMSIEM/main/deploy/get.sh | sudo bash
# 이후에는
sudo rkmsiem-setup                  # 메뉴: 설치 · 자체 점검 · 업데이트(GitHub 최신 자동 받기) · 외부 접속 허용 · 상태 · 제거
```

압축 파일로 받았다면 `sudo ./deploy/setup-tui.sh` 가 같은 화면입니다. 명령으로 직접 하려면:

```bash
# 프로젝트를 서버로 복사한 뒤 (git clone 또는 scp), 프로젝트 루트에서
sudo ./deploy/install.sh            # 기본: simulate 모드 (탐지·사건·승인은 실제, 차단/잠금은 기록만)
sudo ./deploy/smoketest.sh          # 실제 경로로 동작 검증 (아래 표)
# 확인이 끝나면 실제 대응 켜기:
sudo sed -i 's/^  mode: simulate /  mode: live     /' /etc/rkmsiem/config/settings.yaml && sudo systemctl restart rkmsiem
sudo ./deploy/smoketest.sh          # live 에서 nft 차단·해제까지 검증
```

| 구성 | 실제로 하는 일 |
|---|---|
| 수집 | `/var/log/auth.log` 를 tail (22.04 전통 형식 · 24.04 RFC3339 형식) — sshd/sshd-session 실패·성공, sudo, su 추출. rsyslog 없는 서버는 `journald-auth` 소스로 전환 |
| 차단 | 전용 nftables 테이블 `inet rkmsiem` 의 세트에 IP 추가(시간 제한 자동 해제). 서비스에 `CAP_NET_ADMIN` 만 부여 (root 아님). 재시작 시 DB 의 유효 차단을 다시 적용 |
| 계정 잠금 | root 소유 헬퍼 `/usr/local/lib/rkmsiem/rkmsiem-account` 만 sudo 허용 → `usermod --lock` + `--expiredate 1`(키 인증 SSH 도 거부) + 세션 종료. UID<1000·root·보호 계정은 헬퍼가 거부 |
| 위협 인텔 | FireHOL Level1 · Spamhaus DROP · abuse.ch Feodo 를 주기적으로 내려받아 IP 평판에 사용 (샘플 없음) |
| IP 평판 (AbuseIPDB) | `/etc/rkmsiem/rkmsiem.env` 에 `RKMSIEM_ABUSEIPDB_KEY=…` 를 넣고 `sudo systemctl restart rkmsiem` → 플레이북 `ip_reputation` 이 AbuseIPDB 점수(≥75 악성 · ≥25 의심)와 피드 중 더 위험한 판정 사용. 같은 IP 6시간 캐시 · 한도 소진/키 오류/장애 시 피드로 계속 · 콘솔 `rep <IP>` · 점검 `dashboard doctor` |
| 메일 · PDF 보고서 | `settings.yaml` 의 `mail`(SMTP 주소·포트·starttls/ssl/none·보낸 사람·허용 수신자) + `rkmsiem.env` 의 `RKMSIEM_SMTP_PASSWORD` → 경보 알림(심각도 기준·60초 묶음)·승인 요청 메일, 사건 종결 시 사건 보고서 PDF, `reports.schedule` 정기 요약 보고서(일간·주간). 플레이북 `send_email` 단계(사건 보고서 첨부 가능, simulate 모드에서는 기록만). 콘솔 `dashboard mail`(상태·테스트·발송 기록), `report incident <번호>` / `report 7d` (PDF 받기). 받는 사람은 허용 목록 안에서만 · 시간당 상한 · 모든 발송은 감사 로그 |
| 웹 설정 (`dashboard settings`) | 메일 서버(Gmail·Naver·Outlook·사내 릴레이 프리셋, 저장 전 테스트) · 받는 사람(주소를 칸으로 끌어다 놓기: 허용 목록·경보 알림·사건 종결 보고서·정기 보고서) · 보고서 일정 · 목록(차단 금지·사내망·보호 계정) · AbuseIPDB 기준. 저장하면 재시작 없이 바로 적용, 버전·감사 로그. 처음 실행 때 settings.yaml 의 mail·reports·reputation 값을 가져오고 이후에는 웹 값이 우선. SMTP 비밀번호·AbuseIPDB 키는 웹에서 입력 → DB 에 암호화(Fernet) 저장, 다시 읽기 불가, 암호화 키는 `rkmsiem.env` 의 `RKMSIEM_SECRET_KEY` (install.sh 가 생성) |
| 데이터 초기화 | 콘솔 `dashboard settings data` 또는 `python -m rkmsiem reset test|all [--dry-run]`. test = 문서용 IP 대역(192.0.2.x · 198.51.100.x · 203.0.113.x)·임시 계정 rkmsmoke*·샘플 데이터와 그에 딸린 경보·사건·실행·차단만, all = 이벤트·경보·사건 전부(확인 문구 필요). 설정·사용자·감사 로그·수집 위치는 유지. `smoketest.sh` 는 끝에 test 정리를 자동 실행 (`KEEP_TEST_DATA=1` 이면 남김). 위협 수준은 '오탐'으로 닫은 사건의 경보를 빼고 판단 |
| Suricata IDS 연동 | IDS 서버에서 `deploy/ids/install-ship.sh --siem http://<SIEM>:8088` → 전송기(`rkmsiem-ship-eve`, 표준 라이브러리만)가 eve.json 의 alert·anomaly 를 `POST /api/ingest/suricata-eve` 로 보냄 (위치 저장·재시도·로그 회전 대응, 중복은 SIEM 이 제거). 규칙: `ids_suricata_alert`(IP·시그니처별, 10분 20회 반복 상향, Suricata 심각도 보정), `ids_then_login`(IDS 경보 IP 가 1시간 안에 로그인 성공 → 긴급). 기존 설치에도 `suricata-eve` 소스가 한 번 자동 추가됨 |
| 담당자 관리 앱 (`staffdir/`, 별도 서비스 `rkmsiem-staff`, 포트 8090) | RKMSIEM 과 다른 프로세스·DB·관리자 로그인. 담당자 이름·팀·메일·연락처·배정 메일 알림·비활성화·삭제, 변경 기록(연락처 값은 남기지 않음). RKMSIEM 은 연동 키(`RKMSIEM_STAFF_SYNC_KEY` = `STAFF_SYNC_KEYS`)로 `GET /api/sync/people` 를 60초마다 가져가고, 명단이 바뀌면 앱이 `POST /api/staff/hook` 으로 알려 바로 다시 가져감. 앱이 꺼져 있어도 마지막 명단으로 계속 동작. 관리자 만들기: `sudo rkmsiem-staff admin add <이름>` |
| 담당자 (`dashboard team`) | 담당자 명단(담당자 관리 앱에서 가져옴)·맡은 열린 사건 수·연동 상태·'지금 가져오기'·'담당자 관리 열기'. 명단에 있으면 로그인 계정이 없어도 배정 가능, 아이디가 같으면 로그인 계정과 연결. 관리자는 로그인 계정(역할·임시 비밀번호·비활성화)을 따로 관리, 마지막 관리자는 권한을 내리거나 비활성화할 수 없음. 사건 화면에서 담당자 선택/나에게 배정, 사건 목록 필터(내 사건·미배정·담당자별), 배정되면 명단의 메일·실시간 알림 |
| 네트워크 토폴로지 (`dashboard topology`) | 서버가 아는 기기 감지(자기 IP·게이트웨이·이웃 ARP·로그·IDS — 스캔 안 함) → 끌어다 놓기, 포트(●)를 끌어 와이어 연결, 이동·이름·종류·IP·메모, 자동 배치, 저장(버전 기록). IP 별 열린 경보 심각도·차단 여부·이벤트를 10초마다 겹쳐 표시 |
| 웹 터미널 (`ssh [계정@]IP`) | 토폴로지에서 기기를 눌러 **터미널 (SSH)** 또는 콘솔 `ssh` → 브라우저 안 창에서 바로 입력 (xterm.js 동봉, 인터넷 불필요). 조건: 권한 `terminal:use`(기본 관리자만) + **저장된 토폴로지에서 SIEM 기기와 와이어로 이어진 기기만** (백엔드가 검사, 와이어를 끊고 저장하면 열린 세션도 즉시 종료). 서버의 ssh 클라이언트를 pty 로 실행 — 비밀번호·호스트 키 확인은 터미널에서 직접 입력, 처음 보는 호스트 키는 묻고 바뀐 키는 거부. 포트 22·2222, 사용자당 3개, 15분 무입력·4시간 최대(`settings.yaml terminal`). 열기·닫기는 감사 로그, 화면 출력은 `/var/lib/rkmsiem/terminal/*.log` |
| 계정 정보 | `/etc/passwd`·`/etc/group` 에서 계정 존재·sudo/adm 그룹(권한 계정) 조회 |
| 웹 | waitress (127.0.0.1:8088) — 외부 공개는 `/etc/rkmsiem/nginx-rkmsiem.conf`(TLS) 로만 |
| 안전장치 | 설치 시 현재 SSH 접속 IP → `never_block`, 설치한 관리자 계정 → `protected_accounts`, sudo 그룹 → `privileged_users`. 차단·잠금은 live 에서도 **항상 사람 승인** 후 실행 |
| 서버 IP 변경 | `sudo ./deploy/set-ip.sh 10.0.0.53/24 [--gw 10.0.0.2] [--dns 8.8.8.8,1.1.1.1] [--iface ens33]` → netplan 백업 후 고정 IP 적용 · 5분 롤백 타이머 → 새 주소로 다시 접속해 `sudo ./deploy/set-ip.sh --confirm`. VMware NAT 포트 포워딩 대상도 새 IP 로 바꿀 것 |

- 설치 위치: 코드 `/opt/rkmsiem` · 설정 `/etc/rkmsiem/config` · 비밀 `/etc/rkmsiem/rkmsiem.env`(0600) · 데이터 `/var/lib/rkmsiem`
- 운영 점검: 웹 콘솔 `dashboard doctor` (서비스 권한으로 nft·헬퍼·수집 권한 점검) · `journalctl -u rkmsiem -f`
- 지도 위치: MaxMind 무료 계정 → `sudo apt install geoipupdate` → `/etc/GeoIP.conf` 설정 → `geoipupdate -d /var/lib/rkmsiem` (GeoLite2-City)
- 제거: `sudo ./deploy/uninstall.sh` (차단 테이블도 삭제) · `--purge` 는 데이터까지

`smoketest.sh` 가 확인하는 것 (모의 없이 실제 경로):
`logger` 로 실제 sshd 로그 기록 → rsyslog → auth.log → 수집·탐지(KISA_OVER·COMPROMISE) → 사건 → 플레이북 승인 대기 → 승인 →
**`nft list set` 에 IP 가 실제로 들어갔는지** → 해제 후 빠졌는지 → 임시 계정을 헬퍼로 실제 잠금(`passwd -S`=L, `chage` 만료) → root 잠금 거부 →
서비스 계정이 헬퍼 외 명령(`usermod`)을 sudo 로 못 쓰는지 → 감사 로그 무결성.

## 3. 설정 (하드코딩 없음)

| 파일 | 내용 |
|---|---|
| `config/settings.yaml` | DB 경로 · 큐 크기/배치 · 재시도 · 보존 기간 · SOAR 모드 · API · GeoIP (환경 변수 `RKMSIEM_<섹션>__<키>` 로 덮어쓰기) |
| `config/rules/*.yaml` | 탐지 규칙 9개 — KISA U-03(10회), CIS(5회·900초), 계정 대입, 분산 공격, 침해 의심, 잠금 미적용, 저속 공격, 권한 상승, 반복 연결 |
| `config/detection.yaml` | 심각도별 위험 점수 · 중복 억제 기간 · 공통 예외 · 사내망 보정 · 위협 수준 5단계 판정 |
| `config/lists.yaml` | 이름 있는 목록(사내망 CIDR, 예외, 보호 계정, 권한 승인 계정) |
| `config/playbooks/*.yaml` | 플레이북 4개 (침해 대응 · 무차별 대입 분류 · 분산 공격 · 수동 보강) |
| `config/workflow.yaml` · `rbac.yaml` · `approval.yaml` | 사건 상태 · 역할별 권한 · 승인 정책(파괴적 조치 승인, 자기 승인 금지, 만료, 웹훅 허용 목록) |
| `config/sources.yaml` | 데이터 소스(수집기 유형·파서·옵션) |

- 운영 중 변경: `PUT /api/rules/<id>` (JSON 또는 `text/yaml`), `POST /api/rules/<id>/enabled`, `POST /api/rules/<id>/rollback`, `PUT /api/config/<kind>`
- 모든 변경은 스키마+의미 검증 → `config_versions` 에 새 버전 → 감사 기록 → 탐지 엔진 즉시 재구성(최근 이벤트로 상태 복원)
- 규칙 변경 전 검증: `POST /api/rules/simulate {"rule": {...}}` — 저장된 이벤트에 재생해 현재 규칙과의 차이(추가/삭제/단계 변경)를 반환
- 자동화 편집기(웹 콘솔 `dashboard automation`, `web/automation.js`): 도구를 끌어다 놓아 플레이북 구성 — 트리거(경보/사건/수동 · 경보 단계 빠른 선택), 단계 순서(끌기·↑↓), 입력값에 변수 끌어다 놓기, 실행 조건, 승인 · 실패 처리 · 재시도 · 보상 작업. 단계 id 를 바꾸면 다른 단계의 `steps.<id>` 참조도 함께 바뀜
  - API: `POST /api/playbooks/validate` (저장 없이 검증 + 최근 경보에 트리거를 대입한 실행 예상 건수·입력값 미리보기), `GET /api/playbooks/<id>` (내용·버전 이력), `PUT /api/playbooks/<id>`, `POST /api/playbooks/<id>/enabled`, `POST /api/playbooks/<id>/rollback`
  - 삭제 대신 비활성화(버전 이력·감사 보존). 편집기에서 저장한 내용은 DB(`config_versions`)에 남으며 `config/playbooks/*.yaml` 파일은 바꾸지 않음
- 확장: `settings.yaml` 의 `plugins` 에 모듈을 적고 `@plugins.collector / parser / action` 으로 등록 (핵심 코드 수정 없음)

## 4. 테스트

```bash
python -m pytest tests test_detector.py --junitxml=reports/test-report.xml
```

| 파일 | 검증 내용 |
|---|---|
| `tests/test_p0_config.py` | 스키마 · 잘못된 설정 거부 · 버전/롤백 · 감사 체인 위·변조 탐지 · 환경 변수 덮어쓰기 |
| `tests/test_p1_ingest.py` | 파서 3종 · 중복 제거 · DLQ/재처리 · 백프레셔 · 대량 입력 · 파일 체크포인트/재시작/잘림 · UDP · 마스킹 |
| `tests/test_p2_detect.py` | 중복 억제·상향 · 예외 · 보정 · unless · sequence · 비활성 규칙 · 규칙 변경 전후 비교 · 재시작 복원 · **기존 탐지기와 결과 동등성** |
| `tests/test_p3_incidents.py` | 경보→사건 묶음 · 워크플로/사유 · 종료 사건 재사용 금지 · 감사 |
| `tests/test_p4_soar.py` | 자동 트리거 · 승인/거절/만료 · 역할·자기 승인 금지 · simulate/live · 멱등 · 취소·보상 · 재시도·타임아웃 · 크래시 복구 · 안전장치 |
| `tests/test_p5_api.py` | 인증 필수 · 로그인 실패/속도 제한 · RBAC · SQL/정렬 인젝션 · 요청 크기 제한 · 민감정보 마스킹 · SSE 1회용 티켓 · API 전체 흐름 |
| `tests/test_p7_e2e.py` | 실제 HTTP 서버 + 파일 + UDP + SSE 로 전체 흐름 · 화면 집계=DB 값 · 5,000건 부하 · 재시작 · 보존 정책 |
| `tests/test_p8_ubuntu.py` | 실제 Ubuntu auth.log(22.04·24.04)·journald 형식 · 운영 설정 유효성 · nft/헬퍼 명령 인자 · live 플레이북→실제 명령 · 재시작 시 차단 재적용 · 차단 금지 대역 · 위협 인텔 피드 · 비밀번호 변경 · 자가 점검 |
| `test_detector.py` | 기존 테스트(수정 없이) — 새 엔진/설정으로도 통과 |

최근 결과: **95 passed, 19 subtests passed** (Python 3.10 · 3.12 · 3.15 각각) · 부하: 로컬에서 약 3,350 events/s (HTTP 배치 500건) · `pyflakes` 경고 0

## 5. 보안

- 비밀번호 PBKDF2-SHA256 600k · 세션 토큰은 해시로만 저장 · 존재하지 않는 사용자도 같은 검증 시간 · 로그인 속도 제한
- 모든 API 백엔드 권한 검사(`config/rbac.yaml`) · 거부 시도 감사 기록 · 승인 권한/자기 승인 금지 서버 검증
- SQL 은 매개변수 바인딩만, 정렬·필터 필드는 허용 목록 · LIKE 와일드카드 이스케이프 · 요청 크기 제한 · JSON Schema 입력 검증
- 응답 보안 헤더(CSP, X-Frame-Options, nosniff, no-referrer) · 정적 파일 경로 탈출 차단
- 로그·원본 조회 시 password/token/authorization 등 마스킹 · werkzeug 요청 로그 억제(티켓 URL 노출 방지)
- SSE 는 60초·1회용 티켓 (세션 토큰을 URL 에 싣지 않음)
- 파괴적 조치(차단·계정 비활성화)는 승인 필수, live 모드에서는 설정과 무관하게 항상 승인 · 사내망/허용 목록 IP 차단 거부 · 보호 계정 비활성화 거부
- 웹훅은 https + 허용 호스트만, 사설/루프백으로 해석되면 거부(SSRF) · 기본 simulate 모드
- 감사 로그: 해시 체인 + DB 트리거로 수정/삭제 차단, `GET /api/audit/verify`

## 6. 한계 (미구현·주의)

- **Ubuntu 실서버 검증 미완료**: 개발 PC(Windows)에 Linux/WSL 이 없어 `install.sh`·`smoketest.sh`·nftables·usermod 를 실제로 돌려 보지 못했습니다.
  대신 실제 Ubuntu 로그 형식 파싱, nft/헬퍼 **명령 인자**, live 플레이북이 그 명령을 호출하는 흐름을 테스트로 검증했고 스크립트는 `bash -n` 문법 검사만 했습니다.
  → **서버에서 `install.sh` 후 반드시 `smoketest.sh` 를 실행**하세요. 실패 항목이 있으면 그 출력이 원인을 알려 줍니다.
- **단일 노드**: SQLite + 프로세스 내부 큐. 수천 EPS 수준까지 (로컬 측정 약 3,350 events/s). 대규모·고가용성은 큐/저장소 어댑터가 필요
- **이벤트 순서**: 상관분석은 도착 순서로 평가합니다(배치 안에서는 발생 시각 정렬). 원격 소스의 큰 지연 도착은 sequence 규칙을 놓칠 수 있음
- **방어 범위**: 차단은 이 서버의 nftables(호스트 방화벽)입니다. 네트워크 장비·클라우드 보안 그룹·AD 계정 연동 어댑터는 없음(플러그인으로 추가)
- **sshd 키 인증 전용 서버**: 기본 추출 규칙은 'Failed password' 기준. 비밀번호 인증을 끈 서버는 `sources.yaml` 의 preauth 규칙을 켜야 공격 시도가 셉니다
- 계정 잠금 헬퍼를 쓰는 동안은 sudo 때문에 systemd `NoNewPrivileges`·`ProtectSystem=strict` 를 걸 수 없음 (`--no-account-lock` 이면 강화 적용)
- 분산 추적은 `trace_id` 전파까지 (OpenTelemetry 미연동) · 플레이북 시각 편집기·사용자 관리 UI 없음 (YAML·API·CLI)
- 프런트엔드 자동화 테스트 없음 (브라우저 수동 검증 + 백엔드 집계=DB 자동 검증)
- KISA U-03 "10회 이하"는 2021년판 상세 가이드 기준 — 인용 전 KISA 최신 원문 확인 필요
- Docker/Compose 파일은 미검증

## 7. 다음 과제

1. 큐/저장소 어댑터 분리(Kafka · PostgreSQL/OpenSearch) 및 수평 확장
2. 늦게 도착한 이벤트 재정렬 버퍼 · 시간 창 워터마크
3. 실제 차단/IAM/티켓팅 액션 어댑터 (최소 권한 전용 계정, 허용 대상 목록)
4. 플레이북 시각 편집기 · 사용자/역할 관리 UI · 프런트엔드 E2E 테스트(Playwright)
5. OpenTelemetry 추적 · Prometheus 경보 규칙 · 감사 체인 외부 앵커링
