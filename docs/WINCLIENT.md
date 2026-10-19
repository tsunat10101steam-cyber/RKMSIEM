# 윈도우 클라이언트 (엔드포인트 에이전트)

리눅스 **서버**(RKMSIEM)에 윈도우 PC가 **클라이언트**로 붙는 구조. 클라이언트가 서버로 *나가서*(아웃바운드) TLS 소켓 하나를 열고, 그 위로 서버가 할 일을 내려보낸다. 윈도우에 공개 포트를 열 필요가 없다.

```
Windows PC (exe) ──TLS 소켓(JSON)──▶ RKMSIEM 서버 :8452
   · 상태·보안 로그 보고(telemetry)        · 조치 명령 내려보냄 → PC 에서 실행
```

HTTP 롱폴링 에이전트(`web/agent/`, 리눅스)와 **같은 두뇌**(토큰·작업큐·결과·인벤토리, `rkmsiem/agents.py`)를 쓴다. 전송만 지속 소켓이라, 콘솔의 **에이전트** 화면·`/api/agents`·사건 타임라인에 똑같이 나온다.

## 서버 쪽 켜기 (리눅스)

`/etc/rkmsiem/rkmsiem.yaml` (또는 `config/settings.yaml`):

```yaml
agent_socket:
  enabled: true          # 켜고 재시작
  port: 8452
  tls: true              # rkmsiem 자체 인증서 (deploy/tls.sh 가 만든 것)
  telemetry_source: http-json
```

```bash
sudo ufw allow 8452/tcp              # 클라이언트가 붙을 포트
sudo systemctl restart rkmsiem
```

인증서 지문 확인(클라이언트가 핀으로 씀):
```bash
sudo /usr/share/rkmsiem/deploy/tls.sh --show      # SHA-256 지문
```

## 내려받기·설치 (윈도우)

릴리스마다 **설치 마법사**를 빌드해 GitHub 릴리스에 올린다:

```
https://github.com/<조직>/RKMSIEM/releases/latest → rkmsiem-winagent-setup.exe
```

**`rkmsiem-winagent-setup.exe` 를 더블클릭** → 일반 프로그램처럼 설치 마법사 GUI 가 뜬다
(다음 → 설치 폴더 → **서버 주소·포트·지문·등록 코드 입력** → 허용 조치 선택 → 설치 → 완료).
설치가 끝나면 설정 파일(`%ProgramData%\RKMSIEM\winagent.env`)을 자동으로 쓰고,
부팅 시 SYSTEM 으로 자동 실행되는 작업(`RKMSIEMAgent`)을 등록·시작한다. **명령줄·`--setup` 불필요.**

같은 릴리스에 **단일 실행 파일** `rkmsiem-winagent.exe` 도 있다(설치 없이 직접 돌리거나 `--setup` 으로 설정할 때).

직접 빌드 (윈도우): `py web\winagent\build-exe.py` (exe) → Inno Setup `ISCC installer.iss` (설치 마법사). 표준 라이브러리만 쓰므로 추가 의존성은 없다.

## 설치 마법사 (권장)

1. 콘솔 → **에이전트** → 등록 코드 발급 (`rke_…`, 1시간 1회용) — 리눅스 에이전트와 같은 버튼
2. exe 를 **관리자 권한**으로 실행:
   ```
   rkmsiem-winagent.exe --setup
   ```
   창(마법사)이 뜬다 — 서버 주소·포트·등록 코드를 넣고:
   - **지문 가져오기** → 서버 인증서 지문을 자동으로 채움 (서버의 `tls.sh --show` 값과 같은지 확인)
   - **연결 테스트** → 지문·연결 확인
   - 허용 조치(프로세스 종료·서비스 재시작)·보안 로그 보고 선택
   - **저장** (`%ProgramData%\RKMSIEM\winagent.env`) → **서비스로 설치·시작** (부팅 시 SYSTEM 으로 자동 실행, schtasks `RKMSIEMAgent`)
   - GUI 가 없는 환경이면 자동으로 콘솔 질문 방식으로 (`--setup --console`)

첫 연결이 되면 콘솔 **에이전트** 목록에 이 PC 가 온라인으로 뜬다.

### 수동 설정 (마법사 대신)

`%ProgramData%\RKMSIEM\winagent.env` 를 직접 써도 된다:
```
RKMSIEM_HOST=10.0.0.53
RKMSIEM_PORT=8452
RKMSIEM_FINGERPRINT=<tls.sh --show 의 지문>
ENROLL_CODE=rke_...            # 첫 연결 뒤에는 지워도 됨 (토큰이 저장됨)
ALLOW=process_kill,service_restart
TELEMETRY=1
```
그다음 `rkmsiem-winagent.exe` (서비스로 늘 켜 두려면 마법사의 '서비스로 설치·시작', 또는
`schtasks /create /tn RKMSIEMAgent /tr "경로\rkmsiem-winagent.exe" /sc onstart /ru SYSTEM /rl HIGHEST`).

## 할 수 있는 조치

| 조치 | 하는 일 | 필수 입력 |
|---|---|---|
| `process_kill` | `taskkill /PID <pid> /F /T` | pid |
| `service_restart` | `sc stop` → `sc start` | service |

무엇을 허용할지는 **클라이언트의 `ALLOW`** 가 정한다 (비우면 보고·텔레메트리만). 서버가 털려도 `ALLOW` 밖의 일은 못 한다.
`PROTECT_PROCESSES`(기본 System·lsass·winlogon 등)·`PROTECT_SERVICES`(기본 WinDefend·EventLog 등)에 든 것은 **클라이언트가 스스로 거부**한다.

## 텔레메트리

`TELEMETRY=1` 이면 보안 로그의 **실패 로그온(이벤트 4625)**을 주기적으로 서버의 `http-json` 수집 소스로 올린다 → 무차별 대입·스프레이 같은 탐지 규칙이 윈도우 PC 까지 본다.

## 보안

- TLS 소켓 + 서버 인증서 **지문 핀**(자체 서명이라 CA 대신 지문으로 확인). 지문이 다르면 연결하지 않음. 내부망 테스트로 TLS 없이 쓰려면 `RKMSIEM_INSECURE=1`.
- 토큰(`rka_…`)은 `%ProgramData%\RKMSIEM\token` 에 저장, 서버 DB 에는 해시만. 콘솔에서 해제하면 즉시 무효.
- 조치 기록은 `token:agent:<이름>` 으로 감사 로그·사건 타임라인에 남는다.
