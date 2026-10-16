# 연동 (connect)

외부 서비스는 제품에 상관없이 같은 방법으로 붙인다: 콘솔 `settings → 당겨오기` 에서 **연동 소스**를 추가한다.
하나의 연동은 두 부분으로 되어 있다 (둘 다 또는 하나만).

| 부분 | 하는 일 | 설정 |
|---|---|---|
| 데이터 | 제품 API 를 주기적으로 조회해 이벤트로 → 탐지·사건 | 주소 · 인증 · 목록 위치 · 필드 매핑 |
| 화면 (view) | 제품의 대시보드를 콘솔 안에서 연다 | 화면 주소 · 처음 열 경로 · 로그인 넘기기 |

콘솔:

- `connect` — 연동 목록(상태·받은 이벤트·화면·대시보드 바로가기) + 첫 화면
- `connect <연동>` · `connect <연동> <대시보드>` — 그 화면 열기 (예: `connect grafana alerts`)
- `dashboard all` 칸에 연동 화면 끼우기 — `settings → 당겨오기` 아래 **대시보드 칸** (바꾸기 / 뒤에 추가, 원래 패널은 `dashboard <이름> raw`)

프리셋은 자주 쓰는 제품의 기본값일 뿐이다 (Prometheus · Grafana · Kubernetes · 일반 JSON API). 다른 제품도 같은 칸을 채우면 된다.

## 화면은 어떻게 열리나

```
콘솔 https://서버:8443  ──iframe──▶  https://서버:8445/connect/<연동>/…  ─▶ RKMSIEM (로그인 확인) ─▶ 제품 (화면 주소)
```

- 연동 화면은 **콘솔과 다른 출처(8445)** 에서 열린다. 제품 페이지에 문제가 있어도 콘솔의 로그인 토큰에 닿지 못한다.
  콘솔 포트(8443)에서는 `/connect/` 가 막혀 있다.
- 콘솔이 `/connect/` 전용 HttpOnly 쿠키를 받는다. 세션 토큰과 별개라 RKMSIEM API 에는 못 쓰고, 로그아웃하면 바로 무효.
- RKMSIEM 서버가 제품에 대신 접속하므로 제품 포트를 PC 에 열 필요가 없다 (제품은 RKMSIEM 서버에서만 닿게 막아 두는 것이 좋다).
- **경로 유지 (권장)**: 제품이 `/connect/<연동>/` 아래에서 동작하도록 제품의 '외부 주소(root URL / external URL / base path)'를
  `https://<서버>:8445/connect/<연동>/` 로 설정한다. 끄면 앞부분을 떼고 넘긴다 (경로를 따로 설정할 수 없는 단순한 화면용).
- **RKMSIEM 로그인 넘기기**: 제품이 헤더 인증(auth proxy)을 지원하면, RKMSIEM 이 `X-WEBAUTH-USER: rk-<계정>`(·역할 헤더)를 붙여 준다.
  브라우저가 보낸 같은 이름 헤더는 버린다. 제품에서는 RKMSIEM 서버 IP 에서 온 헤더만 믿도록 설정할 것.
- 경로에 `{from}` `{to}` 를 쓰면 콘솔의 `range` 로 바뀐다 (`now-24h`/`now` 또는 밀리초).
- 웹소켓은 넘기지 않는다 (제품의 실시간 기능은 주기적 새로 고침으로 동작).

방화벽·포트 포워딩: 콘솔(8443)을 허용한 곳에 8445 도 허용된다 (`tls.sh`·setup 메뉴 '외부 접속 허용'이 같이 처리).
VMware NAT 포트 포워딩을 쓰면 **8445 도 추가**하고, 브라우저가 보는 주소가 다르면 `settings.yaml` 의 `connect.public_origin` 을 맞춘다.

## 예: Grafana

1. 당겨오기 → **Grafana** 프리셋
2. 데이터 (경보): Grafana → Administration → Service accounts → Viewer 계정 → 토큰(`glsa_…`)을 토큰 칸에 → 지금 시험
3. 화면: Grafana 설정 (grafana.ini 또는 도커 환경 변수)
   ```ini
   [server]
   root_url = https://10.0.0.53:8445/connect/grafana/
   serve_from_sub_path = true
   [security]
   allow_embedding = true
   [auth.proxy]
   enabled = true
   header_name = X-WEBAUTH-USER
   header_property = username
   headers = Role:X-WEBAUTH-ROLE
   auto_sign_up = true
   whitelist = 127.0.0.1          ; RKMSIEM 서버 IP (같은 서버면 127.0.0.1)
   ```
   (도커: `GF_SERVER_ROOT_URL=…`, `GF_SERVER_SERVE_FROM_SUB_PATH=true`, `GF_SECURITY_ALLOW_EMBEDDING=true`, `GF_AUTH_PROXY_ENABLED=true` …)
4. 저장 → `connect grafana`. 대시보드 칸에서는 Grafana 대시보드·패널을 목록에서 고를 수 있다.

RKMSIEM 지표용 Grafana 대시보드: `web/grafana/rkmsiem-overview.json` (Import, 데이터 소스는 Prometheus).

## 예: Prometheus

- 데이터: **Prometheus** 프리셋 (울리는 경보)
- 화면: Prometheus 를 `--web.external-url=https://10.0.0.53:8445/connect/prometheus/` 로 실행 (자체 로그인 없음 → 로그인 넘기기 끔)

## 반대 방향: 다른 시스템이 RKMSIEM 을 읽기

`settings → API 토큰` 에서 읽기 전용 토큰(`rkm_…`)을 만든다. Prometheus 가 `/metrics` 를 수집:

```yaml
scrape_configs:
  - job_name: rkmsiem
    scheme: https
    metrics_path: /metrics
    authorization: {type: Bearer, credentials_file: /etc/prometheus/rkmsiem.token}
    tls_config: {insecure_skip_verify: true}      # 또는 ca_file: rkmsiem.crt
    static_configs: [{targets: ['10.0.0.53:8443']}]
```

지표: `rkmsiem_alerts_open{severity}` · `rkmsiem_incidents_open{severity}` · `rkmsiem_threat_level`(0~4) · `rkmsiem_blocked_ips` ·
`rkmsiem_runs_waiting_approval` · `rkmsiem_events_24h{source}` · `rkmsiem_collector_up{source,type}` ·
`rkmsiem_collector_last_event_age_seconds{source}` · `rkmsiem_info{version,mode}` + 파이프라인 지표.
토큰은 읽기 권한만, DB 에는 해시만, 만료·폐기·마지막 사용 시각/IP 기록.
