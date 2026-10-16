# Grafana 연결

RKMSIEM 과 Grafana 를 세 가지로 잇는다. 필요한 것만 쓰면 된다.

| 무엇 | 방향 | 설정 |
|---|---|---|
| ① 지표 수집 | Prometheus → RKMSIEM `/metrics` | API 토큰(읽기 전용) |
| ② Grafana 를 콘솔 안에 | 브라우저 → `https://<서버>:8443/grafana/` | `sudo rkmsiem-grafana` |
| ③ 대시보드 칸에 Grafana 그래프 | `dashboard all` 의 칸을 Grafana 패널로 바꾸거나 뒤에 추가 | 콘솔 `settings → API 토큰 · Grafana` |

(반대 방향 — Prometheus 경보를 RKMSIEM 이 가져오기 — 는 `settings → 당겨오기` 의 Prometheus 프리셋.)

## ① Prometheus 가 RKMSIEM 지표를 수집

1. 콘솔 `dashboard settings tokens` → 새 토큰 (이름 `prometheus`, 권한 `지표 /metrics`) → 한 번만 보이는 값을 복사.
2. Prometheus 서버에 저장: `echo 'rkm_…' | sudo tee /etc/prometheus/rkmsiem.token && sudo chmod 600 /etc/prometheus/rkmsiem.token`
   (도커면 이 파일을 컨테이너에 마운트)
3. `prometheus.yml`:
   ```yaml
   scrape_configs:
     - job_name: rkmsiem
       scheme: https
       metrics_path: /metrics
       authorization:
         type: Bearer
         credentials_file: /etc/prometheus/rkmsiem.token
       tls_config:
         insecure_skip_verify: true        # 자체 서명 인증서 — 또는 ca_file: /etc/prometheus/rkmsiem.crt
       static_configs:
         - targets: ['10.0.0.53:8443']
   ```
4. Prometheus 가 다른 서버면 RKMSIEM 서버 방화벽에서 그 IP 허용 (`sudo rkmsiem-setup` → 외부 접속 허용).

지표: `rkmsiem_alerts_open{severity}` · `rkmsiem_incidents_open{severity}` · `rkmsiem_threat_level`(0 없음~4 긴급) ·
`rkmsiem_blocked_ips` · `rkmsiem_runs_waiting_approval` · `rkmsiem_events_24h{source}` · `rkmsiem_collector_up{source,type}` ·
`rkmsiem_collector_last_event_age_seconds{source}` · `rkmsiem_info{version,mode}` + 파이프라인 지표.

토큰은 읽기 권한만 가질 수 있고(설정 변경·조치 실행·토큰 만들기 불가), DB 에는 해시만, 만료·폐기·마지막 사용 시각/IP 가 남는다.

## ② Grafana 를 RKMSIEM 안에 띄우기

```bash
sudo rkmsiem-setup                                  # HTTPS 가 아직이면 → 외부 접속 허용 (= deploy/tls.sh)
sudo rkmsiem-grafana                                # Grafana 가 같은 서버(127.0.0.1:3000)
sudo rkmsiem-grafana --upstream http://10.0.0.60:3000   # 다른 서버·도커
# 패키지 없이 소스로 설치했다면: sudo ./deploy/grafana-embed.sh …
```

```
브라우저 ─ https://서버:8443/grafana/… ─▶ nginx ─(auth_request)─▶ RKMSIEM: 로그인 확인
                                           └─ X-WEBAUTH-USER: rk-<계정>, X-WEBAUTH-ROLE ─▶ Grafana (auth.proxy)
```

- 같은 주소(8443) 아래라 브라우저의 프레임·쿠키 제한에 걸리지 않는다 (CSP `frame-src 'self'`).
- 콘솔이 `/grafana/` 에만 보내지는 HttpOnly 쿠키를 받는다. 세션 토큰과 별개라 Grafana 쪽에 새어도 RKMSIEM API 에는 못 쓰고, **로그아웃하면 바로 무효**.
- Grafana 계정은 `rk-<RKMSIEM 계정>` 으로 자동 생성 — 관리자 → Admin, 나머지 → Viewer (`settings.yaml` 의 `grafana.roles`).
- 브라우저가 보낸 `X-WEBAUTH-USER` 는 nginx 가 덮어쓴다. Grafana 는 `auth.proxy.whitelist`(nginx 주소)에서 온 헤더만 믿는다.
- 같은 서버의 `grafana-server` 면 스크립트가 systemd drop-in 으로 설정하고 Grafana 를 127.0.0.1 에서만 받게 한다(`--keep-direct` 로 유지).
  다른 서버·도커면 출력되는 `GF_*` 환경 변수를 넣고, **Grafana 3000 포트를 RKMSIEM 서버에서만 닿게** 막을 것.
- 같은 서버의 Grafana 에는 대시보드 `RKMSIEM 보안 개요`(`web/grafana/rkmsiem-overview.json`)가 자동 등록된다. 다른 곳이면 Import.
  데이터 소스는 Grafana 에 Prometheus 를 추가하고 대시보드 위 `Prometheus` 에서 고른다.

콘솔: `grafana` (전체 화면, 키오스크) · `grafana <이름|uid>` · `dashboard grafana`. 끄기: `sudo rkmsiem-grafana --disable`.

## ③ 대시보드 칸에 Grafana 그래프 끼우기

콘솔 `dashboard settings tokens` 아래 **대시보드 칸에 Grafana 그래프 끼우기**:

- 칸(위협 수준·시간대별 로그인·수집기 …) · 방식(**바꾸기** / **뒤에 추가**) · Grafana 대시보드 · 패널 · 제목 · 높이
- 대시보드·패널 목록은 Grafana 에서 바로 읽어 온다 (못 읽으면 uid·패널 번호 직접 입력)
- **추천 배치**: 시간대별 로그인 칸 → `열린 경보 (심각도별)`, 수집기 칸 뒤 → `최근 24시간 이벤트 (출처별)`
- 저장하면 설정 `grafana_panels` 새 버전(감사 로그). 보는 사람은 `metrics:read` 만 있으면 된다.

Grafana 그래프는 콘솔의 `range` 를 따라가고 1분마다 새로 고친다. 바꾼 칸의 원래 패널은 `dashboard hourly raw` 처럼 `raw` 를 붙인다.
