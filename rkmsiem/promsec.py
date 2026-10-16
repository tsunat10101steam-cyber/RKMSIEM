"""Prometheus 용 보안 지표 — /metrics 를 긁을 때마다 DB 에서 계산 (Grafana 대시보드용).

  rkmsiem_alerts_open{severity}        열린 경보 (오탐으로 닫은 사건 제외)
  rkmsiem_incidents_open{severity}     열린 사건
  rkmsiem_threat_level                 열린 경보의 최고 심각도 (0 없음 · 1 낮음 · 2 주의 · 3 높음 · 4 긴급)
  rkmsiem_blocked_ips                  지금 차단 중인 IP
  rkmsiem_runs_waiting_approval        승인 대기 중인 플레이북 실행
  rkmsiem_events_24h{source}           최근 24시간 이벤트 (소스별)
  rkmsiem_collector_up{source,type}    수집기 동작 (1/0) · rkmsiem_collector_last_event_age_seconds{source}
  rkmsiem_info{version,mode}           1
"""
import time

from . import __version__

SEVS = ["info", "low", "medium", "high", "critical"]


def esc(v):
    return str(v).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def _g(lines, name, help_, rows):
    lines += [f"# HELP rkmsiem_{name} {help_}", f"# TYPE rkmsiem_{name} gauge"]
    for labels, v in rows:
        lab = ",".join(f'{k}="{esc(x)}"' for k, x in labels.items())
        lines.append(f"rkmsiem_{name}{{{lab}}} {v}" if lab else f"rkmsiem_{name} {v}")


def security_metrics(p):
    lines, now = [], time.time()
    db = p.db
    al = {r["severity"]: r["n"] for r in db.all(
        "SELECT a.severity, COUNT(*) n FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id "
        "WHERE a.status <> 'closed' AND COALESCE(i.state, '') <> 'false_positive' GROUP BY a.severity")}
    _g(lines, "alerts_open", "열린 경보 수 (심각도별)", [({"severity": s}, al.get(s, 0)) for s in SEVS])
    term = sorted(p.incidents.terminal_states()) or ["__none__"]
    inc = {r["severity"]: r["n"] for r in db.all(
        f"SELECT severity, COUNT(*) n FROM incidents WHERE state NOT IN ({','.join('?' * len(term))}) GROUP BY severity", term)}
    _g(lines, "incidents_open", "열린 사건 수 (심각도별)", [({"severity": s}, inc.get(s, 0)) for s in SEVS])
    top = max((SEVS.index(s) for s, n in al.items() if n and s in SEVS), default=-1)
    _g(lines, "threat_level", "열린 경보의 최고 심각도 0~4", [({}, max(0, top))])
    _g(lines, "blocked_ips", "지금 차단 중인 IP 수",
       [({}, db.scalar("SELECT COUNT(*) FROM blocklist WHERE expires_at IS NULL OR expires_at > ?", (now,)) or 0)])
    _g(lines, "runs_waiting_approval", "승인 대기 중인 플레이북 실행",
       [({}, db.scalar("SELECT COUNT(*) FROM playbook_runs WHERE state = 'waiting_approval'") or 0)])
    ev = db.all("SELECT source_id, COUNT(*) n FROM events WHERE ingested_at >= ? GROUP BY source_id", (now - 86400,))
    _g(lines, "events_24h", "최근 24시간 이벤트 (소스별)", [({"source": r["source_id"]}, r["n"]) for r in ev])
    up, age = [], []
    for c in p.collectors.values():
        st = c.status()
        up.append(({"source": st["id"], "type": st["type"]}, 1 if st["alive"] and st["state"] in ("running", "passive", "waiting") else 0))
        if st.get("last_event_at"):
            age.append(({"source": st["id"]}, round(now - st["last_event_at"], 1)))
    _g(lines, "collector_up", "수집기 동작 여부", up)
    _g(lines, "collector_last_event_age_seconds", "수집기 마지막 수신 뒤 지난 시간", age)
    _g(lines, "info", "RKMSIEM 정보", [({"version": __version__, "mode": p.settings.get("soar.mode")}, 1)])
    return "\n".join(lines) + "\n"
