"""대시보드 집계 — 모든 수치는 저장된 이벤트·경보·사건·실행에서 계산한다(프런트엔드는 표시만)."""
import time
from zoneinfo import ZoneInfo

from .db import loads
from .detect import RANK, SEV


def resolve_range(db, frm, to):
    """기본값: 저장된 최신 이벤트 기준 24시간 (데이터가 없으면 현재 기준)."""
    latest = db.scalar("SELECT MAX(ts) FROM events")
    if to is None:
        to = latest if latest else time.time()
    if frm is None:
        frm = to - 86400
    return float(frm), float(to) + 0.000001, latest


def threat_level(levels_cfg, alerts):
    ids = {a["level_id"] for a in alerts}
    rules = {a["rule_id"] for a in alerts}
    top = max((a["severity_rank"] for a in alerts), default=-1)
    for i, lv in enumerate(levels_cfg):
        if lv.get("any_level_ids") and ids & set(lv["any_level_ids"]):
            return i, lv
        if lv.get("any_rule_ids") and rules & set(lv["any_rule_ids"]):
            return i, lv
        if lv.get("min_severity") and top >= RANK[lv["min_severity"]]:
            return i, lv
        if not (lv.get("any_level_ids") or lv.get("any_rule_ids") or lv.get("min_severity")):
            return i, lv
    return len(levels_cfg) - 1, levels_cfg[-1]


def overview(db, config, locator, frm=None, to=None, tz="UTC"):
    frm, to, latest = resolve_range(db, frm, to)
    span = to - frm
    bucket = 3600 if span <= 2 * 86400 else 86400
    zone = ZoneInfo(tz)
    # 지역 시각 경계에 맞춘 버킷 시작점
    from datetime import datetime
    start_local = datetime.fromtimestamp(frm, zone).replace(minute=0, second=0, microsecond=0)
    if bucket == 86400:
        start_local = start_local.replace(hour=0)
    origin = start_local.timestamp()
    n_buckets = int((to - origin) // bucket) + 1

    ev_where, ev_p = "ts >= ? AND ts < ?", (frm, to)
    tot = db.one(f"SELECT COUNT(*) total, SUM(outcome='failure') fail, SUM(outcome='success') ok, COUNT(DISTINCT source_ip) ips, "
                 f"COUNT(DISTINCT CASE WHEN outcome='failure' THEN source_ip END) fail_ips, SUM(sample) sample FROM events WHERE {ev_where}", ev_p)
    series = [{"t": origin + i * bucket, "fail": 0, "success": 0, "other": 0} for i in range(n_buckets)]
    for r in db.all(f"SELECT CAST((ts - ?) / ? AS INTEGER) b, outcome, COUNT(*) n FROM events WHERE {ev_where} GROUP BY b, outcome",
                    (origin, bucket) + ev_p):
        if 0 <= r["b"] < n_buckets:
            k = {"failure": "fail", "success": "success"}.get(r["outcome"], "other")
            series[r["b"]][k] += r["n"]

    alerts = [dict(a, group=loads(a["group_fields"], {}), risk_basis=loads(a["risk_basis"], {}))
              for a in db.all("SELECT a.*, i.state AS incident_state FROM alerts a LEFT JOIN incidents i ON i.id = a.incident_id "
                              "WHERE a.last_ts >= ? AND a.first_ts < ? ORDER BY a.severity_rank DESC, a.risk_score DESC", (frm, to))]
    # 위협 수준은 '오탐'으로 닫은 사건의 경보를 빼고 판단 (목록·통계에는 그대로 보임)
    real = [a for a in alerts if a.get("incident_state") != "false_positive"]
    det = config.get("detection") or {}
    levels_cfg = det.get("threat_levels") or [{"id": "normal", "label": "정상", "en": "NORMAL"}]
    lv_i, lv = threat_level(levels_cfg, real)
    severe_ids = set(levels_cfg[0].get("any_level_ids", [])) if levels_cfg else set()

    by_sev = {s: 0 for s in SEV}
    for a in alerts:
        by_sev[a["severity"]] += 1

    # 출발 IP 별 묶음 (경보 그룹에 source.ip 가 있는 것)
    offenders = {}
    for a in alerts:
        ip = a["group"].get("source.ip")
        if not ip:
            continue
        o = offenders.setdefault(ip, {"ip": ip, "severity": a["severity"], "severity_rank": a["severity_rank"], "risk": 0, "rules": [],
                                      "max_count": 0, "first_ts": a["first_ts"], "last_ts": a["last_ts"], "severe": False,
                                      "incident_id": a["incident_id"], "users": set(), "internal": False})
        if a["severity_rank"] > o["severity_rank"]:
            o["severity"], o["severity_rank"] = a["severity"], a["severity_rank"]
        o["risk"] = max(o["risk"], a["risk_score"])
        o["max_count"] = max(o["max_count"], a["event_count"])
        o["first_ts"], o["last_ts"] = min(o["first_ts"], a["first_ts"]), max(o["last_ts"], a["last_ts"])
        o["rules"].append({"alert_id": a["id"], "rule_id": a["rule_id"], "level_id": a["level_id"], "title": a["title"], "severity": a["severity"],
                           "count": a["event_count"], "detail": a["detail"], "basis": a["risk_basis"].get("_extra", {}).get("basis", ""),
                           "modifiers": a["risk_basis"].get("modifiers", [])})
        o["severe"] = o["severe"] or (a["level_id"] in severe_ids and a.get("incident_state") != "false_positive")
        if a["group"].get("user.name"):
            o["users"].add(a["group"]["user.name"])
        if a["risk_basis"].get("modifiers"):
            o["internal"] = True
    fails_by_ip = {r["source_ip"]: r for r in db.all(
        f"SELECT source_ip, SUM(outcome='failure') fails, SUM(outcome='success') ok FROM events WHERE {ev_where} AND source_ip IN "
        f"(SELECT value FROM json_each(?)) GROUP BY source_ip", ev_p + (__import__("json").dumps(list(offenders)),))}
    off_list = []
    for o in offenders.values():
        f = fails_by_ip.get(o["ip"], {})
        o.update(fails=f.get("fails") or 0, success=f.get("ok") or 0, users=sorted(o["users"]))
        o["rules"].sort(key=lambda r: -RANK[r["severity"]])
        off_list.append(o)
    off_list.sort(key=lambda o: (-o["severity_rank"], -o["max_count"], -o["fails"]))

    account_alerts = [{"alert_id": a["id"], "rule_id": a["rule_id"], "title": a["title"], "severity": a["severity"], "group": a["group"],
                       "count": a["event_count"], "first_ts": a["first_ts"], "last_ts": a["last_ts"], "detail": a["detail"],
                       "incident_id": a["incident_id"]} for a in alerts if "source.ip" not in a["group"]]

    targets = db.all(f"SELECT user_name AS user, COUNT(*) fails, COUNT(DISTINCT source_ip) ips FROM events WHERE {ev_where} "
                     f"AND outcome='failure' AND user_name IS NOT NULL GROUP BY user_name ORDER BY fails DESC LIMIT 10", ev_p)
    acct_users = {a["group"].get("user.name") for a in account_alerts}
    for t in targets:
        t["account_alert"] = t["user"] in acct_users

    # 국가별 (외부 IP 만)
    countries = {}
    sev_by_ip = {o["ip"]: o["severity"] for o in off_list}
    for r in db.all(f"SELECT source_ip, COUNT(*) n FROM events WHERE {ev_where} AND outcome='failure' AND source_ip IS NOT NULL GROUP BY source_ip", ev_p):
        g = locator.lookup(r["source_ip"])
        if not g:
            continue
        c = countries.setdefault(g["cc"], dict(g, fails=0, ips=0, level=None, alert_ips=[], _lat=0.0, _lon=0.0))
        c["fails"] += r["n"]
        c["ips"] += 1
        c["_lat"] += g["lat"]
        c["_lon"] += g["lon"]
        c["lat"], c["lon"] = c["_lat"] / c["ips"], c["_lon"] / c["ips"]       # 그 나라 IP 위치 평균
        s = sev_by_ip.get(r["source_ip"])
        if s:
            if len(c["alert_ips"]) < 50:
                c["alert_ips"].append(r["source_ip"])
            if c["level"] is None or RANK[s] > RANK[c["level"]]:
                c["level"] = s
    for c in countries.values():
        c.pop("_lat"), c.pop("_lon")
    geo = {"source": locator.source, "db": getattr(locator, "db_name", None), "server": locator.server, "countries": sorted(countries.values(), key=lambda c: -c["fails"])[:60]}

    inc_states = db.all("SELECT state, COUNT(*) n FROM incidents GROUP BY state")
    runs = db.all("SELECT state, COUNT(*) n FROM playbook_runs GROUP BY state")
    rs = {r["state"]: r["n"] for r in runs}
    finished = sum(rs.get(s, 0) for s in ("succeeded", "failed", "cancelled", "compensated"))
    pending = db.all("SELECT a.run_id, a.step_id, a.requested_at, a.expires_at, r.playbook_id, r.incident_id, s.action, s.input "
                     "FROM approvals a JOIN playbook_runs r ON r.id=a.run_id JOIN step_runs s ON s.run_id=a.run_id AND s.step_id=a.step_id "
                     "WHERE a.state='pending' ORDER BY a.requested_at")
    for p_ in pending:
        p_["input"] = loads(p_["input"], {})

    return {
        "meta": {"generated_at": time.time(), "from": frm, "to": to, "bucket_sec": bucket, "timezone": tz, "latest_event_ts": latest,
                 "has_sample": bool(tot["sample"]), "aggregation": f"이벤트 발생 시각 기준 {'1시간' if bucket == 3600 else '1일'} 단위"},
        "totals": {"events": tot["total"] or 0, "fail": tot["fail"] or 0, "success": tot["ok"] or 0, "unique_ips": tot["ips"] or 0,
                   "fail_ips": tot["fail_ips"] or 0, "alerts": len(alerts), "open_alerts": sum(a["status"] == "open" for a in alerts),
                   "severe_ips": sum(o["severe"] for o in off_list),
                   "critical_high_ips": sum(o["severity_rank"] >= RANK["high"] for o in off_list)},
        "threat": {"index": lv_i, "levels": [{"id": l["id"], "label": l["label"], "en": l.get("en", "")} for l in levels_cfg],
                   "current": {"id": lv["id"], "label": lv["label"], "en": lv.get("en", "")},
                   "reasons": {"severe_ips": len({a["group"].get("source.ip") for a in real if a["level_id"] in severe_ids and a["group"].get("source.ip")}),
                               "account_alerts": sum("source.ip" not in a["group"] for a in real),
                               "critical_alerts": sum(a["severity"] == "critical" for a in real),
                               "false_positive_alerts": len(alerts) - len(real)}},
        "series": series, "alerts_by_severity": by_sev, "offenders": off_list, "account_alerts": account_alerts,
        "targets": targets, "geo": geo,
        "incidents": {r["state"]: r["n"] for r in inc_states},
        "playbooks": {"by_state": rs, "finished": finished, "success_rate": round(rs.get("succeeded", 0) / finished, 3) if finished else None,
                      "pending_approvals": pending,
                      "pending_tasks": [dict(t, checklist=loads(t["checklist"], [])) for t in db.all(
                          "SELECT t.id, t.run_id, t.step_id, t.incident_id, t.title, t.checklist, t.requested_at, r.playbook_id FROM manual_tasks t "
                          "JOIN playbook_runs r ON r.id=t.run_id WHERE t.state='pending' ORDER BY t.requested_at")]},
    }
