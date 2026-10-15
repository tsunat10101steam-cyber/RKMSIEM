"""데이터 초기화 — 설치 직후 스모크테스트·샘플 기록을 지워 위협 수준을 정상으로 되돌릴 때.

scope:
  test  테스트 기록만: 문서용 IP 대역(RFC 5737: 192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24, smoketest 가 사용),
        smoketest 임시 계정(rkmsmoke* — 로그 어디에 나오든), RKMSIEM 자신의 헬퍼 실행 기록, 샘플(가상) 데이터
        — 그와 연결된 경보(근거가 모두 테스트 기록인 경보 포함)·사건·플레이북 실행·차단까지
  all   이벤트·경보·사건·실행·알림 전부 (실제 공격 기록 포함)
항상 남는 것: 설정·규칙·플레이북(버전 이력), 사용자, 감사 로그(해시 체인 — 이 초기화도 기록됨), 메일 기록,
              비밀 값, 수집 위치(auth.log 를 처음부터 다시 읽지 않음). 'all' 에서 차단 목록은 include_blocklist 일 때만 지움.
"""
import logging

log = logging.getLogger("rkmsiem.maintenance")
TEST_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
TEST_USER_LIKE = "rkmsmoke%"


class ResetError(Exception):
    pass


def _test_ip(col):
    return "(" + " OR ".join(f"{col} LIKE '{p}%'" for p in TEST_PREFIXES) + ")"


def reset(p, scope, actor, reason=None, dry_run=False, include_blocklist=False):
    if scope not in ("test", "all"):
        raise ResetError("scope 는 test 또는 all")
    test = scope == "test"
    gip, guser = "json_extract(group_fields, '$.\"source.ip\"')", "json_extract(group_fields, '$.\"user.name\"')"
    from .normalize import _SELF
    q = lambda v: str(v).replace("'", "''")                                          # noqa: E731
    selfs = " OR ".join(f"message LIKE '%COMMAND={q(cmd)}%'" for cmd in _SELF["commands"]) or "0"
    self_ev = f"(action IN ('privilege_use', 'service_helper') AND user_name = '{q(_SELF['user'] or '')}' AND ({selfs}))"
    # 테스트 기록 = 문서용 IP · 임시 계정(로그 어디에든 이름이 나오면) · 샘플 · RKMSIEM 자신의 헬퍼 실행
    ev_where = (f"(sample=1 OR {_test_ip('source_ip')} OR user_name LIKE '{TEST_USER_LIKE}' OR message LIKE '%rkmsmoke%' OR {self_ev})"
                if test else "1=1")
    al_where = f"(sample=1 OR {_test_ip(gip)} OR {guser} LIKE '{TEST_USER_LIKE}')" if test else "1=1"
    with p._engine_lock:                               # 그동안 새 이벤트 탐지를 잠시 멈춤 (수집은 큐에 쌓임)
        with p.db.tx() as c:
            # 지울 대상을 임시 표에 모음 (긴 IN 목록 대신 — 많은 행도 안전)
            for t in ("rm_alert", "rm_inc", "rm_run", "rm_event"):
                c.execute(f"CREATE TEMP TABLE IF NOT EXISTS {t} (id INTEGER PRIMARY KEY)")
                c.execute(f"DELETE FROM {t}")
            c.execute(f"INSERT INTO rm_alert SELECT id FROM alerts WHERE {al_where}")
            c.execute(f"INSERT INTO rm_event SELECT id FROM events WHERE {ev_where}")
            if test:                                   # 근거 이벤트가 모두 테스트 기록인 경보도 (예: 서비스 계정의 헬퍼 실행 경보)
                c.execute("INSERT OR IGNORE INTO rm_alert SELECT a.id FROM alerts a WHERE json_array_length(a.evidence) > 0 AND NOT EXISTS "
                          "(SELECT 1 FROM json_each(a.evidence) e WHERE e.value NOT IN (SELECT id FROM rm_event))")
            # 사건: 남는 경보가 하나도 없을 때만 지움 (실제 공격 경보가 섞인 사건은 보존)
            no_left = "NOT EXISTS (SELECT 1 FROM alerts a WHERE a.incident_id = i.id AND a.id NOT IN (SELECT id FROM rm_alert))"
            had = "EXISTS (SELECT 1 FROM alerts a WHERE a.incident_id = i.id)"
            c.execute(f"INSERT INTO rm_inc SELECT i.id FROM incidents i WHERE ({no_left} AND ({had} OR i.sample = 1))" if test
                      else "INSERT INTO rm_inc SELECT id FROM incidents")
            c.execute("INSERT OR IGNORE INTO rm_run SELECT id FROM playbook_runs WHERE incident_id IN (SELECT id FROM rm_inc) "
                      "OR alert_id IN (SELECT id FROM rm_alert)" + ("" if test else " OR 1=1"))
            blocks = [r[0] for r in c.execute("SELECT ip FROM blocklist").fetchall()]
            blocks = [ip for ip in blocks if ip.startswith(TEST_PREFIXES)] if test else (blocks if include_blocklist else [])
            accounts = [r[0] for r in c.execute("SELECT account FROM account_state" + (f" WHERE account LIKE '{TEST_USER_LIKE}'" if test else ""))]
            n = lambda t: c.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]          # noqa: E731
            touched = c.execute("SELECT COUNT(DISTINCT incident_id) FROM alerts WHERE id IN (SELECT id FROM rm_alert) "
                                "AND incident_id IS NOT NULL").fetchone()[0]
            counts = {"events": n("rm_event"), "alerts": n("rm_alert"), "incidents": n("rm_inc"), "runs": n("rm_run"),
                      "blocklist": len(blocks), "accounts": len(accounts), "incidents_kept": max(0, touched - n("rm_inc"))}
            if dry_run:
                return {"scope": scope, "dry_run": True, "counts": counts}
            c.execute("DELETE FROM step_runs WHERE run_id IN (SELECT id FROM rm_run)")
            c.execute("DELETE FROM approvals WHERE run_id IN (SELECT id FROM rm_run)")
            c.execute("DELETE FROM notifications WHERE run_id IN (SELECT id FROM rm_run) OR incident_id IN (SELECT id FROM rm_inc)")
            c.execute("DELETE FROM playbook_runs WHERE id IN (SELECT id FROM rm_run)")
            c.execute("DELETE FROM alerts WHERE id IN (SELECT id FROM rm_alert)")
            c.execute("DELETE FROM incident_timeline WHERE incident_id IN (SELECT id FROM rm_inc)")
            c.execute("DELETE FROM incidents WHERE id IN (SELECT id FROM rm_inc)")
            raw = "SELECT raw_id FROM events WHERE id IN (SELECT id FROM rm_event) AND raw_id IS NOT NULL"
            c.execute("CREATE TEMP TABLE IF NOT EXISTS rm_raw (id INTEGER PRIMARY KEY)")
            c.execute("DELETE FROM rm_raw")
            c.execute(f"INSERT OR IGNORE INTO rm_raw {raw}")
            c.execute("DELETE FROM events WHERE id IN (SELECT id FROM rm_event)")        # events → raw_events 순서 (외래 키)
            c.execute("DELETE FROM raw_events WHERE id IN (SELECT id FROM rm_raw)")
            if not test:
                c.execute("DELETE FROM raw_events")
                c.execute("DELETE FROM dlq")
                c.execute("DELETE FROM notifications")
            for ip in blocks:
                c.execute("DELETE FROM blocklist WHERE ip=?", (ip,))
            for a in accounts:
                c.execute("DELETE FROM account_state WHERE account=?", (a,))
            p.audit.record(actor, "data.reset", "system", scope, reason, dict(counts, include_blocklist=bool(include_blocklist)), conn=c)
        fw = p.response.firewall                       # 방화벽(nft)에서도 빼기
        for ip in blocks:
            if fw:
                try:
                    fw.unblock(ip)
                except Exception as e:     # noqa: BLE001
                    log.warning("reset: nft unblock %s failed: %s", ip, e)
        p.rebuild_engine()                              # 메모리 속 탐지 창도 남은 이벤트로 다시 구성
    p.bus.publish("config", {"kind": "data", "name": scope, "version": None})
    log.info("data reset (%s) by %s: %s", scope, actor, counts)
    return {"scope": scope, "dry_run": False, "counts": counts}
