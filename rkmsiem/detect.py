"""탐지 엔진: 설정(YAML) 규칙을 이벤트 시각 기준 슬라이딩 윈도로 평가하는 스트리밍 상관분석기.

규칙 유형
- match          : 조건에 맞는 단일 이벤트
- threshold      : group_by 별 window_sec 안의 이벤트 수
- distinct_count : group_by 별 window_sec 안의 distinct_field 서로 다른 값 수
- sequence       : first 조건이 (횟수/서로 다른 값 수) 기준에 도달한 뒤 then 조건 이벤트 발생
                   · within_sec  : 마지막 first 이벤트 후 then 까지 허용 시간 (null = 제한 없음)
                   · lookback_sec: 기준 도달 시점부터 then 까지 허용 시간 (null = window+within)
                   · reset_on_then: then 이벤트가 오면 상태 초기화 (예: 로그인 성공 시 실패 연속 기록 초기화)

공통: levels(단계별 기준/심각도) · exceptions · modifiers(위험도 보정) · unless_rules(다른 규칙 경보가 있으면 생략)
· suppress_sec(같은 규칙·같은 그룹 경보를 하나로 묶고 단계가 오르면 상향).
이벤트는 대체로 시간 순서로 들어온다고 가정한다(재생·시뮬레이션은 시각 순 정렬 후 투입).
"""
import collections
import time

from .conditions import Lists, check_all, value_of

SEV = ["info", "low", "medium", "high", "critical"]
RANK = {s: i for i, s in enumerate(SEV)}


def fmt_window(sec):
    if sec is None:
        return "기간 제한 없이"
    if sec % 86400 == 0:
        return f"{sec // 86400}일"
    if sec % 3600 == 0:
        return f"{sec // 3600}시간"
    if sec % 60 == 0:
        return f"{sec // 60}분"
    return f"{sec}초"


class Engine:
    def __init__(self, rules, policy, lists_cfg, metrics=None):
        """rules: {rule_id: rule(+_version)} — enabled 인 것만 평가."""
        self.policy = policy
        self.lists = Lists(lists_cfg)
        self.metrics = metrics
        active = [r for r in rules.values() if r.get("enabled", True)]
        # unless 의존 규칙은 뒤에서 평가해야 같은 이벤트로 생긴 경보를 볼 수 있다
        self.rules = sorted(active, key=lambda r: (bool(r.get("unless_rules")), r["id"]))
        self.state = {r["id"]: {} for r in self.rules}
        self.open = {}                         # dedup_key → alert (억제 기간 동안 같은 경보 갱신)
        self.unless_index = {}                 # (rule_id, field, value) → 마지막 경보 시각
        self.cap = policy.get("evidence_cap", 50)
        self._seq = 0
        self.stats = collections.defaultdict(lambda: {"evaluated": 0, "matched": 0, "alerts": 0, "escalations": 0, "ms": 0.0})

    # ------------------------------------------------------------------ 입력
    def process(self, ev, silent=False):
        """이벤트 1건 평가 → 경보 변경 목록 [{'op': new|escalate|update, 'alert': {...}}]."""
        changes = []
        doc = ev["doc"]
        g_exc = self.policy.get("global_exceptions") or []
        for rule in self.rules:
            t0 = time.perf_counter()
            st = self.stats[rule["id"]]
            st["evaluated"] += 1
            try:
                if g_exc and any(check_all([c], doc, self.lists) for c in g_exc):
                    continue
                if rule.get("exceptions") and any(check_all([c], doc, self.lists) for c in rule["exceptions"]):
                    continue
                ch = self._eval(rule, ev, silent)
                if ch:
                    changes.append(ch)
            finally:
                st["ms"] += (time.perf_counter() - t0) * 1000
        return changes

    def _group(self, rule, doc):
        vals = {}
        for f in rule["group_by"]:
            v = value_of(doc, f)
            if v is None or v == "":
                return None, None
            vals[f] = v
        return vals, "|".join(f"{k}={v}" for k, v in vals.items()) or "*"

    def _eval(self, rule, ev, silent):
        doc, ts, t = ev["doc"], ev["ts"], rule["type"]
        group, gk = self._group(rule, doc)
        if group is None:
            return None
        S = self.state[rule["id"]]
        if t == "match":
            if not check_all(rule["where"], doc, self.lists):
                return None
            self.stats[rule["id"]]["matched"] += 1
            return self._fire(rule, gk, group, 1, ev, [ev["id"]], "조건 일치", silent)

        if t in ("threshold", "distinct_count"):
            if not check_all(rule["where"], doc, self.lists):
                return None
            self.stats[rule["id"]]["matched"] += 1
            w = rule["window_sec"]
            s = S.setdefault(gk, {"q": collections.deque(), "c": collections.Counter()})
            val = value_of(doc, rule["distinct_field"]) if t == "distinct_count" else None
            if t == "distinct_count" and val is None:
                return None
            s["q"].append((ts, ev["id"], val))
            if val is not None:
                s["c"][val] += 1
            while s["q"] and s["q"][0][0] < ts - w:
                _, _, old = s["q"].popleft()
                if old is not None:
                    s["c"][old] -= 1
                    if s["c"][old] <= 0:
                        del s["c"][old]
            n = len(s["c"]) if t == "distinct_count" else len(s["q"])
            ids = [x[1] for x in list(s["q"])[-self.cap:]]
            what = f"서로 다른 {rule['distinct_field']} {n}개" if t == "distinct_count" else f"{n}건"
            return self._fire(rule, gk, group, n, ev, ids, f"{fmt_window(w)} 내 {what}", silent)

        if t == "sequence":
            fc, tc = rule["first"], rule["then"]
            s = S.get(gk)
            if s is None:
                s = S[gk] = dict(q=collections.deque(maxlen=self.cap), n=0, vals=collections.Counter(), tq=collections.deque(),
                                 last_first=None, sat_at=None, peak=0)
            is_first = check_all(fc["where"], doc, self.lists)
            is_then = check_all(tc["where"], doc, self.lists)
            need = min(l["min"] for l in rule["levels"])
            if is_first:
                self.stats[rule["id"]]["matched"] += 1
                w, dfield = fc.get("window_sec"), fc.get("distinct_field")
                val = value_of(doc, dfield) if dfield else None
                s["q"].append(ev["id"])
                s["tq"].append((ts, val))
                if val is not None:
                    s["vals"][val] += 1
                if w:
                    while s["tq"] and s["tq"][0][0] < ts - w:
                        _, old = s["tq"].popleft()
                        if old is not None:
                            s["vals"][old] -= 1
                            if s["vals"][old] <= 0:
                                del s["vals"][old]
                else:
                    s["tq"] = collections.deque(list(s["tq"])[-1:])          # 기간 무제한: 개수만 누적
                    s["n"] += 1
                measure = len(s["vals"]) if dfield else (len(s["tq"]) if w else s["n"])
                s["last_first"] = ts
                if measure >= need:
                    s["sat_at"], s["peak"] = ts, max(s["peak"], measure)
                return None
            if is_then:
                fire = None
                if s["sat_at"] is not None:
                    within, lookback = tc.get("within_sec"), tc.get("lookback_sec")
                    if lookback is None and within is not None:
                        lookback = within + (fc.get("window_sec") or 0)
                    ok_within = within is None or ts - s["last_first"] <= within
                    ok_look = lookback is None or ts - s["sat_at"] <= lookback
                    if ok_within and ok_look:
                        detail = f"조건 이벤트 {s['peak']}건 뒤 {time.strftime('%H:%M:%S', time.localtime(ts))} 후속 이벤트 " \
                                 f"(마지막 조건 이벤트 {int(ts - s['last_first'])}초 뒤)"
                        fire = self._fire(rule, gk, group, s["peak"], ev, list(s["q"]) + [ev["id"]], detail, silent)
                if rule.get("reset_on_then", True):
                    S.pop(gk, None)
                return fire
        return None

    # ------------------------------------------------------------------ 경보
    def _level(self, rule, n):
        best = None
        for l in sorted(rule["levels"], key=lambda l: l["min"]):
            if n >= l["min"]:
                best = l
        return best

    def _fire(self, rule, gk, group, n, ev, evidence, detail, silent):
        level = self._level(rule, n)
        if level is None:
            return None
        ts, doc = ev["ts"], ev["doc"]
        if rule.get("unless_rules"):
            look = rule.get("unless_lookback_sec", rule.get("window_sec", 86400))
            for other in rule["unless_rules"]:
                for f in rule.get("unless_match_fields", rule["group_by"]):
                    last = self.unless_index.get((other, f, group.get(f)))
                    if last is not None and ts - last <= look:
                        return None
        # 심각도 보정
        sev_i, notes = RANK[level["severity"]], []
        for m in (self.policy.get("global_modifiers") or []) + (rule.get("modifiers") or []):
            if check_all(m["when"], doc, self.lists):
                sev_i += m["severity_delta"]
                notes.append({"delta": m["severity_delta"], "note": m.get("note", "")})
        sev_i = max(0, min(len(SEV) - 1, sev_i))
        sev = SEV[sev_i]
        base = self.policy["severity_risk"][sev]
        per = self.policy.get("risk_per_event", 0)
        risk = min(self.policy.get("risk_max", 100), base + per * n)
        basis = {"severity": sev, "severity_base": base, "event_count": n, "per_event": per,
                 "level": level["id"], "level_min": level["min"], "modifiers": notes, "rule_version": rule.get("_version", 0)}
        for f, v in group.items():
            self.unless_index[(rule["id"], f, v)] = ts

        dk = f"{rule['id']}|{gk}"
        suppress = rule.get("suppress_sec", self.policy.get("default_suppress_sec", 3600))
        cur = self.open.get(dk)
        stats = self.stats[rule["id"]]
        if cur is not None and ts - cur["last_ts"] <= suppress:
            op = "update"
            if RANK[sev] > cur["severity_rank"] or level["min"] > cur["level_min"]:
                op = "escalate"
                stats["escalations"] += 1
                cur.update(level_id=level["id"], level_min=level["min"], title=level["title"], basis=level.get("basis", ""),
                           severity=sev, severity_rank=RANK[sev])
            cur.update(last_ts=ts, event_count=max(cur["event_count"], n), risk_score=max(cur["risk_score"], risk),
                       risk_basis=basis, detail=detail, sample=cur["sample"] or ev.get("sample", False),
                       evidence=(cur["evidence"] + [e for e in evidence if e not in cur["evidence"]])[-self.cap:])
            return None if silent else {"op": op, "alert": cur}
        self._seq += 1
        alert = {"id": None, "seq": self._seq, "rule_id": rule["id"], "rule_name": rule["name"],
                 "rule_version": rule.get("_version", 0), "level_id": level["id"], "level_min": level["min"],
                 "title": level["title"], "basis": level.get("basis", ""), "severity": sev, "severity_rank": RANK[sev],
                 "risk_score": risk, "risk_basis": basis, "group_key": gk, "group": group, "dedup_key": dk,
                 "first_ts": ts, "last_ts": ts, "event_count": n, "evidence": list(evidence)[-self.cap:],
                 "detail": detail, "status": "open", "incident_key": {f: value_of(doc, f) for f in rule.get("incident_key", rule["group_by"])},
                 "tags": rule.get("tags", []), "sample": bool(ev.get("sample")), "trigger_received_at": ev.get("received_at")}
        self.open[dk] = alert
        stats["alerts"] += 1
        return None if silent else {"op": "new", "alert": alert}

    # ------------------------------------------------------------------ 재시작 · 시뮬레이션
    def warmup(self, events, open_alerts):
        """재시작 시 최근 이벤트로 창 상태를 복원(경보는 만들지 않음)하고, 열린 경보를 이어받는다."""
        for ev in events:
            self.process(ev, silent=True)
        self.open = {}
        for a in open_alerts:
            self.open[a["dedup_key"]] = a
            for f, v in a["group"].items():
                key = (a["rule_id"], f, v)
                self.unless_index[key] = max(self.unless_index.get(key, 0), a["last_ts"])

    def max_window(self):
        w = [r.get("window_sec") or 0 for r in self.rules]
        w += [(r.get("first") or {}).get("window_sec") or 0 for r in self.rules]
        w += [(r.get("then") or {}).get("within_sec") or 0 for r in self.rules]
        w += [r.get("unless_lookback_sec") or 0 for r in self.rules]
        return max(w + [3600])


def simulate(rules, policy, lists_cfg, events):
    """저장 없이 규칙을 이벤트에 돌려 최종 경보 목록을 돌려준다(규칙 변경 전 검증용)."""
    eng = Engine(rules, policy, lists_cfg)
    for ev in sorted(events, key=lambda e: (e["ts"], e["id"])):
        eng.process(ev)
    return list(eng.open.values()), dict(eng.stats)


def compare(before, after):
    """두 시뮬레이션 결과 비교: (규칙, 그룹) 기준 추가·삭제·단계 변경."""
    key = lambda a: (a["rule_id"], a["group_key"])
    b = {key(a): a for a in before}
    a_ = {key(a): a for a in after}
    added = [a_[k] for k in a_.keys() - b.keys()]
    removed = [b[k] for k in b.keys() - a_.keys()]
    changed = [{"rule_id": k[0], "group_key": k[1], "before": b[k]["level_id"] + "/" + b[k]["severity"],
                "after": a_[k]["level_id"] + "/" + a_[k]["severity"]}
               for k in a_.keys() & b.keys() if (b[k]["level_id"], b[k]["severity"]) != (a_[k]["level_id"], a_[k]["severity"])]
    slim = lambda xs: sorted([{"rule_id": x["rule_id"], "group_key": x["group_key"], "level_id": x["level_id"], "severity": x["severity"]}
                              for x in xs], key=lambda x: (x["rule_id"], x["group_key"]))
    return {"added": slim(added), "removed": slim(removed), "changed": sorted(changed, key=lambda x: (x["rule_id"], x["group_key"])),
            "before_total": len(before), "after_total": len(after)}
