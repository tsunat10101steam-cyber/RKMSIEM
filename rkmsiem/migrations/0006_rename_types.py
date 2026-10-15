"""이미 저장된 경보·사건의 유형 이름을 새 이름으로 (기준 출처·제품명 제거).

경보 제목·단계 id·규칙 id·근거 문구, 사건 제목, 사건 타임라인의 제목을 바꾼다. 감사 로그(해시 체인)는 손대지 않는다.
"""
import json
import re

TITLES = {
    "계정 잠금 기준 도달 (15분 내 5회 이상)": "무차별 대입",
    "KISA 임계값 초과 (15분 내 10회 이상)": "무차별 대입 (심각)",
    "계정 대입 (15분 내 여러 계정 시도)": "패스워드 스프레이",
    "분산 공격 (10분 내 30개 이상 IP가 같은 계정 공격)": "분산 대입",
    "저속 공격 (잠금 기준 회피, 하루 누적)": "저속 대입",
    "침해 의심 (반복 실패 후 로그인 성공)": "대입 후 로그인 성공",
    "침해 의심 (계정 대입 중 로그인 성공)": "스프레이 후 로그인 성공",
    "잠금 미적용 의심 (잠금 시간 안에 로그인 성공)": "잠금 미적용",
    "승인되지 않은 계정의 권한 상승": "권한 상승",
    "반복 연결 시도 (1분 내 20회 이상)": "반복 연결",
    "대량 연결 시도 (1분 내 100회 이상)": "대량 연결",
    "IDS 탐지 (Suricata 시그니처)": "IDS 탐지",
    "IDS 탐지 반복 (10분 내 20회 이상)": "IDS 탐지 (반복)",
    "IDS 경보 뒤 같은 IP 로그인 성공 (침해 의심)": "IDS 탐지 후 로그인 성공",
}
RULE_NAMES = {
    "계정 대입(무차별) — 같은 IP가 같은 계정에 짧은 시간 반복 실패": "무차별 대입",
    "계정 대입(스프레이) — 한 IP가 여러 계정을 돌려 가며 시도": "패스워드 스프레이",
    "분산 공격 — 여러 IP가 짧은 시간에 같은 계정을 공격 (봇넷)": "분산 대입",
    "저속 공격 — 15분 기준은 피했지만 하루 누적 실패가 많음": "저속 대입",
    "침해 의심 — 반복 실패 뒤 같은 계정 로그인 성공": "대입 후 로그인 성공",
    "침해 의심 — 계정 대입 도중 한 계정 로그인 성공": "스프레이 후 로그인 성공",
    "잠금 미적용 의심 — 잠금 기준 도달 후 잠금 시간 안에 로그인 성공": "잠금 미적용",
    "비정상 권한 상승 — 승인 목록에 없는 계정의 관리자 권한 사용": "권한 상승",
    "반복 연결 시도 — 같은 출발지가 짧은 시간에 같은 포트로 반복 접속": "반복 연결",
    "IDS 탐지 — Suricata 시그니처 일치 (출발 IP · 시그니처별)": "IDS 탐지",
    "침해 의심 — IDS 가 잡은 IP 가 1시간 안에 로그인 성공": "IDS 탐지 후 로그인 성공",
}
LEVELS = {"KISA_OVER": "BRUTEFORCE_HIGH", "LOCKOUT": "BRUTEFORCE"}
RULES = {"ids_suricata_alert": "ids_alert"}
NOTES = {"Suricata 심각도 1(높음)": "IDS 심각도 높음", "Suricata 심각도 3(낮음)": "IDS 심각도 낮음"}


def _swap(text):
    for old, new in TITLES.items():
        text = text.replace(old, new)
    for old, new in LEVELS.items():
        text = re.sub(rf"(?<![A-Z_]){old}(?![A-Z_])", new, text)
    for old, new in RULES.items():
        text = text.replace(old, new)
    return text


def migrate(c):
    c.execute("BEGIN IMMEDIATE")
    try:
        for aid, title, lvl, rid, rb in c.execute("SELECT id, title, level_id, rule_id, risk_basis FROM alerts").fetchall():
            try:
                basis = json.loads(rb or "{}")
            except ValueError:
                basis = {}
            extra = basis.get("_extra") or {}
            extra.pop("basis", None)                                   # 기준 출처 문구는 더 이상 보여 주지 않음
            if extra.get("rule_name") in RULE_NAMES:
                extra["rule_name"] = RULE_NAMES[extra["rule_name"]]
            for m in basis.get("modifiers") or []:
                m["note"] = NOTES.get(m.get("note"), m.get("note"))
            rb_new = json.dumps(basis, ensure_ascii=False)
            for old, new in LEVELS.items():                            # 근거 안의 단계 id 도 (NO_LOCKOUT 은 그대로)
                rb_new = re.sub(rf"(?<![A-Z_]){old}(?![A-Z_])", new, rb_new)
            c.execute("UPDATE alerts SET title=?, level_id=?, rule_id=?, risk_basis=? WHERE id=?",
                      (TITLES.get(title, title), LEVELS.get(lvl, lvl), RULES.get(rid, rid), rb_new, aid))
        for iid, title in c.execute("SELECT id, title FROM incidents").fetchall():
            c.execute("UPDATE incidents SET title=? WHERE id=?", (_swap(title), iid))
        for tid, detail in c.execute("SELECT id, detail FROM incident_timeline WHERE detail IS NOT NULL").fetchall():
            new = _swap(detail)
            if new != detail:
                c.execute("UPDATE incident_timeline SET detail=? WHERE id=?", (new, tid))
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise
