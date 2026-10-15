"""⚠ 예제(가상) 데이터 생성기 — 탐지 기준 검증용 samples/auth.log 를 만든다. 운영 데이터가 아님.

시나리오마다 고정 IP를 쓰고, 기대 결과를 EXPECTED 에 적어 둔다.
test_detector.py 가 이 기대 결과로 탐지 엔진을 검증한다.
나머지(정상 사용자, 1회성 스캐너, 봇넷)는 고정 시드의 무작위 배경 트래픽이다.
"""
import random
from datetime import datetime, timedelta

START = datetime(2026, 10, 12, 0, 0, 0)
SPRAY = ["admin", "root", "test", "guest", "oracle", "postgres", "ubuntu", "user", "ftp", "mysql", "support", "pi"]

# IP: (기대 위험도 또는 None, 반드시 걸려야 하는 규칙, 걸리면 안 되는 규칙)
EXPECTED = {
    # 고속 무차별 대입
    "203.0.113.50":   ("critical", {"BRUTEFORCE_HIGH"}, set()),
    "185.220.101.33": ("critical", {"BRUTEFORCE_HIGH"}, set()),
    # 15분 창 횟수 경계값: 4회(통과) / 5회(잠금 기준) / 9회 / 10회(심각)
    "203.0.113.4":    (None, set(), set()),
    "203.0.113.5":    ("high", {"BRUTEFORCE"}, {"BRUTEFORCE_HIGH"}),
    "203.0.113.9":    ("high", {"BRUTEFORCE"}, {"BRUTEFORCE_HIGH"}),
    "203.0.113.10":   ("critical", {"BRUTEFORCE_HIGH"}, {"BRUTEFORCE"}),
    # 4회 + 16분 뒤 4회: 15분 창에 5회가 안 모이고 누적 8회 → 탐지 안 됨
    "203.0.113.20":   (None, set(), set()),
    # 침해: 18회 실패 직후 성공 (잠금 미동작)
    "103.75.190.8":   ("critical", {"COMPROMISE", "NO_LOCKOUT", "BRUTEFORCE_HIGH"}, set()),
    # 침해: 5회 실패 → 20분 기다렸다 성공 (잠금은 동작, 그러나 비밀번호 탈취 의심)
    "198.51.100.77":  ("critical", {"COMPROMISE", "BRUTEFORCE"}, {"NO_LOCKOUT"}),
    # 계정 대입: 12개 계정 × 2회
    "198.51.100.94":  ("high", {"SPRAY"}, {"BRUTEFORCE", "COMPROMISE"}),
    # 계정 대입 경계: 4개 계정 → 탐지 안 됨
    "198.51.100.40":  (None, set(), set()),
    # 계정 대입 중 한 계정 로그인 성공
    "91.240.118.172": ("critical", {"SPRAY", "COMPROMISE"}, set()),
    # 저속 공격: 1시간 간격 14회
    "77.83.36.91":    ("medium", {"SLOW"}, {"BRUTEFORCE"}),
    "141.98.11.62":   ("medium", {"SLOW"}, {"BRUTEFORCE"}),
    # 저속 경계: 하루 9회 → 탐지 안 됨
    "198.51.100.9":   (None, set(), set()),
    # 잠금 회피: 16분마다 4회씩 → 15분 창은 늘 4회지만 누적이 많음
    "45.155.205.17":  ("medium", {"SLOW"}, {"BRUTEFORCE"}),
    # 내부망: 5회 오타 후 20분 뒤 성공 → 한 단계 낮춰 높음
    "10.0.0.12":      ("high", {"COMPROMISE", "BRUTEFORCE"}, {"NO_LOCKOUT"}),
    # 내부망: 4회 오타 후 성공 → 정상
    "10.0.0.15":      (None, set(), set()),
    # 내부망: 6회 실패 직후 성공 → 서버 잠금 설정 누락
    "192.168.1.45":   ("high", {"COMPROMISE", "NO_LOCKOUT"}, set()),
}
EXPECTED_BOTNET_USER = "admin"


def build_events(seed=42):
    rnd = random.Random(seed)
    ev = []
    add = lambda t, st, u, ip: ev.append((t, st, u, ip))
    at = lambda h, m=0, s=0: START + timedelta(hours=h, minutes=m, seconds=s)
    rt = lambda h0=0, h1=24: START + timedelta(seconds=rnd.randint(h0 * 3600, h1 * 3600 - 1))

    def burst(ip, user, n, t, gap=(1, 3)):
        for _ in range(n):
            add(t, "FAIL", user, ip)
            t += timedelta(seconds=rnd.randint(*gap))
        return t

    # ---- 시나리오 ----
    burst("203.0.113.50", "admin", 40, at(2, 5))
    burst("185.220.101.33", "root", 65, at(3, 10))
    burst("203.0.113.4", "test", 4, at(9, 0), (10, 30))
    burst("203.0.113.5", "dev", 5, at(9, 30), (10, 30))
    burst("203.0.113.9", "ops", 9, at(10, 0), (10, 30))
    burst("203.0.113.10", "ops", 10, at(10, 40), (10, 30))
    burst("203.0.113.20", "deploy", 4, at(11, 0), (5, 10))
    burst("203.0.113.20", "deploy", 4, at(11, 17), (5, 10))

    t = burst("103.75.190.8", "backup", 18, at(1, 12), (2, 5))
    add(t, "SUCCESS", "backup", "103.75.190.8")

    t = burst("198.51.100.77", "oracle", 5, at(5, 0), (5, 15))
    add(t + timedelta(minutes=20), "SUCCESS", "oracle", "198.51.100.77")

    t = at(4, 0)
    for u in SPRAY * 2:
        add(t, "FAIL", u, "198.51.100.94")
        t += timedelta(seconds=rnd.randint(2, 6))
    t = at(6, 0)
    for u in SPRAY[:4]:
        add(t, "FAIL", u, "198.51.100.40")
        t += timedelta(seconds=rnd.randint(5, 20))
    t = at(13, 0)
    for u in SPRAY[:8]:
        add(t, "FAIL", u, "91.240.118.172")
        t += timedelta(seconds=rnd.randint(2, 6))
    add(t, "SUCCESS", "support", "91.240.118.172")

    for i in range(14):
        add(at(i + 6, rnd.randint(0, 50)), "FAIL", "admin", "77.83.36.91")
    for i in range(12):
        add(at(i * 2, rnd.randint(0, 50)), "FAIL", "root", "141.98.11.62")
    for i in range(9):
        add(at(i * 2 + 1, rnd.randint(0, 50)), "FAIL", "admin", "198.51.100.9")
    t = at(19, 0)
    for _ in range(11):
        burst("45.155.205.17", "admin", 4, t, (5, 10))
        t += timedelta(minutes=16)

    t = burst("10.0.0.12", "kim", 5, at(9, 2), (5, 15))
    add(t + timedelta(minutes=20), "SUCCESS", "kim", "10.0.0.12")
    t = burst("10.0.0.15", "lee", 4, at(9, 5), (5, 15))
    add(t + timedelta(seconds=10), "SUCCESS", "lee", "10.0.0.15")
    t = burst("192.168.1.45", "jang", 6, at(14, 0), (3, 8))
    add(t + timedelta(seconds=30), "SUCCESS", "jang", "192.168.1.45")

    # ---- 배경 트래픽 ----
    used = set(EXPECTED)

    def rand_ip(internal=False):
        while True:
            if internal:
                ip = rnd.choice([f"10.{rnd.randint(1, 3)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}",
                                 f"192.168.{rnd.randint(2, 10)}.{rnd.randint(1, 254)}"])
            else:
                first = rnd.choice([5, 23, 31, 37, 46, 58, 62, 78, 89, 94, 112, 118, 121, 139, 147, 176, 183, 194, 212, 222])
                ip = f"{first}.{rnd.randint(0, 255)}.{rnd.randint(0, 255)}.{rnd.randint(1, 254)}"
            if ip not in used:
                used.add(ip)
                return ip

    # 정상 사용자: 세션마다 오타 최대 1회
    named = {"hong": "10.0.0.7", "park": "10.0.0.21", "choi": "10.0.0.33", "jung": "10.0.1.4",
             "kang": "10.0.1.8", "yoon": "192.168.1.20", "lim": "192.168.1.77"}
    for u, ip in named.items():
        used.add(ip)
        for _ in range(rnd.randint(4, 9)):
            t = rt(8, 19)
            if rnd.random() < 0.3:
                add(t, "FAIL", u, ip)
                t += timedelta(seconds=rnd.randint(3, 15))
            add(t, "SUCCESS", u, ip)
    for i in range(150):
        ip = rand_ip(internal=rnd.random() < 0.7)
        u = f"emp{i:03d}"
        for _ in range(rnd.randint(1, 4)):
            t = rt(7, 21)
            if rnd.random() < 0.2:
                add(t, "FAIL", u, ip)
                t += timedelta(seconds=rnd.randint(3, 15))
            add(t, "SUCCESS", u, ip)

    # 1회성 스캐너
    for _ in range(700):
        add(rt(), "FAIL", rnd.choice(SPRAY), rand_ip())

    # 분산 공격(봇넷): 250개 IP가 10분 남짓 안에 admin 을 1~2회씩
    t = at(16, 0)
    for _ in range(250):
        ip = rand_ip()
        for _ in range(rnd.choice([1, 1, 2])):
            add(t, "FAIL", "admin", ip)
            t += timedelta(seconds=rnd.randint(0, 2))

    ev.sort()
    return ev


def write(path="auth.log", seed=42):
    ev = build_events(seed)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for t, st, u, ip in ev:
            f.write(f"{t:%Y-%m-%d %H:%M:%S} {st} user={u} ip={ip}\n")
    return len(ev), len({e[3] for e in ev})


if __name__ == "__main__":
    import os
    lines, ips = write(os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples", "auth.log"))
    print(f"auth.log 생성 완료 — {lines}줄, 고유 IP {ips}개")
