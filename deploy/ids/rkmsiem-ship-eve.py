#!/usr/bin/env python3
"""Suricata eve.json → RKMSIEM 전송기 (IDS 서버에서 실행, 표준 라이브러리만 사용).

- eve.json 을 따라 읽으며(tail) alert·anomaly 만 골라 NDJSON 묶음으로 POST /api/ingest/suricata-eve
- 보낸 위치(inode·offset)를 저장 → 재시작·로그 회전 뒤에도 이어서, 실패하면 위치를 올리지 않고 재시도(중복은 SIEM 이 제거)
- 설정: /etc/rkmsiem-ship.env (RKMSIEM_URL, RKMSIEM_INGEST_KEY, EVE_PATH, EVENT_TYPES, START_AT=end|start)
- https + 자체 서명 인증서: RKMSIEM_TLS_FINGERPRINT=<SHA-256> 이면 인증서 지문이 같을 때만 보냄 (가로채기 방지)
"""
import hashlib
import hmac
import http.client
import json
import os
import signal
import ssl
import sys
import time
import urllib.parse

URL = os.environ.get("RKMSIEM_URL", "http://10.0.0.53:8088").rstrip("/") + "/api/ingest/" + os.environ.get("RKMSIEM_SOURCE", "suricata-eve")
KEY = "".join(os.environ.get("RKMSIEM_INGEST_KEY", "").split()).split(",")[0]    # 줄바꿈·공백이 섞여도 안전하게
FP = os.environ.get("RKMSIEM_TLS_FINGERPRINT", "").replace(":", "").strip().lower()     # SIEM 인증서 SHA-256 지문
EVE = os.environ.get("EVE_PATH", "/var/log/suricata/eve.json")
TYPES = {t.strip() for t in os.environ.get("EVENT_TYPES", "alert,anomaly").split(",") if t.strip()}
STATE = os.environ.get("STATE_FILE", "/var/lib/rkmsiem-ship/state.json")
BATCH = int(os.environ.get("BATCH", "200"))
MAX_BYTES = 1_500_000                                   # SIEM 의 요청 크기 상한(2MB)보다 작게
running = True


def log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def load_state():
    try:
        with open(STATE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(st):
    tmp = STATE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f)
    os.replace(tmp, STATE)


class TLSMismatch(OSError):
    pass


def send(body):
    """(상태 코드, 응답 앞부분). https 면 지문(FP) 또는 시스템 CA 로 인증서 확인."""
    u = urllib.parse.urlsplit(URL)
    if u.scheme == "https":
        ctx = ssl.create_default_context()
        if FP:                                           # 자체 서명: CA 대신 지문으로 확인
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=15, context=ctx)
        conn.connect()
        if FP and not hmac.compare_digest(hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(), FP):
            conn.close()
            raise TLSMismatch("SIEM 인증서 지문이 다릅니다")
    else:
        conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=15)
    try:
        conn.request("POST", u.path + (f"?{u.query}" if u.query else ""), body=body,
                     headers={"Content-Type": "application/x-ndjson", "X-API-Key": KEY, "User-Agent": "rkmsiem-ship-eve/2"})
        r = conn.getresponse()
        return r.status, r.read(300).decode("utf-8", "replace").strip()
    finally:
        conn.close()


def post(lines):
    """True=전달됨, False=나중에 다시. 키 오류는 오래 기다림."""
    try:
        code, detail = send(("\n".join(lines) + "\n").encode())
    except TLSMismatch:
        log("✘ SIEM 인증서 지문이 설정(RKMSIEM_TLS_FINGERPRINT)과 다릅니다 — 가로채기 또는 인증서 교체. SIEM 에서 지문을 다시 확인하세요")
        time.sleep(60)
        return False
    except (OSError, http.client.HTTPException) as e:
        log(f"! SIEM 연결 실패 ({e}) — 잠시 뒤 재시도")
        return False
    if code in (200, 202):
        return True
    if code == 401:
        log("✘ 수집 키 거부(401) — /etc/rkmsiem-ship.env 의 RKMSIEM_INGEST_KEY 를 SIEM 의 RKMSIEM_INGEST_KEYS 와 맞추세요")
        time.sleep(60)
    elif code == 404:
        log("✘ SIEM 에 suricata-eve 소스가 없음(404) — SIEM 을 최신으로 업데이트하세요")
        time.sleep(60)
    elif code in (301, 302, 307, 308):
        log(f"✘ SIEM 이 주소를 옮겼습니다({code}) — https 로 바뀌었다면 install-ship.sh --siem https://<SIEM>:8443 --fingerprint <지문> 으로 다시 설치")
        time.sleep(60)
    else:
        log(f"! SIEM 응답 {code} {detail} — 잠시 뒤 재시도")
    return False


def main():
    global running
    signal.signal(signal.SIGTERM, lambda *a: globals().update(running=False))
    if not KEY:
        log("✘ RKMSIEM_INGEST_KEY 가 없습니다 (/etc/rkmsiem-ship.env)")
        return 2
    if not all(33 <= ord(ch) < 127 for ch in KEY):
        log("✘ 수집 키에 쓸 수 없는 문자(한글 등)가 있습니다 — /etc/rkmsiem-ship.env 를 SIEM 의 값으로 다시 맞추세요")
        return 2
    os.makedirs(os.path.dirname(STATE), exist_ok=True)
    st, f, inode, backoff, sent = load_state(), None, None, 1, 0
    log(f"시작: {EVE} → {URL} (종류 {','.join(sorted(TYPES))})")
    while running:
        try:
            s = os.stat(EVE)
        except FileNotFoundError:
            time.sleep(2)
            continue
        if f is None or s.st_ino != inode:                         # 처음 열기 또는 로그 회전
            if f:
                f.close()
            f, inode = open(EVE, "rb"), s.st_ino
            if st.get("inode") == inode and st.get("offset", 0) <= s.st_size:
                f.seek(st["offset"])
            elif st.get("inode") is None and os.environ.get("START_AT", "end") == "end":
                f.seek(0, os.SEEK_END)                             # 첫 실행은 지금부터 (지난 기록 폭주 방지)
            st = {"inode": inode, "offset": f.tell()}
            save_state(st)
            log(f"파일 열기 inode={inode} offset={st['offset']}")
        elif s.st_size < st["offset"]:                             # 같은 파일이 잘림(truncate)
            f.seek(0)
            st["offset"] = 0
        batch, size, pos = [], 0, f.tell()
        while len(batch) < BATCH and size < MAX_BYTES:
            line = f.readline()
            if not line or not line.endswith(b"\n"):                # 아직 다 안 쓴 줄은 다음에
                f.seek(pos)
                break
            pos = f.tell()
            try:
                if json.loads(line).get("event_type") in TYPES:
                    text = line.decode("utf-8", "replace").strip()
                    batch.append(text)
                    size += len(text) + 1
            except ValueError:
                continue
        end = pos
        if batch:
            if post(batch):
                st["offset"], backoff = end, 1
                save_state(st)
                sent += len(batch)
                if sent % 1000 < len(batch):
                    log(f"누적 전송 {sent}건")
            else:
                f.seek(st["offset"])                               # 위치를 올리지 않고 다시
                time.sleep(backoff)
                backoff = min(60, backoff * 2)
                continue
        elif end != st["offset"]:
            st["offset"] = end                                     # 고른 종류가 없던 구간도 지나감
            save_state(st)
        if not batch:
            time.sleep(1)
    if f:
        f.close()
    log("종료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
