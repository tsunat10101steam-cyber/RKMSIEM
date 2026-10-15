"""2단계 인증: TOTP (RFC 6238 — Google Authenticator · Microsoft Authenticator 등 OTP 앱과 호환). 표준 라이브러리만."""
import base64
import hashlib
import hmac
import os
import struct
import time
from urllib.parse import quote

STEP, DIGITS = 30, 6


def new_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _key(secret):
    s = secret.strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


def code_at(secret, step):
    h = hmac.new(_key(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    return str((struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % 10 ** DIGITS).zfill(DIGITS)


def verify(secret, code, last_step=None, now=None, window=1):
    """맞으면 사용한 시간 칸(step) 번호, 아니면 None. 앞뒤 30초 시계 오차 허용, 이미 쓴 칸(재사용)은 거부."""
    code = (code or "").strip().replace(" ", "")
    if not (code.isdigit() and len(code) == DIGITS):
        return None
    cur = int((now if now is not None else time.time()) // STEP)
    for step in range(cur - window, cur + window + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def uri(secret, account, issuer="RKMSIEM"):
    return f"otpauth://totp/{quote(issuer)}:{quote(account)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
