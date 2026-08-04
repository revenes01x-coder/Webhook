import hmac
import hashlib
import secrets
from smartlpr.config import SECRET_KEY

REFRESH_TOKEN_BYTES = 48


def generate_refresh_token() -> str:
    """สุ่ม refresh token แบบ opaque (ไม่ใช่ JWT) ยาว 48 bytes ก่อน encode
    เดาไม่ได้ในทางปฏิบัติ (คล้าย API key มากกว่า OTP) — ไม่มี claim ใดๆ ในตัวเอง
    การเทียบสิทธิ์ทำผ่านการ query hash ใน DB ล้วนๆ ทำให้ revoke ได้ทันที (ต่างจาก JWT
    ที่ revoke ก่อนหมดอายุยากกว่า ต้องพึ่ง blacklist เพิ่ม)"""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """ไม่เก็บ plaintext ลง DB เด็ดขาด เก็บแค่ HMAC-SHA256 keyed ด้วย SECRET_KEY
    (เหมือน otp_utils.py / api_key_utils.py) — deterministic โดยตั้งใจ เพื่อ query DB
    ด้วย hash ตรงๆ ได้เลย ไม่ต้อง loop เทียบทีละ record"""
    return hmac.new(SECRET_KEY.encode(), token.encode(), hashlib.sha256).hexdigest()