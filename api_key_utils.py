import hmac
import hashlib
import secrets
from config import SECRET_KEY

API_KEY_PREFIX = "sk_live_"


def generate_api_key() -> str:
    """สุ่ม API key แบบ cryptographically secure ยาวพอที่จะไม่ต้อง rate-limit การเดา
    (ต่างจาก OTP 6 หลักที่ entropy ต่ำ ต้องมี attempt limit — API key นี้เดาไม่ได้ในทางปฏิบัติ)"""
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    """Hash แบบเดียวกับ OTP (HMAC-SHA256 keyed ด้วย SECRET_KEY) — deterministic โดยตั้งใจ
    เพื่อให้ query DB ด้วย hash ตรงๆ ได้เลย (WHERE api_key_hash = hash_api_key(key_ที่ส่งมา))
    ไม่ต้อง loop เทียบทีละ user เหมือน bcrypt ที่ salt สุ่มทุกครั้ง"""
    return hmac.new(SECRET_KEY.encode(), api_key.encode(), hashlib.sha256).hexdigest()