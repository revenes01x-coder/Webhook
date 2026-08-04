"""
services/token_utils.py

รวม logic การ "สุ่ม + hash" ของ secret ทุกชนิดในระบบไว้ที่เดียว
(เดิมกระจายอยู่ 3 ไฟล์: otp_utils.py, api_key_utils.py, refresh_token_utils.py
 ซึ่งทุกไฟล์ใช้ pattern เดียวกันหมด: HMAC-SHA256 keyed ด้วย SECRET_KEY, deterministic
 hash เพื่อให้ query DB ตรงๆ ได้โดยไม่ต้อง loop เทียบทีละแถว)

หลักการที่ยึดทุกตัวในไฟล์นี้:
- ห้ามเก็บ plaintext ของ secret ใดๆ ลง DB เด็ดขาด เก็บแค่ hash
- สุ่มด้วย `secrets` (CSPRNG) เท่านั้น ห้ามใช้ `random`
- hash แบบ HMAC-SHA256 keyed ด้วย SECRET_KEY (ไม่ใช่ bcrypt) เพราะต้อง query แบบ
  deterministic ตรงๆ ผ่าน WHERE hash = ... ได้เลย ต่างจากรหัสผ่านที่ verify ทีละ user
  เท่านั้น (ดู smartlpr/security.py: verify_password ใช้ bcrypt ตามปกติ ไม่เกี่ยวกับไฟล์นี้)
"""
import hmac
import hashlib
import secrets

from smartlpr.config import SECRET_KEY, OTP_LENGTH

# ---------------------------------------------------------------------------
# Shared primitive — ทุกตัวด้านล่างเรียกผ่านฟังก์ชันนี้ทั้งหมด
# ---------------------------------------------------------------------------


def _hmac_hash(value: str) -> str:
    """HMAC-SHA256 keyed ด้วย SECRET_KEY กลาง ใช้ร่วมกันทุก secret type ในไฟล์นี้"""
    return hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# OTP (6 หลัก, อายุสั้น, ต้องเดายากในเชิง attempt-limit เพราะ entropy ต่ำ
# ดู smartlpr/config.py: OTP_MAX_ATTEMPTS / OTP_EXPIRE_MINUTES)
# ---------------------------------------------------------------------------


def generate_otp() -> str:
    """สุ่มเลข OTP แบบ cryptographically secure ความยาวตาม config (ปกติ 6 หลัก)"""
    upper_bound = 10 ** OTP_LENGTH
    number = secrets.randbelow(upper_bound)
    return str(number).zfill(OTP_LENGTH)


def hash_otp(otp: str) -> str:
    return _hmac_hash(otp)


def verify_otp(otp: str, otp_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), otp_hash)


# ---------------------------------------------------------------------------
# API Key (ระบบอัตโนมัติของ user ใช้แทน JWT ตอนยิงเข้ามาเอง เช่น POST /my/cameras)
# เดาไม่ได้ในทางปฏิบัติ (128-bit+ entropy) จึงไม่ต้อง attempt-limit เหมือน OTP
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "sk_live_"


def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)


def hash_api_key(api_key: str) -> str:
    return _hmac_hash(api_key)


# ---------------------------------------------------------------------------
# Refresh Token (opaque, httpOnly cookie, ไม่ใช่ JWT — ดู smartlpr/security.py
# สำหรับ access token ที่เป็น JWT ปกติ ซึ่งไม่ต้อง hash เพราะ verify ด้วย signature เอง)
# ---------------------------------------------------------------------------

REFRESH_TOKEN_BYTES = 48


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    return _hmac_hash(token)