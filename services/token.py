import hmac
import hashlib
import secrets
from smartlpr.config import SECRET_KEY, OTP_LENGTH

def _hmac_hash(value: str) -> str:
    """HMAC-SHA256 keyed ด้วย SECRET_KEY กลาง ใช้ร่วมกันทุก secret type ในไฟล์นี้"""
    return hmac.new(SECRET_KEY.encode(), value.encode(), hashlib.sha256).hexdigest()

def generate_otp() -> str:
    """สุ่มเลข OTP แบบ cryptographically secure ความยาวตาม config (ปกติ 6 หลัก)"""
    upper_bound = 10 ** OTP_LENGTH
    number = secrets.randbelow(upper_bound)
    return str(number).zfill(OTP_LENGTH)

def hash_otp(otp: str) -> str:
    return _hmac_hash(otp)

def verify_otp(otp: str, otp_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), otp_hash)

API_KEY_PREFIX = "sk_live_"

def generate_api_key() -> str:
    return API_KEY_PREFIX + secrets.token_urlsafe(32)

def hash_api_key(api_key: str) -> str:
    return _hmac_hash(api_key)

REFRESH_TOKEN_BYTES = 48

def generate_refresh_token() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)

def hash_refresh_token(token: str) -> str:
    return _hmac_hash(token)