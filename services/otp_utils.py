import hmac
import hashlib
import secrets
from smartlpr.config import SECRET_KEY, OTP_LENGTH


def generate_otp() -> str:
    """สุ่มเลข OTP แบบ cryptographically secure ความยาวตาม config"""
    upper_bound = 10 ** OTP_LENGTH
    number = secrets.randbelow(upper_bound)
    return str(number).zfill(OTP_LENGTH)


def hash_otp(otp: str) -> str:
    """ไม่เก็บ OTP แบบ plaintext ลง DB เด็ดขาด เก็บแค่ HMAC-SHA256"""
    return hmac.new(SECRET_KEY.encode(), otp.encode(), hashlib.sha256).hexdigest()


def verify_otp(otp: str, otp_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), otp_hash)