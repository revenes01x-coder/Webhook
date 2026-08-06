import os
from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"ไม่พบ Environment Variable '{name}' — กรุณาตั้งค่าใน .env ก่อนรันระบบ"
        )
    return value


# ---- JWT ----
SECRET_KEY = _require("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))

# ---- Refresh Token (httpOnly cookie) ----
# Opaque token (ไม่ใช่ JWT) เก็บแค่ hash ลง DB — ดู refresh_token_utils.py
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
# Cookie ต้อง Secure=True เมื่อรันจริงผ่าน https:// เท่านั้น (ไม่งั้น browser จะไม่ยอมตั้ง cookie ให้)
# ตอน dev บน http://localhost ตั้งใน .env เป็น COOKIE_SECURE=false ได้
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "true").lower() == "true"

# ---- Database ----
DATABASE_URL = _require("DATABASE_URL")

# ---- Email (Gmail SMTP) ----
# ใช้บัญชี Gmail ส่วนตัวส่งแทน ไม่ต้องมีโดเมนของตัวเอง ส่งหาผู้รับคนไหนก็ได้
# วิธีได้ SMTP_APP_PASSWORD: เปิด 2-Step Verification ที่บัญชี Google ก่อน
# แล้วไปที่ https://myaccount.google.com/apppasswords สร้างรหัสผ่านแอป 16 หลัก
SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = _require("SMTP_USER")  # อีเมล gmail ที่จะใช้ส่ง เช่น yourname@gmail.com
SMTP_APP_PASSWORD = _require("SMTP_APP_PASSWORD")

# Gmail จะบังคับให้ From ตรงกับบัญชีที่ authenticate เสมอ จึงตั้งชื่อแสดงผลได้ แต่อีเมลต้องเป็น SMTP_USER
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "SmartLPR")

# ---- OTP ----
OTP_LENGTH = 6
OTP_EXPIRE_MINUTES = 3
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = OTP_EXPIRE_MINUTES * 60
OTP_RESEND_LIMIT_PER_HOUR = 3

# ---- Password Reset (forgot password) ----
PASSWORD_RESET_TOKEN_EXPIRE_MINUTES = 10

# ---- Cleanup job: ลบ OTP record เก่าทิ้ง (used/expired ไปนานแล้ว ไม่มีประโยชน์เก็บต่อ) ----
OTP_RETENTION_DAYS = 7

# ---- Cleanup job: ลบ user ที่สมัครแล้วไม่ยืนยัน OTP เกินเวลาที่กำหนด (hard delete) ----
UNVERIFIED_USER_EXPIRE_HOURS = 24

# ---- PDPA: ลบข้อมูลป้ายทะเบียน (WebhookEvent + รูปภาพ) ที่เก่าเกินกำหนดออกจากระบบ ----
PLATE_DATA_RETENTION_DAYS = 30


PLATE_DETECTION_REPO_PATH = os.getenv("PLATE_DETECTION_REPO_PATH")
PLATE_OCR_MODEL_PATH = os.getenv("PLATE_OCR_MODEL_PATH")
PLATE_OCR_CHAR_FILE = os.getenv("PLATE_OCR_CHAR_FILE")
PLATE_YOLO_MODEL_PATH = os.getenv("PLATE_YOLO_MODEL_PATH")

CAR_DETECTOR_MODEL_PATH = os.getenv("CAR_DETECTOR_MODEL_PATH", "yolo11n.pt")

CAR_COLOR_MODEL_PATH = os.getenv("CAR_COLOR_MODEL_PATH")
CAR_COLOR_CLASSNAMES_PATH = os.getenv("CAR_COLOR_CLASSNAMES_PATH")

CAPTURES_SAVE_DIR = os.getenv("CAPTURES_SAVE_DIR", "captures")

CAPTURE_EVENT_WEBHOOK_URL = os.getenv("CAPTURE_EVENT_WEBHOOK_URL", "http://localhost:8000/capture-event")