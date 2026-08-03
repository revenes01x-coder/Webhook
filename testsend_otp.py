"""
สคริปต์ทดสอบส่ง OTP แบบเดี่ยวๆ ไม่ต้องรัน FastAPI ทั้งระบบ
ใช้เช็คว่า SMTP_USER / SMTP_APP_PASSWORD ตั้งค่าถูกไหม ก่อนต่อเข้ากับ auth.py จริง
"""
import sys
sys.path.insert(0, ".")

from email_service import send_otp_email
from otp_utils import generate_otp

TEST_EMAIL = "phonch01x@gmail.com"  # แก้ตรงนี้ — Gmail SMTP ส่งหาใครก็ได้ ไม่จำกัดเหมือน Resend sandbox

otp = generate_otp()
print(f"กำลังส่ง OTP: {otp} ไปที่ {TEST_EMAIL} ...")
send_otp_email(TEST_EMAIL, otp)
print("ส่งสำเร็จ! เช็คอีเมลได้เลย")