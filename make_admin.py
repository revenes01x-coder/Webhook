"""
วิธีใช้ (รันจาก terminal ที่ root ของโปรเจกต์ ที่ที่มี .env อยู่):
    python make_admin.py user@example.com

ปลด admin กลับ (เผื่อพลาด):
    python make_admin.py user@example.com --revoke
"""
import sys
from smartlpr.database import SessionLocal
from smartlpr import models


def make_admin(email: str, revoke: bool = False) -> None:
    email = email.strip().lower()
    db = SessionLocal()
    try:
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            print(f"ไม่พบผู้ใช้อีเมล {email} ในระบบ — ต้องสมัคร (register) และยืนยัน OTP ก่อน")
            sys.exit(1)

        if not user.is_verified:
            print(f"คำเตือน: {email} ยังไม่ได้ยืนยัน OTP (is_verified=False) — ตั้งเป็น admin ต่อได้ แต่ user จะ login ไม่ได้จนกว่าจะ verify")

        if revoke:
            if not user.is_admin:
                print(f"{email} ไม่ได้เป็น admin อยู่แล้ว")
                return
            user.is_admin = False
            db.commit()
            print(f"ถอดสิทธิ์ admin ของ {email} เรียบร้อยแล้ว")
            return

        if user.is_admin:
            print(f"{email} เป็น admin อยู่แล้ว ไม่ต้องทำอะไรเพิ่ม")
            return

        user.is_admin = True
        db.commit()
        print(f"ตั้งให้ {email} เป็น admin เรียบร้อยแล้ว")

    finally:
        db.close()


if __name__ == "__main__":
    args = sys.argv[1:]
    if len(args) not in (1, 2):
        print("วิธีใช้: python make_admin.py <email> [--revoke]")
        sys.exit(1)

    target_email = args[0]
    do_revoke = "--revoke" in args[1:]
    make_admin(target_email, revoke=do_revoke)