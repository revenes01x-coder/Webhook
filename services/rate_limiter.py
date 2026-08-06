from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from smartlpr import models


def check_rate_limit(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """
    [ของเดิม — ไม่แก้ไข ยังใช้กับ endpoint ที่ไม่ใช่การเดา secret]
    ฟังก์ชันตรวจสอบ Rate Limit แบบ fixed window ปกติ:
    - key: สิ่งที่ใช้อ้างอิง (เช่น IP Address, Email, User ID)
    - action: ประเภทการกระทำ (เช่น 'register', 'login', 'add_webhook')
    - limit: จำนวนครั้งที่อนุญาต
    - window_minutes: กรอบเวลา (นาที)

    หมายเหตุ: window เริ่มนับจาก "ครั้งแรก" ที่เรียกเข้ามา ไม่ใช่จากตอนที่แตะ limit
    ใช้กับ: add_webhook, add_camera, toggle_camera, refresh_token
    """
    now = datetime.now(timezone.utc)

    rate_record = db.query(models.RateLimit).filter(
        models.RateLimit.key == key,
        models.RateLimit.action == action
    ).first()

    if rate_record:
        if now < rate_record.expire_at:
            if rate_record.count >= limit:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"จำกัดการใช้งาน: คุณทำรายการ {action} บ่อยเกินไป กรุณารอสักครู่"
                )
            rate_record.count += 1
        else:
            rate_record.count = 1
            rate_record.expire_at = now + timedelta(minutes=window_minutes)
    else:
        new_record = models.RateLimit(
            key=key,
            action=action,
            count=1,
            expire_at=now + timedelta(minutes=window_minutes)
        )
        db.add(new_record)

    db.commit()


# ---------------------------------------------------------------------------
# Lockout-style functions (ของใหม่)
#
# ต่างจาก check_rate_limit ตรงที่: พอนับถึง limit พอดี -> "รีเซ็ตนาฬิกาเต็ม window_minutes
# ใหม่นับจากวินาทีนั้นเลย" (ไม่ใช่นับต่อจากครั้งแรกที่พลาด) ทำให้ระยะเวลาที่ถูกล็อกจริงคงที่
# เสมอไม่ว่าจะพลาดถี่หรือห่างแค่ไหนก่อนหน้า
#
# แยกเป็น 3 ฟังก์ชันย่อยเพื่อรองรับ 2 รูปแบบการใช้งาน:
#
# 1) "unconditional" (นับทุกครั้งที่เรียก ไม่สนผลลัพธ์) — ใช้ check_and_record() ตัวเดียว
#    เหมือน check_rate_limit เดิมแต่เปลี่ยนคณิตศาสตร์ตอนล็อก
#    ใช้กับ: register, forgot_password, reset_password, resend_otp, regenerate (api-key)
#
# 2) "conditional on failure" (เช็คก่อนทำ action, +1 เฉพาะตอนพลาด, เคลียร์ตอนสำเร็จ) —
#    ใช้ check_lockout() + record_attempt() + clear_lockout() แยกกัน 3 จุดในโค้ด caller
#    ใช้กับ: login เท่านั้น (ต้องบล็อกแม้กรอกรหัสถูกระหว่างล็อกอยู่)
# ---------------------------------------------------------------------------


def check_lockout(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """เช็คว่า key นี้กำลังถูกล็อกอยู่หรือไม่ (read-only ไม่เพิ่ม count)
    เรียก "ก่อน" ทำ action ทุกครั้ง — ถ้าล็อกอยู่ raise 429 ทันที ไม่ว่า action ที่จะทำต่อ
    จะสำเร็จหรือไม่ก็ตาม (เช่น login ต้องบล็อกแม้รหัสผ่านที่กรอกมาถูกต้อง)

    detail เป็น dict เสมอ (ไม่ใช่ string เปล่าๆ เหมือนเดิม) เพื่อให้ frontend อ่าน
    retry_after_seconds ไปนับถอยหลัง/disable ปุ่มได้ตรงเวลาจริง แทนที่จะ parse ข้อความเอา
    (ดู index.html: apiCall เก็บ e.detail ไว้ทั้งก้อน + startButtonLockout ใช้ค่านี้)
    """
    now = datetime.now(timezone.utc)

    record = db.query(models.RateLimit).filter(
        models.RateLimit.key == key,
        models.RateLimit.action == action
    ).first()

    if record and now < record.expire_at and record.count >= limit:
        remaining_seconds = int((record.expire_at - now).total_seconds())
        remaining_minutes = max(1, (remaining_seconds + 59) // 60)  # ปัดขึ้น อย่างน้อย 1 นาที (ใช้แค่ในข้อความ)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "message": (
                    f"ทำรายการ {action} ผิดพลาด/ถี่เกินกำหนด กรุณารออีกประมาณ "
                    f"{remaining_minutes} นาทีแล้วลองใหม่"
                ),
                "retry_after_seconds": max(1, remaining_seconds),
            },
        )


def record_attempt(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """บันทึกการเรียก/พลาด 1 ครั้ง
    ถ้าครั้งนี้ทำให้ count แตะ limit พอดี (เพิ่งเข้าสู่สถานะล็อก) -> รีเซ็ต expire_at เป็น
    now + window_minutes เต็มๆ (เริ่มนับเวลาล็อกใหม่จากตอนที่โดนล็อกจริง)
    ถ้ายังไม่ถึง limit -> แค่ +1 นับสะสมใน window เดิม (ไม่ต่อเวลา)"""
    now = datetime.now(timezone.utc)

    record = db.query(models.RateLimit).filter(
        models.RateLimit.key == key,
        models.RateLimit.action == action
    ).first()

    if record:
        if now < record.expire_at:
            if record.count < limit:
                record.count += 1
                if record.count >= limit:
                    record.expire_at = now + timedelta(minutes=window_minutes)
            # count >= limit อยู่แล้ว: ปกติ check_lockout ด้านบนกันไว้ก่อนถึงจุดนี้แล้ว
            # (เผื่อ caller ไม่ได้เรียก check_lockout ก่อน ก็ไม่ทำอะไรเพิ่ม ไม่ต่อเวลาซ้ำ)
        else:
            record.count = 1
            record.expire_at = now + timedelta(minutes=window_minutes)
    else:
        record = models.RateLimit(
            key=key, action=action, count=1,
            expire_at=now + timedelta(minutes=window_minutes),
        )
        db.add(record)

    db.commit()


def clear_lockout(db: Session, key: str, action: str):
    """ล้าง record ทิ้ง — เรียกตอน action สำเร็จ (เช่น login ผ่าน) กัน user ที่เพิ่งพลาด
    ไม่กี่ครั้งแล้วทำถูกได้จริง ยังโดนนับสะสมค้างไว้รอบหน้าโดยไม่จำเป็น"""
    db.query(models.RateLimit).filter(
        models.RateLimit.key == key,
        models.RateLimit.action == action
    ).delete(synchronize_session=False)
    db.commit()


def check_and_record(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """Convenience function สำหรับ endpoint แบบ 'unconditional counting' (นับทุกครั้งที่เรียก
    ไม่สนผลลัพธ์ว่าสำเร็จหรือไม่) — เทียบเท่าเรียก check_lockout() แล้วตามด้วย record_attempt()
    ใช้แทนที่ check_rate_limit() เดิมตรงๆ ในจุดที่ต้องการ lockout math แบบใหม่
    ใช้กับ: register, forgot_password, reset_password, resend_otp, regenerate (api-key)"""
    check_lockout(db, key, action, limit=limit, window_minutes=window_minutes)
    record_attempt(db, key, action, limit=limit, window_minutes=window_minutes)