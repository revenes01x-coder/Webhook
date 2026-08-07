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

def check_lockout(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """เช็คว่า key นี้กำลังถูกล็อกอยู่หรือไม่ (read-only ไม่เพิ่ม count)
    เรียก "ก่อน" ทำ action ทุกครั้ง — ถ้าล็อกอยู่ raise 429 ทันที ไม่ว่า action ที่จะทำต่อ
    จะสำเร็จหรือไม่ก็ตาม (เช่น login ต้องบล็อกแม้รหัสผ่านที่กรอกมาถูกต้อง)

    บล็อกก็ต่อเมื่อ record นี้ "เข้าสถานะล็อกจริง" แล้วเท่านั้น คือ count >= limit
    (record_attempt ด้านล่างเป็นคนกำหนดว่า count ไหนถือว่าเข้าสถานะล็อก และตั้ง expire_at
    ให้ตอนนั้นเอง — ก่อนหน้านั้น count ที่ยังไม่ถึง limit จะไม่ทำให้ expire_at มีผลอะไร)

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


def record_attempt(
    db: Session,
    key: str,
    action: str,
    limit: int,
    window_minutes: int,
    inactivity_reset_minutes: int | None = None,
):
    """บันทึกการเรียก/พลาด 1 ครั้ง

    พฤติกรรม (อัปเดต): ไม่เริ่มจับเวลา lockout (expire_at) ตั้งแต่พลาดครั้งแรกอีกต่อไป
    - พลาดครั้งที่ 1 ถึง limit-1: แค่นับสะสม (count += 1) ยังไม่ถือว่าเข้าสถานะล็อก
      ไม่แตะ/ไม่ต่อ expire_at เลยในช่วงนี้
    - พลาดครบ limit พอดี: เพิ่งเข้าสถานะล็อกตอนนี้เอง -> ตั้ง expire_at = now + window_minutes
      ใหม่ทั้งก้อน (ให้ lockout มีผลเต็ม window_minutes นับจากตอนที่ล็อกจริง)
    - lockout รอบก่อนหมดอายุไปแล้ว (count >= limit และ now >= expire_at) -> ถือว่าปลดล็อกแล้ว
      รีเซ็ต count กลับเป็น 1 (นับใหม่เหมือนพลาดครั้งแรก)

    inactivity_reset_minutes: ถ้าห่างจาก "ครั้งก่อนหน้า" (last_attempt_at) นานเกินค่านี้
    ให้ถือว่า user เว้นว่างไปนานพอ รีเซ็ต count กลับเป็น 1 เช่นกัน (ให้โอกาสใหม่ ไม่นับสะสม
    ค้างจากพฤติกรรมเก่าที่ผ่านมานานแล้ว) ไม่ระบุ -> ใช้ window_minutes แทน (เท่ากับพฤติกรรม
    เดิมก่อนแก้ไข ใช้ต่อเมื่อยังไม่ได้ตั้งใจ tune ค่านี้แยกสำหรับ action นั้นๆ)
    """
    now = datetime.now(timezone.utc)
    reset_after = timedelta(
        minutes=inactivity_reset_minutes if inactivity_reset_minutes is not None else window_minutes
    )

    record = db.query(models.RateLimit).filter(
        models.RateLimit.key == key,
        models.RateLimit.action == action
    ).first()

    if record:
        stale = (
            record.last_attempt_at is not None
            and (now - record.last_attempt_at) > reset_after
        )
        lockout_expired = record.count >= limit and now >= record.expire_at

        if stale or lockout_expired:
            record.count = 1
        else:
            record.count += 1

        record.last_attempt_at = now

        if record.count >= limit:
            # เพิ่งแตะ/ยังคงอยู่ในสถานะล็อก -> ตั้ง/ต่อเวลาล็อกให้เต็ม window_minutes จากตอนนี้
            record.expire_at = now + timedelta(minutes=window_minutes)
    else:
        record = models.RateLimit(
            key=key,
            action=action,
            count=1,
            last_attempt_at=now,
            # ยังไม่มีผลอะไรจนกว่า count จะแตะ limit (check_lockout เช็ค count >= limit ควบคู่ด้วย)
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

def check_and_record(
    db: Session,
    key: str,
    action: str,
    limit: int,
    window_minutes: int,
    inactivity_reset_minutes: int | None = None,
):
    """Convenience function สำหรับ endpoint แบบ 'unconditional counting' (นับทุกครั้งที่เรียก
    ไม่สนผลลัพธ์ว่าสำเร็จหรือไม่) — เทียบเท่าเรียก check_lockout() แล้วตามด้วย record_attempt()
    ใช้แทนที่ check_rate_limit() เดิมตรงๆ ในจุดที่ต้องการ lockout math แบบใหม่
    ใช้กับ: register, forgot_password, reset_password, resend_otp, regenerate (api-key)

    inactivity_reset_minutes: ส่งต่อให้ record_attempt เฉยๆ ถ้าไม่ระบุจะ default เป็น
    window_minutes ของ action นั้น (เท่ากับพฤติกรรมเดิมก่อนแก้ไข ไม่มีอะไรเปลี่ยนสำหรับ
    action ที่ยังไม่ได้ตั้งใจ tune ค่านี้แยก)"""
    check_lockout(db, key, action, limit=limit, window_minutes=window_minutes)
    record_attempt(
        db, key, action,
        limit=limit,
        window_minutes=window_minutes,
        inactivity_reset_minutes=inactivity_reset_minutes,
    )