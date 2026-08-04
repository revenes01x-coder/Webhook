from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
import models


def check_rate_limit(db: Session, key: str, action: str, limit: int, window_minutes: int):
    """
    ฟังก์ชันตรวจสอบ Rate Limit
    - key: สิ่งที่ใช้อ้างอิง (เช่น IP Address, Email, User ID)
    - action: ประเภทการกระทำ (เช่น 'register', 'login', 'add_webhook')
    - limit: จำนวนครั้งที่อนุญาต
    - window_minutes: กรอบเวลา (นาที)
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