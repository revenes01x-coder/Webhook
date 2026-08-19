from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone
from fastapi import HTTPException, status
from smartlpr import models

async def check_rate_limit(db: AsyncSession, key: str, action: str, limit: int, window_minutes: int):
    now = datetime.now(timezone.utc)

    result = await db.execute(
        select(models.RateLimit)
        .filter(models.RateLimit.key == key, models.RateLimit.action == action)
        .with_for_update()
    )
    rate_record = result.scalar_one_or_none()

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

        await db.commit()
        return

    new_record = models.RateLimit(
        key=key,
        action=action,
        count=1,
        expire_at=now + timedelta(minutes=window_minutes),
    )
    db.add(new_record)
    try:
        await db.commit()
    except IntegrityError:
        # แพ้ race — อีก request คู่ขนานเพิ่ง insert (key, action) นี้ไปพอดีก่อนหน้าเราเสี้ยววินาที
        # rollback แล้วเรียกตัวเองซ้ำ รอบนี้จะเข้า branch "มี record แล้ว" ด้านบนแทน
        await db.rollback()
        await check_rate_limit(db, key, action, limit=limit, window_minutes=window_minutes)

async def check_lockout(db: AsyncSession, key: str, action: str, limit: int, window_minutes: int):
    now = datetime.now(timezone.utc)
    result = await db.execute(
        select(models.RateLimit)
        .filter(models.RateLimit.key == key, models.RateLimit.action == action)
        .with_for_update()
    )
    record = result.scalar_one_or_none()

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


async def record_attempt(
    db: AsyncSession,
    key: str,
    action: str,
    limit: int,
    window_minutes: int,
    inactivity_reset_minutes: int | None = None,
):
    now = datetime.now(timezone.utc)
    reset_after = timedelta(
        minutes=inactivity_reset_minutes if inactivity_reset_minutes is not None else window_minutes
    )

    result = await db.execute(
        select(models.RateLimit)
        .filter(models.RateLimit.key == key, models.RateLimit.action == action)
        .with_for_update()
    )
    record = result.scalar_one_or_none()

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
            # เพิ่ง/ยังคงอยู่ในสถานะล็อก -> ตั้ง/ต่อเวลาล็อกให้เต็ม window_minutes จากตอนนี้
            record.expire_at = now + timedelta(minutes=window_minutes)

        await db.commit()
        return

    new_record = models.RateLimit(
        key=key,
        action=action,
        count=1,
        last_attempt_at=now,
        # ยังไม่มีผลอะไรจนกว่า count จะแตะ limit (check_lockout เช็ค count >= limit ควบคู่ด้วย)
        expire_at=now + timedelta(minutes=window_minutes),
    )
    db.add(new_record)
    try:
        await db.commit()
    except IntegrityError:
        # แพ้ race เหมือนใน check_rate_limit — rollback แล้วเรียกตัวเองซ้ำ รอบนี้จะเจอ record
        # ที่อีกฝั่ง insert ไปก่อนแล้ว เข้า branch ด้านบนแทน (นับ count ต่อให้ถูกต้อง)
        await db.rollback()
        await record_attempt(
            db, key, action,
            limit=limit,
            window_minutes=window_minutes,
            inactivity_reset_minutes=inactivity_reset_minutes,
        )

async def clear_lockout(db: AsyncSession, key: str, action: str):
    """ล้าง record ทิ้ง — เรียกตอน action สำเร็จ (เช่น login ผ่าน) กัน user ที่เพิ่งพลาด
    ไม่กี่ครั้งแล้วทำถูกได้จริง ยังโดนนับสะสมค้างไว้รอบหน้าโดยไม่จำเป็น

    [Async Migration]: เดิมใช้ Query.delete(synchronize_session=False) ตอนนี้ต้องใช้
    sqlalchemy.delete() construct ผ่าน db.execute() แทน (Query object แบบเดิมไม่มีใน
    AsyncSession)"""
    await db.execute(
        delete(models.RateLimit).where(
            models.RateLimit.key == key,
            models.RateLimit.action == action,
        )
    )
    await db.commit()

async def check_and_record(
    db: AsyncSession,
    key: str,
    action: str,
    limit: int,
    window_minutes: int,
    inactivity_reset_minutes: int | None = None,
):
    await check_lockout(db, key, action, limit=limit, window_minutes=window_minutes)
    await record_attempt(
        db, key, action,
        limit=limit,
        window_minutes=window_minutes,
        inactivity_reset_minutes=inactivity_reset_minutes,
    )