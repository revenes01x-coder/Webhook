import logging
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Cookie
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    create_password_reset_token,
    decode_password_reset_token,
    revoke_token,
    get_current_user,
    oauth2_scheme,
)
from services.rate_limiter import (
    check_rate_limit,      # ของเดิม — ใช้กับ refresh_token เท่านั้นในไฟล์นี้ตอนนี้
    check_lockout,
    record_attempt,
    clear_lockout,
    check_and_record,
)
from services.token import generate_otp, hash_otp, verify_otp, generate_refresh_token, hash_refresh_token
from services.email_service import (send_otp_email, send_password_reset_otp_email,send_password_changed_email,)
from smartlpr.config import (
    OTP_EXPIRE_MINUTES,
    OTP_MAX_ATTEMPTS,
    OTP_RESEND_COOLDOWN_SECONDS,
    OTP_RESEND_LIMIT_PER_HOUR,
    REFRESH_TOKEN_EXPIRE_DAYS,
    COOKIE_SECURE,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

REGISTER_PURPOSE = "register"
PASSWORD_RESET_PURPOSE = "password_reset"

REFRESH_TOKEN_COOKIE_NAME = "refresh_token"

LOGIN_LOCKOUT_LIMIT = 5
LOGIN_LOCKOUT_MINUTES = 5

LOGIN_INACTIVITY_RESET_MINUTES = 30

REGISTER_LOCKOUT_LIMIT = 5
REGISTER_LOCKOUT_MINUTES = 5

RESET_PASSWORD_LOCKOUT_LIMIT = 5
RESET_PASSWORD_LOCKOUT_MINUTES = 5

FORGOT_PASSWORD_IP_LOCKOUT_LIMIT = 10
FORGOT_PASSWORD_IP_LOCKOUT_MINUTES = 15

# [Change Password]: ต่างจาก RESET_PASSWORD_* ตรงที่ flow นี้ user login อยู่แล้ว (ไม่ผ่าน OTP)
# คีย์ lockout ผูกกับ user.id ตรงๆ (ไม่ผูก IP เหมือน reset-password ที่ยังไม่ login) กันคนเดา
# current_password รัวๆ ใส่บัญชีที่ session หลุดมือไป
CHANGE_PASSWORD_LOCKOUT_LIMIT = 5
CHANGE_PASSWORD_LOCKOUT_MINUTES = 15


async def _issue_refresh_token(db: AsyncSession, user: models.User, family_id: str | None = None) -> str:
    """สร้าง refresh token ใหม่ 1 ใบ คืน plaintext ให้ caller เอาไปตั้ง cookie (เก็บแค่ hash ลง DB)
    ไม่ส่ง family_id มา (login ครั้งแรก) -> สร้าง family_id ใหม่ทั้งสาย
    ส่ง family_id มา (ตอน rotate ใน POST /auth/refresh) -> ใช้ family_id เดิม
    เพื่อให้ตรวจจับการเอา token เก่าที่ revoke ไปแล้วมาใช้ซ้ำได้ทั้งสาย ไม่ใช่แค่ใบต่อใบ
    """
    plain_token = generate_refresh_token()
    now = datetime.now(timezone.utc)

    record = models.RefreshToken(
        user_id=user.id,
        family_id=family_id or uuid.uuid4().hex,
        token_hash=hash_refresh_token(plain_token),
        is_revoked=False,
        expires_at=now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(record)
    await db.commit()

    return plain_token

def _set_refresh_cookie(response: Response, plain_token: str) -> None:
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE_NAME,
        value=plain_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
        path="/auth",
    )

def _clear_refresh_cookie(response: Response) -> None:
    response.delete_cookie(key=REFRESH_TOKEN_COOKIE_NAME, path="/auth")


async def _revoke_token_family(db: AsyncSession, family_id: str) -> None:
    """Revoke refresh token ทุกใบใน family นี้ที่ยังไม่ถูก revoke — ใช้ตอนตรวจพบการ reuse
    (สัญญาณ token หลุด) และตอน logout (revoke ทั้งสาย ไม่ใช่แค่ใบที่ถืออยู่ตอนนี้)
    """
    await db.execute(
        update(models.RefreshToken)
        .where(
            models.RefreshToken.family_id == family_id,
            models.RefreshToken.is_revoked == False,  # noqa: E712
        )
        .values(is_revoked=True)
    )
    await db.commit()


async def _revoke_all_sessions(db: AsyncSession, user_id: int) -> None:
    """Revoke refresh token ทุก family ที่ยังไม่ถูก revoke ของ user คนนี้ — ใช้ร่วมกันทั้ง
    reset_password (ผ่าน OTP ตอนลืมรหัสผ่าน) และ change_password (login อยู่แล้ว เปลี่ยนเฉยๆ)
    บังคับให้ทุกอุปกรณ์ที่เคย login ไว้ต้อง login ใหม่หลังรหัสผ่านเปลี่ยน — กันเคส token เก่าหลุด
    ไปอยู่ในมือคนอื่นตั้งแต่ก่อนเปลี่ยนรหัสผ่านแล้วยังใช้ต่อได้เรื่อยๆ"""
    active_families_result = await db.execute(
        select(models.RefreshToken.family_id)
        .filter(
            models.RefreshToken.user_id == user_id,
            models.RefreshToken.is_revoked == False,  # noqa: E712
        )
        .distinct()
    )
    for (family_id,) in active_families_result.all():
        await _revoke_token_family(db, family_id)


async def _create_and_send_otp(db: AsyncSession, user: models.User, purpose: str = REGISTER_PURPOSE) -> models.OtpVerification:
    """สร้าง/เขียนทับ OTP ของ (user, purpose) นี้ แล้วส่งอีเมล
    คืน otp_record กลับไปให้ caller เอา expires_at ไปส่งต่อให้ frontend นับถอยหลังได้แม่นยำ
    (ใช้เวลาจริงจาก server ไม่ใช่ค่าคงที่ฝั่ง client)
    """

    result = await db.execute(
        select(models.OtpVerification).filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == purpose,
        )
    )
    otp_record = result.scalar_one_or_none()

    otp_plain = generate_otp()
    now = datetime.now(timezone.utc)

    if otp_record:
        otp_record.otp_hash = hash_otp(otp_plain)
        otp_record.attempt_count = 0
        otp_record.is_used = False
        otp_record.expires_at = now + timedelta(minutes=OTP_EXPIRE_MINUTES)
        otp_record.created_at = now
    else:
        otp_record = models.OtpVerification(
            user_id=user.id,
            purpose=purpose,
            otp_hash=hash_otp(otp_plain),
            attempt_count=0,
            is_used=False,
            expires_at=now + timedelta(minutes=OTP_EXPIRE_MINUTES),
            created_at=now,
        )
        db.add(otp_record)

    await db.commit()
    await db.refresh(otp_record)  # เอา id/expires_at ที่ commit แล้วกลับมาแน่นอน

    if purpose == PASSWORD_RESET_PURPOSE:
        await asyncio.to_thread(send_password_reset_otp_email, user.email, otp_plain)
    else:
        await asyncio.to_thread(send_otp_email, user.email, otp_plain)

    return otp_record


@router.post("/register")
async def register_user(user: schemas.UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    client_ip = request.client.host
    lockout_key = f"register_{client_ip}"

    await check_and_record(db, lockout_key, "register", limit=REGISTER_LOCKOUT_LIMIT, window_minutes=REGISTER_LOCKOUT_MINUTES)

    result = await db.execute(select(models.User).filter(models.User.email == user.email))
    db_user = result.scalar_one_or_none()

    if db_user and db_user.is_verified:
        raise HTTPException(status_code=400, detail="อีเมลนี้มีในระบบแล้ว")

    hashed_password = get_password_hash(user.password)

    if db_user:
        latest_otp_result = await db.execute(
            select(models.OtpVerification).filter(
                models.OtpVerification.user_id == db_user.id,
                models.OtpVerification.purpose == REGISTER_PURPOSE,
            )
        )
        latest_otp = latest_otp_result.scalar_one_or_none()
        if latest_otp:
            elapsed = (datetime.now(timezone.utc) - latest_otp.created_at).total_seconds()
            if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
                wait_more = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "message": f"กรุณารออีก {wait_more} วินาทีก่อนขอ OTP ใหม่",
                        "retry_after_seconds": max(1, wait_more),
                    },
                )

        db_user.hashed_password = hashed_password
        await db.commit()
        new_user = db_user
    else:
        new_user = models.User(email=user.email, hashed_password=hashed_password, is_verified=False)
        db.add(new_user)

        try:
            await db.commit()
            await db.refresh(new_user)
        except IntegrityError:
            await db.rollback()
            raise HTTPException(status_code=400, detail="อีเมลนี้มีในระบบแล้ว")

    try:
        otp_record = await _create_and_send_otp(db, new_user)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"สมัครสมาชิกสำเร็จ แต่{str(e)} กรุณากด 'ส่ง OTP อีกครั้ง'",
        )

    return {
        "message": "สมัครสมาชิกสำเร็จ กรุณากรอก OTP ที่ส่งไปยังอีเมลของคุณเพื่อยืนยันตัวตน",
        "otp_expires_at": otp_record.expires_at,       # ใช้เวลานี้นับถอยหลังฝั่ง frontend
        "otp_expires_in_seconds": OTP_EXPIRE_MINUTES * 60,
    }


@router.post("/verify-otp")
async def verify_otp_endpoint(payload: schemas.OtpVerifyRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.User).filter(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้นี้ในระบบ")

    if user.is_verified:
        return {"message": "บัญชีนี้ยืนยันตัวตนไปแล้ว"}

    otp_result = await db.execute(
        select(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == REGISTER_PURPOSE,
        )
        .with_for_update()  # [Race Fix]: ล็อกแถวกัน concurrent request อ่าน attempt_count เก่าซ้ำกัน (lost update)
    )
    otp_record = otp_result.scalar_one_or_none()

    if not otp_record or otp_record.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่พบ OTP ที่ใช้งานได้ กรุณาขอ OTP ใหม่",
        )

    now = datetime.now(timezone.utc)
    if now > otp_record.expires_at:
        otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP หมดอายุแล้ว กรุณาขอ OTP ใหม่",
        )

    if otp_record.attempt_count >= OTP_MAX_ATTEMPTS:
        otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="กรอก OTP ผิดเกินจำนวนครั้งที่กำหนด กรุณาขอ OTP ใหม่",
        )

    if not verify_otp(payload.otp, otp_record.otp_hash):
        otp_record.attempt_count += 1
        remaining = OTP_MAX_ATTEMPTS - otp_record.attempt_count
        if remaining <= 0:
            otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTP ไม่ถูกต้อง (เหลือโอกาสกรอกอีก {max(remaining, 0)} ครั้ง)",
        )

    user.is_verified = True
    await db.delete(otp_record)
    await db.commit()

    return {"message": "ยืนยันตัวตนสำเร็จ สามารถเข้าสู่ระบบได้แล้ว"}


@router.post("/resend-otp")
async def resend_otp(payload: schemas.OtpResendRequest, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(models.User).filter(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        return {"message": "หากอีเมลนี้อยู่ในระบบ เราได้ส่ง OTP ใหม่ไปให้แล้ว"}

    if user.is_verified:
        return {"message": "บัญชีนี้ยืนยันตัวตนไปแล้ว ไม่จำเป็นต้องขอ OTP อีก"}

    client_ip = request.client.host
    lockout_key = f"resend_otp_{payload.email}_{client_ip}"

    await check_and_record(db, lockout_key, "resend_otp",
    limit=OTP_RESEND_LIMIT_PER_HOUR, window_minutes=60)

    latest_otp_result = await db.execute(
        select(models.OtpVerification).filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == REGISTER_PURPOSE,
        )
    )
    latest_otp = latest_otp_result.scalar_one_or_none()
    if latest_otp:
        elapsed = (datetime.now(timezone.utc) - latest_otp.created_at).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_more = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"กรุณารออีก {wait_more} วินาทีก่อนขอ OTP ใหม่",
                    "retry_after_seconds": max(1, wait_more),
                },
            )

    try:
        otp_record = await _create_and_send_otp(db, user)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

    return {
        "message": "ส่ง OTP ใหม่ไปยังอีเมลของคุณแล้ว",
        "otp_expires_at": otp_record.expires_at,
        "otp_expires_in_seconds": OTP_EXPIRE_MINUTES * 60,
    }


@router.post("/login", response_model=schemas.Token)
async def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.client.host

    normalized_email = form_data.username.strip().lower()
    lockout_key = f"login_fail_{normalized_email}_{client_ip}"

    await check_lockout(db, lockout_key, "login_fail", limit=LOGIN_LOCKOUT_LIMIT, window_minutes=LOGIN_LOCKOUT_MINUTES)

    result = await db.execute(select(models.User).filter(models.User.email == normalized_email))
    user = result.scalar_one_or_none()
    submitted_password = form_data.password.strip()

    if not user or not verify_password(submitted_password, user.hashed_password):
        await record_attempt(
            db, lockout_key, "login_fail",
            limit=LOGIN_LOCKOUT_LIMIT,
            window_minutes=LOGIN_LOCKOUT_MINUTES,
            inactivity_reset_minutes=LOGIN_INACTIVITY_RESET_MINUTES,
        )
        raise HTTPException(status_code=401, detail="อีเมลหรือรหัสผ่านไม่ถูกต้อง")

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="กรุณายืนยันอีเมลด้วย OTP ก่อนเข้าสู่ระบบ",
        )

    # login สำเร็จ -> ล้างประวัติพลาดทิ้ง ไม่ต้องรอ window หมดอายุเอง
    await clear_lockout(db, lockout_key, "login_fail")

    access_token = create_access_token(data={"sub": user.email})

    # ออก refresh token ใบใหม่ (family ใหม่ทั้งสาย) ใส่ httpOnly cookie ให้เลย
    plain_refresh_token = await _issue_refresh_token(db, user)
    _set_refresh_cookie(response, plain_refresh_token)

    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh", response_model=schemas.Token)
async def refresh_access_token(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token ไม่ถูกต้องหรือหมดอายุ กรุณาเข้าสู่ระบบใหม่อีกครั้ง",
    )

    if not refresh_token:
        raise invalid_exception

    client_ip = request.client.host
    await check_rate_limit(db, f"refresh_token_{client_ip}", "refresh_token", limit=30, window_minutes=60)

    token_hash = hash_refresh_token(refresh_token)
    result = await db.execute(select(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash))
    record = result.scalar_one_or_none()

    if not record:
        _clear_refresh_cookie(response)
        raise invalid_exception

    now = datetime.now(timezone.utc)

    if record.is_revoked:
        # ใบนี้เคยถูก rotate ทิ้งไปแล้ว แต่มีคนเอามาใช้ซ้ำ -> สัญญาณ token หลุด revoke ทั้งสายทันที
        await _revoke_token_family(db, record.family_id)
        _clear_refresh_cookie(response)
        raise invalid_exception

    if now > record.expires_at:
        _clear_refresh_cookie(response)
        raise invalid_exception

    user_result = await db.execute(select(models.User).filter(models.User.id == record.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_verified:
        _clear_refresh_cookie(response)
        raise invalid_exception

    # Rotate: ปิดใบเก่า ออกใบใหม่ใน family เดิม
    record.is_revoked = True
    await db.commit()

    new_plain_token = await _issue_refresh_token(db, user, family_id=record.family_id)
    _set_refresh_cookie(response, new_plain_token)

    new_access_token = create_access_token(data={"sub": user.email})
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/forgot-password")
async def forgot_password(
    payload: schemas.ForgotPasswordRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.client.host
    await check_and_record(
        db,
        f"forgot_password_ip_{client_ip}",
        "forgot_password_ip",
        limit=FORGOT_PASSWORD_IP_LOCKOUT_LIMIT,
        window_minutes=FORGOT_PASSWORD_IP_LOCKOUT_MINUTES,
    )

    result = await db.execute(select(models.User).filter(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    generic_message = {"message": "หากอีเมลนี้อยู่ในระบบ เราได้ส่ง OTP สำหรับตั้งรหัสผ่านใหม่ไปให้แล้ว"}

    if not user:
        return generic_message

    if not user.is_verified:
        return generic_message

    lockout_key = f"forgot_password_{payload.email}"

    await check_and_record(db, lockout_key, "forgot_password",
    limit=OTP_RESEND_LIMIT_PER_HOUR, window_minutes=60)

    latest_otp_result = await db.execute(
        select(models.OtpVerification).filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == PASSWORD_RESET_PURPOSE,
        )
    )
    latest_otp = latest_otp_result.scalar_one_or_none()
    if latest_otp:
        elapsed = (datetime.now(timezone.utc) - latest_otp.created_at).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_more = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"กรุณารออีก {wait_more} วินาทีก่อนขอ OTP ใหม่",
                    "retry_after_seconds": max(1, wait_more),
                },
            )

    try:
        otp_record = await _create_and_send_otp(db, user, purpose=PASSWORD_RESET_PURPOSE)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

    return {
        **generic_message,
        "otp_expires_at": otp_record.expires_at,
        "otp_expires_in_seconds": OTP_EXPIRE_MINUTES * 60,
    }


@router.post("/verify-reset-otp", response_model=schemas.ResetTokenResponse)
async def verify_reset_otp(payload: schemas.VerifyResetOtpRequest, request: Request, db: AsyncSession = Depends(get_db)):

    client_ip = request.client.host

    await check_rate_limit(
        db,
        f"verify_reset_otp_{payload.email}_{client_ip}",
        "verify_reset_otp",
        limit=5,
        window_minutes=15,
    )
    invalid_otp_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="OTP ไม่ถูกต้องหรือหมดอายุ กรุณาขอ OTP ใหม่",
    )

    result = await db.execute(select(models.User).filter(models.User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user:
        raise invalid_otp_exception

    otp_result = await db.execute(
        select(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == PASSWORD_RESET_PURPOSE,
        )
        .with_for_update()  # [Race Fix]: เหมือน verify_otp_endpoint กัน lost update บน attempt_count
    )
    otp_record = otp_result.scalar_one_or_none()

    if not otp_record or otp_record.is_used:
        raise invalid_otp_exception

    now = datetime.now(timezone.utc)
    if now > otp_record.expires_at:
        otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP หมดอายุแล้ว กรุณาขอ OTP ใหม่",
        )

    if otp_record.attempt_count >= OTP_MAX_ATTEMPTS:
        otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="กรอก OTP ผิดเกินจำนวนครั้งที่กำหนด กรุณาขอ OTP ใหม่",
        )

    if not verify_otp(payload.otp, otp_record.otp_hash):
        otp_record.attempt_count += 1
        remaining = OTP_MAX_ATTEMPTS - otp_record.attempt_count
        if remaining <= 0:
            otp_record.is_used = True
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTP ไม่ถูกต้อง (เหลือโอกาสกรอกอีก {max(remaining, 0)} ครั้ง)",
        )

    await db.delete(otp_record)
    await db.commit()

    reset_token = create_password_reset_token(user.email)
    return schemas.ResetTokenResponse(reset_token=reset_token)


@router.post("/reset-password")
async def reset_password(payload: schemas.ResetPasswordRequest, request: Request, db: AsyncSession = Depends(get_db)):
    email = await decode_password_reset_token(payload.reset_token, db)

    client_ip = request.client.host
    lockout_key = f"reset_password_{email}_{client_ip}"

    await check_and_record(db, lockout_key, "reset_password", limit=RESET_PASSWORD_LOCKOUT_LIMIT, window_minutes=RESET_PASSWORD_LOCKOUT_MINUTES)

    result = await db.execute(select(models.User).filter(models.User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ไม่พบผู้ใช้นี้ในระบบ")

    user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()

    await revoke_token(db, payload.reset_token)

    await _revoke_all_sessions(db, user.id)

    try:
        await asyncio.to_thread(send_password_changed_email, user.email)
    except RuntimeError as e:
        logging.error(f"ส่งอีเมลแจ้งเปลี่ยนรหัสผ่าน user_id={user.id} ไม่สำเร็จ: {e}")

    return {"message": "ตั้งรหัสผ่านใหม่สำเร็จ กรุณาเข้าสู่ระบบด้วยรหัสผ่านใหม่"}


@router.post("/change-password")
async def change_password(
    payload: schemas.ChangePasswordRequest,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
    current_user: models.User = Depends(get_current_user),
):
    lockout_key = f"change_password_{current_user.id}"

    await check_and_record(
        db, lockout_key, "change_password",
        limit=CHANGE_PASSWORD_LOCKOUT_LIMIT, window_minutes=CHANGE_PASSWORD_LOCKOUT_MINUTES,
    )

    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="รหัสผ่านปัจจุบันไม่ถูกต้อง",
        )

    await clear_lockout(db, lockout_key, "change_password")

    current_user.hashed_password = get_password_hash(payload.new_password)
    await db.commit()

    await revoke_token(db, token)
    await _revoke_all_sessions(db, current_user.id)

    try:
        await asyncio.to_thread(send_password_changed_email, current_user.email)
    except RuntimeError as e:
        logging.error(f"ส่งอีเมลแจ้งเปลี่ยนรหัสผ่าน user_id={current_user.id} ไม่สำเร็จ: {e}")

    return {"message": "เปลี่ยนรหัสผ่านสำเร็จ ระบบให้ทุกอุปกรณ์ต้องเข้าสู่ระบบใหม่อีกครั้งเพื่อความปลอดภัย"}


@router.post("/logout")
async def logout(
    response: Response,
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    """Revoke access token ปัจจุบัน (blacklist ทันทีผ่าน jti) + revoke refresh token ทั้ง family
    (ไม่ใช่แค่ใบที่ถืออยู่ กันใบเก่าที่เคย rotate ไปแล้วแต่ยังไม่หมดอายุหลุดรอด) แล้ว clear cookie
    หลัง logout token ทั้งคู่ใช้ต่อไม่ได้อีกทันที แม้จะยังไม่หมดอายุตามปกติ"""
    await revoke_token(db, token)

    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        result = await db.execute(select(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash))
        record = result.scalar_one_or_none()
        if record:
            await _revoke_token_family(db, record.family_id)

    _clear_refresh_cookie(response)

    return {"message": "ออกจากระบบเรียบร้อยแล้ว"}

@router.get("/me", response_model=schemas.UserMeResponse)
def get_me(current_user: models.User = Depends(get_current_user)):
    return schemas.UserMeResponse(
        email=current_user.email,
        is_verified=current_user.is_verified,
        terms_accepted=current_user.terms_accepted,
        is_admin=current_user.is_admin,
        has_api_key=current_user.api_key_hash is not None,
        is_suspended=current_user.is_suspended,
        suspended_reason=current_user.suspended_reason,
        full_name=current_user.full_name,
        phone=current_user.phone,
        created_at=current_user.created_at,
    )


@router.patch("/me", response_model=schemas.UserMeResponse)
async def update_me(
    payload: schemas.ProfileUpdateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    current_user.full_name = payload.full_name
    current_user.phone = payload.phone
    await db.commit()
    await db.refresh(current_user)

    return schemas.UserMeResponse(
        email=current_user.email,
        is_verified=current_user.is_verified,
        terms_accepted=current_user.terms_accepted,
        is_admin=current_user.is_admin,
        has_api_key=current_user.api_key_hash is not None,
        is_suspended=current_user.is_suspended,
        suspended_reason=current_user.suspended_reason,
        full_name=current_user.full_name,
        phone=current_user.phone,
        created_at=current_user.created_at,
    )