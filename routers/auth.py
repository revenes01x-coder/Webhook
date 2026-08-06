from fastapi import APIRouter, Depends, HTTPException, status, Request, Response, Cookie
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi.security import OAuth2PasswordRequestForm
from datetime import datetime, timedelta, timezone
import uuid

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
from services.email_service import send_otp_email, send_password_reset_otp_email
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

# ---------------------------------------------------------------------------
# Lockout constants (ของใหม่ — ล็อกเวลาเต็มตอนโดน limit แทนที่ fixed window เดิม)
# ตกลงกันไว้: login/register/forgot_password/reset_password = 5 ครั้ง/ล็อก 5 นาที
#            resend_otp = 3 ครั้ง/ล็อก 5 นาที
# หมายเหตุ: verify-otp และ verify-reset-otp "ไม่แตะ" ยังใช้กลไก attempt_count/is_used
# ในตัว OtpVerification record เดิม (มาตรฐานสำหรับป้องกันการเดา OTP อยู่แล้ว)
# ---------------------------------------------------------------------------
LOGIN_LOCKOUT_LIMIT = 5
LOGIN_LOCKOUT_MINUTES = 5

REGISTER_LOCKOUT_LIMIT = 5
REGISTER_LOCKOUT_MINUTES = 5

FORGOT_PASSWORD_LOCKOUT_LIMIT = 5
FORGOT_PASSWORD_LOCKOUT_MINUTES = 5

RESET_PASSWORD_LOCKOUT_LIMIT = 5
RESET_PASSWORD_LOCKOUT_MINUTES = 5

RESEND_OTP_LOCKOUT_LIMIT = 3
RESEND_OTP_LOCKOUT_MINUTES = 5


# ---------------------------------------------------------------------------
# Refresh Token helpers — ใช้ร่วมกันระหว่าง login / refresh / logout
# ---------------------------------------------------------------------------

def _issue_refresh_token(db: Session, user: models.User, family_id: str | None = None) -> str:
    """สร้าง refresh token ใหม่ 1 ใบ คืน plaintext ให้ caller เอาไปตั้ง cook (เก็บแค่ hash ลง DB)

    ไม่ส่ง family_id มา (login ครั้งแรก) -> สร้าง family_id ใหม่ทั้งสาย
    ส่ง family_id มา (ตอน rotate ใน POST /auth/refresh) -> ใช้ family_id เดิม
    เพื่อให้ตรวจจับการเอา token เก่าที่ revoke ไปแล้วมาใช้ซ้ำได้ทั้งสาย ไม่ใช่แค่ใบต่อใบ"""
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
    db.commit()

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


def _revoke_token_family(db: Session, family_id: str) -> None:
    """Revoke refresh token ทุกใบใน family นี้ที่ยังไม่ถูก revoke — ใช้ตอนตรวจพบการ reuse
    (สัญญาณ token หลุด) และตอน logout (revoke ทั้งสาย ไม่ใช่แค่ใบที่ถืออยู่ตอนนี้)"""
    db.query(models.RefreshToken).filter(
        models.RefreshToken.family_id == family_id,
        models.RefreshToken.is_revoked == False,  # noqa: E712
    ).update({"is_revoked": True}, synchronize_session=False)
    db.commit()


def _create_and_send_otp(db: Session, user: models.User, purpose: str = REGISTER_PURPOSE) -> models.OtpVerification:
    """สร้าง/เขียนทับ OTP ของ (user, purpose) นี้ แล้วส่งอีเมล
    ...
    คืน otp_record กลับไปให้ caller เอา expires_at ไปส่งต่อให้ frontend นับถอยหลังได้แม่นยำ
    (ใช้เวลาจริงจาก server ไม่ใช่ค่าคงที่ฝั่ง client)"""

    otp_record = (
        db.query(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == purpose,
        )
        .first()
    )

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

    db.commit()
    db.refresh(otp_record)  # เอา id/expires_at ที่ commit แล้วกลับมาแน่นอน

    if purpose == PASSWORD_RESET_PURPOSE:
        send_password_reset_otp_email(user.email, otp_plain)
    else:
        send_otp_email(user.email, otp_plain)

    return otp_record


@router.post("/register")
def register_user(user: schemas.UserCreate, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host
    lockout_key = f"register_{client_ip}"

    # [Lockout ใหม่]: สมัครได้ 5 ครั้ง / ล็อก 5 นาที (นับทุกครั้งที่เรียก ไม่ว่าอีเมลจะซ้ำหรือไม่
    # ก็ตาม — เหมือน check_rate_limit เดิมที่นับแบบไม่มีเงื่อนไข แค่เปลี่ยนคณิตศาสตร์ตอนล็อก
    # ให้เต็ม 5 นาทีนับจากตอนแตะ limit แทนที่จะนับจากครั้งแรกที่เรียก)
    check_and_record(db, lockout_key, "register", limit=REGISTER_LOCKOUT_LIMIT, window_minutes=REGISTER_LOCKOUT_MINUTES)

    db_user = db.query(models.User).filter(models.User.email == user.email).first()

    # [Unverified resume]: อีเมลซ้ำ "และ" ยืนยันแล้ว -> บล็อกจริง (เป็นบัญชีคนอื่น/เคยสมัครสำเร็จแล้ว)
    # อีเมลซ้ำ "แต่ยังไม่ยืนยัน" -> ไม่ถือเป็นบัญชีซ้ำ เป็นแค่ user สมัครค้างไว้แล้วไม่ได้กรอก OTP
    # ทัน (ปิดแท็บ/รอนานเกินไป) ให้ถือเป็นการ "สมัครต่อ" แทนที่จะบังคับรอ cleanup job ลบทิ้งเอง
    # ใน 24 ชม. (UNVERIFIED_USER_EXPIRE_HOURS) — ป้องกัน user ค้างสมัครไม่ได้ยาวนานโดยไม่จำเป็น
    if db_user and db_user.is_verified:
        raise HTTPException(status_code=400, detail="อีเมลนี้มีในระบบแล้ว")

    hashed_password = get_password_hash(user.password)

    if db_user:
        # [Cooldown]: บัญชีเดิมค้างอยู่ ใช้ cooldown เดียวกับ resend-otp กันกดสมัครซ้ำรัวๆ
        # จนสแปมอีเมล user (register เดิมไม่มี cooldown เพราะไม่เคยมีทางส่งซ้ำมาก่อนจุดนี้)
        latest_otp = (
            db.query(models.OtpVerification)
            .filter(
                models.OtpVerification.user_id == db_user.id,
                models.OtpVerification.purpose == REGISTER_PURPOSE,
            )
            .first()
        )
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

        # อัปเดตรหัสผ่านให้ตรงกับที่กรอกล่าสุดเสมอ (เผื่อพิมพ์ผิด/จำรหัสเดิมไม่ได้ตอนสมัครครั้งแรก
        # — ยังไม่ verify แปลว่าบัญชียังไม่ active จริง เปลี่ยนรหัสผ่านตรงนี้ได้โดยไม่ต้องยืนยันตัวตนซ้ำ)
        db_user.hashed_password = hashed_password
        db.commit()
        new_user = db_user
    else:
        new_user = models.User(email=user.email, hashed_password=hashed_password, is_verified=False)
        db.add(new_user)

        try:
            db.commit()
            db.refresh(new_user)
        except IntegrityError:
            db.rollback()
            raise HTTPException(status_code=400, detail="อีเมลนี้มีในระบบแล้ว")

    try:
        otp_record = _create_and_send_otp(db, new_user)
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
def verify_otp_endpoint(payload: schemas.OtpVerifyRequest, db: Session = Depends(get_db)):
    # หมายเหตุ: endpoint นี้ "ไม่แตะ" ตามที่ตกลงกันไว้ — ยังใช้กลไก attempt_count/is_used
    # ในตัว OtpVerification record เดิม (พลาดครบ OTP_MAX_ATTEMPTS -> OTP ใบนั้นตายทันที
    # ต้องกด resend-otp ขอใหม่) ซึ่งเป็นมาตรฐานสำหรับป้องกันการเดา OTP อยู่แล้ว ไม่ต้องเพิ่ม
    # lockout ระดับ endpoint ซ้อนทับ (ดูเหตุผลที่คุยกันในแชท)
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบผู้ใช้นี้ในระบบ")

    if user.is_verified:
        return {"message": "บัญชีนี้ยืนยันตัวตนไปแล้ว"}

    otp_record = (
        db.query(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == REGISTER_PURPOSE,
        )
        .first()
    )

    if not otp_record or otp_record.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่พบ OTP ที่ใช้งานได้ กรุณาขอ OTP ใหม่",
        )

    now = datetime.now(timezone.utc)
    if now > otp_record.expires_at:
        otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP หมดอายุแล้ว กรุณาขอ OTP ใหม่",
        )

    if otp_record.attempt_count >= OTP_MAX_ATTEMPTS:
        otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="กรอก OTP ผิดเกินจำนวนครั้งที่กำหนด กรุณาขอ OTP ใหม่",
        )

    if not verify_otp(payload.otp, otp_record.otp_hash):
        otp_record.attempt_count += 1
        remaining = OTP_MAX_ATTEMPTS - otp_record.attempt_count
        if remaining <= 0:
            otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTP ไม่ถูกต้อง (เหลือโอกาสกรอกอีก {max(remaining, 0)} ครั้ง)",
        )

    # ถูกต้อง
    otp_record.is_used = True
    user.is_verified = True
    db.commit()

    return {"message": "ยืนยันตัวตนสำเร็จ สามารถเข้าสู่ระบบได้แล้ว"}


@router.post("/resend-otp")
def resend_otp(payload: schemas.OtpResendRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        # ไม่บอกตรงๆ ว่าอีเมลนี้ไม่มีในระบบ เพื่อกัน user enumeration
        return {"message": "หากอีเมลนี้อยู่ในระบบ เราได้ส่ง OTP ใหม่ไปให้แล้ว"}

    if user.is_verified:
        return {"message": "บัญชีนี้ยืนยันตัวตนไปแล้ว ไม่จำเป็นต้องขอ OTP อีก"}

    lockout_key = f"resend_otp_{payload.email}"

    # [Lockout ใหม่]: ขอ resend ได้ 3 ครั้ง / ล็อก 5 นาที (นับทุกครั้งที่เรียกถึงจุดนี้
    # เฉพาะ user ที่มีอยู่จริงและยังไม่ verify เท่านั้น — ตามตำแหน่งเดิมของ check_rate_limit)
    check_and_record(db, lockout_key, "resend_otp", limit=RESEND_OTP_LOCKOUT_LIMIT, window_minutes=RESEND_OTP_LOCKOUT_MINUTES)

    # [Cooldown]: ห้ามขอถี่กว่า 60 วิ ต่อครั้ง — เช็คจาก record เดียวของ (user, purpose) นี้ (มีแค่แถวเดียวเสมอ)
    latest_otp = (
        db.query(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == REGISTER_PURPOSE,
        )
        .first()
    )
    if latest_otp:
        elapsed = (datetime.now(timezone.utc) - latest_otp.created_at).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_more = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            # detail เป็น dict (เหมือน check_lockout) ให้ frontend อ่าน retry_after_seconds
            # ไปนับถอยหลัง/disable ปุ่ม "ส่ง OTP อีกครั้ง" ได้ตรงเวลาจริง แทนที่จะ parse ข้อความเอา
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"กรุณารออีก {wait_more} วินาทีก่อนขอ OTP ใหม่",
                    "retry_after_seconds": max(1, wait_more),
                },
            )

    try:
        otp_record = _create_and_send_otp(db, user)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

    return {
        "message": "ส่ง OTP ใหม่ไปยังอีเมลของคุณแล้ว",
        "otp_expires_at": otp_record.expires_at,
        "otp_expires_in_seconds": OTP_EXPIRE_MINUTES * 60,
    }


@router.post("/login", response_model=schemas.Token)
def login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    client_ip = request.client.host

    normalized_email = form_data.username.strip().lower()
    lockout_key = f"login_fail_{normalized_email}_{client_ip}"

    # [Lockout ใหม่]: เช็คก่อนว่าโดนล็อกอยู่ไหม — ถ้าล็อกอยู่ บล็อกทันทีไม่ว่ารหัสผ่านที่กรอก
    # มาจะถูกหรือผิดก็ตาม (ไม่ทัน verify_password เลยด้วยซ้ำ ประหยัด bcrypt cycle)
    check_lockout(db, lockout_key, "login_fail", limit=LOGIN_LOCKOUT_LIMIT, window_minutes=LOGIN_LOCKOUT_MINUTES)

    user = db.query(models.User).filter(models.User.email == normalized_email).first()

    if not user or not verify_password(form_data.password, user.hashed_password):
        # นับเฉพาะตอนพลาดเท่านั้น — พอแตะ limit พอดี จะรีเซ็ตนาฬิกาเต็ม 5 นาทีให้อัตโนมัติ
        record_attempt(db, lockout_key, "login_fail", limit=LOGIN_LOCKOUT_LIMIT, window_minutes=LOGIN_LOCKOUT_MINUTES)
        raise HTTPException(status_code=401, detail="อีเมลหรือรหัสผ่านไม่ถูกต้อง")

    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="กรุณายืนยันอีเมลด้วย OTP ก่อนเข้าสู่ระบบ",
        )

    # login สำเร็จ -> ล้างประวัติพลาดทิ้ง ไม่ต้องรอ window หมดอายุเอง
    clear_lockout(db, lockout_key, "login_fail")

    access_token = create_access_token(data={"sub": user.email})

    # ออก refresh token ใบใหม่ (family ใหม่ทั้งสาย) ใส่ httpOnly cookie ให้เลย
    plain_refresh_token = _issue_refresh_token(db, user)
    _set_refresh_cookie(response, plain_refresh_token)

    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/refresh", response_model=schemas.Token)
def refresh_access_token(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    """
    ออก access token ใบใหม่จาก refresh token ใน httpOnly cookie — เรียกตอนแอปโหลดขึ้นมาใหม่
    (เช่น กด refresh หน้าเว็บ) หรือตอน access token หมดอายุ (15 นาที) แทนที่จะบังคับ login ใหม่
    Frontend ต้องเรียกด้วย credentials ที่แนบ cookie ไปด้วยเสมอ (เช่น fetch(..., {credentials: "include"}))

    Rotate ทุกครั้งที่เรียกสำเร็จ: refresh token ใบเก่าถูก revoke ทันที ออกใบใหม่แทนที่ใน cookie
    (ใน family เดิม) ป้องกัน token ใบเดียวถูกใช้ซ้ำได้ไม่จำกัดจนกว่าจะหมดอายุ

    Reuse detection: ถ้า token ที่ส่งมาถูก revoke ไปแล้วก่อนหน้า (เช่น โดนขโมยไปใช้ซ้ำหลัง
    เจ้าของตัวจริง refresh ไปแล้ว หรือใครเอา cookie เก่าที่ถูกแทนที่แล้วมายิงซ้ำ) ถือเป็นสัญญาณ
    ว่า token หลุด -> revoke ทั้ง family ทันที บังคับ login ใหม่ทั้งหมดทุกอุปกรณ์

    หมายเหตุ: "ไม่แตะ" — ยังใช้ check_rate_limit เดิม (fixed window) เพราะเป็นการกันสแปมยิง
    endpoint นี้รัวๆ เท่านั้น ไม่ใช่การเดา secret (token มาจาก cookie ไม่ใช่ค่าที่ user พิมพ์เดาได้)
    """
    invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token ไม่ถูกต้องหรือหมดอายุ กรุณาเข้าสู่ระบบใหม่อีกครั้ง",
    )

    if not refresh_token:
        raise invalid_exception

    client_ip = request.client.host
    # [Rate limit — ของเดิม]: กันยิง /auth/refresh รัวๆ — 30 ครั้ง/ชม./IP
    check_rate_limit(db, f"refresh_token_{client_ip}", "refresh_token", limit=30, window_minutes=60)

    token_hash = hash_refresh_token(refresh_token)
    record = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()

    if not record:
        _clear_refresh_cookie(response)
        raise invalid_exception

    now = datetime.now(timezone.utc)

    if record.is_revoked:
        # ใบนี้เคยถูก rotate ทิ้งไปแล้ว แต่มีคนเอามาใช้ซ้ำ -> สัญญาณ token หลุด revoke ทั้งสายทันที
        _revoke_token_family(db, record.family_id)
        _clear_refresh_cookie(response)
        raise invalid_exception

    if now > record.expires_at:
        _clear_refresh_cookie(response)
        raise invalid_exception

    user = db.query(models.User).filter(models.User.id == record.user_id).first()
    if not user or not user.is_verified:
        _clear_refresh_cookie(response)
        raise invalid_exception

    # Rotate: ปิดใบเก่า ออกใบใหม่ใน family เดิม
    record.is_revoked = True
    db.commit()

    new_plain_token = _issue_refresh_token(db, user, family_id=record.family_id)
    _set_refresh_cookie(response, new_plain_token)

    new_access_token = create_access_token(data={"sub": user.email})
    return {"access_token": new_access_token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Forgot Password — flow A: forgot-password -> verify-reset-otp -> reset-password
# แต่ละขั้นตอนมี lockout/rate limit ของตัวเอง แยกจากกัน
# ---------------------------------------------------------------------------

@router.post("/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    generic_message = {"message": "หากอีเมลนี้อยู่ในระบบ เราได้ส่ง OTP สำหรับตั้งรหัสผ่านใหม่ไปให้แล้ว"}

    if not user:
        # ไม่บอกตรงๆ ว่าอีเมลนี้ไม่มีในระบบ เพื่อกัน user enumeration (เหมือน resend-otp)
        return generic_message

    if not user.is_verified:
        # บัญชีที่ยังไม่ verify ไม่มีทางตั้งรหัสผ่านใหม่ได้อยู่แล้ว (login ไม่ได้ตั้งแต่แรก)
        # ตอบ generic message เหมือนเดิม ไม่บอกสถานะบัญชีให้ผู้ไม่หวังดีรู้
        return generic_message

    lockout_key = f"forgot_password_{payload.email}"

    # [Lockout ใหม่]: ขอ OTP รีเซ็ตรหัสผ่านได้ 5 ครั้ง / ล็อก 5 นาที (นับทุกครั้งที่เรียกถึงจุดนี้
    # เฉพาะ user จริงที่ verify แล้วเท่านั้น — ตามตำแหน่งเดิมของ check_rate_limit)
    check_and_record(db, lockout_key, "forgot_password", limit=FORGOT_PASSWORD_LOCKOUT_LIMIT, window_minutes=FORGOT_PASSWORD_LOCKOUT_MINUTES)

    # [Cooldown]: ห้ามขอถี่กว่า 60 วิ ต่อครั้ง — เช็คจาก record เดียวของ (user, purpose) นี้ (มีแค่แถวเดียวเสมอ)
    latest_otp = (
        db.query(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == PASSWORD_RESET_PURPOSE,
        )
        .first()
    )
    if latest_otp:
        elapsed = (datetime.now(timezone.utc) - latest_otp.created_at).total_seconds()
        if elapsed < OTP_RESEND_COOLDOWN_SECONDS:
            wait_more = int(OTP_RESEND_COOLDOWN_SECONDS - elapsed)
            # เหมือนจุด cooldown ใน resend_otp ด้านบน — detail เป็น dict พร้อม retry_after_seconds
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail={
                    "message": f"กรุณารออีก {wait_more} วินาทีก่อนขอ OTP ใหม่",
                    "retry_after_seconds": max(1, wait_more),
                },
            )

    try:
        otp_record = _create_and_send_otp(db, user, purpose=PASSWORD_RESET_PURPOSE)
    except RuntimeError as e:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(e))

    return {
        **generic_message,
        "otp_expires_at": otp_record.expires_at,
        "otp_expires_in_seconds": OTP_EXPIRE_MINUTES * 60,
    }


@router.post("/verify-reset-otp", response_model=schemas.ResetTokenResponse)
def verify_reset_otp(payload: schemas.VerifyResetOtpRequest, request: Request, db: Session = Depends(get_db)):
    # หมายเหตุ: endpoint นี้ "ไม่แตะ" ตามที่ตกลงกันไว้ — ยังใช้ check_rate_limit เดิม
    # (5 ครั้ง/15 นาที ต่อ email+IP) ร่วมกับ attempt_count/is_used ในตัว OtpVerification
    # record เอง (มาตรฐาน 2 ชั้นสำหรับป้องกันการเดา OTP อยู่แล้ว ไม่ต้องเพิ่ม lockout ซ้อน)
    client_ip = request.client.host

    # [Rate limit — ของเดิม]: กันไล่เดา OTP ถี่ๆ ผ่าน endpoint นี้ — 5 ครั้ง/15 นาที/อีเมล+IP
    # (แยกจาก attempt_count ในตัว record เอง ซึ่งจำกัดต่อ OTP หนึ่งใบ ส่วนอันนี้จำกัดภาพรวมของ endpoint)
    check_rate_limit(
        db,
        f"verify_reset_otp_{payload.email}_{client_ip}",
        "verify_reset_otp",
        limit=5,
        window_minutes=15,
    )

    user = db.query(models.User).filter(models.User.email == payload.email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OTP ไม่ถูกต้องหรือหมดอายุ")

    otp_record = (
        db.query(models.OtpVerification)
        .filter(
            models.OtpVerification.user_id == user.id,
            models.OtpVerification.purpose == PASSWORD_RESET_PURPOSE,
        )
        .first()
    )

    if not otp_record or otp_record.is_used:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่พบ OTP ที่ใช้งานได้ กรุณาขอ OTP ใหม่",
        )

    now = datetime.now(timezone.utc)
    if now > otp_record.expires_at:
        otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OTP หมดอายุแล้ว กรุณาขอ OTP ใหม่",
        )

    if otp_record.attempt_count >= OTP_MAX_ATTEMPTS:
        otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="กรอก OTP ผิดเกินจำนวนครั้งที่กำหนด กรุณาขอ OTP ใหม่",
        )

    if not verify_otp(payload.otp, otp_record.otp_hash):
        otp_record.attempt_count += 1
        remaining = OTP_MAX_ATTEMPTS - otp_record.attempt_count
        if remaining <= 0:
            otp_record.is_used = True
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTP ไม่ถูกต้อง (เหลือโอกาสกรอกอีก {max(remaining, 0)} ครั้ง)",
        )

    # ถูกต้อง — ปิด OTP นี้ทันที (ใช้ครั้งเดียว) แล้วออก reset token อายุสั้นแทน
    otp_record.is_used = True
    db.commit()

    reset_token = create_password_reset_token(user.email)
    return schemas.ResetTokenResponse(reset_token=reset_token)


@router.post("/reset-password")
def reset_password(payload: schemas.ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    # ตรวจ token ก่อน (ได้ email กลับมาถ้าถูกต้อง) — token หมดอายุ/ปลอม จะ raise ในนี้เลย
    email = decode_password_reset_token(payload.reset_token)

    client_ip = request.client.host
    lockout_key = f"reset_password_{email}_{client_ip}"

    # [Lockout ใหม่]: กันยิง reset-password รัวๆ ด้วย token ที่หลุด/เดา — 5 ครั้ง / ล็อก 5 นาที
    # / อีเมล+IP (นับทุกครั้งที่ decode token ผ่านมาถึงจุดนี้แล้ว)
    check_and_record(db, lockout_key, "reset_password", limit=RESET_PASSWORD_LOCKOUT_LIMIT, window_minutes=RESET_PASSWORD_LOCKOUT_MINUTES)

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ไม่พบผู้ใช้นี้ในระบบ")

    user.hashed_password = get_password_hash(payload.new_password)
    db.commit()

    # เปลี่ยนรหัสผ่านแล้ว ถือว่า session เก่าทั้งหมดไม่ควรใช้ต่อได้ (เผื่อรหัสผ่านหลุดไปพร้อม
    # refresh token เก่า) revoke refresh token ทุกใบของ user คนนี้ที่ยังไม่ revoke
    active_families = (
        db.query(models.RefreshToken.family_id)
        .filter(
            models.RefreshToken.user_id == user.id,
            models.RefreshToken.is_revoked == False,  # noqa: E712
        )
        .distinct()
        .all()
    )
    for (family_id,) in active_families:
        _revoke_token_family(db, family_id)

    return {"message": "ตั้งรหัสผ่านใหม่สำเร็จ กรุณาเข้าสู่ระบบด้วยรหัสผ่านใหม่"}

@router.post("/logout")
def logout(
    response: Response,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
    refresh_token: str | None = Cookie(default=None, alias=REFRESH_TOKEN_COOKIE_NAME),
):
    """Revoke access token ปัจจุบัน (blacklist ทันทีผ่าน jti) + revoke refresh token ทั้ง family
    (ไม่ใช่แค่ใบที่ถืออยู่ กันใบเก่าที่เคย rotate ไปแล้วแต่ยังไม่หมดอายุหลุดรอด) แล้ว clear cookie
    หลัง logout token ทั้งคู่ใช้ต่อไม่ได้อีกทันที แม้จะยังไม่หมดอายุตามปกติ"""
    revoke_token(db, token)

    if refresh_token:
        token_hash = hash_refresh_token(refresh_token)
        record = db.query(models.RefreshToken).filter(models.RefreshToken.token_hash == token_hash).first()
        if record:
            _revoke_token_family(db, record.family_id)

    _clear_refresh_cookie(response)

    return {"message": "ออกจากระบบเรียบร้อยแล้ว"}

@router.get("/me", response_model=schemas.UserMeResponse)
def get_me(current_user: models.User = Depends(get_current_user)):
    """
    เช็คสถานะบัญชีตัวเองแบบ read-only — ใช้แทนการเดาจาก localStorage ฝั่ง frontend
    (เช่น terms gate ไม่ต้องเด้ง modal ซ้ำถ้าเช็คจาก endpoint นี้แล้วว่า terms_accepted=True จริง
    ข้ามเบราว์เซอร์/เครื่องก็ยังแม่นยำ เพราะอิงจาก DB ไม่ใช่ local storage)
    ไม่มี dependency chain (ไม่ต้อง terms/access approved) เพราะจุดประสงค์คือใช้เช็ค "ก่อน" ตัดสินใจ
    เปิด terms modal หรือไม่ ถ้าบังคับ require_terms_accepted ในนี้ด้วยจะ deadlock ตรรกะ

    เพิ่ม is_suspended/suspended_reason: ใช้ฝั่ง frontend แสดง suspend banner ค้างบน dashboard
    ตราบใดที่ยังถูกระงับอยู่ (login ยัง allow ปกติ เช็คสถานะนี้ได้ก็ต่อเมื่อเข้ามาถึง dashboard
    แล้วเรียก endpoint นี้เท่านั้น ไม่ได้เช็คตั้งแต่หน้า login form)
    """
    return schemas.UserMeResponse(
        email=current_user.email,
        is_verified=current_user.is_verified,
        terms_accepted=current_user.terms_accepted,
        is_admin=current_user.is_admin,
        has_api_key=current_user.api_key_hash is not None,
        is_suspended=current_user.is_suspended,
        suspended_reason=current_user.suspended_reason,
    )