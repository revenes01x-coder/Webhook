from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from smartlpr.database import get_db
from smartlpr.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, PASSWORD_RESET_TOKEN_EXPIRE_MINUTES, CAPTURE_EVENT_SECRET
from services.token import hash_api_key
from smartlpr import models
import uuid
import hmac

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "jti": uuid.uuid4().hex})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_password_reset_token(email: str) -> str:
    """Token ชั่วคราวอายุสั้น (นาที) ออกให้หลัง verify OTP สำเร็จ เพื่อยืนยันสิทธิ์ตั้งรหัสผ่านใหม่
    มี claim purpose='password_reset' แยกจาก access token ปกติ กัน token คนละประเภทเอามาใช้แทนกัน

    มี jti เหมือน access token (create_access_token) — เพื่อให้ single-use ได้: หลังใช้
    ตั้งรหัสผ่านสำเร็จ 1 ครั้ง routers/auth.py:reset_password จะเรียก revoke_token(db, token)
    บันทึก jti นี้ลง revoked_tokens ทันที ป้องกันเอา token ใบเดิมมาใช้ตั้งรหัสผ่านซ้ำได้อีก
    ในช่วงที่ยังไม่หมดอายุตามเวลา"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    to_encode = {
        "sub": email,
        "purpose": "password_reset",
        "exp": expire,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def decode_password_reset_token(token: str, db: AsyncSession) -> str:
    """ตรวจ token จาก create_password_reset_token คืน email ถ้าถูกต้อง ไม่งั้น raise HTTPException

    [Async Migration]: เดิม sync ตอนนี้ async เพราะข้างในเรียก is_token_revoked() ที่ query DB
    ต้อง await ทั้งฟังก์ชันนี้และ caller (routers/auth.py: reset_password) เลยต้อง await ตาม"""
    invalid_exception = HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="ลิงก์/token สำหรับตั้งรหัสผ่านใหม่ไม่ถูกต้องหรือหมดอายุ กรุณาขอ OTP ใหม่อีกครั้ง",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise invalid_exception

    if payload.get("purpose") != "password_reset":
        raise invalid_exception

    email = payload.get("sub")
    jti = payload.get("jti")
    if not email or not jti:
        raise invalid_exception

    if await is_token_revoked(db, jti):
        raise invalid_exception

    return email


async def revoke_token(db: AsyncSession, token: str) -> None:
    """ถอด jti + exp ออกจาก token แล้วบันทึกลง revoked_tokens
    Idempotent: ถ้า jti นี้ถูก revoke ไปแล้ว (เช่นกด logout ซ้ำ) ไม่ error
    token ที่ decode ไม่ผ่าน หรือไม่มี jti/exp จะเงียบๆ ไม่ทำอะไร

    ใช้ร่วมกันทั้ง access token (logout) และ password reset token (reset-password สำเร็จ)"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return

    result = await db.execute(select(models.RevokedToken).filter(models.RevokedToken.jti == jti))
    existing = result.scalar_one_or_none()
    if existing:
        return

    db.add(models.RevokedToken(
        jti=jti,
        revoked_expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
    ))
    await db.commit()


async def is_token_revoked(db: AsyncSession, jti: str | None) -> bool:
    if not jti:
        return False
    result = await db.execute(select(models.RevokedToken).filter(models.RevokedToken.jti == jti))
    return result.scalar_one_or_none() is not None


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="ไม่สามารถยืนยันตัวตนได้ (Token อาจหมดอายุ)",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        jti: str | None = payload.get("jti")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if await is_token_revoked(db, jti):
        raise credentials_exception

    result = await db.execute(select(models.User).filter(models.User.email == email))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    return user


# ---------------------------------------------------------------------------
# Dependency chain ตามลำดับที่ตกลงกันไว้:
#   login (is_verified) -> require_terms_accepted -> require_access_approved
#
# หมายเหตุ: is_suspended ไม่ถูกเช็คใน get_current_user ตั้งใจ — user ที่ถูกระงับ
# ยัง login/ดูข้อมูลของตัวเองได้ปกติ แต่จะถูกบล็อกเฉพาะตอนทำ action สำคัญ ผ่าน
# require_access_approved (เพิ่ม webhook, ขอ/regenerate API key) และ require_api_key
# (ระบบอัตโนมัติของ user ยิงเข้ามาเอง เช่น POST /my/cameras) เท่านั้น
#
# [Async Migration]: require_admin, require_terms_accepted ไม่แตะ DB เลย (แค่เช็ค attribute
# ของ current_user ที่ get_current_user โหลดมาให้แล้ว) จึงยังเป็น sync def ได้ตามเดิม —
# FastAPI รองรับ dependency chain ที่ผสม sync/async ปนกันได้ปกติ (sync ตัวไหนไม่มี I/O ก็
# รันเร็วอยู่แล้ว ไม่จำเป็นต้องแปลงเป็น async ทุกจุด)
# ---------------------------------------------------------------------------

def require_admin(current_user: models.User = Depends(get_current_user)) -> models.User:
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="เฉพาะผู้ดูแลระบบเท่านั้นที่เข้าถึงส่วนนี้ได้",
        )
    return current_user


def require_terms_accepted(
    current_user: models.User = Depends(get_current_user),
) -> models.User:
    if not current_user.terms_accepted:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="กรุณายอมรับข้อตกลงการใช้งานก่อน",
        )
    return current_user


async def require_access_approved(
    current_user: models.User = Depends(require_terms_accepted),
    db: AsyncSession = Depends(get_db),
) -> models.User:
    # [Suspend Guard]: user ที่ถูก admin ระงับ ทำ action สำคัญ (เพิ่ม webhook, ขอ/regenerate
    # API key) ไม่ได้ ถึงแม้จะเคยผ่าน terms + access approved มาแล้วก็ตาม — login ยังทำได้ปกติ
    # เพราะเช็คจุดนี้ ไม่ใช่ใน get_current_user
    if current_user.is_suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="บัญชีนี้ถูกระงับการใช้งานชั่วคราว กรุณาติดต่อผู้ดูแลระบบ",
        )

    result = await db.execute(
        select(models.AccessRequest).filter(
            models.AccessRequest.user_id == current_user.id,
            models.AccessRequest.status == "approved",
        )
    )
    approved = result.scalar_one_or_none()
    if not approved:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="บัญชีนี้ยังไม่ได้รับอนุมัติให้ใช้งานส่วนนี้ กรุณารอ Admin อนุมัติคำขอใช้งาน",
        )
    return current_user

# ---------------------------------------------------------------------------
# API Key auth — สำหรับระบบอัตโนมัติของ user (ไม่ใช่ user นั่ง login เอง)
# ใช้กับ endpoint ที่ระบบภายนอกยิงเข้ามาแบบไม่มีคนกด เช่น POST /my/cameras
# ---------------------------------------------------------------------------

async def require_api_key(
    x_api_key: str = Header(..., description="API key ที่ได้จาก POST /my/api-key/regenerate"),
    db: AsyncSession = Depends(get_db),
) -> models.User:
    """เช็ค header X-API-Key เทียบกับ User.api_key_hash โดย hash ที่ส่งมาแล้ว query ตรงๆ
    (deterministic hash เลย query ได้เลย ไม่ต้อง loop เทียบทีละ user)"""
    invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API key ไม่ถูกต้อง",
        headers={"WWW-Authenticate": "API-Key"},
    )

    if not x_api_key:
        raise invalid_exception

    hashed = hash_api_key(x_api_key)
    result = await db.execute(select(models.User).filter(models.User.api_key_hash == hashed))
    user = result.scalar_one_or_none()
    if not user:
        raise invalid_exception

    # [Suspend Guard]: user ที่ถูกระงับ ห้ามยิง API key เข้ามาเพิ่มกล้องใหม่ (POST /my/cameras)
    # ต่างจาก invalid key ตรงที่ key ถูกต้อง แต่บัญชีถูกล็อกไว้ชั่วคราว -> 403 ไม่ใช่ 401
    if user.is_suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="บัญชีนี้ถูกระงับการใช้งานชั่วคราว",
            headers={"WWW-Authenticate": "API-Key"},
        )

    return user

def require_capture_event_secret(
    x_capture_secret: str = Header(..., alias="X-Capture-Secret"),
) -> None:
    """ยืนยันว่า POST /capture-event มาจาก camera_worker.py ของระบบเราเองเท่านั้น
    ใช้ hmac.compare_digest กัน timing attack เหมือน verify_otp/verify_api_key
    (ไม่แตะ DB เลย จึงไม่จำเป็นต้องเป็น async)"""
    if not hmac.compare_digest(x_capture_secret, CAPTURE_EVENT_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ไม่ได้รับอนุญาต",
        )