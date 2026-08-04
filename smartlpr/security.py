from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status, Header
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from smartlpr.database import get_db
from smartlpr.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, PASSWORD_RESET_TOKEN_EXPIRE_MINUTES
from services.token import hash_api_key
from smartlpr import models
import uuid 

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
    มี claim purpose='password_reset' แยกจาก access token ปกติ กัน token คนละประเภทเอามาใช้แทนกัน"""
    expire = datetime.now(timezone.utc) + timedelta(minutes=PASSWORD_RESET_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": email, "purpose": "password_reset", "exp": expire}
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_password_reset_token(token: str) -> str:
    """ตรวจ token จาก create_password_reset_token คืน email ถ้าถูกต้อง ไม่งั้น raise HTTPException"""
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
    if not email:
        raise invalid_exception

    return email

def revoke_token(db: Session, token: str) -> None:
    """ถอด jti + exp ออกจาก token แล้วบันทึกลง revoked_tokens
    Idempotent: ถ้า jti นี้ถูก revoke ไปแล้ว (เช่นกด logout ซ้ำ) ไม่ error
    token ที่ decode ไม่ผ่าน หรือไม่มี jti/exp (token เก่าก่อน deploy ฟีเจอร์นี้) จะเงียบๆ ไม่ทำอะไร
    เพราะ token แบบนั้นใช้ไม่ได้อยู่แล้ว หรือปล่อยให้หมดอายุเองตามปกติ"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return

    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return

    existing = db.query(models.RevokedToken).filter(models.RevokedToken.jti == jti).first()
    if existing:
        return

    db.add(models.RevokedToken(
        jti=jti,
        revoked_expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
    ))
    db.commit()


def is_token_revoked(db: Session, jti: str | None) -> bool:
    if not jti:
        return False
    return db.query(models.RevokedToken).filter(models.RevokedToken.jti == jti).first() is not None


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
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

    if is_token_revoked(db, jti):
        raise credentials_exception

    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None:
        raise credentials_exception
    return user


# ---------------------------------------------------------------------------
# Dependency chain ตามลำดับที่ตกลงกันไว้:
#   login (is_verified) -> require_terms_accepted -> require_access_approved
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


def require_access_approved(
    current_user: models.User = Depends(require_terms_accepted),
    db: Session = Depends(get_db),
) -> models.User:
    approved = (
        db.query(models.AccessRequest)
        .filter(
            models.AccessRequest.user_id == current_user.id,
            models.AccessRequest.status == "approved",
        )
        .first()
    )
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

def require_api_key(
    x_api_key: str = Header(..., description="API key ที่ได้จาก POST /my/api-key/regenerate"),
    db: Session = Depends(get_db),
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
    user = db.query(models.User).filter(models.User.api_key_hash == hashed).first()
    if not user:
        raise invalid_exception

    return user
