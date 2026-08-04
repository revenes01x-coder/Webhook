import re
from pydantic import BaseModel, EmailStr, HttpUrl, Field, field_validator, model_validator
from datetime import datetime
from typing import Optional, Literal

from smartlpr.pagination import PaginatedResponse  # re-export ให้เรียกผ่าน schemas.PaginatedResponse ได้เหมือนโมเดลอื่น

_PASSWORD_ALLOWED_RE = re.compile(r"^[A-Za-z0-9]+$")
_OTP_RE = re.compile(r"^\d{6}$")

# bcrypt (ที่ใช้ผ่าน passlib ใน security.py) ตัดรหัสผ่านทิ้งอัตโนมัติถ้ายาวเกิน 72 bytes
# ทำให้รหัสผ่านยาวๆ ที่ต่างกันแค่ท้ายๆ กลายเป็น hash เดียวกันแบบเงียบๆ
# เลยบังคับ max length ไว้ตรงนี้กันตั้งแต่ชั้น validation ไม่ให้ผู้ใช้ตั้งรหัสผ่านที่ยาวเกินจริง
PASSWORD_MAX_LENGTH = 72


def _validate_password_rules(v: str) -> str:
    """กติการหัสผ่านกลาง ใช้ร่วมกันทั้งตอนสมัคร (UserCreate) และตั้งรหัสผ่านใหม่ (ResetPasswordRequest)"""
    v = v.strip()
    errors = []

    if len(v) < 8:
        errors.append("ต้องมีความยาวอย่างน้อย 8 ตัวอักษร")

    if len(v) > PASSWORD_MAX_LENGTH:
        errors.append(f"ต้องมีความยาวไม่เกิน {PASSWORD_MAX_LENGTH} ตัวอักษร")

    if not _PASSWORD_ALLOWED_RE.match(v):
        errors.append(
            "ใช้ได้เฉพาะตัวอักษรภาษาอังกฤษ (a-z, A-Z) และตัวเลข (0-9) เท่านั้น "
            "(ห้ามภาษาไทย เว้นวรรค หรืออักขระพิเศษ)"
        )
    else:
        if not any(ch.isalpha() for ch in v):
            errors.append("ต้องมีตัวอักษรภาษาอังกฤษอย่างน้อย 1 ตัว")
        if not any(ch.isdigit() for ch in v):
            errors.append("ต้องมีตัวเลขอย่างน้อย 1 ตัว")

    if errors:
        raise ValueError("รหัสผ่านไม่ถูกต้อง: " + ", ".join(errors))

    return v


# ---- สำหรับการสมัครสมาชิกและเข้าสู่ระบบ ----
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(
        ...,
        max_length=PASSWORD_MAX_LENGTH,
        description=(
            f"รหัสผ่านต้องมีความยาว 8-{PASSWORD_MAX_LENGTH} ตัวอักษร "
            "ใช้ได้เฉพาะตัวอักษรภาษาอังกฤษ (a-z, A-Z) และตัวเลข (0-9) เท่านั้น "
            "และต้องมีทั้งตัวอักษรภาษาอังกฤษอย่างน้อย 1 ตัว และตัวเลขอย่างน้อย 1 ตัว "
            "(ห้ามภาษาไทย เว้นวรรค หรืออักขระพิเศษ)"
        ),
        examples=["Passw0rd"],
    )
    confirm_password: str = Field(
        ...,
        max_length=PASSWORD_MAX_LENGTH,
        description="กรอกรหัสผ่านซ้ำอีกครั้งเพื่อยืนยัน ต้องตรงกับ password",
    )

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        if not v.isascii():
            raise ValueError("อีเมลต้องเป็นภาษาอังกฤษ (a-z, A-Z, 0-9 และสัญลักษณ์มาตรฐาน) เท่านั้น")
        return v.strip().lower()

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        return _validate_password_rules(v)

    @model_validator(mode="after")
    def passwords_must_match(self):
        if self.password != self.confirm_password:
            raise ValueError("รหัสผ่านและรหัสผ่านยืนยันไม่ตรงกัน")
        return self


class Token(BaseModel):
    access_token: str
    token_type: str


# ---- สำหรับ OTP verification ----
class OtpVerifyRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        v = v.strip()
        if not _OTP_RE.match(v):
            raise ValueError("OTP ต้องเป็นตัวเลข 6 หลัก")
        return v


class OtpResendRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


# ---- สำหรับ Forgot Password (flow A: forgot -> verify-reset-otp -> reset-password) ----
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class VerifyResetOtpRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()

    @field_validator("otp")
    @classmethod
    def validate_otp_format(cls, v: str) -> str:
        v = v.strip()
        if not _OTP_RE.match(v):
            raise ValueError("OTP ต้องเป็นตัวเลข 6 หลัก")
        return v


class ResetTokenResponse(BaseModel):
    reset_token: str
    message: str = "ยืนยัน OTP สำเร็จ กรุณาตั้งรหัสผ่านใหม่ภายในเวลาที่กำหนด"


class ResetPasswordRequest(BaseModel):
    reset_token: str
    new_password: str = Field(..., max_length=PASSWORD_MAX_LENGTH, examples=["Passw0rd"])
    confirm_new_password: str = Field(
        ...,
        max_length=PASSWORD_MAX_LENGTH,
        description="กรอกรหัสผ่านใหม่ซ้ำอีกครั้งเพื่อยืนยัน ต้องตรงกับ new_password",
    )

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v: str) -> str:
        return _validate_password_rules(v)

    @model_validator(mode="after")
    def passwords_must_match(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("รหัสผ่านใหม่และรหัสผ่านยืนยันไม่ตรงกัน")
        return self


# ---- สำหรับ Webhook ----
class WebhookCreate(BaseModel):
    url: HttpUrl


class WebhookResponse(BaseModel):
    id: int
    url: str
    is_active: bool
    is_healthy: bool
    consecutive_dead_letters: int
    created_at: datetime

    class Config:
        from_attributes = True


# ---- สำหรับ Access Request (step 3) ----
class AccessRequestCreate(BaseModel):
    organization_name: str = Field(..., min_length=1, max_length=200)
    contact_email: EmailStr
    use_case: str = Field(..., min_length=1, max_length=2000)
    contact_phone: str = Field(..., min_length=1, max_length=30)
    contact_name: str = Field(..., min_length=1, max_length=200)

    @field_validator("organization_name", "use_case", "contact_phone", "contact_name")
    @classmethod
    def strip_and_require_nonblank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v

    @field_validator("contact_email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.strip().lower()


class AccessRequestResponse(BaseModel):
    id: int
    organization_name: str
    contact_email: str
    use_case: str
    contact_phone: str
    contact_name: str
    status: str
    admin_note: Optional[str] = None
    submitted_at: datetime
    reviewed_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ReviewDecision(BaseModel):
    """ใช้ร่วมกันสำหรับ endpoint 'review' (approve/reject รวมเป็นตัวเดียว) ทั้ง
    access-request และ camera-request — admin_note ไม่บังคับ (ใส่เฉพาะตอน reject ก็ได้)"""
    decision: Literal["approve", "reject"]
    admin_note: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("admin_note")
    @classmethod
    def strip_note(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        return v or None  # ถ้าพิมพ์แต่ space ให้ถือว่าไม่ได้ใส่


# ---- สำหรับ Camera — user เพิ่มกล้องของตัวเอง (เจ้าของคนเดียว, active ทันที) ----
_CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class CameraSelfCreate(BaseModel):
    camera_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="รหัสกล้องที่คุณกำหนดเอง ใช้ตั้งค่าฝั่งอุปกรณ์กล้องจริงได้เลย ต้องไม่ซ้ำกับกล้องอื่นในระบบ",
        examples=["cam-front-gate-01"],
    )
    camera_url: str = Field(
        ...,
        min_length=1,
        max_length=500,
        description="ลิงก์ RTSP ของกล้อง ต้องขึ้นต้นด้วย rtsp:// เท่านั้น",
    )

    @field_validator("camera_id")
    @classmethod
    def validate_camera_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        if not _CAMERA_ID_RE.match(v):
            raise ValueError("camera_id ใช้ได้เฉพาะตัวอักษรภาษาอังกฤษ ตัวเลข ขีดกลาง (-) และขีดล่าง (_) เท่านั้น")
        return v

    @field_validator("camera_url")
    @classmethod
    def validate_rtsp_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        if not v.lower().startswith("rtsp://"):
            raise ValueError("ลิงก์กล้องไม่ถูกต้อง: ต้องขึ้นต้นด้วย rtsp:// เท่านั้น")
        return v


class CameraResponse(BaseModel):
    """สำหรับ user ทั่วไป — ไม่โชว์ rtsp_url เพราะเป็นข้อมูล sensitive ของกล้อง"""
    id: str
    is_active: bool
    verification_status: str  # pending / verified / failed
    created_at: datetime

    class Config:
        from_attributes = True


class CameraAdminResponse(CameraResponse):
    """สำหรับ admin เท่านั้น — เห็น rtsp_url และเจ้าของกล้องได้"""
    rtsp_url: str
    owner_user_id: int


class CameraStatusUpdate(BaseModel):
    is_active: bool


class MyCameraResponse(BaseModel):
    """สำหรับ GET /my/cameras — กล้องของตัวเอง ไม่โชว์ rtsp_url
    verification_status: 'pending' = กำลังตรวจสอบ RTSP อยู่เบื้องหลัง, 'verified' = ต่อ stream ได้จริง,
    'failed' = ต่อไม่ได้ (เช็ค URL อีกครั้ง)"""
    camera_id: str
    is_active: bool
    verification_status: str
    created_at: datetime


# ---- สำหรับ In-app Notification ของ admin ----
class AdminNotificationResponse(BaseModel):
    id: int
    request_type: str
    request_id: int
    message: str
    is_read: bool
    resolved_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---- สำหรับ API Key (ระบบอัตโนมัติของ user ใช้แทน JWT ตอนยิงเข้ามาเอง) ----
class ApiKeyResponse(BaseModel):
    api_key: str
    message: str = "กรุณาเก็บ API key นี้ไว้ให้ปลอดภัย ระบบจะไม่แสดงค่านี้ให้เห็นอีกครั้ง"


class ApiKeyStatusResponse(BaseModel):
    has_api_key: bool

# ---- สำหรับ GET /auth/me — เช็คสถานะ user แบบ read-only (terms/admin/api-key) ----
class UserMeResponse(BaseModel):
    email: str
    is_verified: bool
    terms_accepted: bool
    is_admin: bool
    has_api_key: bool

    class Config:
        from_attributes = True