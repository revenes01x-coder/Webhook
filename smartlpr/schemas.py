import re
from pydantic import BaseModel, EmailStr, HttpUrl, Field, field_validator, model_validator
from datetime import datetime
from typing import Optional, Literal, List

from smartlpr.pagination import PaginatedResponse  # re-export ให้เรียกผ่าน schemas.PaginatedResponse ได้เหมือนโมเดลอื่น

_OTP_RE = re.compile(r"^\d{6}$")

PASSWORD_MAX_BYTES = 72
PASSWORD_MIN_LENGTH = 8

# จำกัดจำนวนตัวอักษรสูงสุดที่ยอมรับตอน parse request body (ไม่ใช่ตัวบังคับความปลอดภัย
# หลัก แค่กันไม่ให้ client ส่ง payload ใหญ่ผิดปกติเข้ามา) ตัวบังคับจริงคือ PASSWORD_MAX_BYTES
# ที่เช็คในฟังก์ชัน _validate_password_rules() ด้านล่าง
PASSWORD_INPUT_MAX_CHARS = 256


def _validate_password_rules(v: str) -> str:
    v = v.strip()
    errors = []

    if not v.isascii():
        errors.append("ห้ามใช้ภาษาไทยหรืออักขระอื่นที่ไม่ใช่ภาษาอังกฤษ (a-z, A-Z, 0-9 และสัญลักษณ์มาตรฐาน) เท่านั้น")

    if len(v) < PASSWORD_MIN_LENGTH:
        errors.append(f"ต้องมีความยาวอย่างน้อย {PASSWORD_MIN_LENGTH} ตัวอักษร")

    if len(v) > PASSWORD_MAX_BYTES:
        errors.append(f"ยาวเกินไป: ระบบรองรับรหัสผ่านสูงสุด {PASSWORD_MAX_BYTES} ตัวอักษร")

    if not any(ch.isalpha() for ch in v):
        errors.append("ต้องมีตัวอักษรอย่างน้อย 1 ตัว")
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
        max_length=PASSWORD_INPUT_MAX_CHARS,
        description=(
            f"รหัสผ่านต้องมีความยาวอย่างน้อย {PASSWORD_MIN_LENGTH} ตัวอักษร และไม่เกิน "
            f"{PASSWORD_MAX_BYTES} ไบต์เมื่อเข้ารหัสแบบ UTF-8 ต้องมีทั้งตัวอักษรอย่างน้อย 1 ตัว "
            "และตัวเลขอย่างน้อย 1 ตัว ใช้อักขระอื่นๆ ร่วมได้ (สัญลักษณ์ ภาษาไทย ฯลฯ)"
        ),
        examples=["Passw0rd"],
    )
    confirm_password: str = Field(
        ...,
        max_length=PASSWORD_INPUT_MAX_CHARS,
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
    new_password: str = Field(..., max_length=PASSWORD_INPUT_MAX_CHARS, examples=["Passw0rd"])
    confirm_new_password: str = Field(
        ...,
        max_length=PASSWORD_INPUT_MAX_CHARS,
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


class WebhookAdminResponse(WebhookResponse):
    """สำหรับ admin เท่านั้น — เห็นเจ้าของ webhook (user_id) และเหตุผลที่ถูกปิด (ถ้ามี)
    ใช้กับ GET /admin/webhooks และ PATCH /admin/webhooks/{id}/status"""
    user_id: int
    disabled_reason: Optional[str] = None


class WebhookStatusUpdate(BaseModel):
    """ใช้กับ PATCH /admin/webhooks/{id}/status — admin เปิด/ปิด webhook endpoint ตัวใดตัวหนึ่ง
    admin_note ไม่บังคับ (ใส่เฉพาะตอนปิดก็ได้ — pattern เดียวกับ UserSuspendUpdate)"""
    is_active: bool
    admin_note: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("admin_note")
    @classmethod
    def strip_note(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        return v or None  # ถ้าพิมพ์แต่ space ให้ถือว่าไม่ได้ใส่


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


# ---- สำหรับ Camera — ระบบพาร์ทเนอร์เพิ่มกล้องแทน user ผ่าน API key (ดู routers/partner.py) ----
_CAMERA_ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


class PartnerCameraCreate(BaseModel):
    """Body ของ POST /partner/cameras — ระบบพาร์ทเนอร์ (ยืนยันตัวตนด้วย X-API-Key ของ user
    เจ้าของบัญชี) เป็นคนกำหนด camera_id เอง (ใช้ตั้งค่าฝั่งอุปกรณ์กล้องจริงได้ล่วงหน้า)
    พร้อมระบุ webhook_url ที่จะผูกกล้องนี้ไว้ — ต้องเป็น URL ของ webhook ที่ user คนเดียวกัน
    (เจ้าของ API key) เคยสร้างไว้แล้วผ่าน POST /webhook/add เท่านั้น (กันข้อมูลกล้องหลุด
    ไปเข้า webhook ของ "งาน"/สัญญาอื่นที่ user คนเดียวกันดูแลอยู่โดยไม่ได้ตั้งใจ)

    [ONVIF Support]: partner เลือกระบุลิงก์กล้องได้ 2 ทาง (เลือกอย่างใดอย่างหนึ่งเท่านั้น):
    - camera_url: ส่ง RTSP URL ตรงๆ แบบเดิม (partner รู้ path ของกล้องตัวเองอยู่แล้ว)
    - onvif_ip + onvif_port + onvif_username + onvif_password: ให้ backend ไปเรียก ONVIF
      Media Service (GetProfiles -> GetStreamUri) แทนเพื่อดึง RTSP URL มาเอง (ดู
      security/onvif_client.py) เหมาะกับ partner ที่ไม่รู้ RTSP path ของกล้องตัวเอง
    ห้ามส่งมาทั้งสองทางพร้อมกัน และห้ามไม่ส่งมาเลยทั้งคู่ (ดู exactly_one_connection_method
    ด้านล่าง) — ไม่ว่าจะมาทางไหน สุดท้ายระบบจะ resolve ให้เหลือ RTSP URL เดียวเสมอ แล้วผ่าน
    security/camera_url_guard.py:verify_camera_rtsp_url() ก่อนบันทึกทุกครั้ง"""
    camera_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="รหัสกล้องที่กำหนดเอง ใช้ตั้งค่าฝั่งอุปกรณ์กล้องจริงได้เลย ต้องไม่ซ้ำกับกล้องอื่นในระบบ",
        examples=["cam-front-gate-01"],
    )
    camera_url: Optional[str] = Field(
        default=None,
        max_length=500,
        description=(
            "ทางที่ 1: ลิงก์ RTSP ของกล้องแบบตรงๆ ต้องขึ้นต้นด้วย rtsp:// เท่านั้น "
            "ระบุอย่างใดอย่างหนึ่งระหว่างฟิลด์นี้กับชุด onvif_* เท่านั้น ห้ามระบุทั้งคู่"
        ),
    )
    onvif_ip: Optional[str] = Field(
        default=None,
        max_length=255,
        description="ทางที่ 2 (ผ่าน ONVIF): IP หรือ hostname ของกล้อง ใช้คู่กับ onvif_port/onvif_username/onvif_password",
    )
    onvif_port: Optional[int] = Field(
        default=None,
        ge=1,
        le=65535,
        description="พอร์ต ONVIF ของกล้อง (ปกติ 80 หรือ 8080 แล้วแต่ยี่ห้อ)",
    )
    onvif_username: Optional[str] = Field(default=None, max_length=100, description="username สำหรับยืนยันตัวตนกับ ONVIF service ของกล้อง")
    onvif_password: Optional[str] = Field(default=None, max_length=200, description="password สำหรับยืนยันตัวตนกับ ONVIF service ของกล้อง")
    webhook_url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="URL ของ webhook (ที่เคยสร้างไว้ผ่าน POST /webhook/add) ที่จะผูกกล้องตัวนี้ไว้",
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
    def validate_rtsp_scheme(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None  # ส่งมาเป็น string ว่าง/เว้นวรรค -> ถือว่าไม่ได้ระบุ (เหมือนไม่ส่งฟิลด์นี้มาเลย)
        if not v.lower().startswith("rtsp://"):
            raise ValueError("ลิงก์กล้องไม่ถูกต้อง: ต้องขึ้นต้นด้วย rtsp:// เท่านั้น")
        return v

    @field_validator("onvif_ip", "onvif_username", "onvif_password")
    @classmethod
    def strip_onvif_text_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        return v or None  # ส่งมาเป็น string ว่าง -> ถือว่าไม่ได้ระบุเหมือนกัน

    @field_validator("webhook_url")
    @classmethod
    def strip_webhook_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v

    @model_validator(mode="after")
    def exactly_one_connection_method(self):
        """บังคับว่าต้องเลือกมาแค่ทางเดียวระหว่าง camera_url (RTSP ตรงๆ) กับชุด onvif_*
        (ONVIF) — ถ้าระบุ onvif_* มาไม่ครบทั้ง 4 ฟิลด์ ก็ถือว่าผิดเหมือนกัน (กันเคสกรอกมาครึ่งๆ
        กลางๆ แล้วระบบไปเดาเอาเองว่าจะใช้ทางไหน)"""
        has_rtsp = self.camera_url is not None
        onvif_fields = [self.onvif_ip, self.onvif_port, self.onvif_username, self.onvif_password]
        has_onvif = all(f is not None for f in onvif_fields)
        has_onvif_partial = any(f is not None for f in onvif_fields) and not has_onvif

        if has_onvif_partial:
            raise ValueError(
                "ระบุข้อมูล ONVIF ไม่ครบ ต้องมีทั้ง onvif_ip, onvif_port, onvif_username และ onvif_password"
            )
        if has_rtsp and has_onvif:
            raise ValueError("ระบุได้แค่ทางเดียว: camera_url (RTSP ตรงๆ) หรือชุด onvif_* (ผ่าน ONVIF) ไม่ใช่ทั้งคู่")
        if not has_rtsp and not has_onvif:
            raise ValueError(
                "ต้องระบุ camera_url (RTSP ตรงๆ) หรือชุด onvif_ip/onvif_port/onvif_username/onvif_password (ผ่าน ONVIF) อย่างใดอย่างหนึ่ง"
            )
        return self


class CameraResponse(BaseModel):

    camera_id: str
    is_active: bool
    verification_status: str  # pending / verified / failed
    created_at: datetime

    class Config:
        from_attributes = True


class CameraAdminResponse(CameraResponse):
    """สำหรับ admin เท่านั้น — เห็น rtsp_url และเจ้าของกล้องได้"""
    rtsp_url: str
    owner_user_id: int
    webhook_is_active: bool

class MyCameraResponse(BaseModel):

    camera_id: str
    is_active: bool
    verification_status: str
    webhook_url: str
    webhook_is_active: bool
    created_at: datetime


# ---- สำหรับ Partner Integration — ระบบพาร์ทเนอร์สั่งเปิด/ปิดกล้อง (ดู routers/partner.py) ----
class PartnerCameraStatusUpdate(BaseModel):
    camera_id: str = Field(..., min_length=1, max_length=100)
    is_active: bool

    @field_validator("camera_id")
    @classmethod
    def validate_camera_id(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v

class PartnerCameraStatusResponse(BaseModel):
    """ใช้กับ GET /partner/cameras/{camera_id} — ให้ partner poll ดูผลการตรวจสอบเองได้
    ถ้ากล้องถูกลบไปแล้ว (เกินโควต้าการลองยืนยัน) endpoint จะตอบ 404 แทนที่จะเจอ schema นี้"""
    camera_id: str
    verification_status: str
    is_active: bool

    class Config:
        from_attributes = True


# ---- สำหรับ API Key (ระบบอัตโนมัติของ user ใช้แทน JWT ตอนยิงเข้ามาเอง) ----
class ApiKeyResponse(BaseModel):
    api_key: str
    message: str = "กรุณาเก็บ API key นี้ไว้ให้ปลอดภัย ระบบจะไม่แสดงค่านี้ให้เห็นอีกครั้ง"


class ApiKeyStatusResponse(BaseModel):
    has_api_key: bool

# ---- สำหรับ GET /auth/me — เช็คสถานะ user แบบ read-only (terms/admin/api-key/suspend) ----
class UserMeResponse(BaseModel):
    email: str
    is_verified: bool
    terms_accepted: bool
    is_admin: bool
    has_api_key: bool
    is_suspended: bool
    suspended_reason: Optional[str] = None

    class Config:
        from_attributes = True


# ---- สำหรับ Admin: จัดการ user ----
class UserAdminResponse(BaseModel):
    id: int
    email: str
    is_verified: bool
    terms_accepted: bool
    is_admin: bool
    is_suspended: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserAdminDetailResponse(UserAdminResponse):
    suspended_reason: Optional[str] = None
    webhook_count: int
    camera_count: int
    access_requests: List[AccessRequestResponse] = []


class UserSuspendUpdate(BaseModel):
    is_suspended: bool
    admin_note: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("admin_note")
    @classmethod
    def strip_note(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        return v or None

# ---- สำหรับ Admin Audit Log ----
class AdminAuditLogResponse(BaseModel):
    id: int
    admin_id: int
    admin_email: str
    action: str
    target_type: str
    target_id: Optional[str] = None
    detail: Optional[dict] = None
    created_at: datetime