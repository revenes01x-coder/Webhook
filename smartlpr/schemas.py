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


# ---- สำหรับ Change Password (flow B: user login อยู่แล้ว อยากเปลี่ยนรหัสผ่านเฉยๆ ไม่ได้ลืม) ----
class ChangePasswordRequest(BaseModel):
    """ใช้กับ POST /auth/change-password — ต่างจาก ResetPasswordRequest ตรงที่ flow นี้ไม่ผ่าน
    OTP เลย (user login ค้างอยู่แล้ว) เลยบังคับกรอก current_password มายืนยันตัวตนซ้ำแทน
    (กันเคส session หลุดมือ/เผลอไม่ได้ล็อกจอ แล้วมีคนอื่นมากดเปลี่ยนรหัสผ่านแทนตัวจริง)"""
    current_password: str = Field(..., max_length=PASSWORD_INPUT_MAX_CHARS)
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
    def passwords_must_match_and_differ(self):
        if self.new_password != self.confirm_new_password:
            raise ValueError("รหัสผ่านใหม่และรหัสผ่านยืนยันไม่ตรงกัน")
        if self.new_password == self.current_password:
            raise ValueError("รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสผ่านเดิม")
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
    """สำหรับ admin เท่านั้น — เห็นเจ้าของ webhook (user_id + owner_email) และเหตุผลที่ถูกปิด
    (ถ้ามี) ใช้กับ GET /admin/webhooks และ PATCH /admin/webhooks/{id}/status
    user_id เป็น UUID hex string แล้ว (ตรงกับ User.id หลังเปลี่ยน PK) — nullable เพราะ
    WebhookEndpoint.user_id เดิมไม่ได้บังคับ not-null ไว้ ดังนั้น owner_email ก็ไม่บังคับตาม"""
    user_id: Optional[str] = None
    disabled_reason: Optional[str] = None
    owner_email: Optional[str] = None


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
    ไปเข้า webhook ของ "งาน"/สัญญาอื่นที่ user คนเดียวกันดูแลอยู่โดยไม่ได้ตั้งใจ)"""
    camera_id: str = Field(
        ...,
        min_length=1,
        max_length=100,
        description="รหัสกล้องที่กำหนดเอง ใช้ตั้งค่าฝั่งอุปกรณ์กล้องจริงได้เลย ต้องไม่ซ้ำกับกล้องอื่นในระบบ",
        examples=["cam-front-gate-01"],
    )
    camera_url: str = Field(
        ...,
        max_length=500,
        description="ลิงก์ RTSP ของกล้องแบบตรงๆ ต้องขึ้นต้นด้วย rtsp:// เท่านั้น",
    )
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
    def validate_rtsp_scheme(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("จำเป็นต้องระบุลิงก์ RTSP (camera_url)")
        if not v.lower().startswith("rtsp://"):
            raise ValueError("ลิงก์กล้องไม่ถูกต้อง: ต้องขึ้นต้นด้วย rtsp:// เท่านั้น")
        return v

    @field_validator("webhook_url")
    @classmethod
    def strip_webhook_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v


class CameraResponse(BaseModel):

    camera_id: str
    is_active: bool
    verification_status: str  # pending / verified / failed
    created_at: datetime

    class Config:
        from_attributes = True


class CameraAdminResponse(CameraResponse):
    """สำหรับ admin เท่านั้น — เห็น rtsp_url และเจ้าของกล้อง (owner_user_id + owner_email) ได้
    owner_user_id เป็น UUID hex string แล้ว (ตรงกับ User.id หลังเปลี่ยน PK)"""
    rtsp_url: str
    owner_user_id: str
    owner_email: str
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
    full_name: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


# ---- สำหรับ Admin: จัดการ user ----
class UserAdminResponse(BaseModel):
    # [UUID PK]: id ตอนนี้เป็น UUID hex string (ตรงกับ User.id หลังเปลี่ยน PK) ไม่ใช่ int แล้ว
    id: str
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
    actor_id: Optional[str] = None
    actor_type: str  # "admin" / "user" / "system"
    actor_email: Optional[str] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    detail: Optional[dict] = None
    ip_address: Optional[str] = None
    created_at: datetime

# ---- สำหรับ Admin Dashboard (GET /admin/dashboard) ----
class DashboardUserStats(BaseModel):
    total: int
    verified: int
    suspended: int
    pending_access_requests: int


class DashboardCameraStats(BaseModel):
    total: int
    active: int
    pending_verification: int  # verification_status อยู่ใน (pending, failed)


class DashboardWebhookStats(BaseModel):
    total: int
    active: int
    unhealthy: int  # is_healthy=False (ถูกตัดไฟจาก circuit breaker)


class DashboardEventQueueStats(BaseModel):
    pending: int       # status อยู่ใน (pending, failed) และยังไม่ถูก soft-delete
    dead_letter: int   # status = dead_letter และยังไม่ถูก soft-delete


class AdminDashboardResponse(BaseModel):
    users: DashboardUserStats
    cameras: DashboardCameraStats
    webhooks: DashboardWebhookStats
    events: DashboardEventQueueStats