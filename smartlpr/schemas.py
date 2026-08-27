import re
from pydantic import BaseModel, EmailStr, HttpUrl, Field, field_validator, model_validator
from datetime import datetime
from typing import Optional, Literal, List

from smartlpr.pagination import PaginatedResponse  # re-export ให้เรียกผ่าน schemas.PaginatedResponse ได้เหมือนโมเดลอื่น

_OTP_RE = re.compile(r"^\d{6}$")

PASSWORD_MAX_BYTES = 72
PASSWORD_MIN_LENGTH = 8

PASSWORD_INPUT_MAX_CHARS = 256

# ---- User Contact (ข้อมูลติดต่อส่วนตัวของ user เอง — ดู smartlpr/models.py:UserContact) ----
_USER_CONTACT_CHANNEL_TYPES = {
    "facebook", "line", "phone", "email", "instagram", "whatsapp", "tiktok", "generic",
}
# เบอร์มือถือไทย 10 หลัก ขึ้นต้นด้วย 06/08/09 เท่านั้น (ไม่รองรับเบอร์บ้าน/ต่างประเทศ — ตกลงกันไว้
# ให้ง่ายและบังคับรูปแบบชัดเจน) เช็คกับตัวเลขล้วนหลังตัด - หรือช่องว่างออกแล้วเท่านั้น
_THAI_MOBILE_RE = re.compile(r"^0[689]\d{8}$")
_CONTACT_VALUE_MIN_LENGTH = 4


def normalize_user_contact_value(channel_type: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("ห้ามเว้นว่าง")

    if channel_type == "phone":
        digits = re.sub(r"[^0-9]", "", value)
        if not _THAI_MOBILE_RE.match(digits):
            raise ValueError("เบอร์โทรต้องเป็นเบอร์มือถือไทย 10 หลัก ขึ้นต้นด้วย 06, 08 หรือ 09 เท่านั้น")
        return digits

    if channel_type == "email":
        local_part, _, domain_part = value.partition("@")
        if not local_part or "." not in domain_part or domain_part.startswith(".") or domain_part.endswith("."):
            raise ValueError("รูปแบบอีเมลไม่ถูกต้อง")
        return value

    if len(value) < _CONTACT_VALUE_MIN_LENGTH:
        raise ValueError(f"ต้องมีความยาวอย่างน้อย {_CONTACT_VALUE_MIN_LENGTH} ตัวอักษร")

    return value


# [Cleanup] เดิมไฟล์นี้ประกาศ _CONTACT_CHANNEL_ICONS ซ้ำ 2 รอบ (ตัวแรกอยู่บนสุดของไฟล์ ตัวที่สอง
# อยู่ตรงนี้) ค่าเหมือนกันทุกตัวอักษรและไม่มีการอ้างอิง _CONTACT_CHANNEL_ICONS เลยระหว่างสองจุดนี้
# ตัวแรกจึงเป็นโค้ดที่ตายแล้ว (ถูกตัวนี้ shadow ทับก่อนมีใครใช้งาน) — ลบตัวแรกทิ้ง เหลือประกาศเดียวที่นี่
_CONTACT_CHANNEL_ICONS = {"line", "email", "phone", "clock", "generic", "facebook"}

# ---- Username (มาตรฐาน: unique ทั้งระบบ, ไม่ใช้ login แทนอีเมล — ดู smartlpr/models.py:User) ----
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32


def normalize_username(v: str) -> str:
    v = v.strip()
    if len(v) < USERNAME_MIN_LENGTH or len(v) > USERNAME_MAX_LENGTH:
        raise ValueError(f"username ต้องมีความยาว {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} ตัวอักษร")
    if not _USERNAME_RE.match(v):
        raise ValueError(
            "username ใช้ได้เฉพาะตัวอักษรภาษาอังกฤษ (a-z, A-Z), ตัวเลข (0-9) "
            "และสัญลักษณ์ _ . - เท่านั้น (ห้ามเว้นวรรคหรืออักขระพิเศษอื่น)"
        )
    if v[0] in "_.-" or v[-1] in "_.-":
        raise ValueError("username ห้ามขึ้นต้นหรือลงท้ายด้วย _ . -")
    # เก็บเป็นตัวพิมพ์เล็กเสมอ (แบบเดียวกับ email) กัน "John" กับ "john" ไม่ถือว่าซ้ำกันทั้งที่
    # คนอ่านมองว่าเป็นชื่อเดียวกัน — แลกกับการไม่รักษา case ตามที่ผู้ใช้พิมพ์มาต้นฉบับ
    return v.lower()


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
    username: str = Field(
        ...,
        min_length=USERNAME_MIN_LENGTH,
        max_length=USERNAME_MAX_LENGTH,
        description=(
            f"username ต้องไม่ซ้ำกับผู้ใช้อื่น ความยาว {USERNAME_MIN_LENGTH}-{USERNAME_MAX_LENGTH} "
            "ตัวอักษร ใช้ได้เฉพาะ a-z, A-Z, 0-9 และสัญลักษณ์ _ . - เท่านั้น"
        ),
        examples=["john_doe"],
    )
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

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return normalize_username(v)

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


class UsernameUpdateRequest(BaseModel):
    """ใช้กับ PATCH /auth/username — เปลี่ยน username ของตัวเอง แยกจาก UserProfileUpdate
    (ซึ่งแก้ full_name อย่างเดียว) เพราะ endpoint นี้จำกัดความถี่ 1 ครั้ง/30 วัน (ยกเว้นครั้งแรก
    ที่ยังไม่เคยตั้งเลย) ดู routers/auth.py: update_username"""
    username: str = Field(..., min_length=USERNAME_MIN_LENGTH, max_length=USERNAME_MAX_LENGTH)

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        return normalize_username(v)


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
    username: Optional[str] = None  # None = ยังไม่เคยตั้ง (เช่น user เก่าก่อนมีฟีเจอร์นี้)
    is_verified: bool
    terms_accepted: bool
    is_admin: bool
    has_api_key: bool
    is_suspended: bool
    suspended_reason: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class UserContactCreate(BaseModel):
    channel_type: str = Field(..., description=f"ต้องเป็นหนึ่งใน {sorted(_USER_CONTACT_CHANNEL_TYPES)}")
    value: str = Field(..., min_length=1, max_length=300)

    @field_validator("channel_type")
    @classmethod
    def validate_channel_type(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if v not in _USER_CONTACT_CHANNEL_TYPES:
            raise ValueError(f"channel_type ต้องเป็นหนึ่งใน {sorted(_USER_CONTACT_CHANNEL_TYPES)}")
        return v

    @model_validator(mode="after")
    def normalize_value(self):
        self.value = normalize_user_contact_value(self.channel_type, self.value)
        return self


class UserContactUpdate(BaseModel):
    value: str = Field(..., min_length=1, max_length=300)

    @field_validator("value")
    @classmethod
    def strip_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v


class UserContactResponse(BaseModel):
    id: int
    channel_type: str
    value: str
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---- สำหรับ Admin: จัดการ user ----
class UserAdminResponse(BaseModel):
    id: str
    email: str
    username: Optional[str] = None
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
    # ข้อมูลติดต่อส่วนตัวที่ user กรอกเองผ่าน /my/contacts (facebook/line/เบอร์โทร/ฯลฯ)
    # ให้ admin ดูประกอบการพิจารณาในหน้ารายละเอียด user — read-only ฝั่ง admin (แก้ไม่ได้)
    contacts: List[UserContactResponse] = []


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

class ContactChannelResponse(BaseModel):
    id: int
    label: str
    value: str
    icon: str
    display_order: int

    class Config:
        from_attributes = True


class ContactChannelCreate(BaseModel):
    """[Format Guard]: value ถูกบังคับรูปแบบตาม icon ที่เลือก ด้วยฟังก์ชันเดียวกับที่
    /my/contacts ใช้ (normalize_user_contact_value ด้านบนของไฟล์นี้) — icon="phone" ต้องเป็น
    เบอร์มือถือไทย 10 หลัก (เก็บเป็นตัวเลขล้วนหลัง normalize เหมือน UserContact ทุกประการ),
    icon="email" ต้องมีรูปแบบอีเมลถูกต้อง, ไอคอนอื่นๆ (line/facebook/clock/generic) บังคับความยาว
    ขั้นต่ำ _CONTACT_VALUE_MIN_LENGTH ตัวอักษร — เดิม endpoint นี้เช็คแค่ไม่ว่างเปล่าเท่านั้น
    ทำให้ตั้งไอคอน "เบอร์โทรศัพท์" แต่ค่าเป็นข้อความอะไรก็ได้หลุดผ่านไปแสดงต่อผู้ใช้จริงได้"""
    label: str = Field(..., min_length=1, max_length=100)
    value: str = Field(..., min_length=1, max_length=300)
    icon: str = Field(default="generic")

    @field_validator("label")
    @classmethod
    def strip_and_require_nonblank(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v

    @field_validator("icon")
    @classmethod
    def validate_icon(cls, v: str) -> str:
        v = (v or "generic").strip().lower()
        if v not in _CONTACT_CHANNEL_ICONS:
            raise ValueError(f"icon ต้องเป็นหนึ่งใน {sorted(_CONTACT_CHANNEL_ICONS)}")
        return v

    @model_validator(mode="after")
    def normalize_value(self):
        # ทำหลัง field_validator ของ icon (จึงได้ icon ที่ normalize แล้ว) — icon ที่นี่ไม่ได้อยู่ใน
        # _USER_CONTACT_CHANNEL_TYPES เสมอไป (เช่น "clock") แต่ normalize_user_contact_value ไม่ได้
        # เช็ค membership ของ type เอง มันแค่ switch พฤติกรรมตาม "phone"/"email"/อื่นๆ จึงใช้ร่วมกันได้ตรงๆ
        self.value = normalize_user_contact_value(self.icon, self.value)
        return self


class ContactChannelUpdate(BaseModel):
    """PATCH แบบ partial — ฟิลด์ที่ไม่ส่งมาจะไม่ถูกแตะ (ดู routers/contact.py: exclude_unset=True)

    [Format Guard]: ไม่ validate รูปแบบของ value ตาม icon ที่ระดับ schema นี้ตรงๆ เพราะเป็น partial
    update — ถ้าส่งมาแค่ value โดยไม่ส่ง icon มาด้วย ต้องรู้ icon "เดิม" ของ record นั้นก่อนถึงจะ
    เช็ครูปแบบได้ถูกต้อง (กลับกันก็เช่นกัน: ส่งมาแค่ icon ใหม่ ต้องเอา value เดิมมาเช็คกับ icon ใหม่)
    จุดที่รู้ทั้งค่าเดิมและค่าใหม่พร้อมกันคือ routers/contact.py:update_contact_channel ซึ่งเรียก
    normalize_user_contact_value (ตัวเดียวกับ ContactChannelCreate/UserContactCreate) ที่นั่นแทน"""
    label: Optional[str] = Field(default=None, min_length=1, max_length=100)
    value: Optional[str] = Field(default=None, min_length=1, max_length=300)
    icon: Optional[str] = None

    @field_validator("label")
    @classmethod
    def strip_and_require_nonblank(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not v:
            raise ValueError("ห้ามเว้นว่าง")
        return v

    @field_validator("icon")
    @classmethod
    def validate_icon(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().lower()
        if v not in _CONTACT_CHANNEL_ICONS:
            raise ValueError(f"icon ต้องเป็นหนึ่งใน {sorted(_CONTACT_CHANNEL_ICONS)}")
        return v


class ContactChannelReorderRequest(BaseModel):
    direction: Literal["up", "down"]