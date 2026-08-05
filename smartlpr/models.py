from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Text, JSON, UniqueConstraint
from sqlalchemy.sql import func
from smartlpr.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)

    # --- เพิ่มใหม่: OTP verification ---
    is_verified = Column(Boolean, default=False, nullable=False)

    # --- เพิ่มใหม่: Terms acceptance (ข้อตกลงชุดเดียว ไม่มี version) ---
    terms_accepted = Column(Boolean, default=False, nullable=False)

    # --- เพิ่มใหม่: Admin flag ---
    is_admin = Column(Boolean, default=False, nullable=False)

    # --- เพิ่มใหม่: ระงับการใช้งาน (admin กดระงับ) ---
    # ไม่บล็อก login แต่บล็อก action สำคัญ (เพิ่ม webhook, ขอ/regenerate API key, ยิง API key เข้ามา)
    # ดู smartlpr/security.py: require_access_approved / require_api_key
    is_suspended = Column(Boolean, default=False, nullable=False)
    suspended_reason = Column(Text, nullable=True)  # เหตุผลที่ admin ระบุตอนระงับ (ไม่บังคับ)

    # --- เพิ่มใหม่: API key สำหรับระบบอัตโนมัติของ user (ไม่ใช่ JWT ที่ต้อง login เอง)
    # เก็บแค่ hash (HMAC-SHA256 แบบเดียวกับ OTP) ไม่เก็บ plaintext — unique+index เพราะจะ query
    # หา user ตรงๆ จาก hash เลย (deterministic hash ทำให้ query ตรงได้ ไม่ต้อง loop เทียบทีละคน)
    api_key_hash = Column(String, nullable=True, unique=True, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class OtpVerification(Base):
    """เก็บ OTP แบบ hash เท่านั้น ห้ามเก็บ plaintext ลง DB
    มีแค่ 1 แถวต่อ (user_id, purpose) เสมอ — ขอ OTP ใหม่ = เขียนทับแถวเดิม (upsert)
    ไม่ insert แถวใหม่ซ้อนแถวเก่า เพราะฉะนั้นตารางนี้จะไม่โตขึ้นเรื่อยๆ ตามจำนวนครั้งที่ user กดขอ"""
    __tablename__ = "otp_verifications"
    __table_args__ = (UniqueConstraint("user_id", "purpose", name="uq_otp_user_purpose"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    purpose = Column(String, nullable=False, default="register")  # register, password_reset

    otp_hash = Column(String, nullable=False)
    attempt_count = Column(Integer, default=0, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)  # True = ใช้ยืนยันสำเร็จแล้ว หรือผิดเกินโควต้า (ต้องขอใหม่)

    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())  # อัปเดตทุกครั้งที่ขอ OTP ใหม่ (ใช้เช็ค cooldown)


class AccessRequest(Base):
    """คำขอใช้งานระบบของ user แต่ละคน รอ admin อนุมัติ"""
    __tablename__ = "access_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    organization_name = Column(String, nullable=False)
    contact_email = Column(String, nullable=False)
    use_case = Column(Text, nullable=False)
    contact_phone = Column(String, nullable=False)
    contact_name = Column(String, nullable=False)

    status = Column(String, default="pending", index=True)  # pending, approved, rejected
    admin_note = Column(Text, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

    submitted_at = Column(DateTime(timezone=True), server_default=func.now())


class Camera(Base):
    """กล้องเป็นกรรมสิทธิ์ของ user คนเดียวเท่านั้น (ผู้เพิ่มกล้องเอง ผ่าน POST /my/cameras)
    id เป็น string ที่ user กำหนดเอง (ไม่ใช่ auto-increment) เพื่อให้ user ตั้งค่าฝั่งอุปกรณ์กล้องจริง
    ด้วย camera_id ที่รู้ล่วงหน้าได้เลย ไม่ต้องมา query ทีหลัง ต้อง unique ทั้งระบบ"""
    __tablename__ = "cameras"

    id = Column(String, primary_key=True, index=True)
    owner_user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    rtsp_url = Column(String, nullable=False)

    # is_active เริ่มเป็น False เสมอตอนสร้าง — จะเป็น True ก็ต่อเมื่อ background job
    # (verify_pending_cameras ใน worker.py) ต่อ RTSP stream จริงได้สำเร็จเท่านั้น
    is_active = Column(Boolean, default=False, nullable=False)
    # pending = รอตรวจสอบ, verified = ต่อ RTSP ได้จริง (=> is_active True), failed = ต่อไม่ได้
    verification_status = Column(String, default="pending", nullable=False, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AdminNotification(Base):
    """แจ้งเตือนในเว็บสำหรับ admin เมื่อมีคำขอใหม่เข้ามา (access-request)
    fan-out หนึ่ง record ต่อ admin หนึ่งคนตอนคำขอถูกส่งเข้ามา
    is_read = admin คนนี้เปิดดูรึยัง (ต่อคน), resolved_at = คำขอต้นเรื่องถูก approve/reject ไปแล้วรึยัง
    (ค่าเดียวกันทุก record ที่ผูกกับคำขอเดียวกัน ไม่ว่า admin คนไหนเป็นคนกด)"""
    __tablename__ = "admin_notifications"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)

    request_type = Column(String, nullable=False, index=True)  # ปัจจุบันมีแค่ "access_request"
    request_id = Column(Integer, nullable=False, index=True)

    message = Column(String, nullable=False)
    is_read = Column(Boolean, default=False, nullable=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String, index=True, nullable=False)
    action = Column(String, nullable=False)
    count = Column(Integer, default=1)
    expire_at = Column(DateTime(timezone=True), nullable=False)


class WebhookEndpoint(Base):
    __tablename__ = "webhook_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    url = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)

    # Circuit breaker: ถ้า dead_letter ติดกันครบ threshold -> is_healthy=False (ตัดไฟ)
    # event ใหม่ที่เข้ามาระหว่างตัดไฟจะข้ามการยิงจริงไปเข้า dead_letter ทันที ไม่เสีย 3 รอบ retry
    # Job B (health check ทุก 30 นาที) จะ ping เฉพาะ endpoint ที่ is_healthy=False เพื่อดูว่าฟื้นหรือยัง
    is_healthy = Column(Boolean, default=True, nullable=False)
    consecutive_dead_letters = Column(Integer, default=0, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class WebhookEvent(Base):
    __tablename__ = "webhook_events"

    id = Column(String, primary_key=True, index=True)  # composite: "{source_event_id}_{endpoint_id}"
    user_id = Column(Integer, ForeignKey("users.id"))

    # event_id ต้นฉบับจากกล้อง (ไม่มี suffix endpoint) — ส่งออกไปใน payload จริง
    # เพื่อให้ target_url echo กลับมาให้ worker ใช้ verify ACK ได้
    source_event_id = Column(String, nullable=False, index=True)

    # เพิ่มใหม่: อ้างอิงว่า event นี้มาจากกล้องตัวไหน (จะใช้จริงตอน step 4)
    camera_id = Column(String, ForeignKey("cameras.id"), nullable=True, index=True)

    # อ้างอิง endpoint ที่ event นี้ถูกส่งไป — ใช้ทำ circuit breaker (is_healthy) ต่อ endpoint
    webhook_endpoint_id = Column(Integer, ForeignKey("webhook_endpoints.id"), nullable=True, index=True)

    target_url = Column(String, nullable=False)
    payload = Column(JSON, nullable=False)

    full_image_path = Column(String, nullable=True)
    crop_image_path = Column(String, nullable=True)

    status = Column(String, default="pending", index=True)
    attempt_count = Column(Integer, default=0)
    next_retry_at = Column(DateTime(timezone=True), nullable=True)

    # Soft delete: NULL = ยังไม่ถูกลบ, มีค่า = เวลาที่ถูกลบ (แถวยังอยู่ใน DB เหมือนเดิม)
    deleted_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String, unique=True, index=True, nullable=False)
    revoked_expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RefreshToken(Base):
    """Refresh token สำหรับ httpOnly cookie flow — เก็บแบบ hash เท่านั้น (เหมือน OTP/API key)
    ไม่เก็บ plaintext ลง DB เด็ดขาด (ดู refresh_token_utils.py)

    family_id: uuid เดียวกันตลอดทุกครั้งที่ rotate จาก login ครั้งเดียวกัน ใช้ตรวจจับการ reuse —
    ทุกครั้งที่เรียก POST /auth/refresh สำเร็จ ใบเก่าจะถูก revoke (is_revoked=True) ทันที
    และออกใบใหม่ใน family เดิมแทน ถ้ามีใครเอาใบที่ revoke ไปแล้วมาใช้ซ้ำ (เช่น token หลุด/ถูกขโมย
    แล้ว attacker ใช้ก่อนเจ้าของตัวจริง) ระบบจะ revoke ทั้ง family ทันที บังคับ login ใหม่ทั้งหมด

    worker.py มี cleanup_expired_refresh_tokens() ลบ record ที่ expires_at ผ่านไปแล้วทุก 1 ชม.
    (แถวที่ is_revoked=True แต่ยังไม่หมดอายุจะยังไม่ถูกลบ เผื่อไว้ตรวจสอบ/debug reuse ย้อนหลัง)"""
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    family_id = Column(String, nullable=False, index=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)

    is_revoked = Column(Boolean, default=False, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())