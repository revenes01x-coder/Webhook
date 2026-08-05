import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Optional

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_admin
from services.email_service import send_access_approved_email, send_access_rejected_email
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/admin", tags=["Admin"])

_VALID_STATUSES = {"pending", "approved", "rejected"}
_DEFAULT_REJECT_NOTE = "คำขอของคุณไม่ได้รับการอนุมัติในขณะนี้"


# ---------------------------------------------------------------------------
# Access Request — คำขอใช้งานระบบโดยรวม
# ---------------------------------------------------------------------------

@router.get("/access-requests", response_model=schemas.PaginatedResponse[schemas.AccessRequestResponse])
def list_access_requests(
    status_filter: Optional[str] = Query(
        default="pending",
        alias="status",
        description="กรองตามสถานะ: pending / approved / rejected (ไม่ใส่ = ดูทั้งหมด)",
    ),
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """รองรับ pagination ผ่าน query param ?page=&page_size= (ดีฟอลต์ page=1, page_size=20)"""
    if status_filter and status_filter not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status ต้องเป็นหนึ่งใน {sorted(_VALID_STATUSES)}",
        )

    query = db.query(models.AccessRequest)
    if status_filter:
        query = query.filter(models.AccessRequest.status == status_filter)
    query = query.order_by(models.AccessRequest.id.desc())

    return paginate(query, page_params)


@router.get("/access-requests/{request_id}", response_model=schemas.AccessRequestResponse)
def get_access_request_detail(
    request_id: int,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายละเอียดฟอร์มที่ user กรอกมาแบบเต็มๆ ทีละใบ (ใช้ก่อนตัดสินใจ approve/reject)"""
    req = db.query(models.AccessRequest).filter(models.AccessRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบคำขอนี้")
    return req


@router.patch("/access-requests/{request_id}", response_model=schemas.AccessRequestResponse)
def review_access_request(
    request_id: int,
    payload: schemas.ReviewDecision,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    req = db.query(models.AccessRequest).filter(models.AccessRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบคำขอนี้")
    if req.status != "pending":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"คำขอนี้ถูกพิจารณาไปแล้ว (สถานะปัจจุบัน: {req.status})",
        )

    req.reviewed_by = admin.id
    req.reviewed_at = datetime.now(timezone.utc)

    if payload.decision == "approve":
        req.status = "approved"
    else:
        req.status = "rejected"
        req.admin_note = payload.admin_note  # ไม่บังคับ อาจเป็น None


    db.commit()
    db.refresh(req)

    # ส่งอีเมลแจ้ง user หลัง commit สำเร็จแล้วเท่านั้น ถ้าส่งเมลพังไม่ rollback สถานะ
    # (เหมือน pattern ตอน register: DB เป็นความจริงหลัก อีเมลเป็นแค่การแจ้งเตือน)
    # ส่งไปที่ contact_email ที่กรอกในฟอร์ม ไม่ใช่อีเมล login เพราะอาจเป็นคนละคนกัน
    try:
        if req.status == "approved":
            send_access_approved_email(req.contact_email)
        else:
            send_access_rejected_email(req.contact_email, req.admin_note or _DEFAULT_REJECT_NOTE)
    except RuntimeError as e:
        logging.error(f"ส่งอีเมลแจ้งผล access request id={req.id} ไม่สำเร็จ: {e}")

    return req


# ---------------------------------------------------------------------------
# Camera — ตอนนี้ user เป็นเจ้าของกล้องเอง (POST /my/cameras) admin แค่ดูภาพรวม
# และเปิด/ปิดกล้องของใครก็ได้ (เช่น กรณีผิดกฎ) ไม่มีสิทธิ์สร้าง/แจกจ่ายสิทธิ์แล้ว
# ---------------------------------------------------------------------------

@router.get("/cameras", response_model=schemas.PaginatedResponse[schemas.CameraAdminResponse])
def list_cameras(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูกล้องทั้งหมดในระบบ ไม่ว่าใครเป็นเจ้าของ
    รองรับ pagination ผ่าน query param ?page=&page_size= (ดีฟอลต์ page=1, page_size=20)"""
    query = db.query(models.Camera).order_by(models.Camera.id.desc())
    return paginate(query, page_params)


@router.get("/cameras/{camera_id}", response_model=schemas.CameraAdminResponse)
def get_camera_detail(
    camera_id: str,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    camera = db.query(models.Camera).filter(models.Camera.id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบกล้องนี้")
    return camera


@router.get("/users", response_model=schemas.PaginatedResponse[schemas.UserAdminResponse])
def list_users(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """List user ทั้งหมดในระบบ รองรับ pagination ?page=&page_size= เหมือน endpoint อื่นๆ"""
    query = db.query(models.User).order_by(models.User.id.desc())
    return paginate(query, page_params)


@router.get("/users/{user_id}", response_model=schemas.UserAdminDetailResponse)
def get_user_detail(
    user_id: int,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายละเอียด user คนเดียว พร้อมจำนวน webhook/camera ที่มี (ใช้ประกอบการตัดสินใจระงับ)"""
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบผู้ใช้นี้")

    webhook_count = db.query(models.WebhookEndpoint).filter(
        models.WebhookEndpoint.user_id == user.id
    ).count()
    camera_count = db.query(models.Camera).filter(
        models.Camera.owner_user_id == user.id
    ).count()

    return schemas.UserAdminDetailResponse(
        id=user.id,
        email=user.email,
        is_verified=user.is_verified,
        terms_accepted=user.terms_accepted,
        is_admin=user.is_admin,
        is_suspended=user.is_suspended,
        suspended_reason=user.suspended_reason,
        created_at=user.created_at,
        webhook_count=webhook_count,
        camera_count=camera_count,
    )


@router.patch("/users/{user_id}/suspend", response_model=schemas.UserAdminResponse)
def set_user_suspend_status(
    user_id: int,
    payload: schemas.UserSuspendUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ระงับ/ปลดระงับ user — ห้ามแตะบัญชีของตัวเอง (กัน admin ล็อกตัวเองไม่ได้ตั้งใจ)"""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่สามารถระงับ/ปลดระงับบัญชีของตัวเองได้",
        )

    user = db.query(models.User).filter(models.User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบผู้ใช้นี้")

    user.is_suspended = payload.is_suspended
    user.suspended_reason = payload.admin_note if payload.is_suspended else None
    db.commit()
    db.refresh(user)
    return user