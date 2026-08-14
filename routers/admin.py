import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy.orm import Session
from datetime import datetime, timezone
from typing import List, Optional
from worker import resume_endpoint_now
from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_admin
from services.email_service import (
    send_access_approved_email,
    send_access_rejected_email,
    send_account_suspended_email,
    send_account_unsuspended_email,
    send_webhook_disabled_email,
    send_webhook_enabled_email,
)
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/admin", tags=["Admin"])

_VALID_STATUSES = {"pending", "approved", "rejected"}
_DEFAULT_REJECT_NOTE = "คำขอของคุณไม่ได้รับการอนุมัติในขณะนี้"

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

    try:
        if req.status == "approved":
            send_access_approved_email(req.contact_email)
        else:
            send_access_rejected_email(req.contact_email, req.admin_note or _DEFAULT_REJECT_NOTE)
    except RuntimeError as e:
        logging.error(f"ส่งอีเมลแจ้งผล access request id={req.id} ไม่สำเร็จ: {e}")

    return req

@router.get("/cameras", response_model=schemas.PaginatedResponse[schemas.CameraAdminResponse])
def list_cameras(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูกล้องทั้งหมดในระบบ ไม่ว่าใครเป็นเจ้าของ พร้อมสถานะ webhook ปลายทางที่ผูกไว้
    (webhook_is_active) ให้เห็นได้เลยว่ากล้องไหน is_active=True แต่จริงๆ ไม่ได้รันอยู่เพราะ
    webhook ถูกปิด"""
    base_query = (
        db.query(models.Camera, models.WebhookEndpoint.is_active)
        .join(models.WebhookEndpoint, models.Camera.webhook_endpoint_id == models.WebhookEndpoint.id)
        .order_by(models.Camera.id.desc())
    )

    total = base_query.count()
    rows = base_query.offset(page_params.offset).limit(page_params.page_size).all()
    total_pages = (total + page_params.page_size - 1) // page_params.page_size if total else 0

    return {
        "items": [
            schemas.CameraAdminResponse(
                camera_id=c.id,
                is_active=c.is_active,
                verification_status=c.verification_status,
                created_at=c.created_at,
                rtsp_url=c.rtsp_url,
                owner_user_id=c.owner_user_id,
                webhook_is_active=webhook_is_active,
            )
            for c, webhook_is_active in rows
        ],
        "total": total,
        "page": page_params.page,
        "page_size": page_params.page_size,
        "total_pages": total_pages,
    }

@router.get("/users", response_model=schemas.PaginatedResponse[schemas.UserAdminResponse])
def list_users(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายชื่อ user ทั้งหมดในระบบแบบแบ่งหน้า ใช้กับแท็บ Admin > ผู้ใช้งาน (ตาราง overview)
    รายละเอียดเจาะลึกรายคน (webhook_count/camera_count/suspended_reason) ยังคงต้องเรียก
    GET /admin/users/{user_id} แยกต่างหาก (endpoint เดิม ไม่เปลี่ยน)"""
    query = db.query(models.User).order_by(models.User.id.desc())
    return paginate(query, page_params)


@router.get("/users/{user_id}", response_model=schemas.UserAdminDetailResponse)
def get_user_detail(
    user_id: int,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายละเอียด user คนเดียว พร้อมจำนวน webhook/camera ที่มี """
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

    try:
        if user.is_suspended:
            send_account_suspended_email(user.email, user.suspended_reason)
        else:
            send_account_unsuspended_email(user.email)
    except RuntimeError as e:
        action = "ระงับ" if user.is_suspended else "ปลดระงับ"
        logging.error(f"ส่งอีเมลแจ้ง{action}บัญชี user_id={user.id} ไม่สำเร็จ: {e}")

    return user


@router.get("/webhooks", response_model=schemas.PaginatedResponse[schemas.WebhookAdminResponse])
def list_webhooks(
    user_id: Optional[int] = Query(default=None, description="กรองเฉพาะ webhook ของ user คนนี้"),
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดู webhook endpoint ทั้งหมดในระบบ ไม่ว่าใครเป็นเจ้าของ"""
    query = db.query(models.WebhookEndpoint)
    if user_id is not None:
        query = query.filter(models.WebhookEndpoint.user_id == user_id)
    query = query.order_by(models.WebhookEndpoint.id.desc())
    return paginate(query, page_params)


@router.patch("/webhooks/{webhook_id}/status", response_model=schemas.WebhookAdminResponse)
def set_webhook_status(
    webhook_id: int,
    payload: schemas.WebhookStatusUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    endpoint = db.query(models.WebhookEndpoint).filter(models.WebhookEndpoint.id == webhook_id).first()
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบ webhook endpoint นี้")

    endpoint.is_active = payload.is_active
    endpoint.disabled_reason = payload.admin_note if not payload.is_active else None

    # เก็บไว้ก่อน commit เพื่อรู้ว่าต้อง trigger resume ด้านล่างหรือไม่ (is_healthy ไม่ได้ถูก
    # แตะในฟังก์ชันนี้เลย อ่านตอนไหนก็ค่าเดิม แค่เขียนให้ชัดเจนว่าอ่านจากตอนไหน)
    was_unhealthy = not endpoint.is_healthy

    db.commit()
    db.refresh(endpoint)

    owner = db.query(models.User).filter(models.User.id == endpoint.user_id).first()
    if owner:
        try:
            if endpoint.is_active:
                send_webhook_enabled_email(owner.email, endpoint.url)
            else:
                send_webhook_disabled_email(owner.email, endpoint.url, endpoint.disabled_reason)
        except RuntimeError as e:
            action = "เปิด" if endpoint.is_active else "ปิด"
            logging.error(f"ส่งอีเมลแจ้ง{action}ใช้งาน webhook id={endpoint.id} ไม่สำเร็จ: {e}")

    # [Circuit Breaker]: endpoint นี้เคยถูกตัดไฟ (is_healthy=False) อยู่ก่อน admin เปิดกลับมา
    # -> ลอง ping + resume event ในสุสานทันทีในพื้นหลัง แทนที่จะรอ Job B รอบถัดไป (สูงสุด 30 นาที)
    # ไม่ set is_healthy=True ตรงๆ ในนี้เพราะไม่อยาก trust คำสั่ง admin เฉยๆ โดยไม่เช็คจริง
    if payload.is_active and was_unhealthy:
        background_tasks.add_task(resume_endpoint_now, endpoint.id)

    return endpoint