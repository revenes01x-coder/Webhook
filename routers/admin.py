import asyncio
import logging
from fastapi import APIRouter, Depends, HTTPException, status, Query, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timezone
from typing import List, Optional
from worker import resume_endpoint_now
from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_admin
from services.audit_log import log_admin_action
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
async def list_access_requests(
    status_filter: Optional[str] = Query(
        default="pending",
        alias="status",
        description="กรองตามสถานะ: pending / approved / rejected (ไม่ใส่ = ดูทั้งหมด)",
    ),
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    if status_filter and status_filter not in _VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"status ต้องเป็นหนึ่งใน {sorted(_VALID_STATUSES)}",
        )

    query = select(models.AccessRequest)
    if status_filter:
        query = query.filter(models.AccessRequest.status == status_filter)
    query = query.order_by(models.AccessRequest.id.desc())

    return await paginate(db, query, page_params)

@router.get("/access-requests/{request_id}", response_model=schemas.AccessRequestResponse)
async def get_access_request_detail(
    request_id: int,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    result = await db.execute(select(models.AccessRequest).filter(models.AccessRequest.id == request_id))
    req = result.scalar_one_or_none()
    if not req:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบคำขอนี้")
    return req

@router.patch("/access-requests/{request_id}", response_model=schemas.AccessRequestResponse)
async def review_access_request(
    request_id: int,
    payload: schemas.ReviewDecision,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    result = await db.execute(select(models.AccessRequest).filter(models.AccessRequest.id == request_id))
    req = result.scalar_one_or_none()
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

    # [Audit Log]: บันทึกก่อน commit เสมอ ให้ commit เดียวกันครอบทั้ง action หลักและ log
    # การันตี atomicity — action สำเร็จ = ต้องมี log คู่กันเสมอ (ดู services/audit_log.py)
    log_admin_action(
        db, admin.id,
        action=f"access_request.{payload.decision}",
        target_type="access_request",
        target_id=req.id,
        detail={
            "organization_name": req.organization_name,
            "requester_user_id": req.user_id,
            "admin_note": req.admin_note,
        },
    )

    await db.commit()
    await db.refresh(req)

    owner_result = await db.execute(select(models.User).filter(models.User.id == req.user_id))
    owner = owner_result.scalar_one_or_none()

    if owner:
        try:
            if req.status == "approved":
                await asyncio.to_thread(send_access_approved_email, owner.email)
            else:
                await asyncio.to_thread(send_access_rejected_email, owner.email, req.admin_note or _DEFAULT_REJECT_NOTE)
        except RuntimeError as e:
            logging.error(f"ส่งอีเมลแจ้งผล access request id={req.id} ไม่สำเร็จ: {e}")
    else:
        # ไม่ควรเกิดขึ้นจริง (user_id เป็น FK บังคับ ไม่มี user แปลว่าข้อมูลเพี้ยน) — log ไว้เฉยๆ
        # ไม่ raise เพราะการอนุมัติ/ปฏิเสธ commit ไปแล้วเรียบร้อย ไม่อยากให้ response ล้มเพราะเรื่องนี้
        logging.error(
            f"ไม่พบเจ้าของบัญชี (user_id={req.user_id}) สำหรับ access request id={req.id} "
            "— ข้ามการส่งอีเมลแจ้งผล"
        )

    return req

@router.get("/cameras", response_model=schemas.PaginatedResponse[schemas.CameraAdminResponse])
async def list_cameras(
    owner_user_id: Optional[int] = Query(
        default=None,
        description="กรองเฉพาะกล้องของเจ้าของ (owner_user_id) คนนี้เท่านั้น (exact match) — ไม่ระบุ = ดูทั้งหมด",
    ),
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูกล้องทั้งหมดในระบบ ไม่ว่าใครเป็นเจ้าของ พร้อมสถานะ webhook ปลายทางที่ผูกไว้
    (webhook_is_active) ให้เห็นได้เลยว่ากล้องไหน is_active=True แต่จริงๆ ไม่ได้รันอยู่เพราะ
    webhook ถูกปิด

    ระบุ owner_user_id เพื่อกรองดูเฉพาะกล้องของ user คนเดียว (exact match) ได้ — ใช้ตอนกด
    "ดูกล้องของ user นี้" จาก modal รายละเอียด user (GET /admin/users/{id})"""
    base_query = (
        select(models.Camera, models.WebhookEndpoint.is_active)
        .join(models.WebhookEndpoint, models.Camera.webhook_endpoint_id == models.WebhookEndpoint.id)
    )
    if owner_user_id is not None:
        base_query = base_query.filter(models.Camera.owner_user_id == owner_user_id)
    base_query = base_query.order_by(models.Camera.id.desc())

    count_query = select(func.count()).select_from(base_query.order_by(None).subquery())
    total = (await db.execute(count_query)).scalar_one()

    rows_result = await db.execute(base_query.offset(page_params.offset).limit(page_params.page_size))
    rows = rows_result.all()
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
async def list_users(
    user_id: Optional[int] = Query(
        default=None,
        description="กรองเฉพาะ user ที่มี ID ตรงกับค่านี้เท่านั้น (exact match) — ไม่ระบุ = ดูทั้งหมด",
    ),
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายชื่อ user ทั้งหมดในระบบแบบแบ่งหน้า ใช้กับแท็บ Admin > ผู้ใช้งาน (ตาราง overview)
    ระบุ user_id เพื่อกรองดูเฉพาะ user คนเดียว (exact match) ได้ (ค้นด้วย User ID เท่านั้น
    ไม่รองรับค้นด้วยอีเมล/ค้นบางส่วนตามที่ตกลงไว้)

    รายละเอียดเจาะลึกรายคน (webhook_count/camera_count/suspended_reason) ยังคงต้องเรียก
    GET /admin/users/{user_id} แยกต่างหาก (endpoint เดิม ไม่เปลี่ยน)"""
    query = select(models.User)
    if user_id is not None:
        query = query.filter(models.User.id == user_id)
    query = query.order_by(models.User.id.desc())
    return await paginate(db, query, page_params)


@router.get("/users/{user_id}", response_model=schemas.UserAdminDetailResponse)
async def get_user_detail(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดูรายละเอียด user คนเดียว พร้อมจำนวน webhook/camera ที่มี และประวัติคำขอใช้งานระบบ
    (access_requests) ทั้งหมดที่เคยส่ง เรียงจากล่าสุดไปเก่าสุด — ใช้โชว์ข้อมูลที่ user กรอกตอน
    สมัครขอใช้งาน (องค์กร/ผู้ติดต่อ/วัตถุประสงค์) ในโมดัล "รายละเอียดผู้ใช้" ฝั่ง admin"""
    result = await db.execute(select(models.User).filter(models.User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบผู้ใช้นี้")

    webhook_count = (await db.execute(
        select(func.count(models.WebhookEndpoint.id)).filter(models.WebhookEndpoint.user_id == user.id)
    )).scalar_one()
    camera_count = (await db.execute(
        select(func.count(models.Camera.id)).filter(models.Camera.owner_user_id == user.id)
    )).scalar_one()

    # เพิ่ม: ดึงคำขอใช้งานทั้งหมดของ user คนนี้ (อาจมีหลายใบถ้าเคยถูกปฏิเสธแล้วส่งใหม่)
    access_requests_result = await db.execute(
        select(models.AccessRequest)
        .filter(models.AccessRequest.user_id == user.id)
        .order_by(models.AccessRequest.id.desc())
    )
    access_requests = access_requests_result.scalars().all()

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
        access_requests=access_requests,   # <-- เพิ่มบรรทัดนี้
    )

@router.patch("/users/{user_id}/suspend", response_model=schemas.UserAdminResponse)
async def set_user_suspend_status(
    user_id: int,
    payload: schemas.UserSuspendUpdate,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ระงับ/ปลดระงับ user — ห้ามแตะบัญชีของตัวเอง (กัน admin ล็อกตัวเองไม่ได้ตั้งใจ)"""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่สามารถระงับ/ปลดระงับบัญชีของตัวเองได้",
        )

    result = await db.execute(select(models.User).filter(models.User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบผู้ใช้นี้")

    user.is_suspended = payload.is_suspended
    user.suspended_reason = payload.admin_note if payload.is_suspended else None

    # [Audit Log]: เหมือน review_access_request — บันทึกก่อน commit ให้อยู่ transaction เดียวกัน
    log_admin_action(
        db, admin.id,
        action="user.suspend" if payload.is_suspended else "user.unsuspend",
        target_type="user",
        target_id=user.id,
        detail={"user_email": user.email, "admin_note": user.suspended_reason},
    )

    await db.commit()
    await db.refresh(user)

    try:
        if user.is_suspended:
            await asyncio.to_thread(send_account_suspended_email, user.email, user.suspended_reason)
        else:
            await asyncio.to_thread(send_account_unsuspended_email, user.email)
    except RuntimeError as e:
        action = "ระงับ" if user.is_suspended else "ปลดระงับ"
        logging.error(f"ส่งอีเมลแจ้ง{action}บัญชี user_id={user.id} ไม่สำเร็จ: {e}")

    return user


@router.get("/webhooks", response_model=schemas.PaginatedResponse[schemas.WebhookAdminResponse])
async def list_webhooks(
    user_id: Optional[int] = Query(default=None, description="กรองเฉพาะ webhook ของ user คนนี้"),
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ดู webhook endpoint ทั้งหมดในระบบ ไม่ว่าใครเป็นเจ้าของ"""
    query = select(models.WebhookEndpoint)
    if user_id is not None:
        query = query.filter(models.WebhookEndpoint.user_id == user_id)
    query = query.order_by(models.WebhookEndpoint.id.desc())
    return await paginate(db, query, page_params)


@router.patch("/webhooks/{webhook_id}/status", response_model=schemas.WebhookAdminResponse)
async def set_webhook_status(
    webhook_id: int,
    payload: schemas.WebhookStatusUpdate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    result = await db.execute(select(models.WebhookEndpoint).filter(models.WebhookEndpoint.id == webhook_id))
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบ webhook endpoint นี้")

    endpoint.is_active = payload.is_active
    endpoint.disabled_reason = payload.admin_note if not payload.is_active else None

    # เก็บไว้ก่อน commit เพื่อรู้ว่าต้อง trigger resume ด้านล่างหรือไม่ (is_healthy ไม่ได้ถูก
    # แตะในฟังก์ชันนี้เลย อ่านตอนไหนก็ค่าเดิม แค่เขียนให้ชัดเจนว่าอ่านจากตอนไหน)
    was_unhealthy = not endpoint.is_healthy

    # [Audit Log]: เหมือน 2 endpoint ด้านบน — บันทึกก่อน commit ให้อยู่ transaction เดียวกัน
    log_admin_action(
        db, admin.id,
        action="webhook.enable" if payload.is_active else "webhook.disable",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
        detail={"url": endpoint.url, "admin_note": endpoint.disabled_reason},
    )

    await db.commit()
    await db.refresh(endpoint)

    owner_result = await db.execute(select(models.User).filter(models.User.id == endpoint.user_id))
    owner = owner_result.scalar_one_or_none()
    if owner:
        try:
            if endpoint.is_active:
                await asyncio.to_thread(send_webhook_enabled_email, owner.email, endpoint.url)
            else:
                await asyncio.to_thread(send_webhook_disabled_email, owner.email, endpoint.url, endpoint.disabled_reason)
        except RuntimeError as e:
            action = "เปิด" if endpoint.is_active else "ปิด"
            logging.error(f"ส่งอีเมลแจ้ง{action}ใช้งาน webhook id={endpoint.id} ไม่สำเร็จ: {e}")

    # [Circuit Breaker]: endpoint นี้เคยถูกตัดไฟ (is_healthy=False) อยู่ก่อน admin เปิดกลับมา
    # -> ลอง ping + resume event ในสุสานทันทีในพื้นหลัง แทนที่จะรอ Job B รอบถัดไป (สูงสุด 30 นาที)
    # ไม่ set is_healthy=True ตรงๆ ในนี้เพราะไม่อยาก trust คำสั่ง admin เฉยๆ โดยไม่เช็คจริง
    if payload.is_active and was_unhealthy:
        background_tasks.add_task(resume_endpoint_now, endpoint.id)

    return endpoint


@router.get("/audit-log", response_model=schemas.PaginatedResponse[schemas.AdminAuditLogResponse])
async def list_admin_audit_log(
    admin_id: Optional[int] = Query(default=None, description="กรองเฉพาะรายการที่ทำโดย admin คนนี้ (exact match)"),
    action: Optional[str] = Query(default=None, description="กรองตาม action เช่น 'user.suspend', 'webhook.disable' (exact match)"),
    target_type: Optional[str] = Query(default=None, description="กรองตามประเภทเป้าหมาย: user / webhook_endpoint / access_request"),
    target_id: Optional[str] = Query(default=None, description="กรองตาม target_id (exact match)"),
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """ประวัติการกระทำของ admin ทั้งหมดในระบบ (immutable — ไม่มี endpoint แก้ไข/ลบ record
    ในตารางนี้โดยเจตนา) ครอบคลุมการอนุมัติ/ปฏิเสธคำขอใช้งาน, ระงับ/ปลดระงับ user,
    เปิด/ปิด webhook endpoint — ดู services/audit_log.py และจุดที่เรียกใช้ในไฟล์นี้

    join กับ users เพื่อโชว์อีเมลของ admin ที่ทำรายการแทนที่จะโชว์แค่ id เฉยๆ
    ถูกลบทิ้งอัตโนมัติเป็นระยะตาม ADMIN_AUDIT_LOG_RETENTION_DAYS (ดู worker.py:cleanup_old_audit_logs)"""
    base_query = (
        select(models.AdminAuditLog, models.User.email)
        .join(models.User, models.AdminAuditLog.admin_id == models.User.id)
    )
    if admin_id is not None:
        base_query = base_query.filter(models.AdminAuditLog.admin_id == admin_id)
    if action:
        base_query = base_query.filter(models.AdminAuditLog.action == action)
    if target_type:
        base_query = base_query.filter(models.AdminAuditLog.target_type == target_type)
    if target_id:
        base_query = base_query.filter(models.AdminAuditLog.target_id == target_id)
    base_query = base_query.order_by(models.AdminAuditLog.id.desc())

    count_query = select(func.count()).select_from(base_query.order_by(None).subquery())
    total = (await db.execute(count_query)).scalar_one()

    rows_result = await db.execute(
        base_query.offset(page_params.offset).limit(page_params.page_size)
    )
    rows = rows_result.all()
    total_pages = (total + page_params.page_size - 1) // page_params.page_size if total else 0

    return {
        "items": [
            schemas.AdminAuditLogResponse(
                id=log.id,
                admin_id=log.admin_id,
                admin_email=admin_email,
                action=log.action,
                target_type=log.target_type,
                target_id=log.target_id,
                detail=log.detail,
                created_at=log.created_at,
            )
            for log, admin_email in rows
        ],
        "total": total,
        "page": page_params.page,
        "page_size": page_params.page_size,
        "total_pages": total_pages,
    }