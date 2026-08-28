from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, update, delete, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_access_approved, get_current_user
from security.ssrf_guard import verify_webhook_url
from services.rate_limiter import check_rate_limit
from services.audit_log import log_admin_action
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/webhook", tags=["Webhook Management"])

@router.post("/add", response_model=schemas.WebhookResponse)
async def add_webhook(
    webhook: schemas.WebhookCreate,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):

    # [แก้ไข] check_rate_limit เป็น async def แล้ว เดิมเรียกไม่มี await ทำให้ rate limit จุดนี้ไม่ทำงานจริง
    await check_rate_limit(db, f"add_webhook_{current_user.id}", "add_webhook", limit=20, window_minutes=60)

    url_str = str(webhook.url)

    existing_result = await db.execute(
        select(models.WebhookEndpoint).filter(models.WebhookEndpoint.url == url_str)
    )
    existing = existing_result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL นี้ถูกใช้เป็น webhook ในระบบไปแล้ว กรุณาตรวจสอบรายการ webhook ของคุณ (GET /webhook/my) หรือใช้ URL อื่น",
        )

    await verify_webhook_url(url_str)

    new_endpoint = models.WebhookEndpoint(
        user_id=current_user.id,
        url=url_str,
        is_active=True
    )
    db.add(new_endpoint)
    
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL นี้ถูกใช้เป็น webhook ในระบบไปแล้ว กรุณาตรวจสอบรายการ webhook ของคุณ (GET /webhook/my) หรือใช้ URL อื่น",
        )

    log_admin_action(
        db, current_user.id,
        action="webhook.add",
        target_type="webhook_endpoint",
        target_id=new_endpoint.id,
        detail={"url": url_str},
        actor_type="user",
    )

    await db.commit()
    await db.refresh(new_endpoint)

    return new_endpoint


@router.get("/my", response_model=schemas.PaginatedResponse[schemas.WebhookResponse])
async def list_my_webhooks(
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    # แค่ดูข้อมูล ไม่มีสิทธิ์สร้าง/แก้ -> ใช้ get_current_user เฉยๆ พอ ตาม dependency rule ข้อ 7
    current_user: models.User = Depends(get_current_user),
):
    """
    List webhook endpoint ทั้งหมดของตัวเอง พร้อมสถานะ circuit breaker
    (is_healthy, consecutive_dead_letters) — ใช้ทำ dashboard ดูภาพรวมว่า endpoint ไหน
    กำลังมีปัญหา/ถูกตัดไฟอยู่บ้าง
    """
    query = (
        select(models.WebhookEndpoint)
        .filter(models.WebhookEndpoint.user_id == current_user.id)
        .order_by(models.WebhookEndpoint.id.desc())
    )
    return await paginate(db, query, page_params)


@router.delete("/{webhook_id}")
async def delete_webhook(
    webhook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):

    await check_rate_limit(
        db, f"delete_webhook_{current_user.id}", "delete_webhook", limit=20, window_minutes=60
    )

    result = await db.execute(
        select(models.WebhookEndpoint).filter(
            models.WebhookEndpoint.id == webhook_id,
            models.WebhookEndpoint.user_id == current_user.id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ไม่พบ webhook endpoint นี้ในบัญชีของคุณ",
        )

    # หา id กล้องทั้งหมดที่ผูกกับ endpoint นี้ไว้ก่อน (เอาไปบันทึก audit log — หลังลบจริงหาไม่ได้อีก)
    cameras_result = await db.execute(
        select(models.Camera.id).filter(models.Camera.webhook_endpoint_id == endpoint.id)
    )
    camera_ids = [cid for (cid,) in cameras_result.all()]

    event_count = (await db.execute(
        select(func.count()).select_from(models.WebhookEvent)
        .filter(models.WebhookEvent.webhook_endpoint_id == endpoint.id)
    )).scalar_one()

    if event_count:
        await db.execute(
            update(models.WebhookEvent)
            .where(models.WebhookEvent.webhook_endpoint_id == endpoint.id)
            .values(webhook_endpoint_id=None, camera_id=None)
        )

    if camera_ids:
        await db.execute(
            delete(models.Camera).where(models.Camera.webhook_endpoint_id == endpoint.id)
        )

    log_admin_action(
        db, current_user.id,
        action="webhook.delete",
        target_type="webhook_endpoint",
        target_id=endpoint.id,
        detail={
            "url": endpoint.url,
            "deleted_camera_ids": camera_ids,
            "orphaned_event_count": event_count,
        },
        actor_type="user",
    )

    url = endpoint.url
    await db.delete(endpoint)
    await db.commit()

    camera_note = f"พร้อมกล้องที่ผูกไว้ทั้งหมด {len(camera_ids)} ตัว " if camera_ids else ""

    return {
        "message": (
            f"ลบ webhook '{url}' {camera_note}ออกจากระบบเรียบร้อยแล้ว "
            f"ข้อมูล event ที่เคยบันทึกไว้ ({event_count} รายการ) จะยังคงอยู่ในระบบตามระยะเวลาเก็บข้อมูลปกติ "
            "(ไม่ผูกกับ webhook/กล้องนี้อีกต่อไป) URL นี้สามารถนำไปสร้าง webhook ใหม่ได้ทันที"
        )
    }