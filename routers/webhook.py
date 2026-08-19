from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_access_approved, get_current_user
from security.ssrf_guard import verify_webhook_url
from services.rate_limiter import check_rate_limit
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
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="URL นี้ถูกใช้เป็น webhook ในระบบไปแล้ว กรุณาตรวจสอบรายการ webhook ของคุณ (GET /webhook/my) หรือใช้ URL อื่น",
        )

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