from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_access_approved, get_current_user
from security.ssrf_guard import verify_webhook_url
from services.rate_limiter import check_rate_limit
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/webhook", tags=["Webhook Management"])

@router.post("/add", response_model=schemas.WebhookResponse)
def add_webhook(
    webhook: schemas.WebhookCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):

    # [Rate Limit]: ทดสอบ/เพิ่ม URL ได้ 10 ครั้ง / ชั่วโมง / User
    check_rate_limit(db, f"add_webhook_{current_user.id}", "add_webhook", limit=10, window_minutes=60)

    # ส่ง URL เข้าด่านอรหันต์ SSRF Guard
    verify_webhook_url(str(webhook.url))

    new_endpoint = models.WebhookEndpoint(
        user_id=current_user.id,
        url=str(webhook.url),
        is_active=True
    )
    db.add(new_endpoint)
    db.commit()
    db.refresh(new_endpoint)

    return new_endpoint


@router.get("/my", response_model=schemas.PaginatedResponse[schemas.WebhookResponse])
def list_my_webhooks(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    # แค่ดูข้อมูล ไม่มีสิทธิ์สร้าง/แก้ -> ใช้ get_current_user เฉยๆ พอ ตาม dependency rule ข้อ 7
    current_user: models.User = Depends(get_current_user),
):
    """
    List webhook endpoint ทั้งหมดของตัวเอง พร้อมสถานะ circuit breaker
    (is_healthy, consecutive_dead_letters) — ใช้ทำ dashboard ดูภาพรวมว่า endpoint ไหน
    กำลังมีปัญหา/ถูกตัดไฟอยู่บ้าง
    """
    query = (
        db.query(models.WebhookEndpoint)
        .filter(models.WebhookEndpoint.user_id == current_user.id)
        .order_by(models.WebhookEndpoint.id.desc())
    )
    return paginate(query, page_params)