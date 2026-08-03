from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
import models, schemas
from database import get_db
from security import require_access_approved
from ssrf_guard import verify_webhook_url
from rate_limiter import check_rate_limit

router = APIRouter(prefix="/webhook", tags=["Webhook Management"])

# เปลี่ยนจาก get_current_user -> require_access_approved แล้ว (step 3 พร้อมใช้งาน)
# dependency chain: login (is_verified) -> require_terms_accepted -> require_access_approved

# หมายเหตุ: ตัด POST /webhook/resend/{event_id} ออกแล้ว — ระบบ circuit breaker +
# process_graveyard_resume (worker.py) จัดการ resume event ที่ตกสุสานให้อัตโนมัติทุก 30 นาที
# ไม่ต้องให้ user กดเองอีกต่อไป


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