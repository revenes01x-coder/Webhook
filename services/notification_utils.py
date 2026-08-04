from datetime import datetime, timezone
from sqlalchemy.orm import Session

from smartlpr import models


def notify_admins(db: Session, request_type: str, request_id: int, message: str) -> None:

    admins = db.query(models.User).filter(models.User.is_admin == True).all()  # noqa: E712
    for admin_user in admins:
        db.add(models.AdminNotification(
            admin_id=admin_user.id,
            request_type=request_type,
            request_id=request_id,
            message=message,
        ))


def resolve_notifications(db: Session, request_type: str, request_id: int) -> None:
    """
    ตั้ง resolved_at ให้ notification ทุก record ที่ผูกกับคำขอนี้ (ของ admin ทุกคน ไม่ใช่แค่
    คนที่กด approve/reject) — ไม่แตะ is_read เพื่อให้ยังขึ้นในประวัติว่า "จบแล้วแต่ยังไม่เคยอ่าน" ได้
    เรียกใช้ตอน admin approve/reject คำขอ — ไม่ commit ในนี้เหมือนกัน
    """
    db.query(models.AdminNotification).filter(
        models.AdminNotification.request_type == request_type,
        models.AdminNotification.request_id == request_id,
        models.AdminNotification.resolved_at.is_(None),
    ).update({"resolved_at": datetime.now(timezone.utc)}, synchronize_session=False)