from smartlpr import models


def log_admin_action(
    db,
    admin_id: int,
    action: str,
    target_type: str,
    target_id,
    detail: dict | None = None,
) -> None:
    """เพิ่ม AdminAuditLog เข้า session เฉยๆ (db.add) — ไม่ commit เอง โดยตั้งใจ ให้ caller
    เป็นคนสั่ง commit() พร้อมกับการเปลี่ยนแปลงหลัก (เช่น user.is_suspended = True) ในทีเดียวกัน
    เพื่อการันตี atomicity: action สำเร็จ = ต้องมี log คู่กันเสมอ ไม่มีทางที่ action ผ่านแต่ log
    หายไป (หรือกลับกัน) เพราะทั้งคู่อยู่ใน transaction เดียวกัน

    target_id แปลงเป็น str เสมอ เผื่อในอนาคต target อื่นๆ ใช้ id ที่ไม่ใช่ int (เช่น camera_id)
    """
    db.add(models.AdminAuditLog(
        admin_id=admin_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        detail=detail,
    ))