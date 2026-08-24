from smartlpr import models


def log_admin_action(
    db,
    actor_id: str | None,
    action: str,
    target_type: str,
    target_id,
    detail: dict | None = None,
    ip_address: str | None = None,
    actor_type: str = "admin",
) -> None:
    """เพิ่ม AdminAuditLog เข้า session เฉยๆ (db.add) — ไม่ commit เอง โดยตั้งใจ ให้ caller
    เป็นคนสั่ง commit() พร้อมกับการเปลี่ยนแปลงหลัก (เช่น user.is_suspended = True) ในทีเดียวกัน
    เพื่อการันตี atomicity: action สำเร็จ = ต้องมี log คู่กันเสมอ ไม่มีทางที่ action ผ่านแต่ log
    หายไป (หรือกลับกัน) เพราะทั้งคู่อยู่ใน transaction เดียวกัน

    [Actor Rename]: เดิมพารามิเตอร์ตัวที่ 2 ชื่อ admin_id (บังคับมีค่าเสมอ เพราะตารางนี้เคยบันทึก
    แค่ action ของ admin เท่านั้น) ตอนนี้เปลี่ยนชื่อเป็น actor_id และรับ None ได้ — ใช้ร่วมกันทั้ง
    3 ประเภทผู้ทำรายการผ่านพารามิเตอร์ actor_type ใหม่:

      - actor_type="admin"  (ค่าเริ่มต้น ไม่กระทบ caller เดิมที่เรียกแบบ positional จาก
        routers/admin.py — ยังส่ง (db, admin.id, ...) แบบเดิมได้เลยไม่ต้องแก้)
      - actor_type="user"   ผู้ใช้ทำรายการกับทรัพยากร/บัญชีของตัวเอง เช่น login, เพิ่ม webhook
      - actor_type="system" background worker ทำเอง ไม่มี actor เป็นมนุษย์ — เรียกด้วย
        actor_id=None, ip_address=None เสมอ (ไม่มี request context ให้ดึง)

    target_id แปลงเป็น str เสมอ เผื่อในอนาคต target อื่นๆ ใช้ id ที่ไม่ใช่ int (เช่น camera_id)

    ip_address: IP ของผู้ทำรายการ (caller ส่ง request.client.host มาให้ — ดู routers/*.py)
    ไม่บังคับ (None ได้ เผื่อจุดเรียกในอนาคตที่ไม่มี request context หรือเป็น actor_type="system")
    """
    db.add(models.AdminAuditLog(
        actor_id=actor_id,
        actor_type=actor_type,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        detail=detail,
        ip_address=ip_address,
    ))