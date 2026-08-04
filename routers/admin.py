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


@router.patch("/cameras/{camera_id}/status", response_model=schemas.CameraAdminResponse)
def set_camera_status(
    camera_id: str,
    payload: schemas.CameraStatusUpdate,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """
    เปิด/ปิดใช้งานกล้องของ user คนไหนก็ได้ (เช่น พบการใช้งานผิดกฎ)
    พอ is_active=False แล้ว camera_manager.py จะ terminate process ของกล้องนี้เอง
    อัตโนมัติในรอบ poll ถัดไป (สูงสุด 30 วิ) ไม่ต้องทำอะไรเพิ่ม
    """
    camera = db.query(models.Camera).filter(models.Camera.id == camera_id).first()
    if not camera:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบกล้องนี้")

    camera.is_active = payload.is_active
    db.commit()
    db.refresh(camera)
    return camera

