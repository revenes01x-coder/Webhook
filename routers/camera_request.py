from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

import models, schemas
from database import get_db
from security import require_access_approved, get_current_user
from notification_utils import notify_admins

router = APIRouter(tags=["Camera Access Request"])


@router.get("/cameras/available", response_model=List[schemas.CameraResponse])
def list_available_cameras(
    db: Session = Depends(get_db),
    # ต้องผ่าน require_access_approved ก่อน (คำขอใช้งานระบบโดยรวมต้องถูกอนุมัติก่อน
    # ถึงจะมาขอสิทธิ์กล้องเฉพาะเจาะจงต่อได้)
    current_user: models.User = Depends(require_access_approved),
):
    """รายชื่อกล้องที่ยื่นขอสิทธิ์ได้ (ไม่โชว์ rtsp_url เพราะเป็นข้อมูล sensitive) เฉพาะกล้องที่ active"""
    return (
        db.query(models.Camera)
        .filter(models.Camera.is_active == True)
        .order_by(models.Camera.name)
        .all()
    )


@router.post("/camera-request/submit", response_model=schemas.CameraAccessRequestResponse)
def submit_camera_request(
    payload: schemas.CameraAccessRequestCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):
    camera = (
        db.query(models.Camera)
        .filter(models.Camera.id == payload.camera_id, models.Camera.is_active == True)
        .first()
    )
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ไม่พบกล้องนี้ หรือกล้องถูกปิดใช้งานอยู่",
        )

    # มีสิทธิ์รับข้อมูลจากกล้องนี้อยู่แล้ว (active) ไม่ต้องขอซ้ำ
    existing_access = (
        db.query(models.CameraAccess)
        .filter(
            models.CameraAccess.camera_id == payload.camera_id,
            models.CameraAccess.user_id == current_user.id,
            models.CameraAccess.is_active == True,
        )
        .first()
    )
    if existing_access:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="คุณมีสิทธิ์รับข้อมูลจากกล้องนี้อยู่แล้ว",
        )

    # กันยื่นซ้ำถ้ามี pending request ของกล้องเดียวกันค้างอยู่
    existing_pending = (
        db.query(models.CameraAccessRequest)
        .filter(
            models.CameraAccessRequest.camera_id == payload.camera_id,
            models.CameraAccessRequest.user_id == current_user.id,
            models.CameraAccessRequest.status == "pending",
        )
        .first()
    )
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="คุณมีคำขอสิทธิ์กล้องนี้ที่รอการอนุมัติอยู่แล้ว",
        )

    new_request = models.CameraAccessRequest(
        user_id=current_user.id,
        camera_id=payload.camera_id,
        reason=payload.reason,
        status="pending",
    )
    db.add(new_request)
    db.flush()  # ได้ new_request.id ก่อน commit จริง เอาไปใส่ในข้อความแจ้งเตือน

    notify_admins(
        db,
        request_type="camera_request",
        request_id=new_request.id,
        message=f"คำขอสิทธิ์กล้อง {camera.name} ใหม่จาก {current_user.email} (#{new_request.id})",
    )

    db.commit()
    db.refresh(new_request)
    return new_request


@router.get("/camera-request/my-status", response_model=List[schemas.CameraAccessRequestResponse])
def my_camera_requests(
    db: Session = Depends(get_db),
    # แค่ดูข้อมูลของตัวเอง ไม่ต้อง block ด้วย terms/approved ตาม dependency rule ข้อ 7
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.CameraAccessRequest)
        .filter(models.CameraAccessRequest.user_id == current_user.id)
        .order_by(models.CameraAccessRequest.id.desc())
        .all()
    )