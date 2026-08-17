from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_api_key
from security.camera_url_guard import verify_camera_rtsp_url
from services.rate_limiter import check_rate_limit

router = APIRouter(prefix="/partner", tags=["Partner Integration"])

@router.post("/cameras", response_model=schemas.MyCameraResponse)
def add_camera_from_partner(
    payload: schemas.PartnerCameraCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):
  
    # [Rate Limit]: เพิ่มกล้องได้ 5 ตัว / ชั่วโมง / user (กันสแปม/API key หลุดแล้วโดนยิงรัว)
    check_rate_limit(db, f"partner_add_camera_{current_user.id}", "partner_add_camera", limit=5, window_minutes=60)

    existing_id = db.query(models.Camera).filter(models.Camera.id == payload.camera_id).first()
    if existing_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"camera_id '{payload.camera_id}' ถูกใช้ไปแล้ว กรุณาตั้งชื่ออื่น",
        )

    existing_url = db.query(models.Camera).filter(models.Camera.rtsp_url == payload.camera_url).first()
    if existing_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ลิงก์นี้ถูกเพิ่มเข้าระบบไปแล้ว",
        )

    webhook = db.query(models.WebhookEndpoint).filter(
        models.WebhookEndpoint.url == payload.webhook_url,
        models.WebhookEndpoint.user_id == current_user.id,
    ).first()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "ไม่พบ webhook_url นี้ในบัญชีของคุณ กรุณาสร้าง webhook ก่อนผ่าน POST /webhook/add "
                "แล้วใช้ URL เดียวกันมาผูกกับกล้อง"
            ),
        )

    verify_camera_rtsp_url(payload.camera_url)

    new_camera = models.Camera(
        id=payload.camera_id,
        owner_user_id=current_user.id,
        rtsp_url=payload.camera_url,
        webhook_endpoint_id=webhook.id,
        is_active=False,               # จะเป็น True ก็ต่อเมื่อ background job verify สำเร็จ
        verification_status="pending",
    )
    db.add(new_camera)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"camera_id '{payload.camera_id}' ถูกใช้ไปแล้ว กรุณาตั้งชื่ออื่น",
        )

    db.refresh(new_camera)

    return schemas.MyCameraResponse(
        camera_id=new_camera.id,
        is_active=new_camera.is_active,
        verification_status=new_camera.verification_status,
        webhook_url=webhook.url,
        webhook_is_active=webhook.is_active,
        created_at=new_camera.created_at,
    )


@router.post("/cameras/status")
def update_camera_status_from_partner(
    payload: schemas.PartnerCameraStatusUpdate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):

    camera = db.query(models.Camera).filter(
        models.Camera.id == payload.camera_id,
        models.Camera.owner_user_id == current_user.id,
    ).first()
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ไม่พบกล้อง camera_id='{payload.camera_id}' ในบัญชีของคุณ",
        )

    if payload.is_active and camera.verification_status != "verified":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"ไม่สามารถเปิดกล้องนี้ได้: กล้องยังไม่ผ่านการตรวจสอบ RTSP "
                f"(สถานะปัจจุบัน: {camera.verification_status})"
            ),
        )

    camera.is_active = payload.is_active
    db.commit()

    status_text = "เปิด" if payload.is_active else "ปิด"
    return {"message": f"{status_text}ใช้งานกล้อง '{camera.id}' เรียบร้อยแล้ว"}

@router.get("/cameras/{camera_id}", response_model=schemas.PartnerCameraStatusResponse)
def get_camera_verification_status(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):
    check_rate_limit(db, f"camera_status_check_{current_user.id}", "camera_status_check", limit=20, window_minutes=60)

    camera = db.query(models.Camera).filter(
        models.Camera.id == camera_id,
        models.Camera.owner_user_id == current_user.id,
    ).first()
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"ไม่พบกล้อง camera_id='{camera_id}' ในบัญชีของคุณ อาจยังไม่เคยสร้างหรือถูกลบ"
                "ออกจากระบบแล้วเนื่องจากยืนยันการเชื่อมต่อ RTSP ไม่สำเร็จ กรุณาตรวจสอบลิงก์กล้อง"
                "แล้วลองสร้างใหม่อีกครั้ง"
            ),
        )

    return schemas.PartnerCameraStatusResponse(
        camera_id=camera.id,
        verification_status=camera.verification_status,
        verify_attempt_count=camera.verify_attempt_count,
        is_active=camera.is_active,
    )