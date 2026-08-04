from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_api_key
from security.camera_url_guard import verify_camera_rtsp_url
from services.rate_limiter import check_rate_limit
from smartlpr.pagination import PageParams

router = APIRouter(prefix="/my", tags=["My Cameras"])


@router.post("/cameras", response_model=schemas.MyCameraResponse)
def add_my_camera(
    payload: schemas.CameraSelfCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):
    """
    User เพิ่มกล้องของตัวเอง — เจ้าของคือ current_user คนเดียวเท่านั้น (ไม่มีการแชร์สิทธิ์ให้ user อื่น)
    ยืนยันตัวตนด้วย API key (header X-API-Key) ไม่ใช่ JWT เพราะ endpoint นี้ออกแบบให้ระบบ
    อัตโนมัติของ user ยิงเข้ามาเอง ไม่ใช่ user นั่ง login ผ่านเว็บ — ขอ API key ได้ที่
    POST /my/api-key/regenerate (ต้อง login ด้วย JWT ก่อนครั้งเดียวตอนขอ key)
    User เป็นคนกำหนด camera_id เอง (ไม่ auto-generate) เพื่อให้ตั้งค่าฝั่งอุปกรณ์กล้องจริงได้ล่วงหน้า
    ตรวจสอบ 2 จังหวะ:
      1) ทันที: กัน camera_id ซ้ำ + URL ซ้ำ + SSRF guard (scheme ต้อง rtsp://, host ต้องไม่ใช่ private/loopback IP)
      2) เบื้องหลัง: background job (worker.py) จะลองต่อ RTSP จริงภายในไม่กี่นาที
         ถ้าต่อได้ -> is_active=True, verification_status="verified"
         ถ้าต่อไม่ได้ -> verification_status="failed" (ตรวจสอบ URL อีกครั้ง)
    กล้องจะยังไม่ active จนกว่าจังหวะที่ 2 จะผ่าน
    """
    # [Rate Limit]: เพิ่มกล้องได้ 5 ตัว / ชั่วโมง / user (กันสแปม/API key หลุดแล้วโดนยิงรัว)
    check_rate_limit(db, f"add_camera_{current_user.id}", "add_camera", limit=5, window_minutes=60)

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

    verify_camera_rtsp_url(payload.camera_url)

    new_camera = models.Camera(
        id=payload.camera_id,
        owner_user_id=current_user.id,
        rtsp_url=payload.camera_url,
        is_active=False,               # จะเป็น True ก็ต่อเมื่อ background job verify สำเร็จ
        verification_status="pending",
    )
    db.add(new_camera)
    db.commit()
    db.refresh(new_camera)

    return schemas.MyCameraResponse(
        camera_id=new_camera.id,
        is_active=new_camera.is_active,
        verification_status=new_camera.verification_status,
        created_at=new_camera.created_at,
    )


@router.get("/cameras", response_model=schemas.PaginatedResponse[schemas.MyCameraResponse])
def list_my_cameras(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """List กล้องของตัวเองทั้งหมด พร้อม verification_status (pending/verified/failed)

    รองรับ pagination ผ่าน query param ?page=&page_size= (ดีฟอลต์ page=1, page_size=20)
    เขียน paginate เองในนี้ (ไม่เรียก pagination.paginate ตรงๆ) เพราะต้อง map
    Camera (ORM) -> MyCameraResponse เอง ก่อนใส่ลง items (field ไม่ตรงกับคอลัมน์ตรงๆ)
    """
    base_query = db.query(models.Camera).filter(models.Camera.owner_user_id == current_user.id)

    total = base_query.count()
    cameras = (
        base_query
        .order_by(models.Camera.id.desc())
        .offset(page_params.offset)
        .limit(page_params.page_size)
        .all()
    )
    total_pages = (total + page_params.page_size - 1) // page_params.page_size if total else 0

    return {
        "items": [
            schemas.MyCameraResponse(
                camera_id=c.id,
                is_active=c.is_active,
                verification_status=c.verification_status,
                created_at=c.created_at,
            )
            for c in cameras
        ],
        "total": total,
        "page": page_params.page,
        "page_size": page_params.page_size,
        "total_pages": total_pages,
    }


@router.delete("/cameras/{camera_id}")
def delete_my_camera(
    camera_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    """
    User ลบกล้องของตัวเองได้ (เฉพาะเจ้าของเท่านั้น) — hard delete
    พอกล้องหายไปจาก DB แล้ว camera_manager.py จะ terminate process ของกล้องนี้เองอัตโนมัติ
    ในรอบ poll ถัดไป (สูงสุด 30 วิ) เพราะไม่เจอกล้องนี้ในรายชื่อ active อีกต่อไป

    หมายเหตุ: WebhookEvent เก่าที่เคยผูกกับกล้องนี้ (camera_id) จะยังอยู่ในระบบต่อไปเป็นประวัติ
    ไม่ได้ถูกลบตาม ไม่กระทบ webhook ที่เคยส่งสำเร็จไปแล้ว
    """
    camera = db.query(models.Camera).filter(
        models.Camera.id == camera_id,
        models.Camera.owner_user_id == current_user.id,
    ).first()

    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="ไม่พบกล้องนี้ หรือคุณไม่ใช่เจ้าของกล้องนี้",
        )

    db.delete(camera)
    db.commit()

    return {"message": f"ลบกล้อง '{camera.id}' เรียบร้อยแล้ว"}