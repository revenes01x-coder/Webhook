from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

import models, smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_terms_accepted
from services.notification_utils import notify_admins
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/access-request", tags=["Access Request"])


@router.post("/submit", response_model=schemas.AccessRequestResponse)
def submit_access_request(
    payload: schemas.AccessRequestCreate,
    db: Session = Depends(get_db),
    # ต้องผ่าน require_terms_accepted ก่อนเสมอ (login -> terms -> access-request)
    current_user: models.User = Depends(require_terms_accepted),
):
    # ห้ามส่งซ้ำถ้ามี request ที่ status "pending" อยู่แล้ว
    existing_pending = (
        db.query(models.AccessRequest)
        .filter(
            models.AccessRequest.user_id == current_user.id,
            models.AccessRequest.status == "pending",
        )
        .first()
    )
    if existing_pending:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="คุณมีคำขอที่รอการอนุมัติอยู่แล้ว กรุณารอผลก่อนส่งคำขอใหม่",
        )

    new_request = models.AccessRequest(
        user_id=current_user.id,
        organization_name=payload.organization_name,
        contact_email=payload.contact_email,
        use_case=payload.use_case,
        contact_phone=payload.contact_phone,
        contact_name=payload.contact_name,
        status="pending",
    )
    db.add(new_request)
    db.flush()  # ได้ new_request.id ก่อน commit จริง เอาไปใส่ในข้อความแจ้งเตือน

    notify_admins(
        db,
        request_type="access_request",
        request_id=new_request.id,
        message=f"คำขอใช้งานระบบใหม่จาก {new_request.organization_name} (#{new_request.id})",
    )

    db.commit()
    db.refresh(new_request)
    return new_request


@router.get("/my-status", response_model=schemas.PaginatedResponse[schemas.AccessRequestResponse])
def my_access_requests(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    # แค่ดูข้อมูลของตัวเอง ไม่ต้อง block ด้วย terms/approved (ตาม dependency rule ข้อ 7)
    current_user: models.User = Depends(get_current_user),
):
    """
    List คำขอใช้งานของตัวเองทั้งหมด เรียงล่าสุดก่อน
    รองรับ pagination ผ่าน query param ?page=&page_size= (ดีฟอลต์ page=1, page_size=20)
    เหมือน endpoint อื่นๆ ในระบบ (ดู pagination.py) — ปกติ user คนหนึ่งไม่ได้ส่งคำขอเยอะ
    แต่ทำไว้ให้สอดคล้องกันทั้งระบบ และกัน response โตไม่จำกัดในระยะยาว
    """
    query = (
        db.query(models.AccessRequest)
        .filter(models.AccessRequest.user_id == current_user.id)
        .order_by(models.AccessRequest.id.desc())
    )
    return paginate(query, page_params)