from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_terms_accepted
from smartlpr.pagination import PageParams, paginate

router = APIRouter(prefix="/access-request", tags=["Access Request"])


@router.post("/submit", response_model=schemas.AccessRequestResponse)
async def submit_access_request(
    payload: schemas.AccessRequestCreate,
    db: AsyncSession = Depends(get_db),
    # ต้องผ่าน require_terms_accepted ก่อนเสมอ (login -> terms -> access-request)
    current_user: models.User = Depends(require_terms_accepted),
):
    already_approved_result = await db.execute(
        select(models.AccessRequest).filter(
            models.AccessRequest.user_id == current_user.id,
            models.AccessRequest.status == "approved",
        )
    )
    already_approved = already_approved_result.scalar_one_or_none()
    if already_approved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="คุณได้รับอนุมัติให้ใช้งานระบบนี้ไปแล้ว ไม่จำเป็นต้องส่งคำขอใหม่",
        )

    existing_pending_result = await db.execute(
        select(models.AccessRequest).filter(
            models.AccessRequest.user_id == current_user.id,
            models.AccessRequest.status == "pending",
        )
    )
    existing_pending = existing_pending_result.scalar_one_or_none()
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
    await db.commit()
    await db.refresh(new_request)
    return new_request

@router.get("/my-status", response_model=schemas.PaginatedResponse[schemas.AccessRequestResponse])
async def my_access_requests(
    page_params: PageParams = Depends(),
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    query = (
        select(models.AccessRequest)
        .filter(models.AccessRequest.user_id == current_user.id)
        .order_by(models.AccessRequest.id.desc())
    )

    return await paginate(db, query, page_params)