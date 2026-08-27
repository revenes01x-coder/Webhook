from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_admin
from services.audit_log import log_admin_action

router = APIRouter(tags=["Contact"])


async def _get_channel_or_404(db: AsyncSession, channel_id: int) -> models.ContactChannel:
    result = await db.execute(
        select(models.ContactChannel).filter(models.ContactChannel.id == channel_id)
    )
    channel = result.scalar_one_or_none()
    if not channel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="ไม่พบช่องทางติดต่อนี้")
    return channel


@router.get("/contact", response_model=list[schemas.ContactChannelResponse])
async def list_contact_channels(
    db: AsyncSession = Depends(get_db),
    # ใช้ get_current_user เฉยๆ (ไม่ผ่าน require_terms_accepted/require_access_approved) —
    # ตั้งใจให้ user ที่บัญชีถูกระงับหรือคำขอใช้งานยังไม่อนุมัติ เข้าดูช่องทางติดต่อทีมงานได้เสมอ
    current_user: models.User = Depends(get_current_user),
):
    """รายการช่องทางติดต่อทั้งหมด เรียงตาม display_order"""
    result = await db.execute(
        select(models.ContactChannel)
        .order_by(models.ContactChannel.display_order.asc(), models.ContactChannel.id.asc())
    )
    return result.scalars().all()


@router.post("/admin/contact-channels", response_model=schemas.ContactChannelResponse)
async def create_contact_channel(
    payload: schemas.ContactChannelCreate,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """เพิ่มช่องทางติดต่อใหม่ — ต่อท้ายลิสต์เสมอ (display_order = ค่าสูงสุดปัจจุบัน + 1)
    admin ใช้ปุ่มเลื่อนขึ้น/ลง (ดู reorder_contact_channel ด้านล่าง) จัดลำดับใหม่เองทีหลังได้"""
    max_order = (await db.execute(select(func.max(models.ContactChannel.display_order)))).scalar_one()

    new_channel = models.ContactChannel(
        label=payload.label,
        value=payload.value,
        link=payload.link,
        icon=payload.icon,
        display_order=(max_order or 0) + 1,
    )
    db.add(new_channel)
    await db.flush()

    log_admin_action(
        db, admin.id,
        action="contact_channel.create",
        target_type="contact_channel",
        target_id=new_channel.id,
        detail={"label": new_channel.label, "value": new_channel.value, "icon": new_channel.icon},
    )

    await db.commit()
    await db.refresh(new_channel)
    return new_channel


@router.patch("/admin/contact-channels/{channel_id}", response_model=schemas.ContactChannelResponse)
async def update_contact_channel(
    channel_id: int,
    payload: schemas.ContactChannelUpdate,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """แก้ไขบางฟิลด์ (partial update) — ฟิลด์ที่ไม่ได้ส่งมาใน body จะไม่ถูกแตะเลย
    (exclude_unset=True) ต่างจากส่ง link=null ตรงๆ ซึ่งหมายถึง "ล้างลิงก์ทิ้ง ให้เหลือข้อความล้วน\""""
    channel = await _get_channel_or_404(db, channel_id)

    updates = payload.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ไม่มีข้อมูลที่จะแก้ไข",
        )

    for field, value in updates.items():
        setattr(channel, field, value)

    log_admin_action(
        db, admin.id,
        action="contact_channel.update",
        target_type="contact_channel",
        target_id=channel.id,
        detail=updates,
    )

    await db.commit()
    await db.refresh(channel)
    return channel


@router.delete("/admin/contact-channels/{channel_id}")
async def delete_contact_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    channel = await _get_channel_or_404(db, channel_id)

    log_admin_action(
        db, admin.id,
        action="contact_channel.delete",
        target_type="contact_channel",
        target_id=channel.id,
        detail={"label": channel.label, "value": channel.value},
    )

    await db.delete(channel)
    await db.commit()

    return {"message": f"ลบช่องทางติดต่อ '{channel.label}' เรียบร้อยแล้ว"}


@router.post(
    "/admin/contact-channels/{channel_id}/reorder",
    response_model=list[schemas.ContactChannelResponse],
)
async def reorder_contact_channel(
    channel_id: int,
    payload: schemas.ContactChannelReorderRequest,
    db: AsyncSession = Depends(get_db),
    admin: models.User = Depends(require_admin),
):
    """สลับ display_order ของช่องทางนี้กับตัวที่อยู่ติดกันในทิศทางที่ระบุ (ขึ้น/ลง) แล้วคืนลิสต์
    เต็มที่เรียงใหม่แล้วกลับไปเลย (frontend เอาไปวาดใหม่ตรงๆ ไม่ต้อง GET /contact ซ้ำ)

    ถ้าอยู่บนสุด/ล่างสุดอยู่แล้ว (ไม่มีตัวข้างเคียงให้สลับในทิศทางนั้น) ไม่ error แค่ไม่ทำอะไร
    แล้วคืนลิสต์เดิมกลับไปเฉยๆ — ปุ่มขึ้น/ลงฝั่ง frontend ก็ disable ไว้ล่วงหน้าอยู่แล้วในเคสนี้"""
    channel = await _get_channel_or_404(db, channel_id)

    all_channels_result = await db.execute(
        select(models.ContactChannel)
        .order_by(models.ContactChannel.display_order.asc(), models.ContactChannel.id.asc())
    )
    all_channels = all_channels_result.scalars().all()

    idx = next(i for i, c in enumerate(all_channels) if c.id == channel.id)
    neighbor_idx = idx - 1 if payload.direction == "up" else idx + 1

    if 0 <= neighbor_idx < len(all_channels):
        neighbor = all_channels[neighbor_idx]
        channel.display_order, neighbor.display_order = neighbor.display_order, channel.display_order

        log_admin_action(
            db, admin.id,
            action="contact_channel.reorder",
            target_type="contact_channel",
            target_id=channel.id,
            detail={"direction": payload.direction, "swapped_with": neighbor.id},
        )

        await db.commit()

        result = await db.execute(
            select(models.ContactChannel)
            .order_by(models.ContactChannel.display_order.asc(), models.ContactChannel.id.asc())
        )
        all_channels = result.scalars().all()

    return all_channels