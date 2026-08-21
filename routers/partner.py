import asyncio
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import require_api_key
from security.camera_url_guard import verify_camera_rtsp_url
from security.ip_guard import SSRFBlockedError
from security.onvif_client import resolve_onvif_stream_uri, OnvifResolutionError
from services.rate_limiter import check_rate_limit

router = APIRouter(prefix="/partner", tags=["Partner Integration"])

@router.post("/cameras", response_model=schemas.MyCameraResponse)
async def add_camera_from_partner(
    payload: schemas.PartnerCameraCreate,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):

    # [Rate Limit]: เพิ่มกล้องได้ 5 ตัว / ชั่วโมง / user (กันสแปม/API key หลุดแล้วโดนยิงรัว)
    await check_rate_limit(db, f"partner_add_camera_{current_user.id}", "partner_add_camera", limit=5, window_minutes=60)

    existing_id_result = await db.execute(select(models.Camera).filter(models.Camera.id == payload.camera_id))
    existing_id = existing_id_result.scalar_one_or_none()
    if existing_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"camera_id '{payload.camera_id}' ถูกใช้ไปแล้ว กรุณาตั้งชื่ออื่น",
        )

    webhook_result = await db.execute(
        select(models.WebhookEndpoint).filter(
            models.WebhookEndpoint.url == payload.webhook_url,
            models.WebhookEndpoint.user_id == current_user.id,
        )
    )
    webhook = webhook_result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "ไม่พบ webhook_url นี้ในบัญชีของคุณ กรุณาสร้าง webhook ก่อนผ่าน POST /webhook/add "
                "แล้วใช้ URL เดียวกันมาผูกกับกล้อง"
            ),
        )

    # [ONVIF Support]: schemas.PartnerCameraCreate บังคับแล้วว่าต้องมีมาแค่ทางเดียว (ดู
    # exactly_one_connection_method) — ตรงนี้แค่แยกว่าจะ resolve rtsp_url ยังไงตามทางที่มา
    if payload.camera_url:
        rtsp_url = payload.camera_url
    else:
        try:
            rtsp_url = await resolve_onvif_stream_uri(
                payload.onvif_ip, payload.onvif_port, payload.onvif_username, payload.onvif_password
            )
        except SSRFBlockedError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except OnvifResolutionError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"เชื่อมต่อกล้องผ่าน ONVIF ไม่สำเร็จ: {e}",
            )

    # เช็ค rtsp_url ซ้ำ — ต้องทำหลัง resolve เสร็จแล้วเท่านั้น (ทาง ONVIF ยังไม่รู้ rtsp_url
    # จริงจนกว่าจะ resolve เสร็จ เลยเช็คซ้ำก่อนหน้านี้ไม่ได้)
    existing_url_result = await db.execute(select(models.Camera).filter(models.Camera.rtsp_url == rtsp_url))
    existing_url = existing_url_result.scalar_one_or_none()
    if existing_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ลิงก์นี้ถูกเพิ่มเข้าระบบไปแล้ว",
        )

    # [SSRF Guard]: เช็คซ้ำเสมอไม่ว่า rtsp_url จะมาจากทางไหน — ทาง ONVIF ก็ต้องเช็คซ้ำเพราะ
    # GetStreamUri ไม่ถูก nat_override rewrite ให้ (ดู docstring ใน security/onvif_client.py)
    await asyncio.to_thread(verify_camera_rtsp_url, rtsp_url)

    new_camera = models.Camera(
        id=payload.camera_id,
        owner_user_id=current_user.id,
        rtsp_url=rtsp_url,
        webhook_endpoint_id=webhook.id,
        is_active=False,               # จะเป็น True ก็ต่อเมื่อ background job verify สำเร็จ
        verification_status="pending",
    )
    db.add(new_camera)

    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()

        recheck_result = await db.execute(select(models.Camera).filter(models.Camera.id == payload.camera_id))
        if recheck_result.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"camera_id '{payload.camera_id}' ถูกใช้ไปแล้ว กรุณาตั้งชื่ออื่น",
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ลิงก์นี้ถูกเพิ่มเข้าระบบไปแล้ว",
        )

    await db.refresh(new_camera)

    return schemas.MyCameraResponse(
        camera_id=new_camera.id,
        is_active=new_camera.is_active,
        verification_status=new_camera.verification_status,
        webhook_url=webhook.url,
        webhook_is_active=webhook.is_active,
        created_at=new_camera.created_at,
    )


@router.post("/cameras/status")
async def update_camera_status_from_partner(
    payload: schemas.PartnerCameraStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):

    result = await db.execute(
        select(models.Camera).filter(
            models.Camera.id == payload.camera_id,
            models.Camera.owner_user_id == current_user.id,
        )
    )
    camera = result.scalar_one_or_none()
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
    await db.commit()

    status_text = "เปิด" if payload.is_active else "ปิด"
    return {"message": f"{status_text}ใช้งานกล้อง '{camera.id}' เรียบร้อยแล้ว"}

@router.get("/cameras/{camera_id}", response_model=schemas.PartnerCameraStatusResponse)
async def get_camera_verification_status(
    camera_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_api_key),
):
    await check_rate_limit(db, f"camera_status_check_{current_user.id}", "camera_status_check", limit=60, window_minutes=60)

    result = await db.execute(
        select(models.Camera).filter(
            models.Camera.id == camera_id,
            models.Camera.owner_user_id == current_user.id,
        )
    )
    camera = result.scalar_one_or_none()
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
        is_active=camera.is_active,
    )