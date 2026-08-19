from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_access_approved
from services.token import generate_api_key, hash_api_key
from services.rate_limiter import check_and_record

router = APIRouter(prefix="/my/api-key", tags=["API Key"])

# [Lockout ใหม่]: ตกลงกันไว้ = 3 ครั้ง / ล็อก 5 นาที ต่อ user
REGEN_API_KEY_LOCKOUT_LIMIT = 3
REGEN_API_KEY_LOCKOUT_MINUTES = 5


@router.post("/regenerate", response_model=schemas.ApiKeyResponse)
async def regenerate_api_key(
    db: AsyncSession = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):
    await check_and_record(
        db,
        f"regen_api_key_{current_user.id}",
        "regen_api_key",
        limit=REGEN_API_KEY_LOCKOUT_LIMIT,
        window_minutes=REGEN_API_KEY_LOCKOUT_MINUTES,
    )

    plain_key = generate_api_key()
    current_user.api_key_hash = hash_api_key(plain_key)
    await db.commit()

    return schemas.ApiKeyResponse(api_key=plain_key)

@router.get("/status", response_model=schemas.ApiKeyStatusResponse)
def api_key_status(
    current_user: models.User = Depends(get_current_user),
):
    """เช็คว่ามี API key อยู่แล้วหรือยัง (ไม่โชว์ค่าจริง แค่บอกว่ามี/ไม่มี) ใช้ทำ UI เช่น
    ปุ่ม 'สร้าง API key' vs 'สร้างใหม่ (regenerate)'"""
    return schemas.ApiKeyStatusResponse(has_api_key=current_user.api_key_hash is not None)