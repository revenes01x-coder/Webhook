from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

import models, smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user, require_access_approved
from services.token import generate_api_key, hash_api_key
from services.rate_limiter import check_rate_limit

router = APIRouter(prefix="/my/api-key", tags=["API Key"])


@router.post("/regenerate", response_model=schemas.ApiKeyResponse)
def regenerate_api_key(
    db: Session = Depends(get_db),
    current_user: models.User = Depends(require_access_approved),
):
    """
    ออก API key ใหม่ให้ user คนนี้ — เขียนทับของเดิมเสมอ (ใช้ endpoint เดียวกันทั้งตอน
    generate ครั้งแรกและตอน regenerate ทีหลัง) API key เก่าใช้ไม่ได้ทันทีที่กดปุ่มนี้
    เก็บแค่ hash ลง DB — plaintext จะแสดงให้เห็น "ครั้งเดียว" ในการตอบกลับนี้เท่านั้น
    ถ้าพลาดไม่ได้บันทึกไว้ ต้องกดขอใหม่อีกรอบ (ดูค่าเดิมย้อนหลังไม่ได้)

    ต้องผ่าน require_access_approved (login -> terms_accepted -> access-request ที่ admin
    อนุมัติแล้ว) เท่านั้นถึงจะขอ API key ได้ — ป้องกันไม่ให้ใครก็สมัครแล้วขอ key ยิงเข้าระบบได้ทันที
    """
    # [Rate Limit]: regenerate ได้ 5 ครั้ง / ชั่วโมง / user (แต่ละครั้งทำให้ key เดิมใช้ไม่ได้ทันที
    # จำกัดไว้แน่นหน่อยกันกดพลาด/สแปมจนระบบอัตโนมัติของ user เองหลุด auth ไปเรื่อยๆ)
    check_rate_limit(db, f"regen_api_key_{current_user.id}", "regen_api_key", limit=5, window_minutes=60)

    plain_key = generate_api_key()
    current_user.api_key_hash = hash_api_key(plain_key)
    db.commit()

    return schemas.ApiKeyResponse(api_key=plain_key)


@router.get("/status", response_model=schemas.ApiKeyStatusResponse)
def api_key_status(
    current_user: models.User = Depends(get_current_user),
):
    """เช็คว่ามี API key อยู่แล้วหรือยัง (ไม่โชว์ค่าจริง แค่บอกว่ามี/ไม่มี) ใช้ทำ UI เช่น
    ปุ่ม 'สร้าง API key' vs 'สร้างใหม่ (regenerate)'"""
    return schemas.ApiKeyStatusResponse(has_api_key=current_user.api_key_hash is not None)