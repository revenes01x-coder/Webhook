import secrets

from fastapi import APIRouter, Depends, HTTPException, Header, status
from sqlalchemy.orm import Session

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.config import PARTNER_WEBHOOK_SECRET

router = APIRouter(prefix="/partner", tags=["Partner Integration"])


def verify_partner_secret(x_partner_secret: str = Header(..., description="Secret key ที่ตกลงกันไว้กับระบบพาร์ทเนอร์")):
    """
    เช็ค header X-Partner-Secret เทียบกับ PARTNER_WEBHOOK_SECRET ใน .env
    ใช้ secrets.compare_digest กัน timing attack (เหมือน pattern hmac.compare_digest
    ที่ใช้เทียบ OTP/refresh token ในระบบ — ตรงนี้เทียบ string ตรงๆ เพราะเป็น shared secret
    ไม่ใช่ hash)

    ไม่ผูกกับ user/JWT/API key ใดๆ เพราะ endpoint นี้เป็นการสื่อสารระหว่างระบบพาร์ทเนอร์กับ
    เซิร์ฟเวอร์เราโดยตรง (server-to-server) ไม่มี "เจ้าของบัญชี" มาเกี่ยวข้องในจังหวะนี้
    """
    if not secrets.compare_digest(x_partner_secret, PARTNER_WEBHOOK_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Secret key ไม่ถูกต้อง",
        )


@router.post("/cameras/status")
def update_camera_status_from_partner(
    payload: schemas.PartnerCameraStatusUpdate,
    db: Session = Depends(get_db),
    _: None = Depends(verify_partner_secret),
):
    camera = db.query(models.Camera).filter(models.Camera.id == payload.camera_id).first()
    if not camera:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"ไม่พบกล้อง camera_id='{payload.camera_id}' ในระบบ",
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