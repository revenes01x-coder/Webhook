import asyncio
import logging
from onvif import ONVIFCamera
from zeep.exceptions import Fault, TransportError
from security.ip_guard import resolve_and_check_ip, SSRFBlockedError

ONVIF_CONNECT_TIMEOUT_SECONDS = 10


class OnvifResolutionError(Exception):
    """ครอบคลุม error จากขั้นตอน ONVIF ทั้งหมด (auth ผิด, ต่อไม่ติด, ไม่มี media profile,
    กล้องตอบ URI ที่ไม่ใช่ RTSP) — caller (routers/partner.py) แปลงเป็น HTTPException 400 เอง"""
    pass

async def resolve_onvif_stream_uri(host: str, port: int, username: str, password: str) -> str:
    """ฟังก์ชันหลักที่ routers/partner.py เรียก — คืน RTSP URL (ยังไม่ผ่าน verify_camera_rtsp_url
    ซ้ำ — caller ต้องเรียกเองต่อ ดู docstring ด้านบนของไฟล์)

    raise SSRFBlockedError ถ้า host ไม่ผ่านการตรวจสอบ (เหมือน RTSP guard ทุกประการ)
    raise OnvifResolutionError ถ้าขั้นตอน ONVIF ล้มเหลว หรือเกินเวลา ONVIF_CONNECT_TIMEOUT_SECONDS
    """
    ip = resolve_and_check_ip(host)  # raise SSRFBlockedError ถ้าไม่ผ่าน — เช็คก่อนต่อเสมอ

    try:
        return await asyncio.wait_for(
            _fetch_stream_uri(ip, port, username, password),
            timeout=ONVIF_CONNECT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError as e:
        raise OnvifResolutionError(
            f"เชื่อมต่อ ONVIF เกินเวลาที่กำหนด ({ONVIF_CONNECT_TIMEOUT_SECONDS} วินาที)"
        ) from e


async def _fetch_stream_uri(ip: str, port: int, username: str, password: str) -> str:
    try:
        camera = ONVIFCamera(ip, port, username, password, nat_override=True)
        await camera.update_xaddrs()

        media_service = camera.create_media_service()
        profiles = await media_service.GetProfiles()

        if not profiles:
            raise OnvifResolutionError("กล้องไม่มี media profile ให้เลือกเลย (GetProfiles คืนค่าว่าง)")

        # เลือก profile แรกเสมอตาม policy ปัจจุบัน (ถ้าอยากให้ partner เลือกเองในอนาคต
        # ค่อยเพิ่ม parameter profile_token รับเข้ามาแทน)
        profile_token = profiles[0].token

        stream_uri_response = await media_service.GetStreamUri({
            "StreamSetup": {"Stream": "RTP-Unicast", "Transport": {"Protocol": "RTSP"}},
            "ProfileToken": profile_token,
        })

        rtsp_uri = stream_uri_response.Uri
        if not rtsp_uri or not rtsp_uri.lower().startswith("rtsp://"):
            raise OnvifResolutionError(
                f"กล้องตอบ URI ที่ไม่ใช่ RTSP กลับมา ('{rtsp_uri}') — อาจเป็นกล้องที่ไม่รองรับ RTSP transport"
            )

        return rtsp_uri

    except (Fault, TransportError) as e:
        # Fault = กล้องตอบ SOAP error กลับมา (เช่น username/password ผิด, ProfileToken ไม่ถูกต้อง)
        # TransportError = ต่อ HTTP ไม่ติดเลย (connection refused, DNS fail หลัง pin IP ไปแล้ว ฯลฯ)
        logging.warning(f"[ONVIF] เชื่อมต่อกล้อง {ip}:{port} ไม่สำเร็จ: {e}")
        raise OnvifResolutionError(f"เชื่อมต่อ ONVIF ไม่สำเร็จ: {e}") from e