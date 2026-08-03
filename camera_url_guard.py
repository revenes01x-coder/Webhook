import socket
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException, status


def verify_camera_rtsp_url(rtsp_url: str) -> None:
    """
    ตรวจสอบ rtsp_url ก่อนบันทึกลงระบบ ป้องกันไม่ให้ camera_manager.py (ซึ่งรันบน server ของเรา)
    ถูกสั่งให้ไป connect หา IP ภายในเครือข่ายของเราเอง (SSRF ผ่านช่อง RTSP)

    หมายเหตุ: ต่างจาก ssrf_guard.py (สำหรับ webhook URL) ตรงที่ RTSP ไม่ใช่ HTTP
    เลยไม่มีการยิง request ทดสอบ handshake จริง เช็คได้แค่ scheme + การ resolve DNS/IP เท่านั้น
    """
    parsed = urlparse(rtsp_url)

    if parsed.scheme.lower() != "rtsp":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ต้องเป็นลิงก์ rtsp:// เท่านั้น",
        )

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ไม่พบ host ในลิงก์ที่ระบุ",
        )

    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ไม่สามารถค้นหาที่อยู่ IP ของ host นี้ได้",
        )

    if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ลิงก์กล้องไม่ถูกต้อง: ไม่อนุญาตให้ใช้ IP ภายในเครือข่าย (Private/Loopback IP)",
        )