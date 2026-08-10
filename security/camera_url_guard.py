from urllib.parse import urlparse, urlunparse
import ipaddress
from fastapi import HTTPException, status
from security.ip_guard import resolve_and_check_ip, SSRFBlockedError


def verify_camera_rtsp_url(rtsp_url: str) -> None:
    """
    ตรวจสอบ rtsp_url ก่อนบันทึกลงระบบ ป้องกันไม่ให้ camera_manager.py/camera_worker.py
    (ซึ่งรันบนเครื่อง user เอง) ถูกสั่งให้ไป connect หา IP ภายในเครือข่ายของตัวเอง (SSRF ผ่านช่อง RTSP)

    หมายเหตุ: ต่างจาก ssrf_guard.py (สำหรับ webhook URL) ตรงที่ RTSP ไม่ใช่ HTTP
    เลยไม่มีการยิง request ทดสอบ handshake จริง เช็คได้แค่ scheme + การ resolve DNS/IP เท่านั้น

    นี่คือการเช็คตอนสร้างเท่านั้น — การปิด DNS rebinding ตอนเชื่อมต่อจริงทุกครั้งอยู่ที่
    resolve_rtsp_url_pinned() ด้านล่าง ซึ่ง worker.py + camera_worker.py เรียกก่อน
    cv2.VideoCapture ทุกครั้ง (ไม่ใช่แค่เช็ค แต่แทน IP ตรงๆ ใน URL เลย เพราะ FFmpeg resolve DNS
    เองอีกรอบ ไม่ผ่าน Python — ดู docstring ของฟังก์ชันนั้นสำหรับรายละเอียด)
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
        resolve_and_check_ip(hostname)
    except SSRFBlockedError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


def resolve_rtsp_url_pinned(rtsp_url: str) -> str:
    """
    Resolve hostname ใน rtsp_url เป็น IP แล้วคืน URL ใหม่ที่ต่อด้วย IP นั้นตรงๆ แทน hostname เดิม
    (แทนที่เฉพาะ host:port ใน netloc คง user:pass@ และ path/query เดิมไว้ทั้งหมด)

    ทำไมต้อง "แทน IP" ไม่ใช่แค่ "เช็คแล้วปล่อยผ่าน hostname เดิม":
    cv2.VideoCapture เปิด RTSP ผ่าน FFmpeg (C library) ซึ่ง resolve DNS เองอีกรอบ ไม่ผ่าน
    Python socket เลย ต่อให้ Python เช็คแล้วว่า IP ปลอดภัย ก็ไม่การันตีว่า FFmpeg จะได้ IP
    เดียวกัน (DNS อาจถูกเปลี่ยนในช่วงเสี้ยววินาทีนั้นพอดี = DNS rebinding) การแทน IP ตรงๆ ใน URL
    ก่อนส่งให้ FFmpeg คือทางเดียวที่ปิดช่องนี้ได้จริง 100%

    IPv6 literal ต้องครอบด้วย [] เสมอเวลาใส่ใน URL (RFC 3986) เช่น [2001:db8::1]:554
    ไม่งั้น urlunparse จะแยก host กับ :port ไม่ออก (โดน : ที่เป็นส่วนหนึ่งของ IPv6 เองบังตา)
    resolve_and_check_ip() (ip_guard.py) เช็คทั้ง IPv4/IPv6 แล้วอาจคืน IP แบบ IPv6 กลับมาได้
    เลยต้องเช็ค version แล้วครอบ bracket ให้ตรงนี้ก่อนประกอบกลับเป็น URL — IPv4 ไม่ต้องทำอะไรเพิ่ม

    ใช้ได้อย่างปลอดภัยเพราะ RTSP ปกติไม่ทำ TLS/SNI validation กับ hostname (ต่างจาก HTTPS)
    การต่อด้วย IP ตรงๆ จึงไม่กระทบการทำงานปกติ (ยกเว้นเคสหายากที่กล้อง/เซิร์ฟเวอร์ RTSP ทำ
    virtual host แยกตาม hostname ซึ่งไม่ใช่ pattern ปกติของอุปกรณ์กล้อง IP)

    raise SSRFBlockedError ถ้า resolve ไม่ได้ หรือ IP เป็น private/loopback/link-local
    เรียกก่อน cv2.VideoCapture ทุกครั้ง (worker.py._try_open_rtsp, camera_worker.py.open_stream)
    """
    parsed = urlparse(rtsp_url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("ไม่พบ host ใน RTSP URL")

    ip = resolve_and_check_ip(hostname)

    ip_obj = ipaddress.ip_address(ip)
    host_str = f"[{ip}]" if ip_obj.version == 6 else ip

    netloc = host_str
    if parsed.port:
        netloc = f"{host_str}:{parsed.port}"
    if parsed.username:
        userinfo = parsed.username
        if parsed.password:
            userinfo += f":{parsed.password}"
        netloc = f"{userinfo}@{netloc}"

    return urlunparse(parsed._replace(netloc=netloc))