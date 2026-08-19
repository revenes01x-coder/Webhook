import os
import uuid
import ipaddress
import mimetypes
import asyncio
import httpx
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlparse, urlunparse
from fastapi import HTTPException, status
from security.ip_guard import resolve_and_check_ip, SSRFBlockedError
from smartlpr.config import TEST_WEBHOOK_IMAGE_PATH


@lru_cache(maxsize=1)
def _load_test_image() -> tuple[bytes, str]:
    """อ่านไฟล์รูปจริงจากดิสก์ (path กำหนดผ่าน TEST_WEBHOOK_IMAGE_PATH ใน .env) ไว้แนบเป็น
    ไฟล์ทดสอบตอนยิง webhook ทดสอบ (build_test_webhook_payload ด้านล่าง) คืน (bytes, content_type)

    cache ด้วย lru_cache เพราะไฟล์นี้ไม่เปลี่ยนระหว่างที่ process รันอยู่ ไม่ต้องอ่านดิสก์ใหม่
    ทุกครั้งที่ทดสอบ (เรียกทั้งตอนสร้าง endpoint ใหม่ และทุกรอบ health check ทุก 30 นาที)

    ยังเป็น sync function (open() แบบ blocking) — caller ในฝั่ง async (verify_webhook_url,
    worker.py:_ping_endpoint) ต้องเรียกผ่าน asyncio.to_thread เสมอ ไม่เรียกตรงๆ

    raise RuntimeError ถ้าไม่พบไฟล์ตาม path ที่ตั้งไว้ (fail fast ชัดเจน ดีกว่าเงียบๆ แล้วส่ง
    payload ที่ไม่มีรูปแนบออกไปโดยไม่รู้ตัว)
    """
    if not os.path.isfile(TEST_WEBHOOK_IMAGE_PATH):
        raise RuntimeError(
            f"ไม่พบไฟล์รูปทดสอบ webhook ที่ '{TEST_WEBHOOK_IMAGE_PATH}' "
            "กรุณาตั้งค่า TEST_WEBHOOK_IMAGE_PATH ใน .env ให้ชี้ไปยังไฟล์รูปที่มีอยู่จริง"
        )
    content_type = mimetypes.guess_type(TEST_WEBHOOK_IMAGE_PATH)[0] or "image/jpeg"
    with open(TEST_WEBHOOK_IMAGE_PATH, "rb") as f:
        return f.read(), content_type


def build_test_webhook_payload() -> tuple[str, dict, dict]:
    """ยังเป็น sync function (เรียก _load_test_image ซึ่ง blocking) — caller ฝั่ง async ต้องห่อ
    ด้วย asyncio.to_thread เสมอ (ดู verify_webhook_url ด้านล่าง และ worker.py:_ping_endpoint)"""
    test_event_id = f"TEST_Event_{uuid.uuid4().hex[:8]}"
    test_camera_id = f"TEST_Camera_{uuid.uuid4().hex[:8]}"

    form_data = {
        "event_id": test_event_id,
        "camera_id": test_camera_id,
        "license_plate": "กข 1234",
        "province": "กรุงเทพมหานคร",
        "color": "White",
        "capture_time": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
    }

    image_bytes, content_type = _load_test_image()
    ext = os.path.splitext(TEST_WEBHOOK_IMAGE_PATH)[1] or ".jpg"
    files = {
        "image_full": (f"{test_event_id}_full{ext}", image_bytes, content_type),
        "image_crop": (f"{test_event_id}_crop{ext}", image_bytes, content_type),
    }

    return test_event_id, form_data, files


async def verify_webhook_url(url: str):
    """
    ตรวจสอบ URL เพื่อป้องกัน SSRF และยืนยันว่าปลายทางพร้อมรับข้อมูลได้จริง
    (ตอบ 200 OK + echo event_id กลับมาให้ตรง ตามสัญญาที่ระบบใช้ยืนยัน ACK จริง)

    เรียกครั้งเดียวตอน POST /webhook/add เท่านั้น (สร้าง endpoint ใหม่) — การเช็คซ้ำก่อนยิงจริง
    ทุกครั้งอยู่ที่ build_pinned_request() ด้านล่าง ซึ่ง worker.py เรียกเองก่อน client.post()
    ทุกครั้ง เพื่อกัน DNS rebinding

    [Async Migration]: เดิมใช้ requests.Session (sync) + custom
    _PinnedHostnameHTTPSAdapter ยิง POST ทดสอบแบบ blocking (endpoint POST /webhook/add ที่
    เรียกฟังก์ชันนี้ตอนนี้เป็น async def แล้ว ถ้ายังยิงแบบ sync จะไปค้าง event loop หลักของ
    ทั้งแอปได้นานสุดถึง timeout ต่อ request) เปลี่ยนมาใช้ httpx.AsyncClient แทน — httpx รองรับ
    การ pin SNI/cert hostname ให้ตรงกับ hostname เดิมผ่าน `extensions={"sni_hostname": ...}`
    ในตัวอยู่แล้ว (ใช้ฟังก์ชัน build_pinned_request() ตัวเดียวกับที่ worker.py ใช้อยู่แล้วสำหรับ
    ยิง webhook event จริง แทนที่จะมี pin-helper แยกอีกชุดสำหรับ requests โดยเฉพาะแบบเดิม —
    ลด code path ที่ต้องดูแลซ้ำซ้อนลง) resolve DNS (build_pinned_request) และอ่านไฟล์รูปทดสอบ
    (build_test_webhook_payload) ยังเป็น sync blocking call อยู่ ห่อด้วย asyncio.to_thread
    ให้รันบน thread แยกแทน
    """
    parsed_url = urlparse(url)

    # 1. บังคับใช้ HTTPS เท่านั้น
    if parsed_url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="เพื่อความปลอดภัย URL ต้องเป็น HTTPS เท่านั้น"
        )

    # 2-3. แปลง DNS -> IP, เช็ค private/loopback/link-local (ip_guard.py) แล้วคืน URL ที่
    # ต่อด้วย IP ตรงๆ ไว้ยิงจริงด้านล่าง (resolve ครั้งเดียว ไม่ให้ httpx resolve ซ้ำเอง)
    try:
        pinned_url, extra_kwargs = await asyncio.to_thread(build_pinned_request, url)
    except SSRFBlockedError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 4. ทดสอบยิง POST ไปยังปลายทาง พร้อมข้อมูลครบเหมือน webhook event จริง (field ข้อความ +
    #    ไฟล์รูปจริง image_full/image_crop แบบ multipart) event_id/camera_id ขึ้นต้นด้วย "TEST_"
    #    ตามสัญญาที่แจ้งไว้ในคู่มือ ให้ปลายทางเช็ค event_id.startswith("TEST") แยกจาก event จริงได้
    try:
        test_event_id, dummy_payload, dummy_files = await asyncio.to_thread(build_test_webhook_payload)
    except RuntimeError as e:
        # ไฟล์รูปทดสอบหาไม่เจอ (ตั้งค่า TEST_WEBHOOK_IMAGE_PATH ผิด) — เป็นปัญหาฝั่งเซิร์ฟเวอร์
        # เราเอง ไม่ใช่ URL ที่ user กรอกผิด จึงตอบ 500 ไม่ใช่ 400
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                pinned_url,
                data=dummy_payload,
                files=dummy_files,
                timeout=5,
                **extra_kwargs,
            )

        # 5. เช็คว่าตอบกลับ 2xx OK ไหม
        if response.status_code // 100 != 2:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"เซิร์ฟเวอร์ปลายทางตอบกลับ {response.status_code} (ต้องการ 2xx OK)"
            )

        # 6. เช็คว่า body เป็น JSON และ echo event_id กลับมาตรงกัน (สัญญาเดียวกับตอน ACK จริง)
        try:
            body = response.json()
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="เซิร์ฟเวอร์ปลายทางตอบกลับไม่ใช่ JSON ที่ถูกต้อง",
            )

        if not isinstance(body, dict) or body.get("event_id") != test_event_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "เซิร์ฟเวอร์ปลายทางตอบกลับ 200 OK แต่ไม่ได้ echo event_id กลับมาให้ตรงกัน "
                    "กรุณาตรวจสอบว่า endpoint ตอบ JSON รูปแบบ {\"event_id\": \"...\"} ตามที่กำหนด"
                ),
            )

    except httpx.HTTPError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ปลายทางได้: {str(e)}"
        )

    return True


def build_pinned_request(url: str) -> tuple[str, dict]:
    """
    [DNS rebinding fix — httpx]: resolve+เช็ค IP ปลอดภัยครั้งเดียวแล้ว "ต่อ connection" ไปที่
    IP นั้นตรงๆ (แทนที่จะปล่อยให้ httpx resolve DNS ซ้ำเองตอนยิงจริง) ปิดช่อง DNS rebinding
    แบบ TOCTOU ที่โดเมนเปลี่ยน DNS record ให้ชี้ internal IP พอดีในช่วงเสี้ยววินาทีระหว่างเช็ค
    กับยิงจริง เหมือนที่ resolve_rtsp_url_pinned() ปิดให้ฝั่ง RTSP ไปแล้ว

    ยังเป็น sync function (resolve_and_check_ip ข้างในทำ socket.getaddrinfo แบบ blocking)
    caller ฝั่ง async (worker.py, ssrf_guard.py:verify_webhook_url) ต้องเรียกผ่าน
    asyncio.to_thread เสมอ

    คืน (pinned_url, extra_kwargs) — caller ต้อง unpack extra_kwargs เข้า client.post(...)
    เสมอ เช่น client.post(pinned_url, **extra_kwargs, data=..., files=..., timeout=...)
    ห้ามยิงแค่ pinned_url เฉยๆ โดยไม่ใส่ extra_kwargs เพราะจะกลายเป็นต่อด้วย IP ตรงๆ แบบ RTSP
    ซึ่งฝั่ง HTTPS จะ cert validation fail / เข้าผิด virtual host

    raise SSRFBlockedError เหมือน resolve_and_check_ip เดิมทุกประการ
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("ไม่พบ host ใน URL")

    ip = resolve_and_check_ip(hostname)

    ip_obj = ipaddress.ip_address(ip)
    host_str = f"[{ip}]" if ip_obj.version == 6 else ip
    netloc = host_str
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"

    pinned_url = urlunparse(parsed._replace(netloc=netloc))

    extra_kwargs = {
        # Host header ต้องเป็น hostname เดิม ไม่งั้นปลายทางที่ทำ virtual host จะ route ผิดเว็บ
        "headers": {"Host": hostname},
        # sni_hostname บอก httpx ให้ทำ TLS handshake (SNI + cert hostname verification)
        # เหมือนกำลังต่อ hostname เดิม ทั้งที่ connection จริงไปที่ IP ที่ pin ไว้แล้ว
        "extensions": {"sni_hostname": hostname},
    }

    return pinned_url, extra_kwargs