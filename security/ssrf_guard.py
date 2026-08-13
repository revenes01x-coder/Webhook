import os
import uuid
import mimetypes
import requests
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlparse
from fastapi import HTTPException, status
from security.ip_guard import resolve_and_check_ip, SSRFBlockedError
from smartlpr.config import TEST_WEBHOOK_IMAGE_PATH


@lru_cache(maxsize=1)
def _load_test_image() -> tuple[bytes, str]:
    """อ่านไฟล์รูปจริงจากดิสก์ (path กำหนดผ่าน TEST_WEBHOOK_IMAGE_PATH ใน .env) ไว้แนบเป็น
    ไฟล์ทดสอบตอนยิง webhook ทดสอบ (build_test_webhook_payload ด้านล่าง) คืน (bytes, content_type)

    cache ด้วย lru_cache เพราะไฟล์นี้ไม่เปลี่ยนระหว่างที่ process รันอยู่ ไม่ต้องอ่านดิสก์ใหม่
    ทุกครั้งที่ทดสอบ (เรียกทั้งตอนสร้าง endpoint ใหม่ และทุกรอบ health check ทุก 30 นาที)

    raise RuntimeError ถ้าไม่พบไฟล์ตาม path ที่ตั้งไว้ (fail fast ชัดเจน ดีกว่าเงียบๆ แล้วส่ง
    payload ที่ไม่มีรูปแนบออกไปโดยไม่รู้ตัว) — caller เป็นคนแปลง error นี้ต่อเอง (ดู
    verify_webhook_url ที่แปลงเป็น HTTPException 500 / worker.py:_ping_endpoint ที่จับแล้ว
    log แค่ error กลับ False เพราะไม่ได้อยู่ใน request context)
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


def verify_webhook_url(url: str):
    """
    ตรวจสอบ URL เพื่อป้องกัน SSRF และยืนยันว่าปลายทางพร้อมรับข้อมูลได้จริง
    (ตอบ 200 OK + echo event_id กลับมาให้ตรง ตามสัญญาที่ระบบใช้ยืนยัน ACK จริง)

    เรียกครั้งเดียวตอน POST /webhook/add เท่านั้น (สร้าง endpoint ใหม่) — การเช็คซ้ำก่อนยิงจริง
    ทุกครั้งอยู่ที่ is_url_host_safe() ด้านล่าง ซึ่ง worker.py เรียกเองก่อน client.post() ทุกครั้ง
    เพื่อกัน DNS rebinding (โดเมนถูกเปลี่ยน DNS record หลังผ่านการเช็คตอนสร้าง endpoint ไปแล้ว)
    """
    parsed_url = urlparse(url)

    # 1. บังคับใช้ HTTPS เท่านั้น
    if parsed_url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="เพื่อความปลอดภัย URL ต้องเป็น HTTPS เท่านั้น"
        )

    hostname = parsed_url.hostname

    # 2-3. แปลง DNS -> IP แล้วเช็ค private/loopback/link-local (logic กลางอยู่ที่ ip_guard.py)
    try:
        resolve_and_check_ip(hostname)
    except SSRFBlockedError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    # 4. ทดสอบยิง POST ไปยังปลายทาง พร้อมข้อมูลครบเหมือน webhook event จริง (field ข้อความ +
    #    ไฟล์รูปจริง image_full/image_crop แบบ multipart) event_id/camera_id ขึ้นต้นด้วย "TEST_"
    #    ตามสัญญาที่แจ้งไว้ในคู่มือ ให้ปลายทางเช็ค event_id.startswith("TEST") แยกจาก event จริงได้
    try:
        test_event_id, dummy_payload, dummy_files = build_test_webhook_payload()
    except RuntimeError as e:
        # ไฟล์รูปทดสอบหาไม่เจอ (ตั้งค่า TEST_WEBHOOK_IMAGE_PATH ผิด) — เป็นปัญหาฝั่งเซิร์ฟเวอร์
        # เราเอง ไม่ใช่ URL ที่ user กรอกผิด จึงตอบ 500 ไม่ใช่ 400
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )

    try:
        response = requests.post(url, data=dummy_payload, files=dummy_files, timeout=5)

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

    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ปลายทางได้: {str(e)}"
        )

    return True


def is_url_host_safe(url: str) -> bool:
    """
    เช็คซ้ำแบบเบา (ไม่ยิง POST ทดสอบ ไม่บังคับ HTTPS ซ้ำ — เช็คตอนสร้างไปแล้วและ target_url
    ที่เก็บใน DB การันตี https:// อยู่แล้ว) — resolve DNS ใหม่จาก hostname เดิมทุกครั้งที่เรียก
    ใช้ก่อนยิงเว็บฮุคจริงทุกครั้งใน worker.py (_send_webhook_request, _ping_endpoint)

    กัน DNS rebinding: โดเมนที่ผ่านการเช็คตอนสร้าง endpoint (verify_webhook_url) แล้ว แต่ภายหลัง
    เจ้าของโดเมนเปลี่ยน DNS record ให้ชี้ไปยัง internal IP จะถูกจับได้ตรงนี้ก่อนยิงจริงทุกรอบ

    คืน True/False เฉยๆ ไม่ raise เพราะ caller (worker.py) ไม่ได้อยู่ใน request context —
    ต้องจัดการผลลัพธ์เป็น "ส่งไม่สำเร็จ" ธรรมดาแล้วปล่อยให้เข้า retry/circuit-breaker logic เดิม
    """
    hostname = urlparse(url).hostname
    if not hostname:
        return False
    try:
        resolve_and_check_ip(hostname)
        return True
    except SSRFBlockedError:
        return False