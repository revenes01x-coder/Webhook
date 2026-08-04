import uuid
import requests
from urllib.parse import urlparse
from fastapi import HTTPException, status
from betacode.security.ip_guard import resolve_and_check_ip, SSRFBlockedError


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

    # 4. ทดสอบยิง POST ไปยังปลายทาง พร้อม field จริง (camera_id/event_id ขึ้นต้นด้วย "TEST_"
    #    ตามสัญญาที่แจ้งไว้ในคู่มือ ให้ปลายทางเช็ค event_id.startswith("TEST") แยกออกจาก event จริงได้)
    test_event_id = f"TEST_Event_{uuid.uuid4().hex[:8]}"
    test_camera_id = f"TEST_Camera_{uuid.uuid4().hex[:8]}"
    dummy_payload = {"camera_id": test_camera_id, "event_id": test_event_id}

    try:
        response = requests.post(url, data=dummy_payload, timeout=5)

        # 5. เช็คว่าตอบกลับ 200 OK ไหม
        if response.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"เซิร์ฟเวอร์ปลายทางตอบกลับ {response.status_code} (ต้องการ 200 OK)"
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
    ใช้ก่อนยิง webhook จริงทุกครั้งใน worker.py (_send_webhook_request, _ping_endpoint)

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