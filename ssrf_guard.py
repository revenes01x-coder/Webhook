import socket
import ipaddress
import uuid
import requests
from urllib.parse import urlparse
from fastapi import HTTPException, status

def verify_webhook_url(url: str):
    """
    ตรวจสอบ URL เพื่อป้องกัน SSRF และยืนยันว่าปลายทางพร้อมรับข้อมูลได้จริง
    (ตอบ 200 OK + echo event_id กลับมาให้ตรง ตามสัญญาที่ระบบใช้ยืนยัน ACK จริง)
    """
    parsed_url = urlparse(url)
    
    # 1. บังคับใช้ HTTPS เท่านั้น 
    if parsed_url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="เพื่อความปลอดภัย URL ต้องเป็น HTTPS เท่านั้น"
        )
    
    hostname = parsed_url.hostname
    
    try:
        # 2. แปลงชื่อโดเมน (DNS) ให้กลายเป็น IP Address
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)
        
        # 3. เช็คว่าเป็น IP ภายใน (Private / Loopback) หรือไม่
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="ไม่อนุญาตให้ใช้ IP ภายในเครือข่าย (Private/Loopback IP)"
            )
    except socket.gaierror:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail="ไม่สามารถค้นหาที่อยู่ IP ของโดเมนนี้ได้ "
        )

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