import os
import uuid
import ipaddress
import mimetypes
import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
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


class _PinnedHostnameHTTPSAdapter(HTTPAdapter):
    """
    Mount เข้ากับ requests.Session() เฉพาะ scheme https:// ก่อนยิง POST ทดสอบใน
    verify_webhook_url() เท่านั้น — สร้างใหม่ทุกครั้งที่เรียก (ไม่ reuse/cache ข้าม request)
    เพราะผูก hostname เดียวไว้ตายตัวตอน __init__

    เหตุผลที่ต้องมี adapter เอง: ถ้าแค่เอา pinned_url (host เป็น IP) ไปยิงตรงๆ ผ่าน requests
    ปกติ — urllib3 (ที่ requests ใช้ข้างใน) จะเอา host จาก pinned_url ไปใช้ทำทั้ง TLS SNI และ
    cert hostname verification โดย default กลายเป็น verify cert กับ IP literal แทน hostname
    จริง (ปลายทางส่วนใหญ่ cert ไม่ได้ออกให้ IP เลย จะ verify fail) — ต้อง inject
    server_hostname/assert_hostname เข้า connection pool ตรงๆ เพื่อบังคับให้ SNI + cert check
    ยังอิง hostname เดิม แม้ว่า connection จริงจะไปที่ IP ที่ pin ไว้แล้วก็ตาม
    """

    def __init__(self, hostname: str):
        self._hostname = hostname
        super().__init__()

    def init_poolmanager(self, *args, **kwargs):
        kwargs["server_hostname"] = self._hostname
        kwargs["assert_hostname"] = self._hostname
        self.poolmanager = PoolManager(*args, **kwargs)


def _build_pinned_https_request(url: str) -> tuple[str, str, dict]:
    """
    Sync version ของแนวคิด "pin IP" (เทียบเท่ากับ resolve_rtsp_url_pinned ฝั่ง RTSP และ
    build_pinned_request ฝั่ง httpx) — สำหรับ verify_webhook_url() ที่ใช้ requests (sync)
    คืน (pinned_url, hostname, headers) ให้ caller เอาไปยิงผ่าน session ที่ mount
    _PinnedHostnameHTTPSAdapter(hostname) แล้ว

    resolve+เช็ค IP ครั้งเดียวตรงนี้ แล้ว "ต่อ connection" ไปที่ IP นั้นตรงๆ (แทนที่จะปล่อยให้
    requests.post() resolve DNS ซ้ำเองตอนยิงจริง) ปิดช่อง DNS rebinding แบบ TOCTOU ที่โดเมน
    เปลี่ยน DNS record ให้ชี้ internal IP พอดีในช่วงเสี้ยววินาทีระหว่างเช็คกับยิงจริง

    raise SSRFBlockedError เหมือน resolve_and_check_ip เดิมทุกประการ (ไม่พบ host ใน URL,
    resolve ไม่ได้, หรือ IP เป็น private/loopback/link-local)
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
    # Host header ต้องส่งมาเองตรงๆ ไม่งั้น urllib3 จะเอา host จาก pinned_url (=IP) ไปตั้ง
    # Host header อัตโนมัติแทน ทำให้ปลายทางที่ทำ virtual host route ผิดเว็บ
    return pinned_url, hostname, {"Host": hostname}


def verify_webhook_url(url: str):
    """
    ตรวจสอบ URL เพื่อป้องกัน SSRF และยืนยันว่าปลายทางพร้อมรับข้อมูลได้จริง
    (ตอบ 200 OK + echo event_id กลับมาให้ตรง ตามสัญญาที่ระบบใช้ยืนยัน ACK จริง)

    เรียกครั้งเดียวตอน POST /webhook/add เท่านั้น (สร้าง endpoint ใหม่) — การเช็คซ้ำก่อนยิงจริง
    ทุกครั้งอยู่ที่ is_url_host_safe() ด้านล่าง ซึ่ง worker.py เรียกเองก่อน client.post() ทุกครั้ง
    เพื่อกัน DNS rebinding (โดเมนถูกเปลี่ยน DNS record หลังผ่านการเช็คตอนสร้าง endpoint ไปแล้ว)

    [DNS rebinding fix]: ตัว POST ทดสอบในฟังก์ชันนี้เองก็ยิงด้วย IP ที่ resolve+เช็คแล้วตรงๆ
    (ผ่าน _build_pinned_https_request + _PinnedHostnameHTTPSAdapter) แทนที่จะปล่อยให้ requests
    resolve DNS ซ้ำเองตอน post() จริง — ปิดช่องที่โดเมนถูกเปลี่ยน DNS record ให้ชี้ internal IP
    พอดีในช่วงเสี้ยววินาทีระหว่างเช็คกับยิงจริง (เดิม resolve_and_check_ip เช็คแล้วทิ้งผล ปล่อยให้
    requests.post(url, ...) resolve เองอีกรอบ = ช่อง TOCTOU) เทียบเท่ากับที่
    resolve_rtsp_url_pinned()/build_pinned_request() ปิดให้ฝั่ง RTSP/httpx ไปแล้ว
    """
    parsed_url = urlparse(url)

    # 1. บังคับใช้ HTTPS เท่านั้น
    if parsed_url.scheme != "https":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="เพื่อความปลอดภัย URL ต้องเป็น HTTPS เท่านั้น"
        )

    # 2-3. แปลง DNS -> IP, เช็ค private/loopback/link-local (ip_guard.py) แล้วคืน URL ที่
    # ต่อด้วย IP ตรงๆ ไว้ยิงจริงด้านล่าง (resolve ครั้งเดียว ไม่ให้ requests resolve ซ้ำเอง)
    try:
        pinned_url, hostname, pin_headers = _build_pinned_https_request(url)
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

    session = requests.Session()
    session.mount("https://", _PinnedHostnameHTTPSAdapter(hostname))

    try:
        response = session.post(
            pinned_url,
            data=dummy_payload,
            files=dummy_files,
            headers=pin_headers,
            timeout=5,
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

    except requests.RequestException as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"ไม่สามารถเชื่อมต่อเซิร์ฟเวอร์ปลายทางได้: {str(e)}"
        )
    finally:
        session.close()

    return True

def build_pinned_request(url: str) -> tuple[str, dict]:
    """
    [DNS rebinding fix — httpx]: เหมือน _build_pinned_https_request() ด้านบนแต่คืนรูปแบบ
    kwargs ที่ httpx.AsyncClient ใช้ได้ตรงๆ (worker.py ใช้ httpx ไม่ใช่ requests) —
    resolve+เช็ค IP ครั้งเดียวแล้ว "ต่อ connection" ไปที่ IP นั้นตรงๆ แต่ยังคง Host header
    และ TLS SNI เป็น hostname เดิม — httpx validate cert กับ hostname เดิมได้ปกติผ่าน
    extension "sni_hostname" (รองรับตั้งแต่ httpx 0.21+) ปิดช่อง TOCTOU เดียวกับที่
    resolve_rtsp_url_pinned() ปิดให้ฝั่ง RTSP ไปแล้ว

    คืน (pinned_url, extra_kwargs) — caller ต้อง unpack extra_kwargs เข้า client.post(...)
    เสมอ เช่น client.post(pinned_url, **extra_kwargs, data=..., files=..., timeout=...)
    ห้ามยิงแค่ pinned_url เฉยๆ โดยไม่ใส่ extra_kwargs เพราะจะกลายเป็นต่อด้วย IP ตรงๆ แบบ RTSP
    ซึ่งฝั่ง HTTPS จะ cert validation fail / เข้าผิด virtual host

    raise SSRFBlockedError เหมือน resolve_and_check_ip เดิมทุกประการ — caller (worker.py)
    จับเองแล้วแปลงเป็น "ส่งไม่สำเร็จ" ธรรมดา ไม่ raise HTTPException เพราะไม่ได้อยู่ใน
    request context
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