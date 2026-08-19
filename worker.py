import asyncio
import uuid
import logging
import httpx
import cv2
from datetime import datetime, timedelta, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.orm import Session
from smartlpr import models
from smartlpr.database import SessionLocal
from services.email_service import send_webhook_endpoint_unhealthy_email
from smartlpr.config import UNVERIFIED_USER_EXPIRE_HOURS, PLATE_DATA_RETENTION_DAYS
from security.ssrf_guard import build_pinned_request, build_test_webhook_payload
from security.camera_url_guard import resolve_rtsp_url_pinned
from security.ip_guard import SSRFBlockedError

RETRY_DELAYS = {1: 3, 2: 5, 3: 10}
DEAD_LETTER_THRESHOLD = 3

REALTIME_CONCURRENCY = 5
RESUME_CONCURRENCY = 3

HEALTH_CHECK_TIMEOUT_SECONDS = 5

# Camera RTSP verification: timeout ต่อกล้อง 1 ตัว (วินาที) ตอนลอง connect+อ่านเฟรมจริง
CAMERA_VERIFY_TIMEOUT_SECONDS = 15
CAMERA_VERIFY_MAX_ATTEMPTS = 5


def _is_valid_ack(event: models.WebhookEvent, response: httpx.Response) -> bool:
    """
    ACK ถูกต้องก็ต่อเมื่อ status 2xx + body เป็น JSON parse ได้ + event_id ตรงกับ source_event_id
"""
    try:
        body = response.json()
    except ValueError:
        return False
    if not isinstance(body, dict):
        return False

    received_event_id = body.get("event_id")
    if not isinstance(received_event_id, str):
        return False

    try:
        return uuid.UUID(received_event_id) == uuid.UUID(event.source_event_id)
    except (ValueError, AttributeError, TypeError):
        # source_event_id หรือค่าที่ปลายทางตอบมา parse เป็น UUID ไม่ได้ (ผิดปกติ) -> ถือว่าไม่ตรง
        return False


def _read_event_images(event: models.WebhookEvent) -> dict:
    """อ่านไฟล์รูป full/crop แบบ sync (blocking disk I/O) — เรียกผ่าน asyncio.to_thread เท่านั้น
    ไม่ให้ blocking I/O นี้ไปแช่ event loop ตอนมีหลาย event ยิงพร้อมกัน (REALTIME_CONCURRENCY=5 /
    RESUME_CONCURRENCY=3 ผ่าน asyncio.gather) — หลักการเดียวกับที่ build_pinned_request() ถูกห่อ
    ด้วย asyncio.to_thread ใน _send_webhook_request() ด้านล่าง (DNS resolve ก็เป็น blocking call
    เหมือนกัน) ไฟล์นี้ไม่มี ปล่อยให้ FileNotFoundError จาก open() ลอยออกไปให้ caller จับเอง
    (ดู except FileNotFoundError ใน _send_webhook_request)"""
    with open(event.full_image_path, "rb") as f_full, \
         open(event.crop_image_path, "rb") as f_crop:
        return {
            "image_full": (f"{event.id}_full.jpg", f_full.read(), "image/jpeg"),
            "image_crop": (f"{event.id}_crop.jpg", f_crop.read(), "image/jpeg"),
        }


async def _send_webhook_request(client: httpx.AsyncClient, event: models.WebhookEvent):
    """ยิง 1 event จริงออกไป คืน (result_type, error_msg) เท่านั้น ไม่แตะ DB ในนี้เลย
    (กัน sync DB call ไปบล็อก event loop ตอนรันพร้อมกันหลาย coroutine ผ่าน asyncio.gather)"""

    # [SSRF Guard]: resolve+เช็ค IP ปลอดภัยซ้ำก่อนยิงจริงทุกครั้ง แล้วต่อ connection ไปยัง IP
    # ที่ resolve ได้ตรงๆ (ไม่ resolve ซ้ำอีกรอบตอน client.post() เหมือนโค้ดเดิม) ปิดช่อง DNS
    # rebinding แบบ TOCTOU ได้สมบูรณ์ (โดเมนถูกเปลี่ยน DNS record ระหว่างช่วงเช็คกับช่วงยิงจริง)
    # เหมือนที่ resolve_rtsp_url_pinned() ปิดให้ฝั่ง RTSP ไปแล้ว — ดู build_pinned_request()
    # ใน ssrf_guard.py สำหรับรายละเอียดว่าทำไมฝั่ง HTTPS ต้องคง Host header/SNI เป็น hostname เดิม
    try:
        pinned_url, pin_kwargs = await asyncio.to_thread(build_pinned_request, event.target_url)
    except SSRFBlockedError as e:
        logging.warning(
            f"[SSRF Guard] ปฏิเสธการส่ง Event ID: {event.id} — {e} "
            f"(อาจเป็น DNS rebinding)"
        )
        return "ssrf_blocked", (
            f"ปฏิเสธการส่ง: {e} "
            "(อาจเกิดจาก DNS ถูกเปลี่ยนหลังผ่านการตรวจสอบตอนสร้าง endpoint ไปแล้ว)"
        )

    try:
        # อ่านไฟล์รูป (blocking disk I/O) ใน thread แยก เหมือนหลักการเดียวกับ SSRF check
        # ด้านบน — ไม่งั้นตอนมีหลาย event วิ่งพร้อมกัน การอ่านไฟล์ของ event หนึ่งจะไปบล็อก
        # event loop จนกระทบ event อื่นที่กำลังรอ network I/O (client.post) อยู่พร้อมกัน
        files = await asyncio.to_thread(_read_event_images, event)

        response = await client.post(
            pinned_url,
            data=event.payload,
            files=files,
            timeout=10,
            **pin_kwargs,
        )

        if response.status_code // 100 != 2:
            return "http_error", f"เซิร์ฟเวอร์ลูกค้าตอบกลับ HTTP {response.status_code}"

        if _is_valid_ack(event, response):
            return "success", None

        return "ack_mismatch", (
            f"ปลายทางตอบ 2xx แต่ body ไม่ตรง/parse ไม่ได้ "
            f"(คาดหวัง event_id={event.source_event_id}) ได้: {response.text[:300]!r}"
        )

    except FileNotFoundError as e:
        return "file_not_found", str(e)
    except Exception as e:
        return "error", str(e)


async def _send_with_semaphore(semaphore: asyncio.Semaphore, client: httpx.AsyncClient, event: models.WebhookEvent):
    async with semaphore:
        result_type, error_msg = await _send_webhook_request(client, event)
    return event, result_type, error_msg


def _get_suspended_user_ids(db: Session, user_ids: set) -> set:
    """คืน set ของ user_id ที่ is_suspended=True ในกลุ่ม user_ids ที่ให้มา (query ครั้งเดียว
    ต่อรอบ ไม่ query ทีละ event) ใช้ร่วมกันทั้ง process_webhook_queue และ process_graveyard_resume
    เพื่อกัน event ของ user ที่ถูกระงับไม่ให้ถูกส่งออกไปจริง"""
    if not user_ids:
        return set()
    rows = db.query(models.User.id).filter(
        models.User.id.in_(user_ids),
        models.User.is_suspended == True,  # noqa: E712
    ).all()
    return {uid for (uid,) in rows}


def _mark_endpoint_outcome(endpoint: models.WebhookEndpoint, success: bool) -> bool:
    """
    Circuit breaker bookkeeping (แค่แก้ attribute เฉยๆ ไม่ commit ในนี้):
    - success -> ล้าง streak dead_letter ทิ้ง (มี event ผ่านคั่นกลาง นับ streak ใหม่)
    - ไม่ success (ตกสุสาน) -> เพิ่ม streak ติดกัน ครบ threshold -> ตัดไฟ (is_healthy=False)
    คืนค่า True ถ้าการเรียกครั้งนี้เป็นตัวที่ทำให้เพิ่งตัดไฟ (healthy -> unhealthy) พอดี
    เพื่อให้ caller รู้ว่าต้องส่งอีเมลแจ้งเตือน user ครั้งเดียวตอนนี้ ไม่ใช่ทุกครั้งที่ยังตัดไฟอยู่
    """
    if success:
        endpoint.consecutive_dead_letters = 0
        return False

    was_healthy = endpoint.is_healthy
    endpoint.consecutive_dead_letters += 1
    if endpoint.consecutive_dead_letters >= DEAD_LETTER_THRESHOLD:
        endpoint.is_healthy = False
        return was_healthy and not endpoint.is_healthy  # เพิ่งเปลี่ยนจาก True -> False ตอนนี้เลย
    return False


def _apply_send_result(event, endpoint, result_type, error_msg):
    """คืน endpoint ที่ "เพิ่งถูกตัดไฟ" จากการเรียกครั้งนี้ (หรือ None ถ้าไม่มี) ให้ caller เอาไปส่งอีเมลแจ้ง user"""
    now = datetime.now(timezone.utc)
    just_tripped_endpoint = None

    if result_type == "success":
        event.status = "success"
        if endpoint:
            _mark_endpoint_outcome(endpoint, success=True)

    elif result_type == "file_not_found":
        logging.warning(f"ไม่พบไฟล์รูปของ Event ID: {event.id} | {error_msg}")
        event.attempt_count += 1
        event.status = "dead_letter"
        event.next_retry_at = None
        if endpoint:
            if _mark_endpoint_outcome(endpoint, success=False):
                just_tripped_endpoint = endpoint

    else:
        # ครอบคลุมทั้ง http_error, ack_mismatch, ssrf_blocked, error ธรรมดา — เข้า retry logic เดียวกันหมด
        # (ssrf_blocked ก็ถือเป็นความล้มเหลวของ endpoint นี้เหมือนกัน ถ้าเกิดติดกันครบ threshold
        # circuit breaker จะตัดไฟให้เองเหมือนเหตุผลอื่นๆ ไม่ต้องมี branch พิเศษแยก)
        logging.warning(f"ส่งข้อมูลไม่สำเร็จ Event ID: {event.id} | ประเภท: {result_type} | Error: {error_msg}")
        event.attempt_count += 1

        if event.attempt_count > 3:
            event.status = "dead_letter"
            event.next_retry_at = None
            if endpoint:
                if _mark_endpoint_outcome(endpoint, success=False):
                    just_tripped_endpoint = endpoint
        else:
            event.status = "failed"
            delay_minutes = RETRY_DELAYS.get(event.attempt_count, 10)
            event.next_retry_at = now + timedelta(minutes=delay_minutes)

    return just_tripped_endpoint


def _notify_endpoints_tripped(db: Session, tripped_endpoints: dict) -> None:
    """ส่งอีเมลแจ้ง user ว่า endpoint ของตัวเองถูกตัดไฟ — เรียกหลัง db.commit() แล้วเท่านั้น
    ไม่ให้ endpoint เดียวกันถูกแจ้งซ้ำในรอบเดียวกัน (tripped_endpoints คีย์ด้วย endpoint.id อยู่แล้ว)
    ส่งเมลพังไม่กระทบ transaction หลัก (แค่ log error ทิ้ง)
"""
    for endpoint in tripped_endpoints.values():
        owner = db.query(models.User).filter(models.User.id == endpoint.user_id).first()
        if not owner:
            continue
        try:
            send_webhook_endpoint_unhealthy_email(owner.email, endpoint.url)
        except RuntimeError as e:
            logging.error(f"ส่งอีเมลแจ้งเตือน endpoint ตัดไฟ (id={endpoint.id}) ไม่สำเร็จ: {e}")


async def process_webhook_queue():
    """
    Job A — realtime: event ใหม่ + event ที่กำลัง retry ปกติเท่านั้น (status pending/failed)
    ไม่แตะ dead_letter เลย นั่นเป็นหน้าที่ของ Job B (process_graveyard_resume) โดยเฉพาะ
    ใช้ Semaphore(REALTIME_CONCURRENCY) แยกเด็ดขาดจาก Job B ไม่แย่ง concurrency กัน
    """
    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc)

        events = db.query(models.WebhookEvent).filter(
            models.WebhookEvent.status.in_(["pending", "failed"]),
            (models.WebhookEvent.next_retry_at <= now) | (models.WebhookEvent.next_retry_at == None),
            models.WebhookEvent.deleted_at.is_(None),
        ).all()

        if not events:
            return

        endpoint_ids = {e.webhook_endpoint_id for e in events if e.webhook_endpoint_id}
        endpoints_by_id = {}
        if endpoint_ids:
            endpoints_by_id = {
                ep.id: ep
                for ep in db.query(models.WebhookEndpoint).filter(
                    models.WebhookEndpoint.id.in_(endpoint_ids)
                ).all()
            }

        # [Suspend Guard]: หาว่า event ไหนเป็นของ user ที่ถูกระงับอยู่ตอนนี้บ้าง (query ครั้งเดียว)
        suspended_user_ids = _get_suspended_user_ids(db, {e.user_id for e in events if e.user_id})

        # Circuit breaker: endpoint ถูกตัดไฟอยู่ -> ข้าม 3 รอบ retry ไปเลย เข้าสุสานทันที ประหยัดเวลา
        to_send = []
        for event in events:
            if event.user_id in suspended_user_ids:
                continue

            endpoint = endpoints_by_id.get(event.webhook_endpoint_id)

            if endpoint and not endpoint.is_active:
                continue

            if endpoint and not endpoint.is_healthy:
                event.status = "dead_letter"
                event.next_retry_at = None
                logging.info(
                    f"Event ID: {event.id} ข้ามการส่งจริง เพราะ endpoint id={endpoint.id} "
                    f"ถูกตัดไฟอยู่ (is_healthy=False)"
                )
                continue
            to_send.append(event)

        tripped_endpoints = {}  # endpoint.id -> endpoint, กันแจ้งซ้ำถ้าหลาย event ตัดไฟ endpoint เดียวกันพร้อมกัน

        if to_send:
            semaphore = asyncio.Semaphore(REALTIME_CONCURRENCY)
            async with httpx.AsyncClient() as client:
                results = await asyncio.gather(
                    *(_send_with_semaphore(semaphore, client, event) for event in to_send)
                )

            for event, result_type, error_msg in results:
                endpoint = endpoints_by_id.get(event.webhook_endpoint_id)
                just_tripped = _apply_send_result(event, endpoint, result_type, error_msg)
                if just_tripped:
                    tripped_endpoints[just_tripped.id] = just_tripped

        db.commit()

        if to_send and tripped_endpoints:
            # [Fix - Blocking I/O]: เดิมเรียก _notify_endpoints_tripped(db, tripped_endpoints) ตรงๆ
            # แบบ sync ในนี้ ซึ่งข้างในยิง SMTP blocking -> ค้าง event loop หลักของทั้งแอปได้นานสุด
            # ถึง timeout ต่ออีเมล ตอนนี้ห่อด้วย asyncio.to_thread ให้ทำงานบนเธรดแยกแทน
            # (ดูคำอธิบายเรื่องความปลอดภัยของการส่ง db ข้าม thread ใน docstring ของฟังก์ชันนั้นเอง)
            await asyncio.to_thread(_notify_endpoints_tripped, db, tripped_endpoints)

    except Exception as e:
        db.rollback()
        logging.error(f"Background Worker (realtime) ทำงานผิดพลาด: {e}")
    finally:
        db.close()


async def _ping_endpoint(client: httpx.AsyncClient, url: str) -> bool:
    # [SSRF Guard]: resolve+เช็ค IP ปลอดภัยซ้ำก่อนยิงจริงเหมือน _send_webhook_request แล้วต่อ
    # connection ไปยัง IP ที่ resolve ได้ตรงๆ (ไม่ resolve ซ้ำตอน client.post()) — endpoint ที่
    # ถูกตัดไฟอาจโดน DNS rebinding ระหว่างที่ตัดไฟอยู่ก็ได้ ไม่ควรถือว่า "ฟื้น" แค่เพราะ ping ผ่าน
    # ด้วย hostname ที่อาจไม่ได้ต่อไปยัง IP เดียวกับที่เช็คจริง
    try:
        pinned_url, pin_kwargs = await asyncio.to_thread(build_pinned_request, url)
    except SSRFBlockedError as e:
        logging.warning(f"[SSRF Guard] ข้าม health check เพราะ {url} — {e}")
        return False

    try:
        test_event_id, dummy_payload, dummy_files = build_test_webhook_payload()

        response = await client.post(
            pinned_url, data=dummy_payload, files=dummy_files, timeout=HEALTH_CHECK_TIMEOUT_SECONDS,
            **pin_kwargs,
        )
        if response.status_code // 100 != 2:
            return False

        body = response.json()
        return isinstance(body, dict) and body.get("event_id") == test_event_id
    except RuntimeError as e:
        logging.error(f"[Health Check] ไม่สามารถโหลดรูปทดสอบ webhook: {e}")
        return False
    except Exception:
        return False


async def process_graveyard_resume(endpoint_ids: list[int] | None = None):
    """
    Job B — แยกเด็ดขาดจาก Job A ทั้งคิวและ Semaphore (RESUME_CONCURRENCY)
    ทุก 30 นาที (default): เช็คเฉพาะ endpoint ที่ถูกตัดไฟ (is_healthy=False) ว่าฟื้นหรือยัง
    ...(docstring เดิม)...

    endpoint_ids: ไม่ระบุ (None) = พฤติกรรมเดิมทุกประการ (เรียกจาก scheduler ทุก 30 นาที)
    ระบุมา = จำกัด scope เฉพาะ endpoint ที่ระบุ ใช้ตอน routers/admin.py:set_webhook_status
    เรียกทันทีหลัง admin เปิด endpoint ที่เคยถูกตัดไฟกลับมา (ผ่าน resume_endpoint_now ด้านล่าง)
    ไม่ต้องรอ cron รอบถัดไป — logic ที่เหลือเหมือนเดิมทุกอย่าง ยังต้อง ping สำเร็จจริงก่อนถึงจะ
    ปลดล็อกและ resume ไม่ได้ trust คำสั่ง admin เฉยๆ
    """
    db: Session = SessionLocal()
    try:
        query = db.query(models.WebhookEndpoint).filter(
            models.WebhookEndpoint.is_healthy == False,  # noqa: E712
            models.WebhookEndpoint.is_active == True,
        )
        if endpoint_ids is not None:
            query = query.filter(models.WebhookEndpoint.id.in_(endpoint_ids))
        unhealthy_endpoints = query.all()

        if not unhealthy_endpoints:
            return

        recovered_endpoints = []
        async with httpx.AsyncClient() as client:
            for endpoint in unhealthy_endpoints:
                if await _ping_endpoint(client, endpoint.url):
                    endpoint.is_healthy = True
                    endpoint.consecutive_dead_letters = 0
                    recovered_endpoints.append(endpoint)

            # เปิดไฟให้ endpoint ที่ฟื้นก่อน commit ทันที แม้ resume ด้านล่างจะพังก็ไม่เสีย progress ตรงนี้
            db.commit()

            if not recovered_endpoints:
                return

            recovered_ids = [ep.id for ep in recovered_endpoints]
            dead_events = db.query(models.WebhookEvent).filter(
                models.WebhookEvent.webhook_endpoint_id.in_(recovered_ids),
                models.WebhookEvent.status == "dead_letter",
                models.WebhookEvent.deleted_at.is_(None),
            ).all()

            if not dead_events:
                logging.info(
                    f"[Graveyard Resume] endpoint ฟื้น {len(recovered_endpoints)} ตัว "
                    f"แต่ไม่มี event ค้างในสุสาน"
                )
                return

            # [Suspend Guard]: endpoint ฟื้นแล้วก็จริง แต่ถ้าเจ้าของ event ยังถูกระงับอยู่ ไม่ควร
            # resume ส่งให้ — ตัดออกจากรอบนี้ไปก่อน (ยังคงเป็น dead_letter เหมือนเดิม รอ Job B
            # รอบถัดไปตอนที่ endpoint ยังฟื้นอยู่ และเจ้าของถูกปลดระงับแล้วค่อยลองใหม่)
            suspended_user_ids = _get_suspended_user_ids(db, {e.user_id for e in dead_events if e.user_id})
            skipped_suspended = [e for e in dead_events if e.user_id in suspended_user_ids]
            dead_events = [e for e in dead_events if e.user_id not in suspended_user_ids]

            if skipped_suspended:
                logging.info(
                    f"[Graveyard Resume] ข้าม {len(skipped_suspended)} event เพราะเจ้าของถูกระงับอยู่"
                )

            if not dead_events:
                return

            endpoints_by_id = {ep.id: ep for ep in recovered_endpoints}
            semaphore = asyncio.Semaphore(RESUME_CONCURRENCY)
            results = await asyncio.gather(
                *(_send_with_semaphore(semaphore, client, event) for event in dead_events)
            )

        tripped_endpoints = {}
        for event, result_type, error_msg in results:
            endpoint = endpoints_by_id.get(event.webhook_endpoint_id)
            if result_type == "success":
                event.status = "success"
                if endpoint:
                    _mark_endpoint_outcome(endpoint, success=True)
            else:
                logging.warning(f"Resume ส่งไม่สำเร็จอีกครั้ง Event ID: {event.id} | {result_type} | {error_msg}")
                event.status = "dead_letter"  # กลับไปสุสาน รอ health check รอบหน้า (อีก 30 นาที)
                if endpoint:
                    if _mark_endpoint_outcome(endpoint, success=False):
                        tripped_endpoints[endpoint.id] = endpoint

        db.commit()

        if tripped_endpoints:
            # [Fix - Blocking I/O]: เหมือนจุดเดียวกันใน process_webhook_queue ด้านบน — ห่อด้วย
            # asyncio.to_thread กัน SMTP ไปค้าง event loop หลักของแอป
            await asyncio.to_thread(_notify_endpoints_tripped, db, tripped_endpoints)

        logging.info(
            f"[Graveyard Resume] endpoint ที่ฟื้น {len(recovered_endpoints)} ตัว, "
            f"resume event ทั้งหมด {len(dead_events)} รายการ"
        )

    except Exception as e:
        db.rollback()
        logging.error(f"Graveyard resume job ทำงานผิดพลาด: {e}")
    finally:
        db.close()


def _try_open_rtsp(rtsp_url: str) -> bool:
    """
    เรียกใน thread แยก (blocking call จริง) — ลอง connect RTSP แล้วอ่านเฟรม
    หมายเหตุ: cv2.VideoCapture เป็น native blocking call ถ้า network ห่วยมากๆ อาจค้างเกิน
    timeout ที่ตั้งไว้ได้จริง (asyncio.wait_for จะ "เลิกรอ" แต่ thread เบื้องหลังอาจยังค้างอยู่)
    เป็นข้อจำกัดที่รู้อยู่แล้วของ OpenCV ไม่ใช่บั๊ก

    [SSRF Guard]: pin IP ก่อน connect เสมอ (resolve_rtsp_url_pinned) กัน DNS rebinding
    """
    try:
        pinned_url = resolve_rtsp_url_pinned(rtsp_url)
    except SSRFBlockedError as e:
        logging.warning(f"[SSRF Guard] ปฏิเสธการตรวจสอบ RTSP: {e}")
        return False

    cap = None
    try:
        cap = cv2.VideoCapture(pinned_url)
        if not cap.isOpened():
            return False

        # ลองอ่านได้สูงสุด 3 เฟรม เผื่อเฟรมแรกๆ ยังว่าง (I-frame ยังไม่มาถึง) ไม่ตัดสิน fail
        # จากการอ่านครั้งเดียว — ยังอยู่ในกรอบเวลา timeout เดิม (CAMERA_VERIFY_TIMEOUT_SECONDS)
        for _ in range(3):
            ret, frame = cap.read()
            if ret and frame is not None:
                return True
        return False
    except Exception as e:
        logging.warning(f"[Camera Verify] เปิด RTSP ผิดพลาด: {e}")
        return False
    finally:
        if cap is not None:
            cap.release()


async def verify_pending_cameras():
    """
    Background verification จังหวะที่ 2 (จังหวะที่ 1 คือ SSRF guard ตอน POST /partner/cameras)
    เช็คกล้องที่ verification_status อยู่ใน (pending, failed) และยังไม่ครบโควต้าการลอง
    (verify_attempt_count < CAMERA_VERIFY_MAX_ATTEMPTS) ทีละตัว ลอง connect RTSP จริงแบบมี timeout

    ผ่าน -> is_active=True, verification_status='verified'
    ไม่ผ่านแต่ยังไม่ครบโควต้า -> verification_status='failed' รอ job รอบหน้าลองใหม่ (ทุก 2 นาที)
    ไม่ผ่านและครบโควต้าแล้ว -> [Bounded Retry] ลบ row ทิ้งเลย ไม่ค้างเป็น failed ตลอดไป
    partner จะรู้ผลเองตอนยิง GET /partner/cameras/{id} แล้วเจอ 404 (ดู routers/partner.py)
    """
    db: Session = SessionLocal()
    try:
        cameras_to_check = db.query(models.Camera).filter(
            models.Camera.verification_status.in_(["pending", "failed"]),
            models.Camera.verify_attempt_count < CAMERA_VERIFY_MAX_ATTEMPTS,
        ).all()

        if not cameras_to_check:
            return

        for camera in cameras_to_check:
            try:
                is_ok = await asyncio.wait_for(
                    asyncio.to_thread(_try_open_rtsp, camera.rtsp_url),
                    timeout=CAMERA_VERIFY_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                is_ok = False

            camera.verify_attempt_count += 1

            if is_ok:
                camera.is_active = True
                camera.verification_status = "verified"
                logging.info(f"[Camera Verify] camera id={camera.id} เชื่อมต่อ RTSP สำเร็จ -> verified")

            elif camera.verify_attempt_count >= CAMERA_VERIFY_MAX_ATTEMPTS:
                logging.warning(
                    f"[Camera Verify] camera id={camera.id} เชื่อมต่อ RTSP ไม่สำเร็จครบ "
                    f"{CAMERA_VERIFY_MAX_ATTEMPTS} ครั้ง -> ลบออกจากระบบ (partner ต้องสร้างใหม่เอง)"
                )
                db.delete(camera)

            else:
                camera.verification_status = "failed"
                logging.warning(
                    f"[Camera Verify] camera id={camera.id} เชื่อมต่อ RTSP ไม่สำเร็จ "
                    f"(ครั้งที่ {camera.verify_attempt_count}/{CAMERA_VERIFY_MAX_ATTEMPTS}) -> ลองใหม่รอบหน้า"
                )

        db.commit()

    except Exception as e:
        db.rollback()
        logging.error(f"Camera verification job ทำงานผิดพลาด: {e}")
    finally:
        db.close()

async def cleanup_unverified_users():
    """
    ลบ user ที่สมัครแล้วไม่ยืนยัน OTP ภายในเวลาที่กำหนด (hard delete)
    เกณฑ์: created_at เกิน UNVERIFIED_USER_EXPIRE_HOURS ชั่วโมง และ is_verified == False
    ลบ OtpVerification ที่ผูกกับ user นั้นก่อน (กัน FK constraint) แล้วค่อยลบ user
    ไม่แตะ user ที่ verify แล้ว ไม่ว่าจะสมัครมานานแค่ไหน
    """
    db: Session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(hours=UNVERIFIED_USER_EXPIRE_HOURS)

        stale_users = db.query(models.User).filter(
            models.User.is_verified == False,  # noqa: E712
            models.User.created_at <= cutoff,
        ).all()

        if not stale_users:
            return

        for user in stale_users:
            db.query(models.OtpVerification).filter(
                models.OtpVerification.user_id == user.id
            ).delete(synchronize_session=False)
            logging.info(
                f"ลบ user ที่ไม่ verify เกิน {UNVERIFIED_USER_EXPIRE_HOURS} ชม.: "
                f"{user.email} (id={user.id}, สมัครเมื่อ {user.created_at})"
            )
            db.delete(user)

        db.commit()

    except Exception as e:
        db.rollback()
        logging.error(f"Cleanup unverified users ทำงานผิดพลาด: {e}")
    finally:
        db.close()


async def cleanup_old_plate_data():
    db: Session = SessionLocal()
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=PLATE_DATA_RETENTION_DAYS)
        now = datetime.now(timezone.utc)

        result = db.query(models.WebhookEvent).filter(
            models.WebhookEvent.created_at <= cutoff,
            models.WebhookEvent.deleted_at.is_(None),
        ).update({"deleted_at": now}, synchronize_session=False)

        db.commit()

        if result:
            logging.info(
                f"Soft delete ข้อมูลป้ายทะเบียนที่เก็บเกิน {PLATE_DATA_RETENTION_DAYS} วัน "
                f"จำนวน {result} รายการ"
            )

    except Exception as e:
        db.rollback()
        logging.error(f"Cleanup ข้อมูลป้ายทะเบียนเก่าทำงานผิดพลาด: {e}")
    finally:
        db.close()

async def cleanup_expired_revoked_tokens():
    """ลบ record ใน revoked_tokens ที่ revoked_expires_at ผ่านไปแล้ว
    (token หมดอายุไปเองตามธรรมชาติแล้ว ไม่มีประโยชน์ต้องเก็บ record ไว้เช็คต่อ)"""
    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        result = db.query(models.RevokedToken).filter(
            models.RevokedToken.revoked_expires_at <= now,
        ).delete(synchronize_session=False)
        db.commit()
        if result:
            logging.info(f"ลบ revoked token ที่หมดอายุไปแล้ว {result} รายการ")
    except Exception as e:
        db.rollback()
        logging.error(f"Cleanup revoked tokens ทำงานผิดพลาด: {e}")
    finally:
        db.close()


async def cleanup_expired_refresh_tokens():
    """ลบ refresh token ที่หมดอายุไปแล้ว (ไม่ว่าจะเคยถูก rotate/revoke ไปก่อนหน้าหรือไม่ก็ตาม)
    เกณฑ์เดียวคือ expires_at ผ่านไปแล้ว — ไม่มีประโยชน์ต้องเก็บไว้ต่อเพราะยืนยันตัวตนอะไรไม่ได้แล้ว
    (แถวที่ revoked_at ไม่ใช่ None แต่ expires_at ยังไม่ถึง จะยังไม่ถูกลบ เผื่อไว้ตรวจสอบ/debug replay ย้อนหลัง)"""
    db: Session = SessionLocal()
    try:
        now = datetime.now(timezone.utc)
        result = db.query(models.RefreshToken).filter(
            models.RefreshToken.expires_at <= now,
        ).delete(synchronize_session=False)
        db.commit()
        if result:
            logging.info(f"ลบ refresh token ที่หมดอายุไปแล้ว {result} รายการ")
    except Exception as e:
        db.rollback()
        logging.error(f"Cleanup refresh tokens ทำงานผิดพลาด: {e}")
    finally:
        db.close()

async def resume_endpoint_now(endpoint_id: int) -> None:
    await process_graveyard_resume(endpoint_ids=[endpoint_id])

def start_scheduler():
    scheduler = AsyncIOScheduler()
    scheduler.add_job(process_webhook_queue, 'interval', seconds=30)
    scheduler.add_job(process_graveyard_resume, 'interval', minutes=30)
    scheduler.add_job(verify_pending_cameras, 'interval', minutes=1)
    scheduler.add_job(cleanup_unverified_users, 'interval', hours=1)
    scheduler.add_job(cleanup_old_plate_data, 'interval', hours=24)
    scheduler.add_job(cleanup_expired_revoked_tokens, 'interval', hours=1)
    scheduler.add_job(cleanup_expired_refresh_tokens, 'interval', hours=1)
    scheduler.start()
    return scheduler