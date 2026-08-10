from fastapi import FastAPI, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
from smartlpr import models
from smartlpr.database import engine, get_db
from routers import auth, webhook, terms, admin, access_request, my_cameras, api_key, partner
from worker import start_scheduler

models.Base.metadata.create_all(bind=engine)

# Lifespan: สั่งให้ Worker ทำงานตอนเปิดเซิร์ฟเวอร์ และปิด Worker ตอนปิดเซิร์ฟเวอร์
@asynccontextmanager
async def lifespan(app: FastAPI):
    print(" เริ่มระบบ SmartLPR Webhook API และ Background Worker...")
    scheduler = start_scheduler()
    yield
    print(" กำลังปิดระบบและหยุดการทำงานของ Worker...")
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan, title="SmartLPR Webhook System")

# ---------------------------------------------------------------------------
# CORS — อนุญาตให้หน้า static (index.html ที่รันแยกด้วย `python -m http.server`
# บน origin คนละพอร์ตกับ backend นี้) เรียก fetch() เข้ามาได้
# ถ้า deploy หน้าเว็บที่ domain/พอร์ตอื่น ต้องมาแก้ allow_origins ให้ตรงด้วย
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "null",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# นำ Endpoint จากไฟล์ routers มาเสียบเข้ากับแอปหลัก
app.include_router(auth.router)
app.include_router(terms.router)
app.include_router(access_request.router)
app.include_router(webhook.router)
app.include_router(api_key.router)
app.include_router(my_cameras.router)
app.include_router(admin.router)
app.include_router(partner.router)

@app.post("/capture-event", tags=["Internal System"])
def receive_from_rtsp(
    camera_id: str = Form(...),
    event_id: str = Form(...),
    plate: str = Form(...),
    province: str = Form(""),
    color: str = Form(""),
    timestamp: str = Form(...),
    full_image_path: str = Form(...),
    crop_image_path: str = Form(...),
    db: Session = Depends(get_db),
):

    # 1. เช็คว่า camera_id นี้มีจริงและ is_active=True ไหม ถ้าไม่ผ่าน -> ignore
    camera = db.query(models.Camera).filter(models.Camera.id == camera_id).first()
    if not camera or not camera.is_active:
        return {"status": "ignored", "message": "ไม่พบกล้องนี้ในระบบ หรือกล้องถูกปิดใช้งานอยู่"}

    # 2. เจ้าของกล้องคือ owner_user_id ตรงๆ (กล้องเป็นกรรมสิทธิ์ของ user คนเดียว ไม่มี many-to-many แล้ว)
    owner_user_id = camera.owner_user_id

    # 2.5 [Suspend Guard]: เจ้าของกล้องถูกระงับอยู่ -> ไม่สร้าง WebhookEvent ใหม่เข้าคิวเลย
    # (ตอบ "ignored" เงียบๆ เหมือน case อื่นในนี้ ไม่ error ให้กล้อง/สคริปต์ที่ยิง /capture-event
    # เข้ามาต้อง handle error พิเศษ — เป็นชั้นป้องกันสำรองด้วย เผื่อกล้องบาง process ยัง capture
    # อยู่ทันเวลาก่อนที่ camera_manager.py จะ terminate ให้ในรอบ poll ถัดไป)
    owner = db.query(models.User).filter(models.User.id == owner_user_id).first()
    if not owner or owner.is_suspended:
        return {"status": "ignored", "message": "บัญชีเจ้าของกล้องนี้ถูกระงับการใช้งานอยู่ ไม่ส่งข้อมูลต่อ"}

    # 3. เก็บข้อมูลข้อความไว้ใน payload (path รูปเก็บแยกคนละ column)
    #    field name ตรงตามคู่มือที่แจกให้ user: license_plate, capture_time, camera_id
    #    (event_id คงชื่อเดิมไว้ตามที่ตกลง ไม่เปลี่ยนตามคู่มือที่ใช้ received_event_id)
    text_payload = {
        "event_id": event_id,
        "camera_id": camera_id,
        "license_plate": plate,
        "province": province,
        "color": color,
        "capture_time": timestamp,
    }

    # 4. หา WebhookEndpoint ที่กล้องตัวนี้ผูกไว้ (Camera.webhook_endpoint_id) -> สร้าง
    #    WebhookEvent ลงคิว 1 event ต่อ 1 กล้อง/1 การตรวจจับเท่านั้น (เปลี่ยนจากเดิมที่
    #    fan-out ไปทุก active webhook ของเจ้าของกล้อง — ตอนนี้ 1 กล้อง ผูกกับ webhook
    #    เดียวเสมอตั้งแต่ตอนสร้าง ผ่าน POST /partner/cameras ดู smartlpr/models.py: Camera)
    endpoint = db.query(models.WebhookEndpoint).filter(
        models.WebhookEndpoint.id == camera.webhook_endpoint_id,
        models.WebhookEndpoint.is_active == True
    ).first()

    if not endpoint:
        return {"status": "ignored", "message": "Webhook ที่กล้องนี้ผูกไว้ถูกปิดใช้งานอยู่"}

    new_event = models.WebhookEvent(
        id=f"{event_id}_{endpoint.id}",  # ทำให้ ID ไม่ซ้ำ (primary key)
        source_event_id=event_id,        # event_id ต้นฉบับ ใช้ verify ACK
        user_id=owner_user_id,
        camera_id=camera_id,
        webhook_endpoint_id=endpoint.id,
        target_url=endpoint.url,
        payload=text_payload,
        full_image_path=full_image_path,
        crop_image_path=crop_image_path,
        status="pending",
        attempt_count=0,
        next_retry_at=datetime.now(timezone.utc)  # สั่งให้ทำทันที
    )
    db.add(new_event)

    try:
        db.commit()
    except IntegrityError:
        # กันกรณีกล้องยิง event_id ซ้ำ (เช่น retry เอง) ไม่ให้ 500
        db.rollback()
        return {"status": "ignored", "message": "event_id นี้เคยถูกบันทึกไปแล้ว"}

    return {"status": "success", "message": "เพิ่มข้อมูลลงคิวเรียบร้อย Worker จะจัดการส่งต่อให้ทันที"}