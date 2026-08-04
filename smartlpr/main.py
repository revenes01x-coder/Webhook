from fastapi import FastAPI, Depends, Request, Form
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timezone
import models
from smartlpr.database import engine, get_db
from routers import auth, webhook, terms, admin, access_request, my_cameras, api_key
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

    # 4. หา WebhookEndpoint ที่ active ของเจ้าของกล้อง -> สร้าง WebhookEvent ลงคิว
    #    หนึ่ง event ต่อหนึ่ง endpoint ของเจ้าของกล้องคนนี้
    active_endpoints = db.query(models.WebhookEndpoint).filter(
        models.WebhookEndpoint.user_id == owner_user_id,
        models.WebhookEndpoint.is_active == True
    ).all()

    if not active_endpoints:
        return {"status": "ignored", "message": "เจ้าของกล้องนี้ยังไม่ได้ตั้งค่า Webhook URL"}

    for endpoint in active_endpoints:
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