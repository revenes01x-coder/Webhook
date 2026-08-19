"""
Sync database engine/session — ใช้เฉพาะกับโค้ดที่รันนอก FastAPI event loop เท่านั้น
(ตอนนี้มีแค่ camera/camera_manager.py ซึ่งเป็น multiprocessing entry point แยกต่างหาก
ไม่ได้ผูกกับ event loop ของ uvicorn เลย จึงไม่ได้ประโยชน์จาก AsyncSession และใช้
db.query()/db.close() แบบ sync เดิมไม่ได้ ถ้าเอา SessionLocal จาก smartlpr/database.py
(ซึ่งเป็น async_sessionmaker ไปแล้ว) มาใช้ตรงๆ — AsyncSession ไม่มี .query() ให้เรียก

[ไฟล์นี้ถูกอ้างถึงใน comment ของ smartlpr/database.py มาก่อนแล้ว แต่ยังไม่เคยถูกสร้างขึ้นจริง
ทำให้ camera_manager.py ยัง import ผิดจุดอยู่ — เพิ่งสร้างไฟล์นี้ขึ้นมาให้ตรงตามที่ตั้งใจไว้]

ห้าม import ไฟล์นี้จากโค้ดที่รันอยู่ใน FastAPI event loop (routers/*, worker.py,
security.py ฯลฯ) เด็ดขาด — ใช้ smartlpr/database.py (async) เท่านั้นสำหรับส่วนนั้น
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from smartlpr.config import DATABASE_URL

# DATABASE_URL ใน config.py ถูกบังคับให้เป็น async scheme ไปแล้ว (ดู
# smartlpr/database.py: _ensure_async_driver) เช่น sqlite+aiosqlite://, postgresql+asyncpg://
# ต้องแปลงกลับเป็น sync scheme ก่อนสร้าง engine ธรรมดาตรงนี้
_ASYNC_TO_SYNC_PREFIX = {
    "sqlite+aiosqlite://": "sqlite://",
    "postgresql+asyncpg://": "postgresql+psycopg2://",
    "postgres+asyncpg://": "postgresql+psycopg2://",
    "mysql+asyncmy://": "mysql+pymysql://",
}


def _to_sync_url(url: str) -> str:
    for async_prefix, sync_prefix in _ASYNC_TO_SYNC_PREFIX.items():
        if url.startswith(async_prefix):
            return sync_prefix + url[len(async_prefix):]
    # ไม่เข้าเคสไหนเลย (เผื่ออนาคตมี driver อื่นเพิ่ม) — ใช้ค่าเดิมไปก่อน ปล่อยให้
    # SQLAlchemy โยน error ของตัวเองถ้าใช้ไม่ได้จริง อ่านง่ายกว่าไป raise ซ้อนเองตรงนี้
    return url


SYNC_DATABASE_URL = _to_sync_url(DATABASE_URL)

# หมายเหตุ: ถ้า production ใช้ Postgres/MySQL ต้องติดตั้ง driver sync เพิ่มเองด้วย
# (pip install psycopg2-binary หรือ pip install pymysql --break-system-packages) เพราะ
# asyncpg/aiosqlite/asyncmy ที่ติดตั้งไว้แล้วสำหรับฝั่ง async ใช้กับ engine sync ตัวนี้ไม่ได้
# (sqlite ไม่ต้องติดตั้งอะไรเพิ่ม ใช้ sqlite3 built-in ได้เลย)
sync_engine = create_engine(SYNC_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)