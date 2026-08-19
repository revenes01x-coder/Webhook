from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from smartlpr.config import DATABASE_URL

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