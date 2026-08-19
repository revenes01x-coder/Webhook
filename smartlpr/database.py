from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from smartlpr.config import DATABASE_URL

# ---------------------------------------------------------------------------
# [Async Migration]
# เดิม: create_engine(DATABASE_URL) + sessionmaker (sync, db.query()/db.commit() ธรรมดา)
# ใหม่: create_async_engine + async_sessionmaker (ต้อง await db.execute()/db.commit() ทุกจุด)
#
# ต้องเปลี่ยน driver ใน DATABASE_URL (.env) ด้วย เพราะ driver แบบ sync (sqlite3/psycopg2)
# ใช้กับ async engine ไม่ได้:
#   sqlite:///./smartlpr.db          -> sqlite+aiosqlite:///./smartlpr.db   (pip install aiosqlite)
#   postgresql://user:pass@host/db   -> postgresql+asyncpg://user:pass@host/db (pip install asyncpg)
#   mysql://user:pass@host/db        -> mysql+asyncmy://user:pass@host/db  (pip install asyncmy)
#
# หมายเหตุ: camera/camera_manager.py ไม่ได้ใช้ engine ตัวนี้แล้ว — มันเป็น process แยก ไม่ได้
# รันใน FastAPI event loop จึงไม่ได้ประโยชน์จาก async เลย (ดู smartlpr/database_sync.py)
# ---------------------------------------------------------------------------


def _ensure_async_driver(url: str) -> str:
    """เช็คเบื้องต้นว่า DATABASE_URL ยังเป็น scheme แบบ sync เดิมอยู่หรือเปล่า ถ้าใช่ ให้ raise
    error ที่อ่านเข้าใจง่ายทันที แทนที่จะปล่อยให้ SQLAlchemy โยน error เรื่อง "driver ไม่รองรับ"
    ซึ่งอ่านแล้วงงกว่ามากตอน debug ครั้งแรกหลัง migrate"""
    sync_to_async_hint = {
        "sqlite://": "sqlite+aiosqlite://",
        "postgresql://": "postgresql+asyncpg://",
        "postgres://": "postgresql+asyncpg://",
        "mysql://": "mysql+asyncmy://",
    }
    for sync_prefix, async_hint in sync_to_async_hint.items():
        if url.startswith(sync_prefix):
            raise RuntimeError(
                f"DATABASE_URL ใน .env ยังใช้ scheme แบบ sync ('{sync_prefix}...') ซึ่งใช้กับ "
                f"async engine (หลัง migrate) ไม่ได้ กรุณาแก้เป็น '{async_hint}...' แทน "
                "(และติดตั้ง driver async ที่เกี่ยวข้อง เช่น pip install aiosqlite หรือ "
                "pip install asyncpg --break-system-packages)"
            )
    return url

DATABASE_URL = _ensure_async_driver(DATABASE_URL)
engine = create_async_engine(DATABASE_URL, future=True)

SessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, autocommit=False, autoflush=False, expire_on_commit=False
)
Base = declarative_base()

async def get_db():
    async with SessionLocal() as db:
        yield db