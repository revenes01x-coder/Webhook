from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from smartlpr.config import DATABASE_URL

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