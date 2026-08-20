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
    return url

SYNC_DATABASE_URL = _to_sync_url(DATABASE_URL)
sync_engine = create_engine(SYNC_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)