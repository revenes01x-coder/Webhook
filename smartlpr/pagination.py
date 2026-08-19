from typing import TypeVar, Generic, List
from pydantic import BaseModel
from fastapi import Query
from sqlalchemy import select, func
from sqlalchemy.sql import Select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100


class PageParams:
    """Dependency กลางสำหรับรับ page/page_size จาก query string
    ใช้ร่วมกันได้ทุก endpoint ที่ list ข้อมูล ผ่าน Depends(PageParams)
    เช่น: page_params: PageParams = Depends()

    (ไม่แตะ DB เลย ไม่ต้องเป็น async)"""

    def __init__(
        self,
        page: int = Query(default=1, ge=1, description="เลขหน้า เริ่มที่ 1"),
        page_size: int = Query(
            default=DEFAULT_PAGE_SIZE,
            ge=1,
            le=MAX_PAGE_SIZE,
            description=f"จำนวนรายการต่อหน้า (สูงสุด {MAX_PAGE_SIZE})",
        ),
    ):
        self.page = page
        self.page_size = page_size
        self.offset = (page - 1) * page_size


class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


async def paginate(db: AsyncSession, query: Select, params: PageParams) -> dict:
    count_query = select(func.count()).select_from(query.order_by(None).subquery())
    total = (await db.execute(count_query)).scalar_one()

    result = await db.execute(query.offset(params.offset).limit(params.page_size))
    items = result.scalars().all()

    total_pages = (total + params.page_size - 1) // params.page_size if total else 0
    return {
        "items": items,
        "total": total,
        "page": params.page,
        "page_size": params.page_size,
        "total_pages": total_pages,
    }