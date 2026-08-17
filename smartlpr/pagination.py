from typing import TypeVar, Generic, List
from pydantic import BaseModel
from fastapi import Query
from sqlalchemy.orm import Query as SAQuery

T = TypeVar("T")

DEFAULT_PAGE_SIZE = 10
MAX_PAGE_SIZE = 100


class PageParams:
    """Dependency กลางสำหรับรับ page/page_size จาก query string
    ใช้ร่วมกันได้ทุก endpoint ที่ list ข้อมูล ผ่าน Depends(PageParams)
    เช่น: page_params: PageParams = Depends()"""

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


def paginate(query: SAQuery, params: PageParams) -> dict:
    """รับ SQLAlchemy query (ที่ filter/order_by มาเรียบร้อยแล้ว) คืน dict
    ที่ตรงกับ field ของ PaginatedResponse พอดี (ใช้เป็น return value ของ endpoint ได้เลย
    FastAPI จะ validate ผ่าน response_model=PaginatedResponse[...] ให้เอง)

    ยิง 2 query: count() (นับทั้งหมดตาม filter ปัจจุบัน) + offset/limit (ดึงเฉพาะหน้านี้)
    ปลอดภัยและอ่านง่ายกว่าการใช้ window function แบบ query เดียว
    """
    total = query.count()
    items = query.offset(params.offset).limit(params.page_size).all()
    total_pages = (total + params.page_size - 1) // params.page_size if total else 0
    return {
        "items": items,
        "total": total,
        "page": params.page,
        "page_size": params.page_size,
        "total_pages": total_pages,
    }