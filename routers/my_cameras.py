from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from smartlpr import models
import smartlpr.schemas as schemas
from smartlpr.database import get_db
from smartlpr.security import get_current_user
from smartlpr.pagination import PageParams

router = APIRouter(prefix="/my", tags=["My Cameras"])

@router.get("/cameras", response_model=schemas.PaginatedResponse[schemas.MyCameraResponse])
def list_my_cameras(
    page_params: PageParams = Depends(),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    base_query = (
        db.query(models.Camera, models.WebhookEndpoint.url)
        .join(models.WebhookEndpoint, models.Camera.webhook_endpoint_id == models.WebhookEndpoint.id)
        .filter(models.Camera.owner_user_id == current_user.id)
    )

    total = base_query.count()
    rows = (
        base_query
        .order_by(models.Camera.id.desc())
        .offset(page_params.offset)
        .limit(page_params.page_size)
        .all()
    )
    total_pages = (total + page_params.page_size - 1) // page_params.page_size if total else 0

    return {
        "items": [
            schemas.MyCameraResponse(
                camera_id=c.id,
                is_active=c.is_active,
                verification_status=c.verification_status,
                webhook_url=webhook_url,
                created_at=c.created_at,
            )
            for c, webhook_url in rows
        ],
        "total": total,
        "page": page_params.page,
        "page_size": page_params.page_size,
        "total_pages": total_pages,
    }