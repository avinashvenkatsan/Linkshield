from fastapi import APIRouter, HTTPException, Request, status

from app.core.config import get_settings
from app.schemas.scan import StatsResponse
from app.security.rate_limit import enforce_read_limit
from app.services.store import get_store

router = APIRouter()


@router.get("/stats", response_model=StatsResponse)
def stats(request: Request) -> dict:
    settings = get_settings()
    if not settings.stats_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Statistics are disabled")
    enforce_read_limit(request, settings.rate_limit_read_per_minute)
    return get_store().stats()
