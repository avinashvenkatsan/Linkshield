from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import get_or_create_client_id
from app.core.config import get_settings
from app.core.logging import extra_safe, get_logger
from app.schemas.scan import ScanCreateRequest, ScanListResponse, ScanSummary
from app.security.rate_limit import enforce_read_limit, enforce_scan_limit
from app.services.scan_orchestrator import run_scan
from app.services.store import get_store
from app.services.url_parser import UrlValidationError

router = APIRouter()
logger = get_logger(__name__)


def _summary(record: dict) -> ScanSummary:
    return ScanSummary(
        id=record["id"],
        display_url=record["display_url"],
        hostname=record["hostname"],
        risk_score=record.get("risk_score"),
        risk_classification=record.get("risk_classification") or "unknown",
        status=record["status"],
        created_at=record["created_at"],
        completed_at=record.get("completed_at"),
    )


@router.post("/scans", status_code=status.HTTP_201_CREATED)
async def create_scan(payload: ScanCreateRequest, request: Request, response: Response) -> dict:
    settings = get_settings()
    enforce_scan_limit(request, settings.rate_limit_scan_per_minute)
    client_id = get_or_create_client_id(request, response)
    try:
        record = await run_scan(
            payload.url,
            client_id=client_id,
            save_history=payload.save_history,
            allow_external_intel=payload.allow_external_intel,
        )
    except UrlValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"message": str(exc), "code": exc.code}) from exc
    logger.info("scan_completed", extra=extra_safe(scan_id=record["id"], classification=record.get("risk_classification")))
    return record


@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, request: Request, response: Response) -> dict:
    settings = get_settings()
    enforce_read_limit(request, settings.rate_limit_read_per_minute)
    client_id = get_or_create_client_id(request, response)
    record = get_store().get(scan_id, client_id)
    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return record


@router.get("/scans", response_model=ScanListResponse)
def list_scans(request: Request, response: Response) -> ScanListResponse:
    settings = get_settings()
    enforce_read_limit(request, settings.rate_limit_read_per_minute)
    client_id = get_or_create_client_id(request, response)
    items = get_store().list_for_client(client_id)
    return ScanListResponse(items=[_summary(i) for i in items], total=len(items))


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scan(scan_id: str, request: Request, response: Response) -> Response:
    client_id = get_or_create_client_id(request, response)
    deleted = get_store().delete(scan_id, client_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/scans", status_code=status.HTTP_204_NO_CONTENT)
def clear_scans(request: Request, response: Response) -> Response:
    client_id = get_or_create_client_id(request, response)
    get_store().clear_client(client_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
