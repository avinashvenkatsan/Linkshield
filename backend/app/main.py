from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.database.base import Base
from app.database.session import get_engine
from app.security.headers import SecurityHeadersMiddleware

configure_logging()
logger = get_logger(__name__)
settings = get_settings()

app = FastAPI(
    title="LinkShield API",
    version=settings.app_version,
    description="Evidence-based suspicious URL analysis. A low score is not a guarantee of safety.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):  # noqa: ARG001
    if isinstance(exc, HTTPException):
        raise exc
    logger.exception("unhandled_error")
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. No destination was opened."},
    )


@app.on_event("startup")
def on_startup() -> None:
    if settings.database_enabled:
        engine = get_engine()
        if engine is not None:
            Base.metadata.create_all(bind=engine)
            logger.info("database_ready")
        else:
            logger.warning("database_url_set_but_engine_failed")
    else:
        logger.info("running_with_memory_store")
    if not settings.gsb_configured:
        logger.info("google_safe_browsing_not_configured")
    if not settings.virustotal_configured:
        logger.info("virustotal_not_configured")


app.include_router(api_router, prefix="/api/v1")
