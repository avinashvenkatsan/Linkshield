from fastapi import APIRouter

from app.core.config import get_settings
from app.database.session import get_engine

router = APIRouter()


@router.get("/health")
def health() -> dict:
    settings = get_settings()
    db_ok = True
    db_mode = "memory"
    if settings.database_enabled:
        db_mode = "postgresql"
        try:
            engine = get_engine()
            if engine is not None:
                with engine.connect() as conn:
                    conn.exec_driver_sql("SELECT 1")
        except Exception:  # noqa: BLE001
            db_ok = False
    return {
        "status": "ok" if db_ok else "degraded",
        "service": settings.app_name,
        "version": settings.app_version,
        "database": {"enabled": settings.database_enabled, "ok": db_ok, "mode": db_mode},
        "integrations": {
            "google_safe_browsing": "configured" if settings.gsb_configured else "not_configured",
            "virustotal": "configured" if settings.virustotal_configured else "not_configured",
            "external_intel_enabled": settings.external_intel_enabled,
        },
    }
