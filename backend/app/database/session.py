from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings

_engine = None
_SessionLocal = None


def get_engine():
    global _engine, _SessionLocal
    settings = get_settings()
    if not settings.database_enabled:
        return None
    if _engine is None:
        _engine = create_engine(settings.database_url, pool_pre_ping=True, future=True)
        _SessionLocal = sessionmaker(bind=_engine, autocommit=False, autoflush=False, class_=Session)
    return _engine


def SessionLocal() -> Session:
    get_engine()
    if _SessionLocal is None:
        raise RuntimeError("Database is not configured")
    return _SessionLocal()


def db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
