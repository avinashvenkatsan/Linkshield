import os

os.environ.setdefault("DATABASE_URL", "")
os.environ.setdefault("GOOGLE_SAFE_BROWSING_API_KEY", "")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
os.environ.setdefault("FRONTEND_ORIGIN", "http://localhost:5173")

from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.services import store as store_mod


@pytest.fixture(autouse=True)
def reset_singletons() -> Generator[None, None, None]:
    get_settings.cache_clear()
    store_mod._store = store_mod.MemoryStore()
    yield
    get_settings.cache_clear()
    store_mod._store = None


@pytest.fixture
def client() -> TestClient:
    from app.main import app

    return TestClient(app)
