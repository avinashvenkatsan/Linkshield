import httpx
import pytest

from app.integrations.google_safe_browsing import GoogleSafeBrowsingProvider
from app.integrations.virustotal import VirusTotalProvider


class DummyResponse:
    def __init__(self, status_code: int, payload=None) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}

    def json(self):
        if self._payload == "bad":
            raise ValueError("nope")
        return self._payload


@pytest.mark.asyncio
async def test_gsb_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    from app.core.config import get_settings

    get_settings.cache_clear()
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", True)
    assert result.status == "not_configured"


@pytest.mark.asyncio
async def test_gsb_unauthorized_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    from app.core.config import get_settings

    get_settings.cache_clear()
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", False)
    assert result.status == "incomplete"


@pytest.mark.asyncio
async def test_gsb_match_and_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_SAFE_BROWSING_API_KEY", "test-key")
    from app.core.config import get_settings

    get_settings.cache_clear()

    class FakeClient:
        def __init__(self, response):
            self._response = response

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            if isinstance(self._response, Exception):
                raise self._response
            return self._response

    monkeypatch.setattr("app.integrations.google_safe_browsing.httpx.AsyncClient", lambda timeout=None: FakeClient(DummyResponse(200, {"matches": [{"threatType": "MALWARE"}]})))
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", True)
    assert result.status == "threat_detected"

    monkeypatch.setattr("app.integrations.google_safe_browsing.httpx.AsyncClient", lambda timeout=None: FakeClient(DummyResponse(200, {})))
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", True)
    assert result.status == "no_threat_detected"

    monkeypatch.setattr("app.integrations.google_safe_browsing.httpx.AsyncClient", lambda timeout=None: FakeClient(DummyResponse(429, {})))
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", True)
    assert result.status == "rate_limited"

    monkeypatch.setattr("app.integrations.google_safe_browsing.httpx.AsyncClient", lambda timeout=None: FakeClient(httpx.TimeoutException("t")))
    result = await GoogleSafeBrowsingProvider().check_url("https://example.com", True)
    assert result.status == "check_unavailable"


@pytest.mark.asyncio
async def test_vt_404_is_not_malicious(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    from app.core.config import get_settings

    get_settings.cache_clear()

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def get(self, *args, **kwargs):
            return DummyResponse(404, {})

    monkeypatch.setattr("app.integrations.virustotal.httpx.AsyncClient", lambda timeout=None: FakeClient())
    result = await VirusTotalProvider().check_url("https://example.com", True)
    assert result.status == "no_threat_detected"
    assert result.stats.get("not_found") is True
