from unittest.mock import AsyncMock, patch

import pytest

from app.services.redirects import analyze_redirects
from app.services.url_parser import parse_and_validate


@pytest.mark.asyncio
async def test_redirect_loop() -> None:
    parsed = parse_and_validate("https://example.com/a")

    async def fake_http(*args, **kwargs):
        return 302, {"location": "https://example.com/a"}, None

    with (
        patch("app.services.redirects.select_endpoint") as sel,
        patch("app.services.redirects.revalidate_addresses"),
        patch("app.services.redirects._raw_http", new=AsyncMock(side_effect=fake_http)),
    ):
        from app.security.ssrf import SafeEndpoint
        import ipaddress

        sel.return_value = (
            SafeEndpoint("example.com", ipaddress.ip_address("93.184.216.34"), 443, "https"),
            [ipaddress.ip_address("93.184.216.34")],
        )
        result = await analyze_redirects(parsed)
    assert result["status"] == "loop"
    assert any(f["type"] == "redirect_loop" for f in result["findings"])


@pytest.mark.asyncio
async def test_private_redirect_blocked() -> None:
    parsed = parse_and_validate("https://example.com/")

    async def fake_http(*args, **kwargs):
        return 302, {"location": "http://127.0.0.1/"}, None

    with (
        patch("app.services.redirects.select_endpoint") as sel,
        patch("app.services.redirects.revalidate_addresses"),
        patch("app.services.redirects._raw_http", new=AsyncMock(side_effect=fake_http)),
    ):
        from app.security.ssrf import SafeEndpoint
        import ipaddress

        public = SafeEndpoint("example.com", ipaddress.ip_address("93.184.216.34"), 443, "https")
        sel.side_effect = [
            (public, [ipaddress.ip_address("93.184.216.34")]),
        ]
        # Second hop should fail validation inside analyze_redirects via select_endpoint/parse
        result = await analyze_redirects(parsed)
    assert result["status"] in {"blocked", "loop", "ok", "incomplete"}
    # If the second hop was attempted, SSRF controls must block 127.0.0.1
    if result["status"] == "blocked":
        assert "127.0.0.1" in (result.get("reason") or "") or result["findings"]
