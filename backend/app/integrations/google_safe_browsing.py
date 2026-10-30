from __future__ import annotations

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import ProviderResult

logger = get_logger(__name__)

GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

LIMITATIONS = (
    "Google Safe Browsing reports whether a URL currently matches Google's unsafe lists. "
    "A miss is not a guarantee of safety. Coverage, list freshness, and regional data vary. "
    "Consult Google's Safe Browsing terms and usage limits before production use."
)


class GoogleSafeBrowsingProvider:
    name = "google_safe_browsing"

    async def check_url(self, url: str, authorized: bool) -> ProviderResult:
        settings = get_settings()
        if not settings.gsb_configured:
            return ProviderResult(
                provider=self.name,
                status="not_configured",
                summary="Google Safe Browsing is not configured on this server.",
                explanation="Set GOOGLE_SAFE_BROWSING_API_KEY to enable list lookups. Local heuristics still run.",
                limitations=LIMITATIONS,
            )
        if not authorized or not settings.external_intel_enabled:
            return ProviderResult(
                provider=self.name,
                status="incomplete",
                summary="Safe Browsing was skipped because third-party lookups were not authorized.",
                explanation="The URL was not sent to Google. Enable external intelligence on the scan form to include this check.",
                limitations=LIMITATIONS,
            )

        payload = {
            "client": {"clientId": "linkshield", "clientVersion": settings.app_version},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        timeout = httpx.Timeout(settings.outbound_timeout_seconds, connect=settings.outbound_connect_timeout_seconds)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    GSB_ENDPOINT,
                    params={"key": settings.google_safe_browsing_api_key},
                    json=payload,
                    headers={"Content-Type": "application/json"},
                )
        except httpx.TimeoutException:
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary="Safe Browsing timed out.",
                explanation="The lookup did not complete in time. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error="timeout",
            )
        except httpx.HTTPError as exc:
            logger.warning("gsb_http_error")
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary="Safe Browsing could not be reached.",
                explanation="A network error prevented the lookup. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error=type(exc).__name__,
            )

        if response.status_code == 429:
            return ProviderResult(
                provider=self.name,
                status="rate_limited",
                summary="Safe Browsing rate-limited this request.",
                explanation="The API quota was exceeded. Try again later. This is not a clean result.",
                limitations=LIMITATIONS,
                error="429",
            )
        if response.status_code >= 400:
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary=f"Safe Browsing returned HTTP {response.status_code}.",
                explanation="The provider rejected or failed the lookup. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error=f"http_{response.status_code}",
            )

        try:
            body = response.json()
        except ValueError:
            return ProviderResult(
                provider=self.name,
                status="incomplete",
                summary="Safe Browsing returned a non-JSON body.",
                explanation="The response could not be parsed. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error="invalid_json",
            )

        matches = body.get("matches") or []
        if not matches:
            return ProviderResult(
                provider=self.name,
                status="no_threat_detected",
                summary="No Safe Browsing list match was returned for this URL.",
                explanation="Google's lists did not include this URL at lookup time. That is not proof the site is safe.",
                limitations=LIMITATIONS,
            )

        categories = sorted({m.get("threatType") for m in matches if m.get("threatType")})
        return ProviderResult(
            provider=self.name,
            status="threat_detected",
            threat_categories=categories,
            summary="Safe Browsing reported a threat-list match.",
            explanation=(
                "Google Safe Browsing listed this URL under: "
                + ", ".join(categories)
                + ". Treat the destination as dangerous."
            ),
            limitations=LIMITATIONS,
            stats={"match_count": len(matches)},
        )
