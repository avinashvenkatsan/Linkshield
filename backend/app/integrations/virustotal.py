from __future__ import annotations

import base64

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.integrations.base import ProviderResult

logger = get_logger(__name__)

VT_URL = "https://www.virustotal.com/api/v3/urls/"

LIMITATIONS = (
    "VirusTotal aggregates scanner opinions. Engines disagree, can be stale, and may not have seen a URL. "
    "A zero-malicious count is not a clean bill of health. VirusTotal's terms restrict redistribution of "
    "raw engine data and impose rate limits; LinkShield stores only summary counts, not full engine reports."
)


def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


class VirusTotalProvider:
    name = "virustotal"

    async def check_url(self, url: str, authorized: bool) -> ProviderResult:
        settings = get_settings()
        if not settings.virustotal_configured:
            return ProviderResult(
                provider=self.name,
                status="not_configured",
                summary="VirusTotal is not configured on this server.",
                explanation="Set VIRUSTOTAL_API_KEY to enable reputation lookups. Local heuristics still run.",
                limitations=LIMITATIONS,
            )
        if not authorized or not settings.external_intel_enabled:
            return ProviderResult(
                provider=self.name,
                status="incomplete",
                summary="VirusTotal was skipped because third-party lookups were not authorized.",
                explanation="The URL was not sent to VirusTotal. Enable external intelligence on the scan form to include this check.",
                limitations=LIMITATIONS,
            )

        timeout = httpx.Timeout(settings.outbound_timeout_seconds, connect=settings.outbound_connect_timeout_seconds)
        headers = {"x-apikey": settings.virustotal_api_key, "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(VT_URL + url_id(url), headers=headers)
        except httpx.TimeoutException:
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary="VirusTotal timed out.",
                explanation="The lookup did not complete in time. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error="timeout",
            )
        except httpx.HTTPError:
            logger.warning("vt_http_error")
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary="VirusTotal could not be reached.",
                explanation="A network error prevented the lookup. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error="http_error",
            )

        if response.status_code == 429:
            return ProviderResult(
                provider=self.name,
                status="rate_limited",
                summary="VirusTotal rate-limited this request.",
                explanation="Free API tiers are strictly limited. This is not a clean result.",
                limitations=LIMITATIONS,
                error="429",
            )
        if response.status_code == 404:
            return ProviderResult(
                provider=self.name,
                status="no_threat_detected",
                summary="VirusTotal has no report for this URL.",
                explanation=(
                    "No existing analysis was found. LinkShield does not submit new URL scans to VirusTotal "
                    "in this version, so unknown URLs stay unclassified rather than being uploaded."
                ),
                limitations=LIMITATIONS,
                stats={"not_found": True},
            )
        if response.status_code >= 400:
            return ProviderResult(
                provider=self.name,
                status="check_unavailable",
                summary=f"VirusTotal returned HTTP {response.status_code}.",
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
                summary="VirusTotal returned a non-JSON body.",
                explanation="The response could not be parsed. This is not treated as a clean result.",
                limitations=LIMITATIONS,
                error="invalid_json",
            )

        attributes = ((body.get("data") or {}).get("attributes")) or {}
        stats = attributes.get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious") or 0)
        suspicious = int(stats.get("suspicious") or 0)
        harmless = int(stats.get("harmless") or 0)
        undetected = int(stats.get("undetected") or 0)
        summary_stats = {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "timeout": int(stats.get("timeout") or 0),
        }

        if malicious > 0:
            status = "threat_detected"
            summary = f"VirusTotal engines labelled this URL malicious ({malicious} detections)."
            explanation = (
                f"{malicious} engine(s) reported malicious and {suspicious} reported suspicious. "
                "Engine opinions are not ground truth, but a non-zero malicious count is treated as a confirmed threat match for scoring."
            )
        elif suspicious > 0:
            status = "no_threat_detected"
            summary = f"VirusTotal reported {suspicious} suspicious engine(s) and 0 malicious."
            explanation = (
                "Suspicious-only results are shown as intel context and feed heuristics, not as a confirmed malware/phishing match."
            )
        else:
            status = "no_threat_detected"
            summary = "VirusTotal returned a report with no malicious engine detections."
            explanation = (
                f"{harmless} harmless / {undetected} undetected. Absence of detections does not prove the URL is safe."
            )

        return ProviderResult(
            provider=self.name,
            status=status,
            threat_categories=["malicious"] if malicious else (["suspicious"] if suspicious else []),
            summary=summary,
            explanation=explanation,
            limitations=LIMITATIONS,
            stats=summary_stats,
        )
