from __future__ import annotations

import asyncio
import hashlib
import uuid
from typing import Any

from app.core.config import get_settings
from app.core.logging import extra_safe, get_logger
from app.integrations.google_safe_browsing import GoogleSafeBrowsingProvider
from app.integrations.virustotal import VirusTotalProvider
from app.services.dns_inspect import inspect_dns
from app.services.heuristics import analyze_url_patterns
from app.services.redirects import analyze_redirects
from app.services.scoring import compute_risk
from app.services.store import get_store, ttl_for, utcnow
from app.services.tls_inspect import inspect_tls
from app.services.url_parser import ParsedUrl, parse_and_validate

logger = get_logger(__name__)

PROVIDERS = [GoogleSafeBrowsingProvider(), VirusTotalProvider()]


def _url_hash(normalized: str) -> str:
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _assessment_text(risk: dict[str, Any], findings: list[dict[str, Any]], incomplete: list[str]) -> str:
    classification = risk["classification"]
    if classification == "high":
        if risk.get("confirmed_threat_providers"):
            return (
                "A threat-intelligence provider reported a match, or several strong indicators were present. "
                "Do not open this link."
            )
        return "Strong suspicious signals were detected. Do not open this link until you can verify it independently."
    if classification == "medium":
        return (
            "One or more suspicious indicators require attention. A medium result is not a confirmed compromise, "
            "and it is also not a clean bill of health."
        )
    if classification == "unknown":
        return (
            "Important checks did not complete, so LinkShield cannot classify this URL with the available evidence. "
            "Missing data is never treated as safety."
        )
    if not findings:
        return (
            "The checks that ran did not surface significant indicators. That is not a guarantee of safety. "
            "New phishing sites often have no history and no list matches."
        )
    return (
        "Only weak or informational signals were found. Treat unexpected links with caution even when the score is low."
    )


def _recommendations(risk: dict[str, Any], parsed: ParsedUrl) -> list[str]:
    recs = [
        "Do not click the scanned destination from this report. LinkShield never opens the site for you.",
        f"Read the registrable domain '{parsed.registrable_domain}' and confirm it through a bookmark or vendor site you already trust.",
        "If this arrived by email or chat, contact the purported sender through a known-good channel — not by replying to the message.",
    ]
    if risk["classification"] in {"high", "medium"}:
        recs.insert(0, "Assume the link is unsafe until an independent source confirms otherwise.")
    if risk["classification"] == "unknown":
        recs.insert(0, "Treat the result as inconclusive. Missing checks are not the same as a clean scan.")
    recs.append("A lock icon or HTTPS certificate is not evidence that a site is legitimate.")
    return recs


async def run_scan(
    url: str,
    *,
    client_id: str,
    save_history: bool,
    allow_external_intel: bool,
) -> dict[str, Any]:
    parsed = parse_and_validate(url)
    scan_id = str(uuid.uuid4())
    created = utcnow()
    expires = created + ttl_for(save_history)
    settings = get_settings()

    logger.info("scan_started", extra=extra_safe(scan_id=scan_id, host=parsed.hostname))

    heuristic_findings = analyze_url_patterns(parsed)
    dns_result, tls_result, redirect_result = await asyncio.gather(
        inspect_dns(parsed),
        inspect_tls(parsed),
        analyze_redirects(parsed),
    )

    provider_results = list(
        await asyncio.gather(
            *[provider.check_url(parsed.normalized, allow_external_intel) for provider in PROVIDERS]
        )
    )
    providers = [p.to_dict() for p in provider_results]

    findings: list[dict[str, Any]] = []
    findings.extend(heuristic_findings)
    findings.extend(dns_result.get("findings") or [])
    findings.extend(tls_result.get("findings") or [])
    findings.extend(redirect_result.get("findings") or [])

    incomplete: list[str] = []
    if dns_result.get("status") in {"incomplete"}:
        incomplete.append("dns")
    if tls_result.get("status") in {"incomplete", "error"}:
        incomplete.append("tls")
    if redirect_result.get("status") in {"incomplete"}:
        incomplete.append("redirects")
    intel_wanted = allow_external_intel and settings.external_intel_enabled
    if intel_wanted:
        usable = [p for p in providers if p["status"] in {"threat_detected", "no_threat_detected"}]
        failed = [p for p in providers if p["status"] in {"check_unavailable", "rate_limited", "incomplete"}]
        configured = [p for p in providers if p["status"] != "not_configured"]
        if configured and not usable and failed:
            incomplete.append("threat_intel")

    risk = compute_risk(findings, providers, incomplete)
    completed = utcnow()
    report_findings = [f for f in findings if f.get("status") != "info" or f.get("type") == "https_present"]

    record: dict[str, Any] = {
        "id": scan_id,
        "client_id": client_id,
        "status": "completed",
        "save_history": save_history,
        "allow_external_intel": allow_external_intel,
        "submitted_url": parsed.original,
        "normalized_url": parsed.normalized,
        "display_url": parsed.display_url,
        "hostname": parsed.hostname,
        "registrable_domain": parsed.registrable_domain,
        "url_hash": _url_hash(parsed.normalized),
        "created_at": created.isoformat(),
        "completed_at": completed.isoformat(),
        "expires_at": expires.isoformat(),
        "risk_score": risk["score"],
        "risk_classification": risk["classification"],
        "risk": risk,
        "assessment": _assessment_text(risk, report_findings, incomplete),
        "recommendations": _recommendations(risk, parsed),
        "findings": report_findings,
        "finding_count": len([f for f in report_findings if f.get("severity") in {"high", "medium", "low"}]),
        "providers": providers,
        "dns": {k: v for k, v in dns_result.items() if k != "findings"},
        "tls": {k: v for k, v in tls_result.items() if k != "findings"},
        "redirects": {k: v for k, v in redirect_result.items() if k != "findings"},
        "incomplete_checks": incomplete,
        "local_only": not (allow_external_intel and (settings.gsb_configured or settings.virustotal_configured)),
        "limitations": [
            "LinkShield does not execute JavaScript, download files, or render the destination.",
            "A low or empty finding list is not a guarantee that the URL is safe.",
            "Threat-intelligence coverage is incomplete and may be delayed or unavailable.",
            "Redirect and TLS inspection are skipped when SSRF controls cannot guarantee a safe connection.",
        ],
    }
    get_store().save(record)
    return record
