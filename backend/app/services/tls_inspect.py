from __future__ import annotations

import asyncio
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID

from app.core.config import get_settings
from app.security.ssrf import UnsafeTargetError, revalidate_addresses, select_endpoint
from app.services.url_parser import ParsedUrl


def _names_from_cert(cert: x509.Certificate) -> list[str]:
    names: list[str] = []
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    names.extend(attr.value for attr in cn)
    return names


def _hostname_matches(hostname: str, patterns: list[str]) -> bool:
    host = hostname.lower().rstrip(".")
    for pattern in patterns:
        p = pattern.lower().rstrip(".")
        if p.startswith("*.") and host.count(".") == p.count("."):
            if host.split(".", 1)[-1] == p[2:]:
                return True
        elif host == p:
            return True
    return False


async def inspect_tls(parsed: ParsedUrl) -> dict[str, Any]:
    settings = get_settings()
    result: dict[str, Any] = {
        "status": "skipped",
        "reason": None,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "san": [],
        "hostname_match": None,
        "findings": [],
    }
    if parsed.scheme != "https":
        result["reason"] = "URL is not HTTPS. TLS was not inspected. HTTPS alone would not prove trustworthiness."
        return result
    if parsed.port not in settings.allowed_ports:
        result["status"] = "skipped"
        result["reason"] = "TLS inspection only runs against ports 80/443 to reduce SSRF risk."
        return result

    try:
        endpoint, addresses = select_endpoint(parsed.hostname, parsed.port or 443, "https")
        revalidate_addresses(parsed.hostname, addresses)
    except UnsafeTargetError as exc:
        result["status"] = "blocked"
        result["reason"] = str(exc)
        return result

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                str(endpoint.ip),
                endpoint.port,
                ssl=ctx,
                server_hostname=parsed.hostname,
            ),
            timeout=settings.outbound_connect_timeout_seconds,
        )
    except ssl.SSLCertVerificationError as exc:
        result["status"] = "error"
        result["reason"] = "Certificate could not be verified against default CA trust."
        result["findings"].append(
            {
                "type": "certificate_untrusted",
                "title": "Certificate not trusted by default CAs",
                "severity": "medium",
                "status": "detected",
                "evidence": str(exc),
                "explanation": "The TLS certificate did not chain to a public CA in this environment. Misconfiguration and interception both produce this error.",
                "why_it_matters": "An untrusted certificate means the scanner could not authenticate the service.",
                "suggested_action": "Do not treat the site as authenticated. Avoid opening the link.",
                "source": "tls",
                "score_contribution": 16,
            }
        )
        return result
    except Exception as exc:  # noqa: BLE001
        result["status"] = "incomplete"
        result["reason"] = f"TLS handshake failed ({type(exc).__name__})."
        return result

    try:
        sslobj = writer.get_extra_info("ssl_object")
        der = sslobj.getpeercert(binary_form=True) if sslobj else None
        if not der:
            result["status"] = "incomplete"
            result["reason"] = "Peer certificate was not available after handshake."
            return result
        cert = x509.load_der_x509_certificate(der, default_backend())
        san = _names_from_cert(cert)
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        match = _hostname_matches(parsed.hostname, san)
        result.update(
            {
                "status": "ok",
                "issuer": issuer,
                "subject": subject,
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "san": san[:20],
                "hostname_match": match,
            }
        )
        if not match:
            result["findings"].append(
                {
                    "type": "certificate_hostname_mismatch",
                    "title": "Certificate hostname mismatch",
                    "severity": "high",
                    "status": "detected",
                    "evidence": f"Certificate SAN/CN {san[:8]} does not match {parsed.hostname}.",
                    "explanation": "The certificate presented by the pinned IP is not valid for the URL hostname.",
                    "why_it_matters": "Name mismatch is a classic sign of a misconfigured host, interception, or shared hosting abuse.",
                    "suggested_action": "Do not open the link. The TLS identity does not match the URL.",
                    "source": "tls",
                    "score_contribution": 24,
                }
            )
        if now > not_after:
            result["findings"].append(
                {
                    "type": "certificate_expired",
                    "title": "Expired TLS certificate",
                    "severity": "medium",
                    "status": "detected",
                    "evidence": f"Certificate expired at {not_after.isoformat()}.",
                    "explanation": "Expired certificates break authentication. They can be accidental or indicate an abandoned host.",
                    "why_it_matters": "Browsers will warn or block; attackers also reuse expired names.",
                    "suggested_action": "Do not ignore certificate warnings in the browser.",
                    "source": "tls",
                    "score_contribution": 18,
                }
            )
        result["findings"].append(
            {
                "type": "https_present",
                "title": "HTTPS is present",
                "severity": "info",
                "status": "info",
                "evidence": f"A certificate issued by {issuer} was observed.",
                "explanation": "TLS encrypts the path to this host. Encryption does not identify a trustworthy operator. Phishing sites routinely use valid certificates.",
                "why_it_matters": "A padlock is not a safety rating.",
                "suggested_action": "Use the rest of this report, not HTTPS alone, when deciding what to do.",
                "source": "tls",
                "score_contribution": 0,
            }
        )
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass
    return result
