from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import dns.exception
import dns.resolver
import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.security.ssrf import UnsafeTargetError, is_blocked_ip, parse_ip, resolve_public_addresses
from app.services.url_parser import ParsedUrl

logger = get_logger(__name__)


def _records(name: str, rdtype: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, rdtype, lifetime=3.0)
        return sorted({rdata.to_text().rstrip(".") for rdata in answers})
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except dns.exception.DNSException:
        return []


async def inspect_dns(parsed: ParsedUrl) -> dict[str, Any]:
    hostname = parsed.hostname
    result: dict[str, Any] = {
        "hostname": hostname,
        "status": "ok",
        "a": [],
        "aaaa": [],
        "mx": [],
        "ns": [],
        "txt_count": 0,
        "error": None,
        "findings": [],
        "registration": None,
    }

    if parsed.hostname_is_ip:
        ip = parse_ip(hostname)
        result["a"] = [hostname] if ip and ip.version == 4 else []
        result["aaaa"] = [hostname] if ip and ip.version == 6 else []
        result["status"] = "ip_literal"
        return result

    def _query() -> dict[str, Any]:
        a = _records(hostname, "A")
        aaaa = _records(hostname, "AAAA")
        mx = _records(parsed.registrable_domain, "MX")
        ns = _records(parsed.registrable_domain, "NS")
        txt = _records(parsed.registrable_domain, "TXT")
        return {"a": a, "aaaa": aaaa, "mx": mx, "ns": ns, "txt_count": len(txt)}

    try:
        data = await asyncio.to_thread(_query)
        result.update(data)
        if not data["a"] and not data["aaaa"]:
            result["status"] = "no_address_records"
            result["findings"].append(
                {
                    "type": "dns_failed",
                    "title": "No public A/AAAA records",
                    "severity": "medium",
                    "status": "detected",
                    "evidence": f"No A or AAAA records were returned for {hostname}.",
                    "explanation": "The hostname did not resolve in public DNS during this scan. It may be down, newly registered, or only visible internally.",
                    "why_it_matters": "A name that does not resolve cannot be a normal public website at this moment.",
                    "suggested_action": "Treat the link as incomplete until the domain resolves through a trusted resolver.",
                    "source": "dns",
                    "score_contribution": 8,
                }
            )
        else:
            for addr in data["a"] + data["aaaa"]:
                ip = parse_ip(addr)
                if ip and is_blocked_ip(ip):
                    result["status"] = "blocked_resolution"
                    result["findings"].append(
                        {
                            "type": "dns_private",
                            "title": "Hostname resolved to a non-public address",
                            "severity": "high",
                            "status": "detected",
                            "evidence": f"{hostname} resolved to {addr}, which is not a public unicast address.",
                            "explanation": "LinkShield blocks outbound connections to loopback, private, link-local, and metadata ranges.",
                            "why_it_matters": "Links that resolve internally can be used for SSRF or to trick scanners.",
                            "suggested_action": "Do not open the link. It does not point at a public website.",
                            "source": "dns",
                            "score_contribution": 20,
                        }
                    )
                    break
            try:
                resolve_public_addresses(hostname)
            except UnsafeTargetError:
                pass
    except Exception as exc:  # noqa: BLE001
        result["status"] = "incomplete"
        result["error"] = type(exc).__name__
        result["findings"].append(
            {
                "type": "dns_failed",
                "title": "DNS lookup incomplete",
                "severity": "info",
                "status": "incomplete",
                "evidence": "The DNS query raised an error and was not retried against other resolvers.",
                "explanation": "Missing DNS data is treated as incomplete, not as a clean result.",
                "why_it_matters": "Without DNS, LinkShield cannot validate where the name points.",
                "suggested_action": "Retry later or inspect the domain in a trusted DNS tool.",
                "source": "dns",
                "score_contribution": 0,
            }
        )

    if get_settings().rdap_enabled and not parsed.hostname_is_ip:
        result["registration"] = await lookup_rdap(parsed.registrable_domain)
        reg = result["registration"]
        if reg and reg.get("age_days") is not None and reg["age_days"] < 30:
            result["findings"].append(
                {
                    "type": "young_domain",
                    "title": "Recently created domain",
                    "severity": "medium",
                    "status": "detected",
                    "evidence": f"RDAP reports a registration start of {reg.get('created')} ({reg['age_days']} days ago).",
                    "explanation": "Newly registered domains are commonly used in short-lived phishing campaigns. New domains are also legitimate.",
                    "why_it_matters": "There is little public history to corroborate the operator.",
                    "suggested_action": "Be extra cautious with unexpected messages that use a brand-new domain.",
                    "source": "rdap",
                    "score_contribution": 14,
                }
            )
    return result


async def lookup_rdap(domain: str) -> dict[str, Any] | None:
    settings = get_settings()
    url = settings.rdap_base_url.rstrip("/") + "/" + domain
    timeout = httpx.Timeout(settings.outbound_timeout_seconds, connect=settings.outbound_connect_timeout_seconds)
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(url, headers={"Accept": "application/rdap+json, application/json"})
    except httpx.HTTPError:
        return {"status": "unavailable", "created": None, "age_days": None, "error": "rdap_unreachable"}
    if response.status_code == 404:
        return {"status": "not_found", "created": None, "age_days": None}
    if response.status_code >= 400:
        return {"status": "unavailable", "created": None, "age_days": None, "error": f"http_{response.status_code}"}
    try:
        body = response.json()
    except ValueError:
        return {"status": "unavailable", "created": None, "age_days": None, "error": "invalid_json"}

    created = None
    for event in body.get("events") or []:
        if event.get("eventAction") in {"registration", "registered"}:
            created = event.get("eventDate")
            break
    age_days = None
    if created:
        try:
            parsed_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            age_days = max(0, (datetime.now(timezone.utc) - parsed_dt).days)
        except ValueError:
            created = created
    return {
        "status": "ok",
        "created": created,
        "age_days": age_days,
        "rdap_source": "rdap.org",
    }
