from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urljoin, urlparse

from app.core.config import get_settings
from app.security.ssrf import UnsafeTargetError, revalidate_addresses, select_endpoint
from app.services.url_parser import ParsedUrl, UrlValidationError, parse_and_validate


class RedirectAborted(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


async def _raw_http(endpoint_ip: str, port: int, hostname: str, path: str, scheme: str, timeout: float) -> tuple[int | None, dict[str, str], str | None]:
    ssl_flag = scheme == "https"
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(endpoint_ip, port, ssl=ssl_flag, server_hostname=hostname if ssl_flag else None),
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001
        return None, {}, type(exc).__name__

    target = path or "/"
    request = (
        f"GET {target} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "User-Agent: LinkShield/0.1 (+https://localhost; URL safety scanner)\r\n"
        "Accept: text/html,application/xhtml+xml;q=0.1\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    try:
        writer.write(request.encode("ascii", errors="strict"))
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(get_settings().outbound_max_response_bytes), timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        writer.close()
        return None, {}, type(exc).__name__
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass

    try:
        header_blob, _, _body = raw.partition(b"\r\n\r\n")
        lines = header_blob.decode("iso-8859-1", errors="replace").split("\r\n")
        status_line = lines[0]
        parts = status_line.split(" ")
        status = int(parts[1]) if len(parts) > 1 else None
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return status, headers, None
    except Exception as exc:  # noqa: BLE001
        return None, {}, type(exc).__name__


async def analyze_redirects(parsed: ParsedUrl) -> dict[str, Any]:
    settings = get_settings()
    chain: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    current = parsed.normalized
    seen: set[str] = set()
    status = "ok"
    reason = None

    if parsed.port not in settings.allowed_ports:
        return {
            "status": "skipped",
            "reason": "Redirect inspection is limited to ports 80 and 443.",
            "chain": [],
            "findings": [],
        }

    for hop in range(settings.outbound_max_redirects + 1):
        if current in seen:
            findings.append(
                {
                    "type": "redirect_loop",
                    "title": "Redirect loop",
                    "severity": "medium",
                    "status": "detected",
                    "evidence": f"URL {current} was visited more than once in the hop chain.",
                    "explanation": "A loop prevents a stable destination from being identified.",
                    "why_it_matters": "Looping redirects can hide the real landing page or exhaust scanners.",
                    "suggested_action": "Do not follow the link; the destination is not stable.",
                    "source": "redirects",
                    "score_contribution": 16,
                }
            )
            status = "loop"
            break
        seen.add(current)

        try:
            hop_parsed = parse_and_validate(current) if hop else parsed
        except UrlValidationError as exc:
            status = "blocked"
            reason = str(exc)
            break

        try:
            endpoint, addresses = select_endpoint(hop_parsed.hostname, hop_parsed.port or 443, hop_parsed.scheme)
            revalidate_addresses(hop_parsed.hostname, addresses)
        except UnsafeTargetError as exc:
            status = "blocked"
            reason = str(exc)
            chain.append(
                {
                    "url_display": hop_parsed.display_url,
                    "hostname": hop_parsed.hostname,
                    "blocked": True,
                    "reason": str(exc),
                }
            )
            findings.append(
                {
                    "type": "redirect_blocked",
                    "title": "Redirect target blocked by SSRF controls",
                    "severity": "high",
                    "status": "detected",
                    "evidence": str(exc),
                    "explanation": "A hop resolved to a private, loopback, link-local, or otherwise restricted address.",
                    "why_it_matters": "This pattern is used to probe internal services.",
                    "suggested_action": "Do not open the link.",
                    "source": "redirects",
                    "score_contribution": 22,
                }
            )
            break

        http_status, headers, error = await _raw_http(
            str(endpoint.ip),
            endpoint.port,
            hop_parsed.hostname,
            hop_parsed.path + (f"?{hop_parsed.query}" if hop_parsed.query else ""),
            hop_parsed.scheme,
            settings.outbound_timeout_seconds,
        )
        hop_info = {
            "index": hop,
            "url_display": hop_parsed.display_url,
            "hostname": hop_parsed.hostname,
            "ip": str(endpoint.ip),
            "status_code": http_status,
            "error": error,
        }
        chain.append(hop_info)
        if error or http_status is None:
            status = "incomplete"
            reason = error or "No HTTP status received"
            break
        if http_status in {301, 302, 303, 307, 308}:
            location = headers.get("location")
            if not location:
                status = "incomplete"
                reason = "Redirect status without Location header"
                break
            nxt = urljoin(f"{hop_parsed.scheme}://{hop_parsed.hostname}{hop_parsed.path}", location)
            parsed_next = urlparse(nxt)
            if parsed_next.scheme.lower() not in {"http", "https"}:
                status = "blocked"
                reason = "Redirect used an unsupported scheme"
                break
            if hop_parsed.registrable_domain and parsed_next.hostname:
                try:
                    nxt_parsed = parse_and_validate(nxt)
                    if nxt_parsed.registrable_domain.lower() != hop_parsed.registrable_domain.lower():
                        findings.append(
                            {
                                "type": "redirect_domain_change",
                                "title": "Redirect changes registered domain",
                                "severity": "medium",
                                "status": "detected",
                                "evidence": f"{hop_parsed.registrable_domain} → {nxt_parsed.registrable_domain}",
                                "explanation": "The hop moved to a different registrable domain. This is common for CDNs and SSO, and also for phishing kits behind shorteners.",
                                "why_it_matters": "The page you land on may not belong to the host you were shown first.",
                                "suggested_action": "Read the final hostname in this report before making any decision.",
                                "source": "redirects",
                                "score_contribution": 18,
                            }
                        )
                except UrlValidationError:
                    status = "blocked"
                    reason = "Redirect Location failed URL validation"
                    break
            current = nxt
            continue
        break
    else:
        status = "incomplete"
        reason = "Redirect hop limit reached"
        findings.append(
            {
                "type": "redirect_max_hops",
                "title": "Too many redirects",
                "severity": "medium",
                "status": "detected",
                "evidence": f"Stopped after {settings.outbound_max_redirects} hops.",
                "explanation": "LinkShield caps redirect following to reduce abuse and loops.",
                "why_it_matters": "The final destination was not established.",
                "suggested_action": "Treat the destination as unknown.",
                "source": "redirects",
                "score_contribution": 10,
            }
        )

    return {"status": status, "reason": reason, "chain": chain, "findings": findings, "hops": len(chain)}
