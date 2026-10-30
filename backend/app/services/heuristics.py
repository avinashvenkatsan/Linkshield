from __future__ import annotations

import re
import unicodedata
from typing import Any

from app.core.config import get_settings
from app.services.url_parser import SUSPICIOUS_TLDS, URL_SHORTENERS, ParsedUrl, encoding_depth

KNOWN_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com", "google.co.uk"],
    "gmail": ["gmail.com", "google.com"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com"],
    "wellsfargo": ["wellsfargo.com"],
    "chase": ["chase.com"],
    "github": ["github.com"],
    "linkedin": ["linkedin.com"],
}

HOMOGLYPHS = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "5": "s",
        "7": "t",
        "@": "a",
    }
)


def _finding(
    finding_type: str,
    title: str,
    severity: str,
    status: str,
    evidence: str,
    explanation: str,
    why_it_matters: str,
    action: str,
    source: str,
    score_contribution: int,
    *,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "type": finding_type,
        "title": title,
        "severity": severity,
        "status": status,
        "evidence": evidence,
        "explanation": explanation,
        "why_it_matters": why_it_matters,
        "suggested_action": action,
        "source": source,
        "score_contribution": score_contribution,
    }
    if extra:
        payload["extra"] = extra
    return payload


def _normalized_labels(hostname: str) -> str:
    folded = unicodedata.normalize("NFKC", hostname).lower()
    return folded.translate(HOMOGLYPHS).replace("-", "")


def analyze_url_patterns(parsed: ParsedUrl) -> list[dict[str, Any]]:
    settings = get_settings()
    findings: list[dict[str, Any]] = []

    if parsed.userinfo_present:
        findings.append(
            _finding(
                "embedded_credentials",
                "Embedded credentials in the URL",
                "high",
                "detected",
                "The URL contains a username, password, or '@' userinfo component.",
                "Attackers sometimes hide the real destination after an '@' or include stolen credentials in a link.",
                "Browsers may send those credentials to a different host than the one a person expects to see.",
                "Do not open the link. Treat any exposed password as compromised.",
                "local_heuristics",
                28,
            )
        )

    if parsed.hostname_is_ip:
        findings.append(
            _finding(
                "ip_hostname",
                "IP-address hostname",
                "medium",
                "detected",
                f"The host is an IP address (IPv{parsed.ip_version}) rather than a domain name.",
                "Legitimate consumer sites almost always use a domain name. Raw IPs are more common in phishing kits and malware droppers, but they are also used for some internal tools.",
                "Without a domain name it is harder to verify who operates the site.",
                "Confirm the address through an independent channel before considering a visit.",
                "local_heuristics",
                20,
            )
        )

    subdomain_count = len([p for p in parsed.subdomain.split(".") if p])
    if subdomain_count >= 3:
        findings.append(
            _finding(
                "excessive_subdomains",
                "Unusual number of subdomains",
                "medium",
                "detected",
                f"The hostname uses {subdomain_count} subdomain labels: {parsed.hostname}.",
                "Deep subdomain chains can make a URL look as if it belongs to a well-known brand while the registrable domain is different.",
                "People often read the leftmost labels and miss the actual registered domain.",
                f"Verify that {parsed.registrable_domain} is the organization you expect.",
                "local_heuristics",
                12,
            )
        )

    if parsed.port not in settings.allowed_ports:
        findings.append(
            _finding(
                "unusual_port",
                "Non-standard port",
                "medium",
                "detected",
                f"The URL specifies port {parsed.port} instead of 80 or 443.",
                "Unusual ports can point to non-web services or locally bound admin panels. They are not automatically malicious.",
                "Browsers still fetch the resource, but the service may not be a normal website.",
                "Treat this as a warning and avoid opening the link unless you trust the operator.",
                "local_heuristics",
                10,
            )
        )

    if parsed.suffix.lower() in SUSPICIOUS_TLDS:
        findings.append(
            _finding(
                "uncommon_tld",
                "Uncommon or frequently abused TLD",
                "low",
                "detected",
                f"The domain uses the .{parsed.suffix} public suffix.",
                "Some top-level domains appear more often in opportunistic phishing. This is a weak signal on its own.",
                "Registration is cheap and fast on several of these suffixes, which can attract throwaway campaigns.",
                "Combine this with other findings; do not treat the TLD as proof of malice.",
                "local_heuristics",
                6,
            )
        )

    registrable = parsed.registrable_domain.lower()
    if registrable in URL_SHORTENERS or parsed.hostname.lower() in URL_SHORTENERS:
        findings.append(
            _finding(
                "url_shortener",
                "Known URL shortener",
                "medium",
                "detected",
                f"{parsed.hostname} matches a commonly used URL-shortening service.",
                "Shorteners hide the final destination until they are resolved. LinkShield only follows redirects when it can do so with SSRF safeguards.",
                "A shortened link prevents you from inspecting the destination by reading the URL.",
                "Prefer the expanded destination from a trusted preview, or ask the sender for the original URL.",
                "local_heuristics",
                14,
            )
        )

    # Lookalike / brand mismatch
    haystack = _normalized_labels(parsed.hostname)
    for brand, official in KNOWN_BRANDS.items():
        official_set = {d.lower() for d in official}
        if parsed.registrable_domain.lower() in official_set:
            continue
        if brand in haystack or brand in parsed.hostname.replace("-", "").lower():
            findings.append(
                _finding(
                    "lookalike_brand",
                    "Possible brand lookalike",
                    "high",
                    "detected",
                    f"The hostname '{parsed.hostname}' contains '{brand}' but the registrable domain is '{parsed.registrable_domain}', which is not in the known official set ({', '.join(official)}).",
                    "This is a heuristic comparison against a small built-in brand list. It can produce false positives for fan sites, regional affiliates, or unrelated words.",
                    "Phishing pages often place a brand name in a subdomain or a lookalike domain.",
                    "Confirm the domain through a bookmark or vendor documentation, not by clicking the link.",
                    "local_heuristics",
                    26,
                    extra={"brand": brand, "official_domains": official},
                )
            )
            break

    if parsed.hostname.startswith("xn--") or ".xn--" in parsed.hostname:
        findings.append(
            _finding(
                "punycode",
                "Internationalized (punycode) hostname",
                "medium",
                "detected",
                f"The hostname is encoded as punycode: {parsed.hostname}.",
                "IDN is legitimate for many languages. It is also used in homograph attacks that visually imitate another brand.",
                "Characters from different scripts can look identical in the address bar.",
                "Inspect the decoded domain carefully and compare it with a known-good destination.",
                "local_heuristics",
                16,
            )
        )

    path_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
    depth = encoding_depth(path_query)
    if depth >= 2:
        findings.append(
            _finding(
                "nested_encoding",
                "Nested URL encoding",
                "medium",
                "detected",
                f"Path or query values appear to be percent-encoded {depth} times.",
                "Repeated encoding can hide a second URL or evade naive filters. It also appears in some legitimate frameworks.",
                "Hidden nested destinations are a common open-redirect and phishing trick.",
                "Do not trust a destination that is only visible after decoding the query string.",
                "local_heuristics",
                12,
            )
        )

    if parsed.query:
        keys = [k.lower() for k, _ in parsed.query_params]
        suspicious_keys = {"url", "redirect", "next", "return", "dest", "destination", "continue", "r", "u"}
        hit = [k for k in keys if k in suspicious_keys]
        values = [v for _, v in parsed.query_params]
        nested_url = any(re.match(r"https?://", v, re.I) or v.lower().startswith("http%") for v in values)
        if hit and nested_url:
            findings.append(
                _finding(
                    "redirect_parameter",
                    "Embedded redirect parameter",
                    "medium",
                    "detected",
                    f"Query parameter(s) {hit} appear to contain another URL.",
                    "Open redirects can send a visitor from a trusted-looking domain to an unrelated site. This check does not fetch the nested URL.",
                    "The first hostname in the address bar may not be the final destination.",
                    "Inspect the nested destination separately rather than following this link.",
                    "local_heuristics",
                    14,
                )
            )

    hyphen_ratio = parsed.hostname.count("-")
    if hyphen_ratio >= 4:
        findings.append(
            _finding(
                "hyphenated_host",
                "Heavily hyphenated hostname",
                "low",
                "detected",
                f"The hostname contains {hyphen_ratio} hyphens.",
                "Long hyphenated names are sometimes used in lookalike domains. This is a weak signal.",
                "Extra words can make a domain resemble a support notice or invoice.",
                f"Read the registrable domain ({parsed.registrable_domain}) rather than the full phrase.",
                "local_heuristics",
                5,
            )
        )

    if len(parsed.path) > 120:
        findings.append(
            _finding(
                "long_path",
                "Unusually long path",
                "low",
                "detected",
                f"The URL path is {len(parsed.path)} characters long.",
                "Long paths can hide encoded payloads or tracking blobs. They are also used by some CDNs and document-sharing tools.",
                "A long opaque path makes visual inspection harder.",
                "Prefer sharing or opening a known homepage instead of this deep link if you were not expecting it.",
                "local_heuristics",
                4,
            )
        )

    return findings
