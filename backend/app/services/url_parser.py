from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qsl, unquote, urlparse, urlsplit, urlunsplit

import idna
import tldextract

SUPPORTED_SCHEMES = {"http", "https"}
MAX_URL_LENGTH = 2048
MAX_LABEL_LENGTH = 63
SUSPICIOUS_TLDS = {"zip", "mov", "tk", "gq", "ml", "cf", "ga", "xyz", "top", "click", "country"}
URL_SHORTENERS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "tiny.cc",
    "lnkd.in",
    "db.tt",
    "qr.ae",
    "adf.ly",
    "bit.do",
    "shorturl.at",
    "rb.gy",
}

_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=False)


class UrlValidationError(ValueError):
    def __init__(self, message: str, code: str = "invalid_url") -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ParsedUrl:
    original: str
    normalized: str
    scheme: str
    hostname: str
    registrable_domain: str
    subdomain: str
    suffix: str
    port: Optional[int]
    path: str
    query: str
    fragment_present: bool
    userinfo_present: bool
    hostname_is_ip: bool
    ip_version: Optional[int]
    idna_hostname: str
    display_url: str
    path_only_display: str
    labels: list[str] = field(default_factory=list)
    query_params: list[tuple[str, str]] = field(default_factory=list)


def _extract(host: str) -> tldextract.ExtractResult:
    return _EXTRACTOR(host)


def privacy_display(scheme: str, hostname: str, path: str, has_query: bool) -> str:
    safe_path = path if path else "/"
    if len(safe_path) > 64:
        safe_path = safe_path[:64] + "…"
    suffix = "?[query-redacted]" if has_query else ""
    return f"{scheme}://{hostname}{safe_path}{suffix}"


def normalize_hostname(hostname: str) -> str:
    host = hostname.strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        return host
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return idna.encode(host).decode("ascii")
    except idna.IDNAError as exc:
        raise UrlValidationError(f"Invalid internationalized domain: {exc}", "invalid_idn") from exc


def parse_and_validate(raw: str) -> ParsedUrl:
    if raw is None or not str(raw).strip():
        raise UrlValidationError("Enter an HTTP or HTTPS URL to scan.", "empty")
    url = raw.strip()
    if len(url) > MAX_URL_LENGTH:
        raise UrlValidationError("URL exceeds the maximum supported length of 2048 characters.", "too_long")
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", url):
        raise UrlValidationError("URL contains control characters.", "control_chars")
    if "://" not in url:
        raise UrlValidationError("Include a scheme, for example https://example.com.", "missing_scheme")

    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise UrlValidationError("Only http and https URLs are supported.", "unsupported_scheme")
    if not parsed.netloc:
        raise UrlValidationError("URL is missing a hostname.", "missing_host")

    userinfo_present = bool(parsed.username or parsed.password)
    hostname = parsed.hostname
    if not hostname:
        raise UrlValidationError("URL is missing a hostname.", "missing_host")

    at_in_host_path = "@" in parsed.netloc or (parsed.path or "").count("@") > 0

    idna_hostname = normalize_hostname(hostname)
    extracted = _extract(idna_hostname)
    registrable = ".".join(part for part in [extracted.domain, extracted.suffix] if part)
    labels = [label for label in idna_hostname.split(".") if label]
    if any(len(label) > MAX_LABEL_LENGTH for label in labels):
        raise UrlValidationError("A DNS label exceeds 63 characters.", "label_length")

    hostname_is_ip = False
    ip_version = None
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        hostname_is_ip = True
        ip_version = ip_obj.version
        registrable = str(ip_obj)
    except ValueError:
        if not extracted.domain or not extracted.suffix:
            # Allow hostnames like localhost to be rejected later by SSRF, but public-looking
            # names without a suffix are invalid for scanning.
            if not hostname_is_ip:
                raise UrlValidationError("Hostname is not a valid registered domain or IP address.", "invalid_host")

    default_port = 443 if scheme == "https" else 80
    port = parsed.port or default_port

    path = parsed.path or "/"
    query = parsed.query or ""
    # Drop fragment from normalized form; fragments are never sent to servers.
    normalized = urlunsplit((scheme, parsed.netloc.lower(), path, query, ""))
    # Rebuild netloc with IDNA host and without userinfo
    hostport = idna_hostname
    if parsed.port:
        hostport = f"{idna_hostname}:{parsed.port}"
    if hostname_is_ip and ip_version == 6:
        hostport = f"[{hostname.strip('[]')}]"
        if parsed.port:
            hostport = f"{hostport}:{parsed.port}"
    normalized = urlunsplit((scheme, hostport, path, query, ""))

    display = privacy_display(scheme, idna_hostname if not hostname_is_ip else hostname, path, bool(query))
    path_display = privacy_display(scheme, registrable or idna_hostname, "/", False)

    return ParsedUrl(
        original=url,
        normalized=normalized,
        scheme=scheme,
        hostname=idna_hostname if not hostname_is_ip else hostname.strip("[]"),
        registrable_domain=registrable or idna_hostname,
        subdomain=extracted.subdomain,
        suffix=extracted.suffix,
        port=port,
        path=path,
        query=query,
        fragment_present=bool(parsed.fragment),
        userinfo_present=userinfo_present or "@" in urlsplit(url).netloc,
        hostname_is_ip=hostname_is_ip,
        ip_version=ip_version,
        idna_hostname=idna_hostname,
        display_url=display,
        path_only_display=path_display,
        labels=labels,
        query_params=parse_qsl(query, keep_blank_values=True),
    )


def decode_once(value: str) -> str:
    return unquote(value)


def encoding_depth(value: str, limit: int = 4) -> int:
    current = value
    depth = 0
    for _ in range(limit):
        decoded = unquote(current)
        if decoded == current:
            break
        depth += 1
        current = decoded
    return depth
