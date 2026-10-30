from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Iterable, Sequence
from urllib.parse import urlparse

BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("192.88.99.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("255.255.255.255/32"),
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("::ffff:0:0/96"),
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("2001:db8::/32"),
]

METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "kubernetes.default.svc",
}


class UnsafeTargetError(ValueError):
    """Raised when a destination is not safe to contact."""


def _normalize_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return mapped
        # Handle :ffff:x.x.x.x already covered; teredo etc. treated as IPv6
    return ip


def is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    ip = _normalize_ip(ip)
    if any(
        [
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_multicast,
            ip.is_reserved,
            ip.is_unspecified,
        ]
    ):
        return True
    if isinstance(ip, ipaddress.IPv6Address) and getattr(ip, "is_site_local", False):
        return True
    return any(ip in network for network in BLOCKED_NETWORKS)


def parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def assert_hostname_allowed(hostname: str) -> None:
    lowered = hostname.lower().rstrip(".")
    if lowered in METADATA_HOSTNAMES or lowered.endswith(".internal"):
        raise UnsafeTargetError("Hostname points to a metadata or internal service")
    literal = parse_ip(lowered)
    if literal is not None and is_blocked_ip(literal):
        raise UnsafeTargetError("Literal IP address is not publicly routable")


def resolve_public_addresses(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve A/AAAA records and reject any non-public result set."""
    assert_hostname_allowed(hostname)
    literal = parse_ip(hostname)
    if literal is not None:
        if is_blocked_ip(literal):
            raise UnsafeTargetError("Literal IP address is not publicly routable")
        return [literal]

    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"DNS resolution failed: {exc}") from exc

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for info in infos:
        sockaddr = info[4]
        ip_str = sockaddr[0]
        if ip_str in seen:
            continue
        seen.add(ip_str)
        ip_obj = ipaddress.ip_address(ip_str)
        if is_blocked_ip(ip_obj):
            raise UnsafeTargetError("Resolved address is not publicly routable")
        addresses.append(ip_obj)
    if not addresses:
        raise UnsafeTargetError("No usable public addresses resolved")
    return addresses


def revalidate_addresses(
    hostname: str,
    previous: Sequence[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    current = resolve_public_addresses(hostname)
    prev_set = {str(_normalize_ip(ip)) for ip in previous}
    cur_set = {str(_normalize_ip(ip)) for ip in current}
    if not prev_set.intersection(cur_set):
        raise UnsafeTargetError("DNS answers changed before connect (possible rebinding)")
    return current


@dataclass(frozen=True)
class SafeEndpoint:
    hostname: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    port: int
    scheme: str


def select_endpoint(hostname: str, port: int, scheme: str) -> tuple[SafeEndpoint, list[ipaddress.IPv4Address | ipaddress.IPv6Address]]:
    addresses = resolve_public_addresses(hostname)
    # Prefer IPv4 for simpler pinning; fall back to IPv6.
    chosen = next((a for a in addresses if isinstance(a, ipaddress.IPv4Address)), addresses[0])
    return SafeEndpoint(hostname=hostname, ip=chosen, port=port, scheme=scheme), addresses


def host_from_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.hostname:
        raise UnsafeTargetError("URL has no hostname")
    return parsed.hostname


def any_blocked(addresses: Iterable[str]) -> bool:
    return any(is_blocked_ip(ipaddress.ip_address(addr)) for addr in addresses)
