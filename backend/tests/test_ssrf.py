import ipaddress

import pytest

from app.security.ssrf import (
    UnsafeTargetError,
    assert_hostname_allowed,
    is_blocked_ip,
    revalidate_addresses,
    resolve_public_addresses,
)


@pytest.mark.parametrize(
    "value",
    [
        "127.0.0.1",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.0.4",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fc00::1",
        "fe80::1",
        "224.0.0.1",
        "255.255.255.255",
        "100.64.0.1",
    ],
)
def test_blocked_ranges(value: str) -> None:
    assert is_blocked_ip(ipaddress.ip_address(value))


def test_public_ip_allowed() -> None:
    assert not is_blocked_ip(ipaddress.ip_address("1.1.1.1"))


def test_metadata_hostname_blocked() -> None:
    with pytest.raises(UnsafeTargetError):
        assert_hostname_allowed("metadata.google.internal")


def test_loopback_literal_blocked() -> None:
    with pytest.raises(UnsafeTargetError):
        resolve_public_addresses("127.0.0.1")


def test_private_literal_blocked() -> None:
    with pytest.raises(UnsafeTargetError):
        resolve_public_addresses("10.1.2.3")


def test_ipv4_mapped_loopback_blocked() -> None:
    assert is_blocked_ip(ipaddress.ip_address("::ffff:127.0.0.1"))


def test_dns_rebinding_detected() -> None:
    previous = [ipaddress.ip_address("1.1.1.1")]
    with pytest.raises(UnsafeTargetError):
        revalidate_addresses("8.8.8.8", previous)
