from app.services.heuristics import analyze_url_patterns
from app.services.url_parser import parse_and_validate


def _types(url: str) -> set[str]:
    return {f["type"] for f in analyze_url_patterns(parse_and_validate(url))}


def test_ip_hostname() -> None:
    assert "ip_hostname" in _types("https://8.8.8.8/")


def test_excessive_subdomains() -> None:
    assert "excessive_subdomains" in _types("https://a.b.c.d.example.com/")


def test_shortener() -> None:
    assert "url_shortener" in _types("https://bit.ly/abc")


def test_lookalike_paypal() -> None:
    types = _types("https://paypal.com.secure-login.example.net/invoice")
    assert "lookalike_brand" in types


def test_unusual_port() -> None:
    assert "unusual_port" in _types("https://example.com:8443/")


def test_nested_url_param() -> None:
    types = _types("https://example.com/out?next=https://evil.example/phish")
    assert "redirect_parameter" in types
