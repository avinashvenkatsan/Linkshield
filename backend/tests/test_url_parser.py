import pytest

from app.services.url_parser import UrlValidationError, parse_and_validate


def test_valid_https() -> None:
    parsed = parse_and_validate("https://example.com/path")
    assert parsed.scheme == "https"
    assert parsed.hostname == "example.com"
    assert parsed.registrable_domain == "example.com"


def test_valid_http() -> None:
    parsed = parse_and_validate("http://example.org")
    assert parsed.scheme == "http"


def test_rejects_empty() -> None:
    with pytest.raises(UrlValidationError) as exc:
        parse_and_validate("  ")
    assert exc.value.code == "empty"


def test_rejects_javascript_scheme() -> None:
    with pytest.raises(UrlValidationError) as exc:
        parse_and_validate("javascript:alert(1)")
    assert exc.value.code == "unsupported_scheme"


def test_rejects_ftp() -> None:
    with pytest.raises(UrlValidationError):
        parse_and_validate("ftp://files.example.com/a")


def test_rejects_missing_scheme() -> None:
    with pytest.raises(UrlValidationError) as exc:
        parse_and_validate("example.com")
    assert exc.value.code == "missing_scheme"


def test_idn_punycode() -> None:
    parsed = parse_and_validate("https://münich.example.com/")
    assert "xn--" in parsed.hostname or parsed.hostname.endswith("example.com")


def test_ip_host() -> None:
    parsed = parse_and_validate("https://8.8.8.8/")
    assert parsed.hostname_is_ip
    assert parsed.ip_version == 4


def test_credentials_flagged() -> None:
    parsed = parse_and_validate("https://user:pass@example.com/")
    assert parsed.userinfo_present


def test_query_redacted_in_display() -> None:
    parsed = parse_and_validate("https://example.com/login?token=secret-value")
    assert "secret-value" not in parsed.display_url
    assert "[query-redacted]" in parsed.display_url


def test_double_encoding_depth() -> None:
    from app.services.url_parser import encoding_depth

    assert encoding_depth("%252Fpath") >= 2
