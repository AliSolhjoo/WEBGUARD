import pytest
from apps.assets.domain_validation import normalize_domain, validate_public_addresses, safe_redirect_url, UnsafeTarget

@pytest.mark.parametrize("value,expected", [
    ("Example.COM.", "example.com"),
    ("sub.example.com", "sub.example.com"),
])
def test_normalize_domain(value, expected):
    assert normalize_domain(value) == expected

@pytest.mark.parametrize("value", ["", "https://example.com", "example.com/path", "*.example.com", "localhost", "service.local", "127.0.0.1", "example.com:8443", "user@example.com"])
def test_reject_invalid_or_unsafe_domains(value):
    with pytest.raises(UnsafeTarget):
        normalize_domain(value)

def test_validate_public_ip():
    assert validate_public_addresses(["1.1.1.1"]) == ["1.1.1.1"]

@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.169.254", "::1", "fc00::1", "224.0.0.1"])
def test_private_reserved_and_special_ips_are_blocked(address):
    with pytest.raises(UnsafeTarget):
        validate_public_addresses([address])

def test_mixed_public_private_answers_are_blocked():
    with pytest.raises(UnsafeTarget):
        validate_public_addresses(["1.1.1.1", "10.0.0.1"])

def test_redirect_must_stay_on_verified_https_host():
    assert safe_redirect_url("http://example.com/", "https://example.com/login", "example.com") == "https://example.com/login"
    with pytest.raises(UnsafeTarget):
        safe_redirect_url("https://example.com/", "https://evil.example/", "example.com")
    with pytest.raises(UnsafeTarget):
        safe_redirect_url("https://example.com/", "http://example.com/", "example.com")

def test_rejects_host_with_excessive_address_set():
    addresses = [f"1.1.1.{n}" for n in range(1, 10)]
    with pytest.raises(UnsafeTarget):
        validate_public_addresses(addresses)

def test_redirect_rejects_invalid_port():
    with pytest.raises((UnsafeTarget, ValueError)):
        safe_redirect_url("https://example.com/", "https://example.com:99999/", "example.com")


def test_redirect_rejects_ambiguous_or_control_characters():
    for location in (
        "https://example.com/a\\b",
        "https://example.com/a\r\nInjected:yes",
        "https://example.com/\tpath",
    ):
        with pytest.raises(UnsafeTarget):
            safe_redirect_url("https://example.com/", location, "example.com")
