import pytest
from apps.scanner.network import ProbeResult, probe_origin
from apps.scanner.safety import resolve_and_validate
from apps.assets.domain_validation import UnsafeTarget


def test_dns_resolution_rejects_private_address(monkeypatch):
    class Record:
        address = "10.0.0.8"
    class Answer:
        rrset = [Record()]
        def __iter__(self): return iter(self.rrset)
    class FakeResolver:
        def __init__(self, **kwargs): self.timeout = None
        def resolve(self, name, record_type, **kwargs):
            assert name == "example.com."
            return Answer() if record_type == "A" else type("NoAnswer", (), {"rrset": None, "__iter__": lambda self: iter(())})()
    monkeypatch.setattr("apps.scanner.safety.dns.resolver.Resolver", FakeResolver)
    with pytest.raises(UnsafeTarget):
        resolve_and_validate("example.com")


def test_dns_resolution_returns_validated_pinned_addresses(monkeypatch):
    records = {"A": ["1.1.1.1"], "AAAA": ["2606:4700:4700::1111"]}
    class Record:
        def __init__(self, address): self.address = address
    class Answer:
        def __init__(self, values): self.rrset = [Record(v) for v in values]
        def __iter__(self): return iter(self.rrset or [])
    class FakeResolver:
        def __init__(self, **kwargs): self.timeout = None
        def resolve(self, name, record_type, **kwargs):
            assert name == "example.com."
            return Answer(records[record_type])
    monkeypatch.setattr("apps.scanner.safety.dns.resolver.Resolver", FakeResolver)
    result = resolve_and_validate("example.com")
    assert result == ["1.1.1.1", "2606:4700:4700::1111"]


def test_probe_follows_only_same_host_https_redirect(monkeypatch):
    calls = []
    def fake_single(host, url, timeout, deadline=None):
        calls.append(url)
        if url.startswith("http://"):
            return ProbeResult("http", 301, {"location": "https://example.com/secure"}, url)
        return ProbeResult("https", 200, {}, url, tls_version="TLSv1.3")
    monkeypatch.setattr("apps.scanner.network._single_head", fake_single)
    result = probe_origin("example.com", "http")
    assert calls == ["http://example.com/", "https://example.com/secure"]
    assert result.status == 200
    assert result.redirect_status == 301


def test_probe_does_not_follow_cross_host_redirect(monkeypatch):
    calls = []
    def fake_single(host, url, timeout, deadline=None):
        calls.append(url)
        return ProbeResult("http", 302, {"location": "https://other.example/"}, url)
    monkeypatch.setattr("apps.scanner.network._single_head", fake_single)
    result = probe_origin("example.com", "http")
    assert calls == ["http://example.com/"]
    assert result.status == 302
    assert result.redirect_status is None

def test_http_connection_uses_pinned_ip_not_hostname_resolution(monkeypatch):
    from apps.scanner.network import PinnedHTTPConnection
    called = {}
    class FakeSocket:
        def close(self): pass
    def fake_create_connection(address, timeout):
        called["address"] = address
        called["timeout"] = timeout
        return FakeSocket()
    monkeypatch.setattr("apps.scanner.network.socket.create_connection", fake_create_connection)
    connection = PinnedHTTPConnection("example.com", "1.1.1.1", timeout=4)
    connection.connect()
    assert called["address"] == ("1.1.1.1", 80)
    assert called["timeout"] == 4
    connection.close()

def test_https_connection_pins_ip_but_keeps_hostname_for_tls(monkeypatch):
    from apps.scanner.network import PinnedHTTPSConnection
    called = {}
    class FakeRaw:
        def close(self): pass
    class FakeSecure:
        def close(self): pass
    class FakeContext:
        def wrap_socket(self, raw, server_hostname):
            called["raw"] = raw
            called["server_hostname"] = server_hostname
            return FakeSecure()
    def fake_create_connection(address, timeout):
        called["address"] = address
        return FakeRaw()
    monkeypatch.setattr("apps.scanner.network.socket.create_connection", fake_create_connection)
    connection = PinnedHTTPSConnection("example.com", "1.1.1.1", timeout=5, context=FakeContext())
    connection.connect()
    assert called["address"] == ("1.1.1.1", 443)
    assert called["server_hostname"] == "example.com"
    connection.close()


def test_probe_respects_redirect_cap_without_extra_request(monkeypatch):
    calls = []
    def fake_single(host, url, timeout, deadline=None):
        calls.append(url)
        return ProbeResult("https", 302, {"location": "https://example.com/next"}, url)
    monkeypatch.setattr("apps.scanner.network._single_head", fake_single)
    monkeypatch.setattr("apps.scanner.network.SCAN_MAX_REDIRECTS", 1)
    result = probe_origin("example.com", "https")
    assert len(calls) == 2  # initial request + one followed redirect
    assert result.status == 302
