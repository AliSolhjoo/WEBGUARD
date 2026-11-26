from apps.scanner.network import ProbeResult
from apps.scanner.checks import run_checks


def test_check_registry_reports_headers_and_cookie_flags():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
        "x-frame-options": "DENY",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"},
       cookies=[{"name": "sid", "secure": True, "httponly": True, "samesite": "lax"}])
    checks = run_checks("example.com", http, https, {"txt": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"]})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HTTP-001"].status == "pass"
    assert by_id["WG-HTTP-002"].status == "pass"
    assert by_id["WG-HDR-001"].status == "pass"
    assert by_id["WG-COOKIE-001"].status == "pass"
    assert by_id["WG-DNS-002"].status == "pass"


def test_missing_security_headers_are_failed_checks():
    http = ProbeResult("http", 200, {}, "http://example.com/")
    https = ProbeResult("https", None, {}, "https://example.com/", error="TLS certificate verification failed")
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HTTP-001"].status == "fail"
    assert by_id["WG-HDR-001"].status == "fail"
    assert by_id["WG-HDR-006"].status == "fail"
    assert by_id["WG-COOKIE-001"].status == "info"

def test_evidence_redacts_redirect_query_and_header_values():
    http = ProbeResult("http", 301, {"location": "https://example.com/?access_token=do-not-store"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/?access_token=do-not-store")
    https = ProbeResult("https", 200, {"content-security-policy": "default-src 'nonce-super-secret-value'"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    redirect = next(item for item in checks if item.check_id == "WG-HTTP-002")
    csp = next(item for item in checks if item.check_id == "WG-HDR-001")
    evidence = str(redirect.evidence) + str(csp.evidence)
    assert "do-not-store" not in evidence
    assert "super-secret-value" not in evidence
    assert redirect.evidence["query_present"] is True
    assert csp.evidence == {"present": True, "recognized_secure_value": True}

def test_hsts_is_not_credited_when_only_http_response_has_it():
    http = ProbeResult("http", 200, {"strict-transport-security": "max-age=31536000"}, "http://example.com/")
    https = ProbeResult("https", None, {}, "https://example.com/", error="TLS failure")
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    hsts = next(item for item in checks if item.check_id == "WG-HDR-002")
    assert hsts.status == "fail"


def test_header_named_like_internal_cookie_field_cannot_crash_checks():
    http = ProbeResult("http", 200, {}, "http://example.com/")
    https = ProbeResult("https", 200, {"__cookies__": "attacker-controlled-header"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    cookie_check = next(item for item in checks if item.check_id == "WG-COOKIE-001")
    assert cookie_check.status == "info"


def test_hsts_zero_max_age_and_invalid_nosniff_value_are_not_credited():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "strict-transport-security": "max-age=0",
        "x-content-type-options": "nosniff-ish",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-002"].status == "fail"
    assert by_id["WG-HDR-003"].status == "fail"


def test_dns_lookup_errors_are_unknown_not_missing_findings():
    http = ProbeResult("http", 200, {}, "http://example.com/")
    https = ProbeResult("https", 200, {}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": [], "errors": {"txt": "LifetimeTimeout", "dmarc": "NoNameservers"}})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-DNS-001"].status == "error"
    assert by_id["WG-DNS-002"].status == "error"
    assert by_id["WG-DNS-001"].severity == "informational"


def test_mixed_content_is_detected_in_bounded_html_sample():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {"content-security-policy": "default-src 'self'"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    content = ProbeResult("https", 200, {"content-type": "text/html"}, "https://example.com/", body_sample='<html><script src="http://cdn.example/script.js"></script><img src="https://img.example/a.png"></html>', content_truncated=False)
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []}, content)
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-CONTENT-001"].status == "fail"
    assert by_id["WG-CONTENT-001"].evidence["observed_hosts"] == ["cdn.example"]


def test_content_disclosure_is_informational_and_does_not_assert_exploitability():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {"server": "nginx/1.24", "x-powered-by": "Express"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    content = ProbeResult("https", 200, {"content-type": "text/html"}, "https://example.com/", body_sample='<meta name="generator" content="CMS 1.0"><!--# sourceMappingURL=main.js.map -->')
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []}, content)
    disclosure = next(item for item in checks if item.check_id == "WG-CONTENT-002")
    assert disclosure.status == "info"
    assert disclosure.severity == "informational"
    assert "nginx/1.24" not in str(disclosure.evidence)


def test_http_to_https_check_rejects_cross_host_redirect_even_if_https_works():
    http = ProbeResult("http", 302, {"location": "https://other.example/"}, "http://example.com/", redirect_status=302, redirect_location="https://other.example/")
    https = ProbeResult("https", 200, {}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    redirect = next(item for item in checks if item.check_id == "WG-HTTP-002")
    assert redirect.status == "fail"
    assert redirect.evidence["host_matches_verified_asset"] is False


def test_clickjacking_check_rejects_wildcard_frame_ancestors():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "content-security-policy": "default-src 'self'; frame-ancestors *",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-006"].status == "fail"


def test_clickjacking_check_rejects_none_combined_with_other_sources():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "content-security-policy": "frame-ancestors 'none' https://partner.example",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-006"].status == "fail"


def test_spf_requires_a_terminal_all_mechanism():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": ["v=spf1 -all include:mail.example"], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-DNS-003"].status == "fail"
    assert by_id["WG-DNS-003"].evidence["missing_terminal_qualifier"] is True


def test_spf_missing_terminal_qualifier_is_not_passed():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": ["v=spf1 include:mail.example"], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-DNS-003"].status == "fail"


def test_referrer_policy_rejects_unsafe_url_without_safe_fallback():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {"referrer-policy": "unsafe-url"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-004"].status == "fail"


def test_referrer_policy_uses_last_recognized_policy():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {"referrer-policy": "unsafe-url, strict-origin-when-cross-origin"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-004"].status == "pass"


def test_check_registry_contains_all_nineteen_expected_check_ids():
    from apps.scanner.network import ProbeResult
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {"content-type": "text/html"}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    content = ProbeResult("https", 200, {"content-type": "text/html"}, "https://example.com/", body_sample="<html></html>")
    checks = run_checks("example.com", http, https, {"txt": ["v=spf1 -all"], "dmarc": ["v=DMARC1; p=reject"], "caa": ["0 issue \"ca.example\""]}, content)
    ids = {item.check_id for item in checks}
    expected = {
        "WG-HTTP-001", "WG-HTTP-002", "WG-TLS-001", "WG-TLS-002",
        "WG-HDR-001", "WG-HDR-002", "WG-HDR-003", "WG-HDR-004", "WG-HDR-005", "WG-HDR-006", "WG-HDR-007",
        "WG-COOKIE-001", "WG-DNS-001", "WG-DNS-002", "WG-DNS-003", "WG-DNS-004", "WG-DNS-005",
        "WG-CONTENT-001", "WG-CONTENT-002",
    }
    assert ids == expected
    assert len(checks) == 19


def test_http_only_headers_are_not_credited_when_tls_is_unavailable():
    http = ProbeResult("http", 200, {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
        "x-frame-options": "DENY",
    }, "http://example.com/")
    https = ProbeResult("https", None, {}, "https://example.com/", error="TLS validation failed")
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    by_id = {item.check_id: item for item in checks}
    assert by_id["WG-HDR-001"].status == "fail"
    assert by_id["WG-HDR-002"].status == "fail"
    assert by_id["WG-HDR-003"].status == "fail"
    assert by_id["WG-HDR-006"].status == "fail"


def test_csp_script_src_elem_and_script_src_attr_are_checked():
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "content-security-policy": "default-src 'self'; script-src 'self'; script-src-elem 'unsafe-inline'",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    checks = run_checks("example.com", http, https, {"txt": [], "dmarc": []})
    csp = next(item for item in checks if item.check_id == "WG-HDR-007")
    assert csp.status == "fail"
    assert csp.evidence["unsafe_inline"] is True
