from types import SimpleNamespace

from apps.scans.assistant import GUIDANCE, GUIDANCE_FA, analyze_finding


def test_every_supported_scanner_check_has_deterministic_guidance():
    assert set(GUIDANCE) == {
        "WG-HTTP-001", "WG-HTTP-002", "WG-HDR-001", "WG-HDR-002", "WG-HDR-003",
        "WG-HDR-004", "WG-HDR-006", "WG-TLS-001", "WG-TLS-002", "WG-COOKIE-001",
        "WG-CONTENT-001", "WG-CONTENT-002", "WG-DNS-001", "WG-DNS-002", "WG-DNS-003",
        "WG-DNS-004", "WG-DNS-005", "WG-HDR-005", "WG-HDR-007",
    }
    for rule in GUIDANCE.values():
        assert rule["priority"] in {"P1", "P2", "P3"}
        assert rule["impact"] and rule["steps"] and rule["validation"]


def test_persian_assistant_guidance_is_localized_and_keeps_technical_id():
    check = SimpleNamespace(check_id="WG-HDR-001", severity="medium", name="Content-Security-Policy", evidence={"present": False})
    scan = SimpleNamespace(asset=SimpleNamespace(domain="example.com"))
    finding = SimpleNamespace(
        pk=7, check_result=check, status="open", name="Content-Security-Policy",
        check_result__scan=scan,
    )
    # The assistant resolves the scan through check_result.scan.
    check.scan = scan
    result = analyze_finding(finding, language="fa")
    assert result["language"] == "fa"
    assert result["check_id"] == "WG-HDR-001"
    assert "CSP" in result["business_impact"]
    assert all(step for step in result["remediation_steps"])
    assert result["validation_criteria"]


def test_persian_rules_cover_every_supported_scanner_check():
    assert set(GUIDANCE_FA) == set(GUIDANCE)
