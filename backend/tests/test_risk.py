from types import SimpleNamespace
from apps.scans.risk import security_score

def test_security_score_is_bounded_and_severity_weighted():
    assert security_score([]) == 100
    assert security_score([SimpleNamespace(severity="critical")]) == 90
    assert security_score([SimpleNamespace(severity="high"), SimpleNamespace(severity="medium")]) == 87
    assert security_score([SimpleNamespace(severity="critical")] * 20) == 0

def test_unknown_severity_has_no_implicit_penalty():
    assert security_score([SimpleNamespace(severity="unknown")]) == 100
