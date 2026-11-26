SEVERITY_WEIGHTS = {"critical": 10, "high": 8, "medium": 5, "low": 2, "informational": 0}

def security_score(failed_checks):
    """Heuristic 0-100 posture score; this is explicitly not CVSS."""
    penalty = sum(SEVERITY_WEIGHTS.get(getattr(item, "severity", None), 0) for item in failed_checks)
    return max(0, 100 - penalty)
