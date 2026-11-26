import pytest
from apps.scans.models import Scan, ScanCheck, Finding
from apps.scanner.network import ProbeResult
from apps.scanner.runner import execute_scan

pytestmark = pytest.mark.django_db

def test_worker_creates_check_results_and_findings_for_verified_asset(monkeypatch, user, verified_asset):
    scan = Scan.objects.create(asset=verified_asset, requested_by=user)
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {
        "strict-transport-security": "max-age=31536000",
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=()",
        "x-frame-options": "DENY",
    }, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"},
       cookies=[{"name": "sessionid", "secure": True, "httponly": True, "samesite": "lax"}])
    monkeypatch.setattr("apps.scanner.runner._probe_asset", lambda domain: (http, https))
    monkeypatch.setattr("apps.scanner.runner.probe_homepage", lambda domain, url: None)
    monkeypatch.setattr("apps.scanner.runner.collect_dns_records", lambda domain: {"txt": ["v=spf1 include:mail.example -all"], "dmarc": ["v=DMARC1; p=reject"]})
    final = execute_scan(scan.id)
    assert final.status == Scan.Status.COMPLETED
    assert final.total_checks >= 10
    assert ScanCheck.objects.filter(scan=scan).count() == final.total_checks
    assert Finding.objects.filter(check_result__scan=scan).count() == final.failed_checks

def test_worker_refuses_pending_unverified_asset(user, organization):
    from apps.assets.models import Asset
    asset = Asset.objects.create(organization=organization, domain="pending.example", status=Asset.Status.PENDING, verification_token="x", created_by=user)
    scan = Scan.objects.create(asset=asset, requested_by=user)
    final = execute_scan(scan.id)
    assert final.status == Scan.Status.FAILED
    assert "verification" in final.error_message.lower()

def test_cancelled_scan_does_not_persist_results(monkeypatch, user, verified_asset):
    scan = Scan.objects.create(asset=verified_asset, requested_by=user)
    http = ProbeResult("http", 200, {}, "http://example.com/")
    https = ProbeResult("https", 200, {}, "https://example.com/", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    def cancel_during_probe(domain):
        Scan.objects.filter(pk=scan.id).update(status=Scan.Status.CANCELLED)
        return http, https
    monkeypatch.setattr("apps.scanner.runner._probe_asset", cancel_during_probe)
    monkeypatch.setattr("apps.scanner.runner.probe_homepage", lambda domain, url: None)
    monkeypatch.setattr("apps.scanner.runner.collect_dns_records", lambda domain: {"txt": [], "dmarc": []})
    final = execute_scan(scan.id)
    assert final.status == Scan.Status.CANCELLED
    assert not ScanCheck.objects.filter(scan=scan).exists()


def test_worker_samples_only_verified_origin_root(monkeypatch, user, verified_asset):
    scan = Scan.objects.create(asset=verified_asset, requested_by=user)
    http = ProbeResult("http", 301, {"location": "https://example.com/"}, "http://example.com/", redirect_status=301, redirect_location="https://example.com/")
    https = ProbeResult("https", 200, {}, "https://example.com/logout?next=/admin", "TLSv1.3", {"not_after": "Dec 31 23:59:59 2030 GMT"})
    sampled = {}
    monkeypatch.setattr("apps.scanner.runner._probe_asset", lambda domain: (http, https))
    monkeypatch.setattr("apps.scanner.runner.probe_homepage", lambda domain, url: sampled.update({"domain": domain, "url": url}) or None)
    monkeypatch.setattr("apps.scanner.runner.collect_dns_records", lambda domain: {"txt": [], "dmarc": []})
    final = execute_scan(scan.id)
    assert final.status == Scan.Status.COMPLETED
    assert sampled == {"domain": "example.com", "url": "https://example.com/"}
