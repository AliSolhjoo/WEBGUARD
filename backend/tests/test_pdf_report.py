import pytest
from apps.scans.models import Scan, ScanCheck
from apps.reports.pdf import build_report

pytestmark = pytest.mark.django_db

def test_pdf_report_generates_pdf_bytes(user, verified_asset):
    scan = Scan.objects.create(asset=verified_asset, requested_by=user, status=Scan.Status.COMPLETED, total_checks=1, failed_checks=1)
    ScanCheck.objects.create(scan=scan, check_id="WG-HDR-001", name="Content-Security-Policy", category="Security Headers", status="fail", severity="medium", description="CSP missing", recommendation="Configure CSP", evidence={"observed": None})
    pdf = build_report(scan).read()
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 500
