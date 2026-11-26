from django.http import FileResponse
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound, ValidationError
from apps.reports.models import SecurityReport
from apps.reports.pdf import build_report
from apps.scans.models import Scan
from apps.organizations.permissions import get_membership, require_write
from apps.audit.services import write_audit

class ReportListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        m = get_membership(request.user)
        rows = SecurityReport.objects.filter(scan__asset__organization=m.organization).select_related("scan", "scan__asset").order_by("-created_at")[:100]
        return Response([{"id": x.id, "scan_id": x.scan_id, "domain": x.scan.asset.domain, "language": x.language, "created_at": x.created_at, "download_url": f"/api/v1/reports/{x.id}/download/"} for x in rows])
    def post(self, request):
        m = get_membership(request.user)
        require_write(m)
        try:
            scan = Scan.objects.select_related("asset").get(pk=request.data.get("scan"), asset__organization=m.organization)
        except (Scan.DoesNotExist, ValueError, TypeError):
            raise NotFound("Scan not found.")
        if scan.status != Scan.Status.COMPLETED:
            raise ValidationError({"scan": "Reports can only be generated for completed scans."})
        language = str(request.data.get("language", "en")).lower()
        if language not in {"en", "fa"}:
            raise ValidationError({"language": "Language must be 'en' or 'fa'."})
        report = SecurityReport.objects.create(scan=scan, created_by=request.user, language=language)
        write_audit(request.user, m.organization, "report.generated", {"report_id": report.id, "scan_id": scan.id}, "report", report.id)
        return Response({"id": report.id, "scan_id": scan.id, "domain": scan.asset.domain, "language": report.language, "download_url": f"/api/v1/reports/{report.id}/download/"}, status=201)

class ReportDownloadView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        m = get_membership(request.user)
        try:
            report = SecurityReport.objects.select_related("scan", "scan__asset").get(pk=pk, scan__asset__organization=m.organization)
        except SecurityReport.DoesNotExist:
            raise NotFound("Report not found.")
        output = build_report(report.scan, language=report.language)
        response = FileResponse(
            output,
            as_attachment=True,
            filename=f"webguard-{report.scan.asset.domain}-scan-{report.scan_id}.pdf",
            content_type="application/pdf",
        )
        response["Cache-Control"] = "private, no-store"
        response["X-Content-Type-Options"] = "nosniff"
        return response
