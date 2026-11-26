from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.audit.services import write_audit
from apps.organizations.permissions import get_membership
from apps.scans.assistant import analyze_finding
from apps.scans.models import Finding


class SecurityAssistantView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "assistant"

    def post(self, request):
        membership = get_membership(request.user)
        raw_id = request.data.get("finding_id")
        try:
            finding_id = int(raw_id)
        except (TypeError, ValueError):
            raise ValidationError({"finding_id": "A valid finding_id is required."})
        try:
            finding = Finding.objects.select_related(
                "check_result", "check_result__scan", "check_result__scan__asset"
            ).get(
                pk=finding_id,
                check_result__scan__asset__organization=membership.organization,
            )
        except Finding.DoesNotExist:
            raise NotFound("Finding not found.")
        language = str(request.data.get("language", "en")).lower()
        if language not in {"en", "fa"}:
            raise ValidationError({"language": "Language must be 'en' or 'fa'."})
        result = analyze_finding(finding, language=language)
        write_audit(request.user, membership.organization, "assistant.analysis_generated", {
            "finding_id": finding.id,
            "check_id": finding.check_result.check_id,
            "mode": "offline-rule-based",
        }, "finding", finding.id)
        return Response(result, status=status.HTTP_200_OK)
