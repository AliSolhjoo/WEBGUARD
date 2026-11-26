from datetime import timedelta

from django.db import transaction
from django.db.models import Count
from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import NotFound, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from apps.assets.models import Asset
from apps.organizations.models import Membership, Organization
from apps.organizations.permissions import get_membership, require_admin, require_write
from apps.scans.models import Finding, Scan
from apps.scans.risk import security_score
from apps.scans.serializers import FindingSerializer, ScanSerializer
from apps.audit.services import write_audit


class ScanListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "scan_create"

    def get(self, request):
        membership = get_membership(request.user)
        rows = (
            Scan.objects.filter(asset__organization=membership.organization)
            .select_related("asset")
            .prefetch_related("checks")
            .order_by("-created_at")[:100]
        )
        return Response(ScanSerializer(rows, many=True).data)

    def post(self, request):
        membership = get_membership(request.user)
        require_write(membership)
        try:
            asset = Asset.objects.get(pk=request.data.get("asset"), organization=membership.organization)
        except (Asset.DoesNotExist, ValueError, TypeError):
            raise ValidationError({"asset": "Select an asset belonging to your organization."})
        if asset.status != Asset.Status.VERIFIED:
            raise ValidationError({"asset": "Domain ownership verification is required before scanning."})
        profile = request.data.get("profile", "passive")
        if profile != "passive":
            raise ValidationError({"profile": "Only the passive assessment profile is currently supported."})
        with transaction.atomic():
            Organization.objects.select_for_update().get(pk=membership.organization_id)
            active_count = Scan.objects.filter(
                asset__organization=membership.organization,
                status__in=[Scan.Status.PENDING, Scan.Status.RUNNING],
            ).count()
            if active_count >= 3:
                raise ValidationError({"detail": "At most three scans may be queued or running for an organization."})
            scan = Scan.objects.create(asset=asset, requested_by=request.user, profile="passive")
            write_audit(request.user, membership.organization, "scan.queued", {"scan_id": scan.id, "domain": asset.domain}, "scan", scan.id)
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)


class ScanDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, request, pk):
        membership = get_membership(request.user)
        try:
            return (
                Scan.objects.select_related("asset")
                .prefetch_related("checks")
                .get(pk=pk, asset__organization=membership.organization)
            )
        except Scan.DoesNotExist:
            raise NotFound("Scan not found.")

    def get(self, request, pk):
        return Response(ScanSerializer(self.get_object(request, pk)).data)

    def post(self, request, pk):
        membership = get_membership(request.user)
        require_write(membership)
        if request.data.get("action") != "cancel":
            raise ValidationError({"action": "Only the 'cancel' action is supported on this endpoint."})
        # Conditional update makes cancellation race-safe with a worker claiming the job.
        updated = Scan.objects.filter(
            pk=pk,
            asset__organization=membership.organization,
            status__in=[Scan.Status.PENDING, Scan.Status.RUNNING],
        ).update(status=Scan.Status.CANCELLED, finished_at=timezone.now())
        if not updated:
            scan = self.get_object(request, pk)
            raise ValidationError({"detail": "Only pending or running scans can be cancelled."})
        scan = self.get_object(request, pk)
        write_audit(request.user, membership.organization, "scan.cancelled", {"scan_id": scan.id}, "scan", scan.id)
        return Response(ScanSerializer(scan).data)


class ScanComparisonView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        membership = get_membership(request.user)
        try:
            current = Scan.objects.select_related("asset").get(pk=pk, asset__organization=membership.organization)
        except Scan.DoesNotExist:
            raise NotFound("Scan not found.")
        if current.status != Scan.Status.COMPLETED:
            raise ValidationError({"detail": "Only completed scans can be compared."})
        previous = Scan.objects.filter(
            asset=current.asset,
            status=Scan.Status.COMPLETED,
            finished_at__lt=current.finished_at,
        ).order_by("-finished_at").first()
        current_failed = set(current.checks.filter(status="fail").values_list("check_id", flat=True))
        current_score = security_score(current.checks.filter(status="fail"))
        if not previous:
            return Response({
                "has_baseline": False,
                "current_scan_id": current.id,
                "current_score": current_score,
                "previous_scan_id": None,
                "new_findings": sorted(current_failed),
                "resolved_findings": [],
                "persistent_findings": [],
            })
        previous_failed = set(previous.checks.filter(status="fail").values_list("check_id", flat=True))
        previous_score = security_score(previous.checks.filter(status="fail"))
        return Response({
            "has_baseline": True,
            "current_scan_id": current.id,
            "current_score": current_score,
            "previous_scan_id": previous.id,
            "previous_score": previous_score,
            "score_change": current_score - previous_score,
            "new_findings": sorted(current_failed - previous_failed),
            "resolved_findings": sorted(previous_failed - current_failed),
            "persistent_findings": sorted(current_failed.intersection(previous_failed)),
        })


class FindingListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        membership = get_membership(request.user)
        rows = Finding.objects.filter(
            check_result__scan__asset__organization=membership.organization
        ).select_related(
            "check_result", "check_result__scan", "check_result__scan__asset", "assigned_to"
        ).order_by("-created_at")
        status_filter = request.query_params.get("status")
        severity_filter = request.query_params.get("severity")
        asset_filter = request.query_params.get("asset")
        search = request.query_params.get("q", "").strip()[:100]
        if status_filter and status_filter in Finding.Status.values:
            rows = rows.filter(status=status_filter)
        if severity_filter and severity_filter in {"critical", "high", "medium", "low", "informational"}:
            rows = rows.filter(check_result__severity=severity_filter)
        if asset_filter:
            rows = rows.filter(check_result__scan__asset_id=asset_filter)
        if search:
            rows = rows.filter(
                check_result__name__icontains=search
            ) | rows.filter(
                check_result__check_id__icontains=search
            ) | rows.filter(
                check_result__scan__asset__domain__icontains=search
            )
        return Response(FindingSerializer(rows[:500], many=True).data)


class FindingUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        membership = get_membership(request.user)
        require_write(membership)
        try:
            finding = Finding.objects.select_related("check_result__scan__asset", "assigned_to").get(
                pk=pk,
                check_result__scan__asset__organization=membership.organization,
            )
        except Finding.DoesNotExist:
            raise NotFound("Finding not found.")

        new_status = request.data.get("status", finding.status)
        notes = request.data.get("notes", finding.notes)
        if new_status not in Finding.Status.values:
            raise ValidationError({"status": "Unsupported finding status."})
        if not isinstance(notes, str) or len(notes) > 3000:
            raise ValidationError({"notes": "Notes must be a string of at most 3000 characters."})

        assigned_to = finding.assigned_to
        if "assigned_to" in request.data:
            raw_assignee = request.data.get("assigned_to")
            if raw_assignee in (None, ""):
                assigned_to = None
            else:
                try:
                    assignee_id = int(raw_assignee)
                except (TypeError, ValueError):
                    raise ValidationError({"assigned_to": "Select a valid workspace member."})
                member = Membership.objects.select_related("user").filter(
                    user_id=assignee_id,
                    organization=membership.organization,
                ).first()
                if not member:
                    raise ValidationError({"assigned_to": "The assignee must belong to this workspace."})
                if member.role == Membership.Role.VIEWER:
                    raise ValidationError({"assigned_to": "A read-only viewer cannot be assigned remediation work."})
                assigned_to = member.user

        finding.status = new_status
        finding.notes = notes
        finding.assigned_to = assigned_to
        finding.save(update_fields=["status", "notes", "assigned_to", "updated_at"])
        write_audit(request.user, membership.organization, "finding.updated", {
            "finding_id": finding.id,
            "status": new_status,
            "assigned_to_user_id": assigned_to.pk if assigned_to else None,
        }, "finding", finding.id)
        return Response(FindingSerializer(finding).data)


class OverviewView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        membership = get_membership(request.user)
        assets = Asset.objects.filter(organization=membership.organization)
        scans = Scan.objects.filter(asset__organization=membership.organization)
        findings = Finding.objects.filter(
            check_result__scan__asset__organization=membership.organization,
            status=Finding.Status.OPEN,
        )
        counts = findings.values("check_result__severity").annotate(total=Count("id"))
        severity = {row["check_result__severity"]: row["total"] for row in counts}
        latest_scans = scans.select_related("asset").order_by("-created_at")[:6]
        latest_completed = scans.filter(status=Scan.Status.COMPLETED).order_by("-finished_at").first()
        score = security_score(latest_completed.checks.filter(status="fail")) if latest_completed else None
        return Response({
            "asset_count": assets.count(),
            "verified_asset_count": assets.filter(status=Asset.Status.VERIFIED).count(),
            "scan_count": scans.count(),
            "active_scans": scans.filter(status__in=[Scan.Status.PENDING, Scan.Status.RUNNING]).count(),
            "open_findings": findings.count(),
            "severity": {key: severity.get(key, 0) for key in ("critical", "high", "medium", "low")},
            "security_score": score,
            "score_method": "100 minus severity weights for the latest completed scan; not CVSS.",
            "recent_scans": ScanSerializer(latest_scans, many=True).data,
        })


class SecurityTrendsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        membership = get_membership(request.user)
        since = timezone.now() - timedelta(days=29)
        rows = list(Scan.objects.filter(
            asset__organization=membership.organization,
            created_at__gte=since,
        ).select_related("asset").prefetch_related("checks").order_by("created_at"))
        day_map = {}
        for item in rows:
            day = timezone.localtime(item.created_at).date().isoformat()
            current = day_map.setdefault(day, {"date": day, "scans": 0, "completed": 0, "failed": 0})
            current["scans"] += 1
            if item.status == Scan.Status.COMPLETED:
                current["completed"] += 1
            elif item.status == Scan.Status.FAILED:
                current["failed"] += 1
        completed = [item for item in rows if item.status == Scan.Status.COMPLETED]
        scores = [{
            "scan_id": item.id,
            "date": timezone.localtime(item.finished_at or item.created_at).date().isoformat(),
            "domain": item.asset.domain,
            "score": security_score(item.checks.filter(status="fail")),
        } for item in completed[-12:]]
        open_findings = Finding.objects.filter(
            check_result__scan__asset__organization=membership.organization,
            status=Finding.Status.OPEN,
        ).values("check_result__severity").annotate(total=Count("id"))
        severity = {row["check_result__severity"]: row["total"] for row in open_findings}
        return Response({
            "daily_scans": sorted(day_map.values(), key=lambda item: item["date"]),
            "score_history": scores,
            "open_findings_by_severity": {key: severity.get(key, 0) for key in ("critical", "high", "medium", "low", "informational")},
            "period_days": 30,
        })


class AuditLogListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from apps.audit.models import AuditLog
        from apps.audit.serializers import AuditLogSerializer
        membership = get_membership(request.user)
        require_admin(membership)
        rows = AuditLog.objects.filter(organization=membership.organization).select_related("user")[:200]
        return Response(AuditLogSerializer(rows, many=True).data)
