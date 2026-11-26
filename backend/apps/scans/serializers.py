from rest_framework import serializers
from apps.scans.models import Scan, ScanCheck, Finding

class ScanCheckSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanCheck
        fields = ["id", "check_id", "name", "category", "status", "severity", "description", "recommendation", "evidence", "duration_ms"]

class ScanSerializer(serializers.ModelSerializer):
    asset_domain = serializers.CharField(source="asset.domain", read_only=True)
    checks = ScanCheckSerializer(many=True, read_only=True)
    class Meta:
        model = Scan
        fields = ["id", "asset", "asset_domain", "status", "profile", "created_at", "started_at", "finished_at", "total_checks", "passed_checks", "failed_checks", "info_checks", "error_message", "checks"]
        read_only_fields = [f for f in fields if f not in ("asset", "profile")]

class FindingSerializer(serializers.ModelSerializer):
    check_id = serializers.CharField(source="check_result.check_id", read_only=True)
    title = serializers.CharField(source="check_result.name", read_only=True)
    category = serializers.CharField(source="check_result.category", read_only=True)
    severity = serializers.CharField(source="check_result.severity", read_only=True)
    description = serializers.CharField(source="check_result.description", read_only=True)
    recommendation = serializers.CharField(source="check_result.recommendation", read_only=True)
    evidence = serializers.JSONField(source="check_result.evidence", read_only=True)
    asset_domain = serializers.CharField(source="check_result.scan.asset.domain", read_only=True)
    scan_id = serializers.IntegerField(source="check_result.scan_id", read_only=True)
    assigned_to_email = serializers.EmailField(source="assigned_to.email", read_only=True, allow_null=True)
    class Meta:
        model = Finding
        fields = ["id", "check_id", "title", "category", "severity", "description", "recommendation", "evidence", "asset_domain", "scan_id", "status", "notes", "assigned_to", "assigned_to_email", "created_at", "updated_at"]
        read_only_fields = [f for f in fields if f not in ("status", "notes", "assigned_to")]
