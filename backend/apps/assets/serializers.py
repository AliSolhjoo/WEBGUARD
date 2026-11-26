import secrets
from rest_framework import serializers
from apps.assets.models import Asset
from apps.assets.domain_validation import normalize_domain, UnsafeTarget

class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = ["id", "domain", "status", "verified_at", "created_at", "last_scanned_at"]
        read_only_fields = ["id", "status", "verified_at", "created_at", "last_scanned_at"]
    def validate_domain(self, value):
        try:
            return normalize_domain(value)
        except UnsafeTarget as exc:
            raise serializers.ValidationError(str(exc))
    def create(self, validated_data):
        validated_data["verification_token"] = secrets.token_urlsafe(24)
        return super().create(validated_data)
