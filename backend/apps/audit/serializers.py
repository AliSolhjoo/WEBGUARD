from rest_framework import serializers
from apps.audit.models import AuditLog, Notification


class AuditLogSerializer(serializers.ModelSerializer):
    actor = serializers.CharField(source="user.email", default="system", read_only=True)

    class Meta:
        model = AuditLog
        fields = ["id", "actor", "action", "object_type", "object_id", "metadata", "ip_address", "created_at"]


class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ["id", "level", "title", "message", "href", "metadata", "read_at", "created_at"]
        read_only_fields = fields
