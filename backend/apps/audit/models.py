from django.conf import settings
from django.db import models


class AuditLog(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    organization = models.ForeignKey("organizations.Organization", null=True, blank=True, on_delete=models.SET_NULL)
    action = models.CharField(max_length=100)
    object_type = models.CharField(max_length=80, blank=True)
    object_id = models.CharField(max_length=80, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "created_at"])]


class Notification(models.Model):
    class Level(models.TextChoices):
        INFO = "info", "Information"
        SUCCESS = "success", "Success"
        WARNING = "warning", "Warning"
        CRITICAL = "critical", "Critical"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="notifications")
    recipient = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="webguard_notifications")
    level = models.CharField(max_length=12, choices=Level.choices, default=Level.INFO)
    title = models.CharField(max_length=180)
    message = models.CharField(max_length=500)
    href = models.CharField(max_length=240, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["recipient", "read_at", "created_at"]),
            models.Index(fields=["organization", "created_at"]),
        ]


def write_audit(user, organization, action, metadata=None, object_type="", object_id="", ip_address=None):
    # Never pass credentials, access tokens, raw response bodies, or secrets into audit metadata.
    safe_metadata = metadata if isinstance(metadata, dict) else {}
    AuditLog.objects.create(
        user=user if getattr(user, "is_authenticated", False) else None,
        organization=organization,
        action=action[:100],
        object_type=object_type[:80],
        object_id=str(object_id)[:80],
        metadata=safe_metadata,
        ip_address=ip_address,
    )


def create_notification(recipient, organization, level, title, message, href="", metadata=None):
    if not recipient or not organization:
        return None
    if level not in Notification.Level.values:
        level = Notification.Level.INFO
    safe_metadata = metadata if isinstance(metadata, dict) else {}
    return Notification.objects.create(
        recipient=recipient,
        organization=organization,
        level=level,
        title=str(title)[:180],
        message=str(message)[:500],
        href=str(href)[:240],
        metadata=safe_metadata,
    )
