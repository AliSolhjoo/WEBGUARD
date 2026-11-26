from django.conf import settings
from django.db import models

class Asset(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending verification"
        VERIFIED = "verified", "Verified"
        SUSPENDED = "suspended", "Suspended"
    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="assets")
    domain = models.CharField(max_length=253)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    verification_token = models.CharField(max_length=100)
    verified_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="assets_created")
    created_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)
    class Meta:
        constraints = [models.UniqueConstraint(fields=["organization", "domain"], name="unique_asset_domain_per_org")]
        indexes = [models.Index(fields=["organization", "status"])]
        ordering = ["-created_at"]
    def __str__(self):
        return self.domain
