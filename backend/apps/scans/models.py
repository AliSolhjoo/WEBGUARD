from django.conf import settings
from django.db import models

class Scan(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"
    asset = models.ForeignKey("assets.Asset", on_delete=models.CASCADE, related_name="scans")
    requested_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="requested_scans")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    profile = models.CharField(max_length=24, default="passive", choices=[("passive", "Passive baseline")])
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    total_checks = models.PositiveIntegerField(default=0)
    passed_checks = models.PositiveIntegerField(default=0)
    failed_checks = models.PositiveIntegerField(default=0)
    info_checks = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["status", "created_at"])]

class ScanCheck(models.Model):
    class Status(models.TextChoices):
        PASS = "pass", "Pass"
        FAIL = "fail", "Fail"
        INFO = "info", "Information"
        ERROR = "error", "Error"
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="checks")
    check_id = models.CharField(max_length=60)
    name = models.CharField(max_length=160)
    category = models.CharField(max_length=60)
    status = models.CharField(max_length=12, choices=Status.choices)
    severity = models.CharField(max_length=16, default="informational")
    description = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    duration_ms = models.PositiveIntegerField(default=0)
    class Meta:
        constraints = [models.UniqueConstraint(fields=["scan", "check_id"], name="unique_check_per_scan")]
        indexes = [models.Index(fields=["scan", "status"])]
        ordering = ["category", "check_id"]

class Finding(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACCEPTED = "accepted", "Risk accepted"
        FIXED = "fixed", "Fixed"
        FALSE_POSITIVE = "false_positive", "False positive"
    check_result = models.OneToOneField(ScanCheck, on_delete=models.CASCADE, related_name="finding")
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    assigned_to = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    notes = models.TextField(blank=True, max_length=3000)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        indexes = [models.Index(fields=["status", "created_at"])]
    @property
    def scan(self):
        return self.check_result.scan
