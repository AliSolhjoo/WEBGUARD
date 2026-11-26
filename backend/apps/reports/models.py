from django.conf import settings
from django.db import models


class SecurityReport(models.Model):
    class Language(models.TextChoices):
        ENGLISH = "en", "English"
        PERSIAN = "fa", "Persian"

    scan = models.ForeignKey("scans.Scan", on_delete=models.CASCADE, related_name="reports")
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT)
    created_at = models.DateTimeField(auto_now_add=True)
    format = models.CharField(max_length=8, default="pdf")
    language = models.CharField(max_length=2, choices=Language.choices, default=Language.ENGLISH)

    class Meta:
        ordering = ["-created_at"]
