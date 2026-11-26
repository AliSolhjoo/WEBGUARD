from django.contrib import admin
from apps.assets.models import Asset
@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("domain", "organization", "status", "created_at")
    search_fields = ("domain",)
    readonly_fields = ("verification_token", "verified_at")
