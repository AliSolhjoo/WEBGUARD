from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from apps.accounts.models import User

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    ordering = ("email",)
    list_display = ("email", "full_name", "is_staff", "is_active")
    fieldsets = ((None, {"fields": ("email", "password")}), ("Personal info", {"fields": ("full_name",)}), ("Permissions", {"fields": ("is_active", "is_staff", "is_superuser", "groups", "user_permissions")}), ("Important dates", {"fields": ("last_login", "date_joined")}))
    add_fieldsets = ((None, {"classes": ("wide",), "fields": ("email", "username", "password1", "password2")}),)
    search_fields = ("email", "full_name")
