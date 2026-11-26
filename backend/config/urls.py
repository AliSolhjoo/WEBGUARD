from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from rest_framework.permissions import AllowAny, BasePermission
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from apps.accounts.views import RegisterView, LoginView, MeView, LogoutView
from apps.organizations.views import OrganizationView, MembersView
from apps.assets.views import AssetListCreateView, AssetDetailView, AssetVerificationView
from apps.scans.views import ScanListCreateView, ScanDetailView, ScanComparisonView, FindingListView, FindingUpdateView, OverviewView, SecurityTrendsView, AuditLogListView
from apps.reports.views import ReportListCreateView, ReportDownloadView
from apps.audit.views import NotificationListView, NotificationReadView
from apps.scans.assistant_views import SecurityAssistantView
from django.conf import settings


def health(request):
    return JsonResponse({"status": "ok", "service": "webguard-api", "version": "2.0.0"})


class SchemaAccessPermission(BasePermission):
    def has_permission(self, request, view):
        return bool(settings.DEBUG or (request.user and request.user.is_staff))

urlpatterns = [
    path("admin/", admin.site.urls),
    path("health/", health),
    path("api/schema/", SpectacularAPIView.as_view(permission_classes=[SchemaAccessPermission]), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema", permission_classes=[SchemaAccessPermission]), name="swagger-ui"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema", permission_classes=[SchemaAccessPermission]), name="redoc"),
    path("api/v1/auth/register/", RegisterView.as_view(), name="register"),
    path("api/v1/auth/login/", LoginView.as_view(), name="token_obtain_pair"),
    path("api/v1/auth/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("api/v1/auth/logout/", LogoutView.as_view(), name="logout"),
    path("api/v1/auth/me/", MeView.as_view(), name="me"),
    path("api/v1/organization/", OrganizationView.as_view(), name="organization"),
    path("api/v1/organization/members/", MembersView.as_view(), name="members"),
    path("api/v1/assets/", AssetListCreateView.as_view(), name="assets"),
    path("api/v1/assets/<int:pk>/", AssetDetailView.as_view(), name="asset-detail"),
    path("api/v1/assets/<int:pk>/verification/", AssetVerificationView.as_view(), name="asset-verification"),
    path("api/v1/scans/", ScanListCreateView.as_view(), name="scans"),
    path("api/v1/scans/<int:pk>/", ScanDetailView.as_view(), name="scan-detail"),
    path("api/v1/scans/<int:pk>/comparison/", ScanComparisonView.as_view(), name="scan-comparison"),
    path("api/v1/findings/", FindingListView.as_view(), name="findings"),
    path("api/v1/findings/<int:pk>/", FindingUpdateView.as_view(), name="finding-detail"),
    path("api/v1/dashboard/overview/", OverviewView.as_view(), name="overview"),
    path("api/v1/dashboard/trends/", SecurityTrendsView.as_view(), name="dashboard-trends"),
    path("api/v1/assistant/analyze/", SecurityAssistantView.as_view(), name="security-assistant"),
    path("api/v1/reports/", ReportListCreateView.as_view(), name="reports"),
    path("api/v1/reports/<int:pk>/download/", ReportDownloadView.as_view(), name="report-download"),
    path("api/v1/audit-logs/", AuditLogListView.as_view(), name="audit-logs"),
    path("api/v1/notifications/", NotificationListView.as_view(), name="notifications"),
    path("api/v1/notifications/<int:pk>/read/", NotificationReadView.as_view(), name="notification-read"),
    path("api/v1/notifications/<int:pk>/", NotificationReadView.as_view(), name="notification-detail"),
]
