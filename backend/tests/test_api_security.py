import pytest
from unittest.mock import patch
from apps.assets.models import Asset
from apps.accounts.models import User
from apps.organizations.models import Organization, Membership
from apps.scans.models import Scan

pytestmark = pytest.mark.django_db

def test_asset_creation_normalizes_hostname_and_starts_unverified(api_client):
    response = api_client.post("/api/v1/assets/", {"domain": "Example.COM."}, format="json")
    assert response.status_code == 201
    assert response.data["domain"] == "example.com"
    assert response.data["status"] == "pending"
    assert "verification_token" not in response.data

def test_asset_creation_rejects_url_and_private_target(api_client):
    for domain in ["http://example.com", "127.0.0.1", "localhost", "example.com/admin"]:
        response = api_client.post("/api/v1/assets/", {"domain": domain}, format="json")
        assert response.status_code == 400

def test_scan_is_blocked_until_domain_is_verified(api_client, organization, user):
    asset = Asset.objects.create(organization=organization, domain="example.com", verification_token="secret", created_by=user)
    response = api_client.post("/api/v1/scans/", {"asset": asset.id, "profile": "passive"}, format="json")
    assert response.status_code == 400
    assert not Scan.objects.exists()

def test_only_passive_profile_is_allowed(api_client, verified_asset):
    response = api_client.post("/api/v1/scans/", {"asset": verified_asset.id, "profile": "active"}, format="json")
    assert response.status_code == 400

def test_tenant_cannot_read_another_organization_assets(api_client, user):
    other_user = User.objects.create_user(username="other@example.test", email="other@example.test", password="Other-Strong-Password-902!")
    other_org = Organization.objects.create(name="Other Lab", slug="other-lab", created_by=other_user)
    Asset.objects.create(organization=other_org, domain="other.example", verification_token="token", created_by=other_user)
    response = api_client.get("/api/v1/assets/")
    assert response.status_code == 200
    assert response.data == []

def test_viewer_cannot_create_asset(api_client, user, organization, membership):
    membership.role = Membership.Role.VIEWER
    membership.save(update_fields=["role"])
    response = api_client.post("/api/v1/assets/", {"domain": "example.org"}, format="json")
    assert response.status_code == 403

def test_dns_verification_uses_exact_challenge(api_client, verified_asset):
    verified_asset.status = Asset.Status.PENDING
    verified_asset.verification_token = "correct-token"
    verified_asset.save()
    class FakeAnswer:
        strings = [b"webguard-verification=correct-token"]
    class FakeResolver:
        lifetime = 0
        def resolve(self, name, record_type, **kwargs):
            assert name == "_webguard-verify.example.com."
            assert record_type == "TXT"
            assert kwargs.get("search") is False
            return [FakeAnswer()]
    with patch("apps.assets.views.dns.resolver.Resolver", return_value=FakeResolver()):
        response = api_client.post(f"/api/v1/assets/{verified_asset.id}/verification/", {}, format="json")
    assert response.status_code == 200
    verified_asset.refresh_from_db()
    assert verified_asset.status == Asset.Status.VERIFIED

def test_dns_verification_reports_missing_txt_record(api_client, verified_asset):
    import dns.resolver
    verified_asset.status = Asset.Status.PENDING
    verified_asset.verification_token = "expected-token"
    verified_asset.save()

    class FakeResolver:
        timeout = 0
        lifetime = 0
        def resolve(self, *args, **kwargs):
            raise dns.resolver.NoAnswer

    with patch("apps.assets.views.dns.resolver.Resolver", return_value=FakeResolver()):
        response = api_client.post(f"/api/v1/assets/{verified_asset.id}/verification/", {}, format="json")
    assert response.status_code == 400
    assert "TXT record was not found" in response.data["detail"]


def test_dns_verification_reports_resolver_timeout(api_client, verified_asset):
    import dns.exception
    verified_asset.status = Asset.Status.PENDING
    verified_asset.verification_token = "expected-token"
    verified_asset.save()

    class FakeResolver:
        timeout = 0
        lifetime = 0
        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout

    with patch("apps.assets.views.dns.resolver.Resolver", return_value=FakeResolver()):
        response = api_client.post(f"/api/v1/assets/{verified_asset.id}/verification/", {}, format="json")
    assert response.status_code == 503
    assert "DNS lookup timed out" in response.data["detail"]


def test_scan_creation_succeeds_for_verified_asset(api_client, verified_asset):
    response = api_client.post("/api/v1/scans/", {"asset": verified_asset.id, "profile": "passive"}, format="json")
    assert response.status_code == 201
    assert response.data["status"] == "pending"
    assert response.data["profile"] == "passive"

def test_scan_and_report_data_are_tenant_scoped(api_client, user, organization, verified_asset):
    other_user = User.objects.create_user(username="other2@example.test", email="other2@example.test", password="Another-Strong-Password-902!")
    other_org = Organization.objects.create(name="Private Lab", slug="private-lab", created_by=other_user)
    other_asset = Asset.objects.create(organization=other_org, domain="private.example", status=Asset.Status.VERIFIED, verification_token="private-token", created_by=other_user)
    other_scan = Scan.objects.create(asset=other_asset, requested_by=other_user, status=Scan.Status.COMPLETED)
    response = api_client.get("/api/v1/scans/")
    assert response.status_code == 200
    assert all(row["id"] != other_scan.id for row in response.data)

def test_viewer_cannot_queue_scan(api_client, user, organization, membership, verified_asset):
    membership.role = Membership.Role.VIEWER
    membership.save(update_fields=["role"])
    response = api_client.post("/api/v1/scans/", {"asset": verified_asset.id, "profile": "passive"}, format="json")
    assert response.status_code == 403

def test_registration_creates_owner_workspace(db):
    from rest_framework.test import APIClient
    client = APIClient()
    response = client.post("/api/v1/auth/register/", {
        "email": "new-owner@example.org",
        "password": "Unrelated-Long-Random-Passphrase-934!",
        "full_name": "New Owner",
        "organization_name": "New Security Group",
    }, format="json")
    assert response.status_code == 201
    assert response.data["user"]["email"] == "new-owner@example.org"
    assert response.data["organization"]["slug"] == "new-security-group"
    assert Membership.objects.filter(user__email="new-owner@example.org", role=Membership.Role.OWNER).exists()

def test_logout_blacklists_refresh_token(api_client, user):
    from rest_framework_simplejwt.tokens import RefreshToken
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
    refresh = RefreshToken.for_user(user)
    response = api_client.post("/api/v1/auth/logout/", {"refresh": str(refresh)}, format="json")
    assert response.status_code == 205
    assert BlacklistedToken.objects.filter(token__jti=refresh["jti"]).exists()


def test_user_cannot_be_added_to_a_second_workspace(api_client, user, organization):
    other_user = User.objects.create_user(username="cross-workspace@example.test", email="cross-workspace@example.test", password="Separate-Strong-Password-883!")
    other_org = Organization.objects.create(name="Already Joined", slug="already-joined", created_by=other_user)
    Membership.objects.create(user=other_user, organization=other_org, role=Membership.Role.ANALYST)
    response = api_client.post("/api/v1/organization/members/", {"email": other_user.email, "role": "viewer"}, format="json")
    assert response.status_code == 409
    assert Membership.objects.filter(user=other_user).count() == 1


def test_workspace_owner_role_cannot_be_changed_through_member_api(api_client, user):
    response = api_client.post("/api/v1/organization/members/", {"email": user.email, "role": "admin"}, format="json")
    assert response.status_code == 400
    membership = Membership.objects.get(user=user)
    assert membership.role == Membership.Role.OWNER


def test_logout_cannot_blacklist_another_users_refresh_token(api_client):
    from rest_framework_simplejwt.tokens import RefreshToken
    other_user = User.objects.create_user(username="token-owner@example.test", email="token-owner@example.test", password="Another-Strong-Password-991!")
    other_refresh = RefreshToken.for_user(other_user)
    response = api_client.post("/api/v1/auth/logout/", {"refresh": str(other_refresh)}, format="json")
    assert response.status_code == 403


def test_viewer_cannot_read_asset_verification_secret(api_client, membership, verified_asset):
    membership.role = Membership.Role.VIEWER
    membership.save(update_fields=["role"])
    response = api_client.get(f"/api/v1/assets/{verified_asset.id}/verification/")
    assert response.status_code == 403


def test_finding_assignment_requires_non_viewer_workspace_member(api_client, organization, membership, user):
    from apps.assets.models import Asset
    from apps.scans.models import ScanCheck, Finding
    viewer = User.objects.create_user(username="viewer@example.test", email="viewer@example.test", password="Viewer-Password-567890!", full_name="Read Only")
    Membership.objects.create(user=viewer, organization=organization, role=Membership.Role.VIEWER)
    asset = Asset.objects.create(organization=organization, domain="assign.example", status=Asset.Status.VERIFIED, verification_token="token", created_by=user)
    scan = Scan.objects.create(asset=asset, requested_by=user, status=Scan.Status.COMPLETED)
    check = ScanCheck.objects.create(scan=scan, check_id="WG-HDR-001", name="CSP", category="Headers", status="fail", severity="medium")
    finding = Finding.objects.create(check_result=check)
    denied = api_client.patch(f"/api/v1/findings/{finding.id}/", {"assigned_to": viewer.id}, format="json")
    assert denied.status_code == 400
    analyst = User.objects.create_user(username="analyst2@example.test", email="analyst2@example.test", password="Analyst-Password-567890!", full_name="Analyst Two")
    Membership.objects.create(user=analyst, organization=organization, role=Membership.Role.ANALYST)
    accepted = api_client.patch(f"/api/v1/findings/{finding.id}/", {"assigned_to": analyst.id, "notes": "Validate CSP policy"}, format="json")
    assert accepted.status_code == 200
    assert accepted.data["assigned_to"] == analyst.id
    assert accepted.data["notes"] == "Validate CSP policy"


def test_offline_security_assistant_is_tenant_scoped_and_bilingual(api_client, user, organization, verified_asset):
    from apps.scans.models import ScanCheck, Finding
    scan = Scan.objects.create(asset=verified_asset, requested_by=user, status=Scan.Status.COMPLETED)
    check = ScanCheck.objects.create(scan=scan, check_id="WG-HDR-001", name="Content-Security-Policy", category="Security Headers", status="fail", severity="medium", evidence={"present": False})
    finding = Finding.objects.create(check_result=check)
    response = api_client.post("/api/v1/assistant/analyze/", {"finding_id": finding.id, "language": "fa"}, format="json")
    assert response.status_code == 200
    assert response.data["mode"] == "offline-rule-based"
    assert response.data["language"] == "fa"
    assert "CSP" in response.data["business_impact"]
    assert all(isinstance(step, str) and step for step in response.data["remediation_steps"])
    invalid = api_client.post("/api/v1/assistant/analyze/", {"finding_id": finding.id, "language": "xx"}, format="json")
    assert invalid.status_code == 400


def test_scan_comparison_is_limited_to_same_asset_and_completed_scans(api_client, user, verified_asset):
    from django.utils import timezone
    from datetime import timedelta
    from apps.scans.models import ScanCheck
    previous_time = timezone.now() - timedelta(days=2)
    previous = Scan.objects.create(asset=verified_asset, requested_by=user, status=Scan.Status.COMPLETED, finished_at=previous_time)
    ScanCheck.objects.create(scan=previous, check_id="WG-HDR-001", name="CSP", category="Headers", status="fail", severity="medium")
    current = Scan.objects.create(asset=verified_asset, requested_by=user, status=Scan.Status.COMPLETED, finished_at=timezone.now())
    ScanCheck.objects.create(scan=current, check_id="WG-HDR-002", name="HSTS", category="Headers", status="fail", severity="low")
    response = api_client.get(f"/api/v1/scans/{current.id}/comparison/")
    assert response.status_code == 200
    assert response.data["has_baseline"] is True
    assert response.data["new_findings"] == ["WG-HDR-002"]
    assert response.data["resolved_findings"] == ["WG-HDR-001"]


def test_notifications_are_recipient_and_organization_scoped(api_client, user, organization):
    from apps.audit.models import Notification
    other = User.objects.create_user(username="notify-other@example.test", email="notify-other@example.test", password="Other-User-Password-5678!")
    Membership.objects.create(user=other, organization=organization, role=Membership.Role.ANALYST)
    own = Notification.objects.create(recipient=user, organization=organization, title="Own", message="Own notification")
    Notification.objects.create(recipient=other, organization=organization, title="Other", message="Private notification")
    response = api_client.get("/api/v1/notifications/")
    assert response.status_code == 200
    assert [row["id"] for row in response.data["results"]] == [own.id]
    read = api_client.post(f"/api/v1/notifications/{own.id}/read/", {}, format="json")
    assert read.status_code == 200
    assert read.data["read_at"] is not None


def test_report_creation_persists_requested_language(api_client, user, verified_asset):
    from apps.reports.models import SecurityReport
    scan = Scan.objects.create(asset=verified_asset, requested_by=user, status=Scan.Status.COMPLETED)
    response = api_client.post("/api/v1/reports/", {"scan": scan.id, "language": "fa"}, format="json")
    assert response.status_code == 201
    assert response.data["language"] == "fa"
    assert SecurityReport.objects.get(pk=response.data["id"]).language == "fa"
    invalid = api_client.post("/api/v1/reports/", {"scan": scan.id, "language": "xx"}, format="json")
    assert invalid.status_code == 400
