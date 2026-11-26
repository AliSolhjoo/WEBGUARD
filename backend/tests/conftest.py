import pytest

@pytest.fixture
def user(db):
    from apps.accounts.models import User
    return User.objects.create_user(username="analyst@example.test", email="analyst@example.test", password="Correct-Horse-Battery-42!", full_name="Test Analyst")

@pytest.fixture
def organization(db, user):
    from apps.organizations.models import Organization
    return Organization.objects.create(name="Test Lab", slug="test-lab", created_by=user)

@pytest.fixture
def membership(db, user, organization):
    from apps.organizations.models import Membership
    return Membership.objects.create(user=user, organization=organization, role=Membership.Role.OWNER)

@pytest.fixture
def api_client(user, membership):
    from rest_framework.test import APIClient
    client = APIClient()
    client.force_authenticate(user=user)
    return client

@pytest.fixture
def verified_asset(db, user, organization):
    from apps.assets.models import Asset
    return Asset.objects.create(organization=organization, domain="example.com", status=Asset.Status.VERIFIED,
        verification_token="fixture-token", created_by=user)
