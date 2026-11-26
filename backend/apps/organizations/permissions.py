from rest_framework.exceptions import PermissionDenied, NotFound
from apps.organizations.models import Membership

WRITE_ROLES = {Membership.Role.OWNER, Membership.Role.ADMIN, Membership.Role.ANALYST}
ADMIN_ROLES = {Membership.Role.OWNER, Membership.Role.ADMIN}

def get_membership(user):
    membership = Membership.objects.select_related("organization").filter(user=user, organization__is_active=True).order_by("id").first()
    if not membership:
        raise NotFound("No active organization is associated with this account.")
    return membership

def require_write(membership):
    if membership.role not in WRITE_ROLES:
        raise PermissionDenied("Your organization role is read-only.")

def require_admin(membership):
    if membership.role not in ADMIN_ROLES:
        raise PermissionDenied("Organization administrator permission is required.")
