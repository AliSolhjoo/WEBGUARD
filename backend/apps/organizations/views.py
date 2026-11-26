from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from apps.organizations.models import Membership
from apps.organizations.permissions import get_membership, require_admin

class OrganizationView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        m = get_membership(request.user)
        return Response({"id": m.organization_id, "name": m.organization.name, "slug": m.organization.slug, "role": m.role, "created_at": m.organization.created_at})

class MembersView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        m = get_membership(request.user)
        rows = Membership.objects.filter(organization=m.organization).select_related("user").order_by("id")
        return Response([{"id": r.id, "user_id": r.user_id, "email": r.user.email, "full_name": r.user.full_name, "role": r.role, "joined_at": r.created_at} for r in rows])
    def post(self, request):
        m = get_membership(request.user)
        require_admin(m)
        email = str(request.data.get("email", "")).strip().lower()
        role = request.data.get("role", Membership.Role.VIEWER)
        if role not in {Membership.Role.ADMIN, Membership.Role.ANALYST, Membership.Role.VIEWER}:
            return Response({"detail": "Unsupported member role."}, status=400)
        from apps.accounts.models import User
        user = User.objects.filter(email=email).first()
        if not user:
            return Response({"detail": "Create the user's account before adding them to this organization."}, status=404)
        existing = Membership.objects.filter(user=user).select_related("organization").first()
        if existing and existing.organization_id != m.organization_id:
            return Response({"detail": "This account already belongs to another workspace. Workspace switching is not supported in v1."}, status=409)
        if existing and existing.role == Membership.Role.OWNER:
            return Response({"detail": "The workspace owner role cannot be changed through member management."}, status=400)
        membership, created = Membership.objects.get_or_create(user=user, organization=m.organization, defaults={"role": role})
        if not created:
            membership.role = role
            membership.save(update_fields=["role"])
        from apps.audit.services import write_audit
        write_audit(request.user, m.organization, "membership.saved", {"member_email": user.email, "role": membership.role}, "membership", membership.id)
        return Response({"id": membership.id, "email": user.email, "role": membership.role}, status=201 if created else 200)
