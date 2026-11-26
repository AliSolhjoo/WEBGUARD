from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import validate_email
from django.utils.text import slugify
from django.db import transaction, IntegrityError
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from apps.accounts.models import User
from apps.organizations.models import Organization, Membership
from apps.audit.services import write_audit

class RegisterView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "register"

    def post(self, request):
        email = str(request.data.get("email", "")).strip().lower()
        password = str(request.data.get("password", ""))
        full_name = str(request.data.get("full_name", "")).strip()[:160]
        org_name = str(request.data.get("organization_name", "")).strip()[:120]
        if not email or not org_name or len(password) < 12:
            return Response({"detail": "Email, organization name and a password of at least 12 characters are required."}, status=400)
        try:
            validate_email(email)
        except DjangoValidationError:
            return Response({"detail": "Enter a valid email address."}, status=400)
        if User.objects.filter(email=email).exists():
            return Response({"detail": "An account with this email already exists."}, status=400)
        candidate = User(email=email, username=email, full_name=full_name)
        try:
            password_validation.validate_password(password, candidate)
        except DjangoValidationError as exc:
            return Response({"detail": list(exc.messages)}, status=400)
        try:
            with transaction.atomic():
                user = User.objects.create_user(username=email, email=email, password=password, full_name=full_name)
                slug_base = slugify(org_name, allow_unicode=False) or "workspace"
                slug = slug_base[:45]
                suffix = 2
                while Organization.objects.filter(slug=slug).exists():
                    slug = f"{slug_base[:40]}-{suffix}"
                    suffix += 1
                org = Organization.objects.create(name=org_name, slug=slug, created_by=user)
                Membership.objects.create(user=user, organization=org, role=Membership.Role.OWNER)
                write_audit(user, org, "account.registered", {"email": email})
        except IntegrityError:
            return Response({"detail": "An account or workspace with these details already exists."}, status=409)
        refresh = RefreshToken.for_user(user)
        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
            "organization": {"id": org.id, "name": org.name, "slug": org.slug},
        }, status=status.HTTP_201_CREATED)

class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = "login"


class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        membership = Membership.objects.select_related("organization").filter(user=request.user).first()
        return Response({
            "id": request.user.id,
            "email": request.user.email,
            "full_name": request.user.full_name,
            "organization": ({"id": membership.organization_id, "name": membership.organization.name, "slug": membership.organization.slug, "role": membership.role} if membership else None),
        })


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        raw_refresh = request.data.get("refresh")
        if not raw_refresh:
            return Response({"detail": "Refresh token is required."}, status=400)
        try:
            token = RefreshToken(raw_refresh)
            if str(token.get("user_id")) != str(request.user.pk):
                return Response({"detail": "The refresh token does not belong to the authenticated account."}, status=403)
            token.blacklist()
        except TokenError:
            return Response({"detail": "Refresh token is invalid or already revoked."}, status=400)
        return Response(status=status.HTTP_205_RESET_CONTENT)
