import dns.resolver
import dns.exception
from django.db import IntegrityError, transaction
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound
from rest_framework import status
from apps.assets.models import Asset
from apps.assets.serializers import AssetSerializer
from apps.organizations.permissions import get_membership, require_write
from apps.audit.services import write_audit

class AssetListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        membership = get_membership(request.user)
        rows = Asset.objects.filter(organization=membership.organization).order_by("-created_at")
        return Response(AssetSerializer(rows, many=True).data)
    def post(self, request):
        membership = get_membership(request.user)
        require_write(membership)
        serializer = AssetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if Asset.objects.filter(organization=membership.organization, domain=serializer.validated_data["domain"]).exists():
            from rest_framework.exceptions import ValidationError
            raise ValidationError({"domain": "This domain is already registered in this workspace."})
        try:
            with transaction.atomic():
                asset = serializer.save(organization=membership.organization, created_by=request.user)
        except IntegrityError:
            from rest_framework.exceptions import ValidationError
            raise ValidationError({"domain": "This domain is already registered in this workspace."})
        write_audit(request.user, membership.organization, "asset.created", {"domain": asset.domain}, "asset", asset.id)
        return Response(AssetSerializer(asset).data, status=status.HTTP_201_CREATED)

class AssetDetailView(APIView):
    permission_classes = [IsAuthenticated]
    def get_object(self, request, pk):
        membership = get_membership(request.user)
        try:
            return Asset.objects.get(pk=pk, organization=membership.organization)
        except Asset.DoesNotExist:
            raise NotFound("Asset not found.")
    def get(self, request, pk):
        return Response(AssetSerializer(self.get_object(request, pk)).data)
    def delete(self, request, pk):
        membership = get_membership(request.user)
        require_write(membership)
        asset = self.get_object(request, pk)
        domain = asset.domain
        asset.delete()
        write_audit(request.user, membership.organization, "asset.deleted", {"domain": domain}, "asset", pk)
        return Response(status=204)

class AssetVerificationView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, pk):
        membership = get_membership(request.user)
        require_write(membership)
        try:
            asset = Asset.objects.get(pk=pk, organization=membership.organization)
        except Asset.DoesNotExist:
            raise NotFound("Asset not found.")
        return Response({
            "asset_id": asset.id,
            "domain": asset.domain,
            "status": asset.status,
            "record_name": f"_webguard-verify.{asset.domain}",
            "record_type": "TXT",
            "expected_value": f"webguard-verification={asset.verification_token}",
            "verified_at": asset.verified_at,
        })
    def post(self, request, pk):
        membership = get_membership(request.user)
        require_write(membership)
        try:
            asset = Asset.objects.get(pk=pk, organization=membership.organization)
        except Asset.DoesNotExist:
            raise NotFound("Asset not found.")
        if asset.status == Asset.Status.VERIFIED:
            return Response({"status": asset.status, "detail": "Asset is already verified."})
        record = f"_webguard-verify.{asset.domain}"
        try:
            resolver = dns.resolver.Resolver(configure=True)
            resolver.timeout = 2
            resolver.lifetime = 5
            answer = resolver.resolve(record + ".", "TXT", search=False)
            values = [b"".join(item.strings).decode("utf-8", "replace") for item in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return Response({"detail": "The verification TXT record was not found. Check DNS propagation and try again."}, status=400)
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            return Response({"detail": "DNS lookup timed out. Check your connection and DNS resolver, then retry."}, status=503)
        except (dns.exception.DNSException, OSError):
            return Response({"detail": "The DNS resolver could not complete the lookup. Try again later."}, status=503)
        expected = f"webguard-verification={asset.verification_token}"
        if expected not in values:
            return Response({"detail": "The DNS TXT record does not match this asset's verification challenge."}, status=400)
        asset.status = Asset.Status.VERIFIED
        asset.verified_at = timezone.now()
        asset.save(update_fields=["status", "verified_at"])
        write_audit(request.user, membership.organization, "asset.verified", {"domain": asset.domain}, "asset", asset.id)
        return Response({"status": asset.status, "verified_at": asset.verified_at})
