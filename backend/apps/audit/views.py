from django.utils import timezone
from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.audit.models import Notification
from apps.audit.serializers import NotificationSerializer
from apps.organizations.permissions import get_membership


class NotificationListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        membership = get_membership(request.user)
        rows = Notification.objects.filter(
            recipient=request.user,
            organization=membership.organization,
        ).order_by("-created_at")[:50]
        unread_count = Notification.objects.filter(
            recipient=request.user,
            organization=membership.organization,
            read_at__isnull=True,
        ).count()
        return Response({"unread_count": unread_count, "results": NotificationSerializer(rows, many=True).data})


class NotificationReadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        membership = get_membership(request.user)
        try:
            item = Notification.objects.get(
                pk=pk,
                recipient=request.user,
                organization=membership.organization,
            )
        except Notification.DoesNotExist:
            raise NotFound("Notification not found.")
        if item.read_at is None:
            item.read_at = timezone.now()
            item.save(update_fields=["read_at"])
        return Response(NotificationSerializer(item).data)

    def delete(self, request, pk):
        membership = get_membership(request.user)
        deleted, _ = Notification.objects.filter(
            pk=pk,
            recipient=request.user,
            organization=membership.organization,
        ).delete()
        if not deleted:
            raise NotFound("Notification not found.")
        return Response(status=204)
