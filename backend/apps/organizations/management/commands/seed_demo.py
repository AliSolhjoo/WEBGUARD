from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.text import slugify
from apps.organizations.models import Organization, Membership
from apps.assets.models import Asset

class Command(BaseCommand):
    help = "Create local demo data only; no scan is queued and no external target is contacted."
    @transaction.atomic
    def handle(self, *args, **options):
        User = get_user_model()
        user, created = User.objects.get_or_create(email="demo@webguard.local", defaults={"username": "demo@webguard.local", "full_name": "WEBGUARD Demo", "password": "!"})
        if created or not user.has_usable_password():
            user.set_password("Change-This-Demo-Password-123!")
            user.save(update_fields=["password"])
        org, _ = Organization.objects.get_or_create(slug="demo-security-lab", defaults={"name": "Demo Security Lab", "created_by": user})
        existing_membership = Membership.objects.filter(user=user).first()
        if existing_membership and existing_membership.organization_id != org.id:
            raise CommandError("The demo account already belongs to another workspace; do not move it automatically.")
        Membership.objects.get_or_create(user=user, organization=org, defaults={"role": Membership.Role.OWNER})
        Asset.objects.get_or_create(organization=org, domain="example.com", defaults={"status": Asset.Status.PENDING, "verification_token": "demo-verification-token", "created_by": user})
        self.stdout.write(self.style.SUCCESS("Demo account: demo@webguard.local / Change-This-Demo-Password-123!"))
        self.stdout.write("Demo asset remains unverified. No external scans are run.")
