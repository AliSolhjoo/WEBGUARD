from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils.text import slugify
import secrets
from apps.organizations.models import Organization, Membership

class Command(BaseCommand):
    help = "Create an initial WEBGUARD administrator and organization."
    def add_arguments(self, parser):
        parser.add_argument("--username", required=True)
        parser.add_argument("--email", required=True)
        parser.add_argument("--organization", required=True)
        parser.add_argument("--slug", required=False)
        parser.add_argument("--password", required=False)
    @transaction.atomic
    def handle(self, *args, **opts):
        User = get_user_model()
        email = opts["email"].strip().lower()
        password = opts.get("password")
        user = User.objects.filter(email=email).first()
        if not user:
            user = User.objects.create_user(username=opts["username"], email=email, password=password or secrets.token_urlsafe(24))
        fields = []
        if not user.is_staff:
            user.is_staff = True
            fields.append("is_staff")
        if not user.is_superuser:
            user.is_superuser = True
            fields.append("is_superuser")
        if fields:
            user.save(update_fields=fields)
        slug = opts.get("slug") or slugify(opts["organization"]) or "security-lab"
        org, _ = Organization.objects.get_or_create(slug=slug, defaults={"name": opts["organization"], "created_by": user})
        existing_membership = Membership.objects.filter(user=user).first()
        if existing_membership and existing_membership.organization_id != org.id:
            raise CommandError("This account already belongs to another workspace; use a separate administrator account.")
        Membership.objects.get_or_create(user=user, organization=org, defaults={"role": Membership.Role.OWNER})
        self.stdout.write(self.style.SUCCESS(f"Administrator {email} is ready for organization {org.name}."))
        if not password:
            self.stdout.write(self.style.WARNING("No password supplied. Set a password for this account using `python manage.py changepassword <username>`."))
