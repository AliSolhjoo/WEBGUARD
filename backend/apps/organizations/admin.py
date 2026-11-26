from django.contrib import admin
from apps.organizations.models import Organization, Membership
admin.site.register(Organization)
admin.site.register(Membership)
