from django.contrib import admin
from apps.scans.models import Scan, ScanCheck, Finding
admin.site.register(Scan)
admin.site.register(ScanCheck)
admin.site.register(Finding)
