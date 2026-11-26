import time
from datetime import timedelta
from django.utils import timezone
from django.core.management.base import BaseCommand
from django.db import OperationalError
from apps.scans.models import Scan
from apps.scanner.runner import execute_scan

class Command(BaseCommand):
    help = "Process queued authorized passive WEBGUARD assessments."
    def add_arguments(self, parser):
        parser.add_argument("--once", action="store_true", help="Process one pending scan then exit.")
        parser.add_argument("--sleep", type=float, default=2.0, help="Polling interval in seconds.")
    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS("WEBGUARD worker started (passive profile only)."))
        last_recovery = timezone.now()
        while True:
            try:
                now = timezone.now()
                if now - last_recovery >= timedelta(minutes=1):
                    stale_before = now - timedelta(minutes=5)
                    recovered = Scan.objects.filter(status=Scan.Status.RUNNING, started_at__lt=stale_before).update(
                        status=Scan.Status.FAILED, finished_at=now, error_message="Worker interruption detected; job was not automatically retried."
                    )
                    if recovered:
                        self.stdout.write(self.style.WARNING(f"Marked {recovered} stale running scan(s) as failed."))
                    last_recovery = now
                scan = Scan.objects.filter(status=Scan.Status.PENDING, asset__status="verified", asset__organization__is_active=True).order_by("created_at").first()
                if scan:
                    self.stdout.write(f"Processing scan #{scan.id} for verified asset {scan.asset.domain}")
                    final = execute_scan(scan.id)
                    self.stdout.write(self.style.SUCCESS(f"Scan #{scan.id}: {final.status}"))
                elif options["once"]:
                    return
            except OperationalError:
                self.stderr.write("Database is temporarily unavailable; retrying.")
            if options["once"]:
                return
            time.sleep(max(0.5, min(options["sleep"], 30)))
