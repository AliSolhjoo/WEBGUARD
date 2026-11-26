import dns.resolver
from django.db import transaction
from django.utils import timezone as django_timezone
from apps.scans.models import Scan, ScanCheck, Finding
from apps.assets.domain_validation import UnsafeTarget
from apps.scanner.network import probe_origin, probe_homepage
from apps.scanner.checks import run_checks
from apps.audit.services import create_notification, write_audit
from apps.assets.models import Asset


def collect_dns_records(domain):
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 3
    data = {"txt": [], "dmarc": [], "caa": [], "errors": {}}

    def collect(name, record_type, field):
        try:
            answer = resolver.resolve(name, record_type, search=False, raise_on_no_answer=False)
            if answer.rrset:
                for record in answer:
                    if record_type == "TXT":
                        value = b"".join(record.strings).decode("utf-8", "replace")
                    else:
                        value = f"{getattr(record, 'flags', 0)} {getattr(record, 'tag', '')} {getattr(record, 'value', '')}"
                    data[field].append(str(value)[:500])
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            # A missing record is a negative observation, not a resolver failure.
            return
        except dns.exception.DNSException as exc:
            data["errors"][field] = type(exc).__name__

    apex = domain.rstrip(".") + "."
    collect(apex, "TXT", "txt")
    collect(f"_dmarc.{domain.rstrip('.')}.", "TXT", "dmarc")
    collect(apex, "CAA", "caa")
    return data


def _probe_asset(domain):
    # Each request resolves and validates the complete A/AAAA set immediately before an IP-pinned connect.
    http_result = probe_origin(domain, "http")
    https_result = probe_origin(domain, "https")
    return http_result, https_result


def execute_scan(scan_id):
    scan = Scan.objects.select_related("asset", "asset__organization").get(pk=scan_id)
    if scan.status != Scan.Status.PENDING:
        return scan
    if scan.asset.status != Asset.Status.VERIFIED or not scan.asset.organization.is_active:
        Scan.objects.filter(pk=scan_id, status=Scan.Status.PENDING).update(status=Scan.Status.FAILED, finished_at=django_timezone.now(), error_message="A verified asset in an active workspace is required before scanning.")
        return Scan.objects.get(pk=scan_id)
    claimed = Scan.objects.filter(pk=scan_id, status=Scan.Status.PENDING).update(status=Scan.Status.RUNNING, started_at=django_timezone.now())
    scan.refresh_from_db()
    if not claimed:
        return scan
    if scan.status != Scan.Status.RUNNING:
        return scan
    try:
        http_result, https_result = _probe_asset(scan.asset.domain)
        scan.refresh_from_db()
        if scan.status != Scan.Status.RUNNING:
            return scan
        dns_records = collect_dns_records(scan.asset.domain)
        scan.refresh_from_db()
        if scan.status != Scan.Status.RUNNING:
            return scan
        content_result = None
        if https_result.status is not None and https_result.error is None:
            # Content sampling is deliberately limited to the verified origin root.
            # Do not turn a server-controlled redirect path (for example /logout)
            # into an arbitrary GET request during a passive assessment.
            content_result = probe_homepage(scan.asset.domain, f"https://{scan.asset.domain}/")
        outcomes = run_checks(scan.asset.domain, http_result, https_result, dns_records, content_result)
        with transaction.atomic():
            scan.refresh_from_db()
            if scan.status != Scan.Status.RUNNING:
                return scan
            ScanCheck.objects.filter(scan=scan).delete()
            for outcome in outcomes:
                check = ScanCheck.objects.create(
                    scan=scan, check_id=outcome.check_id, name=outcome.name, category=outcome.category,
                    status=outcome.status, severity=outcome.severity, description=outcome.description,
                    recommendation=outcome.recommendation, evidence=outcome.evidence,
                    duration_ms=0,  # Per-check timing is not instrumented yet; avoid reporting a fabricated duration.
                )
                if outcome.status == "fail":
                    Finding.objects.create(check_result=check)
            scan.total_checks = len(outcomes)
            scan.passed_checks = sum(x.status == "pass" for x in outcomes)
            scan.failed_checks = sum(x.status == "fail" for x in outcomes)
            scan.info_checks = sum(x.status in {"info", "error"} for x in outcomes)
            scan.status = Scan.Status.COMPLETED
            scan.finished_at = django_timezone.now()
            scan.save(update_fields=["total_checks", "passed_checks", "failed_checks", "info_checks", "status", "finished_at"])
            scan.asset.last_scanned_at = django_timezone.now()
            scan.asset.save(update_fields=["last_scanned_at"])
            write_audit(scan.requested_by, scan.asset.organization, "scan.completed", {"scan_id": scan.id, "failed_checks": scan.failed_checks}, "scan", scan.id)
            high_critical = sum(1 for item in outcomes if item.status == "fail" and item.severity in {"high", "critical"})
            level = "critical" if any(item.status == "fail" and item.severity == "critical" for item in outcomes) else "warning" if high_critical else "success"
            create_notification(
                scan.requested_by,
                scan.asset.organization,
                level,
                "Assessment completed",
                f"Scan #{scan.id} for {scan.asset.domain} completed with {scan.failed_checks} failed check(s); {high_critical} high/critical finding(s).",
                "/findings" if scan.failed_checks else "/scans",
                {"scan_id": scan.id, "domain": scan.asset.domain, "failed_checks": scan.failed_checks, "high_critical_findings": high_critical},
            )
    except UnsafeTarget as exc:
        updated = Scan.objects.filter(pk=scan_id, status=Scan.Status.RUNNING).update(status=Scan.Status.FAILED, finished_at=django_timezone.now(), error_message=str(exc)[:500])
        if updated:
            write_audit(scan.requested_by, scan.asset.organization, "scan.blocked", {"scan_id": scan.id, "reason": str(exc)[:160]}, "scan", scan.id)
            create_notification(scan.requested_by, scan.asset.organization, "warning", "Assessment blocked", f"Scan #{scan.id} was blocked by the target safety policy.", "/scans", {"scan_id": scan.id, "domain": scan.asset.domain})
    except Exception as exc:
        # Do not disclose raw network/library internals to the API or persistent logs.
        updated = Scan.objects.filter(pk=scan_id, status=Scan.Status.RUNNING).update(status=Scan.Status.FAILED, finished_at=django_timezone.now(), error_message=f"Assessment failed ({type(exc).__name__}).")
        if updated:
            write_audit(scan.requested_by, scan.asset.organization, "scan.failed", {"scan_id": scan.id, "error_type": type(exc).__name__}, "scan", scan.id)
            create_notification(scan.requested_by, scan.asset.organization, "warning", "Assessment failed", f"Scan #{scan.id} failed ({type(exc).__name__}). Review the scan status and retry when appropriate.", "/scans", {"scan_id": scan.id, "domain": scan.asset.domain, "error_type": type(exc).__name__})
    return Scan.objects.get(pk=scan_id)
