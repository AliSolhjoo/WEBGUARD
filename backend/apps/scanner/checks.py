"""Explainable, passive checks over bounded HTTP/TLS/DNS observations."""

from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
import re
import ssl
from urllib.parse import urlsplit


@dataclass
class Outcome:
    check_id: str
    name: str
    category: str
    status: str
    severity: str
    description: str
    recommendation: str
    evidence: dict


def result(check_id, name, category, status, severity, description, recommendation, evidence=None):
    return Outcome(check_id, name, category, status, severity, description, recommendation, evidence or {})


class _ResourceParser(HTMLParser):
    """Extract only insecure resource references; do not crawl or fetch links."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.insecure_resources = []
        self.generators = []

    def handle_starttag(self, tag, attrs):
        values = {key.lower(): value for key, value in attrs if key}
        resource_urls = []
        if values.get("src"):
            resource_urls.append(values["src"])
        if values.get("poster"):
            resource_urls.append(values["poster"])
        if values.get("srcset"):
            for item in values["srcset"].split(","):
                candidate = item.strip().split(" ", 1)[0]
                if candidate:
                    resource_urls.append(candidate)
        if tag.lower() == "link" and values.get("href"):
            rel = {item.lower() for item in (values.get("rel") or "").split()}
            if rel.intersection({"stylesheet", "preload", "modulepreload", "icon"}):
                resource_urls.append(values["href"])
        for candidate in resource_urls:
            candidate = (candidate or "").strip()
            if candidate.lower().startswith("http://"):
                try:
                    host = (urlsplit(candidate).hostname or "").lower()[:120]
                except ValueError:
                    host = "invalid-url"
                self.insecure_resources.append(host or "unknown-host")
        if tag.lower() == "meta" and (values.get("name") or "").lower() == "generator":
            if values.get("content"):
                self.generators.append(values["content"][:120])


def _parse_csp_directives(value):
    directives = {}
    for raw in (value or "").split(";"):
        parts = raw.strip().lower().split()
        if parts:
            directives[parts[0]] = parts[1:]
    return directives


def _csp_script_unsafe(value):
    directives = _parse_csp_directives(value)
    fallback = directives.get("default-src", [])
    script_sources = directives.get("script-src", fallback)
    element_sources = directives.get("script-src-elem", script_sources)
    attribute_sources = directives.get("script-src-attr", script_sources)
    return {
        "unsafe_inline": "'unsafe-inline'" in element_sources or "'unsafe-inline'" in attribute_sources,
        "unsafe_eval": "'unsafe-eval'" in script_sources,
    }


def _spf_all_qualifier(record):
    # RFC 7208 requires the all mechanism to be the final mechanism.
    # Return None for missing or non-terminal qualifiers so the policy is not
    # incorrectly described as strict merely because an earlier token was -all.
    terms = (record or "").lower().split()
    if len(terms) < 2 or terms[0] != "v=spf1":
        return None
    terminal = terms[-1]
    return terminal if terminal in {"all", "+all", "-all", "~all", "?all"} else None


def _dmarc_policy(record):
    for directive in (record or "").split(";"):
        key, sep, value = directive.strip().partition("=")
        if sep and key.strip().lower() == "p":
            return value.strip().lower()
    return None


def run_checks(host, http_result, https_result, dns_records, content_result=None):
    outcomes = []
    https_ok = https_result.status is not None and https_result.error is None

    outcomes.append(result(
        "WG-HTTP-001", "HTTPS availability", "Transport Security",
        "pass" if https_ok else "fail", "high",
        "HTTPS endpoint completed a verified TLS handshake." if https_ok else "The HTTPS endpoint could not be reached with a trusted certificate.",
        "Enable HTTPS with a publicly trusted certificate and keep the certificate chain valid.",
        {"https_status": https_result.status, "error": https_result.error},
    ))

    raw_location = http_result.redirect_location or http_result.header("location")
    try:
        parsed_location = urlsplit(raw_location or "")
        location_host_matches = (parsed_location.hostname or "").lower().rstrip(".") == host.lower().rstrip(".")
        location_scheme_is_https = parsed_location.scheme.lower() == "https"
        location_evidence = {
            "scheme": parsed_location.scheme[:12] or None,
            "host_matches_verified_asset": location_host_matches,
            "query_present": bool(parsed_location.query),
        }
    except ValueError:
        location_host_matches = False
        location_scheme_is_https = False
        location_evidence = {"location_parseable": False}
    redirect_ok = bool(
        http_result.redirect_status in {301, 302, 307, 308}
        and location_host_matches and location_scheme_is_https and https_ok
    )
    outcomes.append(result(
        "WG-HTTP-002", "HTTP to HTTPS redirect", "Transport Security",
        "pass" if redirect_ok else "fail", "medium",
        "Plain HTTP redirects to the HTTPS endpoint." if redirect_ok else "The HTTP endpoint did not demonstrate a same-host HTTPS redirect.",
        "Redirect all HTTP requests to the equivalent HTTPS URL using a permanent 301 or 308 redirect.",
        {"http_status": http_result.status, "redirect_status": http_result.redirect_status, **location_evidence},
    ))

    if https_ok:
        cert = https_result.certificate or {}
        not_after = cert.get("not_after")
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            cert_ok = days_left >= 0
            severity = "high" if days_left < 7 else "medium" if days_left < 30 else "low"
            status = "fail" if not cert_ok or days_left < 30 else "pass"
            outcomes.append(result(
                "WG-TLS-001", "TLS certificate expiry", "TLS", status, severity,
                f"Certificate expiry is {not_after}; approximately {days_left} days remain.",
                "Renew certificates before expiry and monitor their validity continuously.",
                {"not_after": not_after, "days_remaining": days_left, "tls_version": https_result.tls_version},
            ))
        except (TypeError, ValueError, OverflowError):
            outcomes.append(result(
                "WG-TLS-001", "TLS certificate expiry", "TLS", "error", "informational",
                "The certificate expiry timestamp could not be parsed.",
                "Review the certificate chain and TLS configuration.", {"not_after": not_after},
            ))
        proto = https_result.tls_version or "unknown"
        weak = proto in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}
        outcomes.append(result(
            "WG-TLS-002", "Negotiated TLS version", "TLS", "fail" if weak else "pass",
            "high" if weak else "low", f"The server negotiated {proto}.",
            "Allow TLS 1.2 or TLS 1.3 and disable obsolete protocol versions.", {"tls_version": proto},
        ))
    else:
        outcomes.append(result(
            "WG-TLS-001", "TLS certificate expiry", "TLS", "error", "informational",
            "Certificate metadata was unavailable because a verified HTTPS connection could not be established.",
            "Restore a valid HTTPS endpoint before evaluating certificate expiry.", {"error": https_result.error},
        ))
        outcomes.append(result(
            "WG-TLS-002", "Negotiated TLS version", "TLS", "error", "informational",
            "The negotiated TLS version could not be observed because HTTPS validation failed.",
            "Restore a valid HTTPS endpoint and allow only TLS 1.2 or TLS 1.3.", {"error": https_result.error},
        ))

    # Do not credit security headers observed only on a clear-text HTTP response.
    headers = https_result.headers if https_ok else {}
    header_checks = [
        ("WG-HDR-001", "Content-Security-Policy", "content-security-policy", "medium", "Configure a restrictive Content-Security-Policy that fits the application and avoid unsafe-inline where practical."),
        ("WG-HDR-002", "Strict-Transport-Security", "strict-transport-security", "medium", "After confirming HTTPS works across the site, configure HSTS with an appropriate max-age; consider includeSubDomains only when all subdomains are HTTPS-ready."),
        ("WG-HDR-003", "X-Content-Type-Options", "x-content-type-options", "low", "Set X-Content-Type-Options: nosniff."),
        ("WG-HDR-004", "Referrer-Policy", "referrer-policy", "low", "Set a privacy-conscious Referrer-Policy such as strict-origin-when-cross-origin."),
        ("WG-HDR-005", "Permissions-Policy", "permissions-policy", "low", "Set a Permissions-Policy that disables browser capabilities the application does not need."),
    ]
    for check_id, title, key, severity, recommendation in header_checks:
        value = headers.get(key)
        if key == "strict-transport-security":
            value = https_result.headers.get(key) if https_ok else None
        passed = bool(value)
        if key == "referrer-policy":
            recognized = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin"}
            policy_tokens = [part.strip().lower() for part in str(value or "").split(",") if part.strip()]
            recognized_tokens = [token for token in policy_tokens if token in recognized]
            # Browsers use the last recognized policy in a comma-separated header.
            passed = bool(recognized_tokens) and recognized_tokens[-1] == policy_tokens[-1]
        elif key == "x-content-type-options":
            passed = str(value or "").strip().lower() == "nosniff"
        elif key == "strict-transport-security":
            max_age = None
            for directive in str(value or "").split(";"):
                name, separator, raw_value = directive.strip().partition("=")
                if name.lower() == "max-age" and separator:
                    try:
                        max_age = int(raw_value.strip().strip('"'))
                    except ValueError:
                        max_age = None
                    break
            passed = max_age is not None and max_age >= 15_768_000
        outcomes.append(result(
            check_id, title, "Security Headers", "pass" if passed else "fail", severity,
            f"{title} contains a recognized secure value." if passed else f"{title} is missing or does not contain a recognized secure value on the root response.",
            recommendation,
            {"present": bool(value), "recognized_secure_value": passed},
        ))

    csp = headers.get("content-security-policy", "").lower()
    xfo = headers.get("x-frame-options", "").lower()
    frame_ancestors = _parse_csp_directives(csp).get("frame-ancestors", [])
    csp_frame_ancestors_restrictive = bool(frame_ancestors) and "*" not in frame_ancestors
    if "'none'" in frame_ancestors and len(frame_ancestors) > 1:
        csp_frame_ancestors_restrictive = False
    frame_protection = bool(xfo in {"deny", "sameorigin"} or csp_frame_ancestors_restrictive)
    outcomes.append(result(
        "WG-HDR-006", "Clickjacking protection", "Security Headers", "pass" if frame_protection else "fail", "medium",
        "A recognized framing restriction was observed." if frame_protection else "No X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors directive was observed.",
        "Set X-Frame-Options: DENY or SAMEORIGIN, or define a restrictive frame-ancestors directive in CSP.",
        {"x_frame_options_restrictive": xfo in {"deny", "sameorigin"},
         "csp_frame_ancestors_restrictive": csp_frame_ancestors_restrictive},
    ))

    if csp:
        unsafe = _csp_script_unsafe(csp)
        status = "fail" if any(unsafe.values()) else "pass"
        outcomes.append(result(
            "WG-HDR-007", "CSP unsafe script directives", "Security Headers", status, "medium",
            "The Content-Security-Policy includes unsafe script directives." if status == "fail" else "No unsafe-inline or unsafe-eval script directive was observed in the sampled CSP.",
            "Remove unsafe-inline and unsafe-eval from script execution directives; use nonces or hashes where inline scripts are required.",
            unsafe,
        ))
    else:
        outcomes.append(result(
            "WG-HDR-007", "CSP unsafe script directives", "Security Headers", "info", "informational",
            "This sub-check could not evaluate script directives because no CSP was observed.",
            "Add a Content-Security-Policy and then review script execution directives.", {"evaluated": False},
        ))

    cookies = https_result.cookies if https_ok else []
    if not cookies:
        outcomes.append(result(
            "WG-COOKIE-001", "Cookie security attributes", "Cookies", "info", "informational",
            "No Set-Cookie headers were observed on the root response, or HTTPS was unavailable.",
            "Review application cookies on authenticated and state-changing routes; session cookies should use Secure, HttpOnly and an appropriate SameSite value.",
            {"cookies_observed": 0},
        ))
    else:
        missing = [
            {"name": cookie["name"], "missing": [
                key for key in ("secure", "httponly", "samesite")
                if not cookie.get(key) or (key == "samesite" and cookie.get(key) not in {"lax", "strict", "none"})
            ]}
            for cookie in cookies
        ]
        missing = [item for item in missing if item["missing"]]
        outcomes.append(result(
            "WG-COOKIE-001", "Cookie security attributes", "Cookies", "fail" if missing else "pass",
            "medium" if missing else "low",
            f"{len(missing)} of {len(cookies)} observed cookies have missing or weak security attributes." if missing else f"All {len(cookies)} observed cookies include Secure, HttpOnly and SameSite attributes.",
            "Set Secure and HttpOnly on sensitive cookies and choose SameSite=Lax or Strict unless cross-site behavior is explicitly required. SameSite=None requires Secure.",
            {"cookies_observed": len(cookies), "cookies_with_missing_attributes": missing},
        ))

    txt_records = dns_records.get("txt", [])
    dmarc_records = dns_records.get("dmarc", [])
    caa_records = dns_records.get("caa", [])
    spf_records = [value for value in txt_records if "v=spf1" in value.lower()]
    dmarc_record = next((value for value in dmarc_records if "v=dmarc1" in value.lower()), None)
    spf_error = dns_records.get("errors", {}).get("txt")
    dmarc_error = dns_records.get("errors", {}).get("dmarc")
    caa_error = dns_records.get("errors", {}).get("caa")

    spf_status = "pass" if spf_records else "error" if spf_error else "fail"
    outcomes.append(result(
        "WG-DNS-001", "SPF record", "DNS", spf_status, "low" if spf_status != "error" else "informational",
        "An SPF TXT record was observed." if spf_records else "SPF lookup failed; record presence is unknown." if spf_error else "No SPF record was observed at the apex domain.",
        "Publish a single SPF policy that accurately lists authorized mail senders; avoid multiple SPF records.",
        {"observed": bool(spf_records), "record_count": len(spf_records), "lookup_error": spf_error},
    ))

    if spf_records:
        qualifiers = [_spf_all_qualifier(record) for record in spf_records]
        permissive = any(value in {"+all", "?all", "all"} for value in qualifiers)
        duplicate = len(spf_records) > 1
        missing_terminal = any(value is None for value in qualifiers)
        status = "fail" if permissive or duplicate or missing_terminal else "pass"
        outcomes.append(result(
            "WG-DNS-003", "SPF policy strictness", "DNS", status, "high" if permissive else "medium" if duplicate or missing_terminal else "low",
            "The SPF policy is overly permissive, missing a terminal all qualifier, or multiple SPF records were observed." if status == "fail" else "The observed SPF policy has one non-permissive terminal qualifier.",
            "Keep one SPF record and end it with an intentional -all or ~all policy after validating all legitimate sending services.",
            {"all_qualifiers": qualifiers, "multiple_spf_records": duplicate, "missing_terminal_qualifier": missing_terminal},
        ))
    else:
        outcomes.append(result(
            "WG-DNS-003", "SPF policy strictness", "DNS", "error" if spf_error else "info", "informational",
            "SPF strictness could not be evaluated because no SPF record was available." if not spf_error else "SPF strictness could not be evaluated because the DNS lookup failed.",
            "Publish and validate one SPF policy before reviewing its all qualifier.", {"evaluated": False, "lookup_error": spf_error},
        ))

    dmarc_status = "pass" if dmarc_record else "error" if dmarc_error else "fail"
    outcomes.append(result(
        "WG-DNS-002", "DMARC record", "DNS", dmarc_status, "low" if dmarc_status != "error" else "informational",
        "A DMARC record was observed." if dmarc_record else "DMARC lookup failed; record presence is unknown." if dmarc_error else f"No DMARC record was observed at _dmarc.{host}.",
        "Publish a DMARC policy, begin with monitoring if needed, then progress toward enforcement after reviewing reports.",
        {"observed": bool(dmarc_record), "lookup_error": dmarc_error},
    ))
    policy = _dmarc_policy(dmarc_record) if dmarc_record else None
    if dmarc_record:
        if policy in {"quarantine", "reject"}:
            dmarc_policy_status, severity = "pass", "low"
        elif policy == "none":
            dmarc_policy_status, severity = "info", "informational"
        else:
            dmarc_policy_status, severity = "fail", "medium"
        outcomes.append(result(
            "WG-DNS-004", "DMARC enforcement policy", "DNS", dmarc_policy_status, severity,
            f"The observed DMARC policy is {policy or 'missing or invalid'}.",
            "After reviewing DMARC aggregate reports, move from p=none to p=quarantine or p=reject when operationally safe.",
            {"policy": policy},
        ))
    else:
        outcomes.append(result(
            "WG-DNS-004", "DMARC enforcement policy", "DNS", "error" if dmarc_error else "info", "informational",
            "DMARC enforcement cannot be evaluated without a readable DMARC record.",
            "Publish a valid DMARC record and review aggregate reports before enforcement.", {"evaluated": False, "lookup_error": dmarc_error},
        ))

    outcomes.append(result(
        "WG-DNS-005", "CAA record", "DNS", "pass" if caa_records else "error" if caa_error else "info",
        "low" if caa_records else "informational",
        "At least one CAA record was observed." if caa_records else "CAA lookup failed; presence is unknown." if caa_error else "No CAA record was observed.",
        "Consider publishing CAA records to limit which certificate authorities may issue certificates for the domain.",
        {"observed": bool(caa_records), "record_count": len(caa_records), "lookup_error": caa_error},
    ))

    sample = getattr(content_result, "body_sample", "") if content_result else ""
    if content_result and getattr(content_result, "status", None) in {200, 203, 206} and sample:
        parser = _ResourceParser()
        try:
            parser.feed(sample)
        except Exception:
            parser = _ResourceParser()
        insecure_hosts = sorted(set(parser.insecure_resources))[:10]
        outcomes.append(result(
            "WG-CONTENT-001", "Mixed content references", "Content Security", "fail" if parser.insecure_resources else "pass",
            "medium" if parser.insecure_resources else "low",
            f"The bounded homepage sample contains {len(parser.insecure_resources)} insecure HTTP resource reference(s)." if parser.insecure_resources else "No insecure HTTP resource references were found in the bounded homepage sample.",
            "Load scripts, stylesheets, images and other active/passive resources over HTTPS or use same-origin relative URLs.",
            {"insecure_reference_count": len(parser.insecure_resources), "observed_hosts": insecure_hosts,
             "sample_truncated": bool(getattr(content_result, "content_truncated", False)),
             "sample_bytes_limit": 65536},
        ))
        version_disclosed = bool(re.search(r"(?:apache|nginx|iis|php|asp\.net|express|openresty)[/\s-]?\d", headers.get("server", "") + " " + headers.get("x-powered-by", ""), re.I))
        meta_generator = bool(parser.generators)
        source_map_reference = bool(re.search(r"sourceMappingURL\s*=", sample, re.I))
        disclosure = bool(headers.get("x-powered-by") or version_disclosed or meta_generator or source_map_reference)
        outcomes.append(result(
            "WG-CONTENT-002", "Public technology disclosure", "Information Disclosure", "info" if disclosure else "pass", "informational",
            "The sampled homepage exposes technology metadata or source-map references." if disclosure else "No obvious technology disclosure markers were found in the sampled headers or HTML.",
            "Avoid unnecessary product/version headers and ensure production source maps are not publicly exposed unless intentionally published.",
            {"server_header_present": bool(headers.get("server")), "x_powered_by_present": bool(headers.get("x-powered-by")),
             "version_token_detected": version_disclosed, "meta_generator_present": meta_generator,
             "source_map_reference_present": source_map_reference, "sample_truncated": bool(getattr(content_result, "content_truncated", False))},
        ))
    else:
        outcomes.append(result(
            "WG-CONTENT-001", "Mixed content references", "Content Security", "info", "informational",
            "Homepage HTML was unavailable or outside the bounded HTML sample; mixed content could not be evaluated.",
            "Review the public homepage and ensure every resource is loaded over HTTPS.",
            {"evaluated": False, "content_type": getattr(content_result, "content_type", None) if content_result else None,
             "status": getattr(content_result, "status", None) if content_result else None},
        ))
        outcomes.append(result(
            "WG-CONTENT-002", "Public technology disclosure", "Information Disclosure", "info", "informational",
            "The homepage HTML was unavailable; technology disclosure review was limited to response headers.",
            "Avoid unnecessary product/version headers and ensure production source maps are not publicly exposed unless intentionally published.",
            {"server_header_present": bool(headers.get("server")), "x_powered_by_present": bool(headers.get("x-powered-by")), "html_sample_available": False},
        ))

    return outcomes
