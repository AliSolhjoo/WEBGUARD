"""Bounded, passive HTTP/TLS probes for explicitly verified public hostnames.

All TCP connections are pinned to an address that was checked immediately before
connection. The scanner never uses environment proxies, never follows a different
origin, never sends request bodies, and reads at most a small HTML sample.
"""

import http.client
import os
import socket
import ssl
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

from apps.assets.domain_validation import UnsafeTarget, safe_redirect_url
from apps.scanner.safety import resolve_and_validate

SCAN_TIMEOUT_SECONDS = max(2, min(int(os.getenv("SCAN_TIMEOUT_SECONDS", "8")), 20))
SCAN_MAX_REDIRECTS = max(0, min(int(os.getenv("SCAN_MAX_REDIRECTS", "3")), 3))
SCAN_TOTAL_TIMEOUT_SECONDS = max(10, min(int(os.getenv("SCAN_TOTAL_TIMEOUT_SECONDS", "30")), 60))
SCAN_HTML_SAMPLE_BYTES = 64 * 1024
SCAN_USER_AGENT = "WEBGUARD-Security-Assessment/2.0 (+authorized passive assessment)"


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, pinned_ip, port=80, timeout=8):
        super().__init__(host, port=port, timeout=timeout)
        self.pinned_ip = pinned_ip

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout)


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, pinned_ip, port=443, timeout=8, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context or ssl.create_default_context())
        self.pinned_ip = pinned_ip

    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout)
        try:
            # Keep SNI and certificate hostname validation tied to the verified domain.
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


@dataclass
class ProbeResult:
    scheme: str
    status: int | None
    headers: dict
    final_url: str
    tls_version: str | None = None
    certificate: dict | None = None
    error: str | None = None
    redirect_status: int | None = None
    redirect_location: str | None = None
    cookies: list[dict] = field(default_factory=list)
    content_type: str | None = None
    body_sample: str = ""
    content_truncated: bool = False

    def header(self, name):
        return self.headers.get(name.lower())


def _cert_details(sock):
    if not sock:
        return None, None
    cert = sock.getpeercert()
    details = {
        "subject": [[list(pair) for pair in group] for group in cert.get("subject", [])],
        "issuer": [[list(pair) for pair in group] for group in cert.get("issuer", [])],
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_name_count": len(cert.get("subjectAltName", [])),
    }
    return details, getattr(sock, "version", lambda: None)()


def _parse_response_headers(response):
    headers = {}
    cookie_metadata = []
    for key, value in response.getheaders():
        name = key.lower()
        raw = str(value)[:1000]
        if name == "set-cookie":
            segments = [part.strip() for part in raw.split(";")]
            cookie_name = segments[0].split("=", 1)[0][:100] if segments else "unknown"
            attrs = {part.split("=", 1)[0].strip().lower() for part in segments[1:] if part}
            same_site = next(
                (part.split("=", 1)[1].strip().lower() for part in segments[1:] if part.lower().startswith("samesite=")),
                None,
            )
            cookie_metadata.append({
                "name": cookie_name,
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": same_site,
            })
        elif name not in headers:
            headers[name] = raw
    return headers, cookie_metadata[:30]


def _connection_for(scheme, host, pinned_ip, port, timeout):
    if scheme == "https":
        return PinnedHTTPSConnection(host, pinned_ip, port=port, timeout=timeout)
    return PinnedHTTPConnection(host, pinned_ip, port=port, timeout=timeout)


def _request(host: str, url: str, method: str, timeout: float, deadline: float | None = None,
             read_html: bool = False) -> ProbeResult:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeTarget("Only HTTP and HTTPS schemes are allowed.")
    try:
        parsed_port = parts.port
    except ValueError as exc:
        raise UnsafeTarget("The URL contains an invalid port.") from exc
    port = parsed_port or (443 if scheme == "https" else 80)
    if port != (443 if scheme == "https" else 80):
        raise UnsafeTarget("Only standard HTTP and HTTPS ports are allowed.")
    if (parts.hostname or "").lower().rstrip(".") != host.lower().rstrip("."):
        raise UnsafeTarget("The URL host is outside the verified asset scope.")
    if parts.username or parts.password or parts.fragment:
        raise UnsafeTarget("Credentials and URL fragments are not allowed in scan targets.")

    path = parts.path or "/"
    if (len(path) > 512 or len(parts.query) > 512
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in path + parts.query)
            or "\\" in path + parts.query):
        raise UnsafeTarget("The requested URL path or query contains unsupported characters or is too long.")
    request_target = path + ("?" + parts.query if parts.query else "")
    addresses = resolve_and_validate(host)
    last_error = None

    for pinned_ip in addresses:
        remaining = (deadline - time.monotonic()) if deadline is not None else timeout
        if remaining <= 0.1:
            last_error = "Assessment time budget exceeded"
            break
        connection = None
        try:
            connection = _connection_for(scheme, host, pinned_ip, port, min(timeout, remaining))
            headers = {
                "Host": host,
                "User-Agent": SCAN_USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
                "Accept-Encoding": "identity",
                "Connection": "close",
                "Cache-Control": "no-cache",
            }
            if read_html:
                # Range is advisory; the client-side read limit is authoritative.
                headers["Range"] = f"bytes=0-{SCAN_HTML_SAMPLE_BYTES - 1}"
            connection.request(method, request_target, headers=headers)
            response = connection.getresponse()
            response_headers, cookies = _parse_response_headers(response)
            certificate, tls_version = _cert_details(connection.sock) if scheme == "https" else (None, None)
            content_type = response_headers.get("content-type", "")[:200] or None
            body_sample = ""
            truncated = False
            if read_html and response.status in {200, 203, 206} and content_type:
                media_type = content_type.split(";", 1)[0].strip().lower()
                if media_type in {"text/html", "application/xhtml+xml"}:
                    try:
                        sample = response.read(SCAN_HTML_SAMPLE_BYTES + 1)
                        truncated = len(sample) > SCAN_HTML_SAMPLE_BYTES
                        sample = sample[:SCAN_HTML_SAMPLE_BYTES]
                        charset = "utf-8"
                        for segment in content_type.split(";")[1:]:
                            key, sep, value = segment.strip().partition("=")
                            if sep and key.strip().lower() == "charset":
                                charset = value.strip().strip('"\'')[:40]
                                break
                        try:
                            body_sample = sample.decode(charset, errors="replace")
                        except LookupError:
                            body_sample = sample.decode("utf-8", errors="replace")
                    except (OSError, http.client.HTTPException, TimeoutError):
                        # A bounded content sample is optional; failed sampling must not
                        # invalidate already obtained status/header/TLS observations.
                        body_sample = ""
            result = ProbeResult(
                scheme=scheme,
                status=response.status,
                headers=response_headers,
                final_url=url,
                tls_version=tls_version,
                certificate=certificate,
                cookies=cookies,
                content_type=content_type,
                body_sample=body_sample,
                content_truncated=truncated,
            )
            response.close()
            return result
        except ssl.SSLCertVerificationError as exc:
            return ProbeResult(scheme, None, {}, url, error=f"TLS certificate verification failed: {exc.verify_message[:180]}")
        except (OSError, ssl.SSLError, http.client.HTTPException, TimeoutError) as exc:
            last_error = f"Connection failed: {type(exc).__name__}"
        finally:
            if connection:
                connection.close()
    return ProbeResult(scheme, None, {}, url, error=last_error or "Connection failed")


def _single_head(host: str, url: str, timeout: float, deadline: float | None = None) -> ProbeResult:
    return _request(host, url, "HEAD", timeout, deadline, read_html=False)


def probe_origin(host: str, scheme: str) -> ProbeResult:
    """HEAD-only origin probe with validated DNS pinning and same-host HTTPS redirects."""
    if scheme not in {"http", "https"}:
        raise UnsafeTarget("Unsupported probe scheme.")
    deadline = time.monotonic() + SCAN_TOTAL_TIMEOUT_SECONDS
    current = urlunsplit((scheme, host, "/", "", ""))
    redirect_status = None
    redirect_location = None

    # Initial request plus at most SCAN_MAX_REDIRECTS followed redirects.
    for redirect_count in range(SCAN_MAX_REDIRECTS + 1):
        if time.monotonic() >= deadline:
            return ProbeResult(urlsplit(current).scheme, None, {}, current,
                               error="Assessment time budget exceeded", redirect_status=redirect_status)
        result = _single_head(host, current, SCAN_TIMEOUT_SECONDS, deadline)
        result.final_url = current
        if result.status not in {301, 302, 303, 307, 308}:
            result.redirect_status = redirect_status
            result.redirect_location = redirect_location
            return result
        location = result.header("location")
        if not location:
            result.redirect_status = redirect_status
            result.redirect_location = redirect_location
            return result
        if redirect_count >= SCAN_MAX_REDIRECTS:
            result.redirect_status = result.status
            result.redirect_location = location[:500]
            return result
        try:
            next_url = safe_redirect_url(current, location, host)
        except UnsafeTarget:
            # Cross-host, downgrade, or non-standard redirects are evidence only.
            result.redirect_status = redirect_status
            result.redirect_location = redirect_location
            return result
        redirect_status = result.status
        redirect_location = location[:500]
        current = next_url
    return ProbeResult(urlsplit(current).scheme, None, {}, current,
                       error="Assessment stopped at redirect limit", redirect_status=redirect_status)


def probe_homepage(host: str, https_url: str) -> ProbeResult:
    """Read at most 64 KiB of HTML from the verified HTTPS origin root without following redirects."""
    parts = urlsplit(https_url)
    if parts.scheme.lower() != "https" or (parts.hostname or "").lower().rstrip(".") != host.lower().rstrip("."):
        raise UnsafeTarget("Homepage content URL is outside the verified HTTPS origin.")
    if parts.username or parts.password or parts.fragment:
        raise UnsafeTarget("Homepage URL contains unsupported authority information.")
    try:
        if parts.port not in (None, 443):
            raise UnsafeTarget("Only standard HTTPS port 443 is allowed.")
    except ValueError as exc:
        raise UnsafeTarget("Homepage URL contains an invalid port.") from exc
    url = urlunsplit(("https", host, parts.path or "/", parts.query[:512], ""))
    deadline = time.monotonic() + min(10, SCAN_TOTAL_TIMEOUT_SECONDS)
    return _request(host, url, "GET", min(5, SCAN_TIMEOUT_SECONDS), deadline, read_html=True)
