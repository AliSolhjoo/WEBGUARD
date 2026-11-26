import ipaddress
import re

_DOMAIN_LABEL = re.compile(r"^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$", re.IGNORECASE)

class UnsafeTarget(ValueError):
    pass

def normalize_domain(value: str) -> str:
    raw = (value or "").strip().rstrip(".")
    if not raw or len(raw) > 253 or "://" in raw or any(ch in raw for ch in "/\\@?#"):
        raise UnsafeTarget("Enter a hostname only, without scheme, path, port, wildcard or credentials.")
    try:
        raw = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise UnsafeTarget("The hostname is not valid IDNA.") from exc
    if len(raw) > 253:
        raise UnsafeTarget("The normalized hostname is too long.")
    if raw in {"localhost", "localhost.localdomain"} or raw.endswith((".localhost", ".local", ".internal", ".test", ".invalid")):
        raise UnsafeTarget("Local and reserved hostnames cannot be registered.")
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        pass
    else:
        raise UnsafeTarget("Register a public DNS hostname, not an IP address.")
    labels = raw.split(".")
    if len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise UnsafeTarget("Enter a valid fully-qualified domain name.")
    if len(labels[-1]) < 2:
        raise UnsafeTarget("The top-level domain is invalid.")
    return raw

def validate_public_addresses(addresses):
    """Reject the whole resolution set if any answer is non-global (DNS rebinding defense)."""
    if not addresses:
        raise UnsafeTarget("The hostname did not resolve to an address.")
    normalized = []
    for value in addresses:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError as exc:
            raise UnsafeTarget("DNS returned an invalid IP address.") from exc
        if not ip.is_global or ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_unspecified:
            raise UnsafeTarget("The target resolves to a non-public or reserved address; scanning is blocked.")
        normalized.append(str(ip))
    unique = sorted(set(normalized))
    if len(unique) > 8:
        raise UnsafeTarget("The hostname resolved to too many addresses for the bounded scanner.")
    return unique

def safe_redirect_url(current_url: str, location: str, expected_host: str) -> str:
    from urllib.parse import urljoin, urlsplit, urlunsplit
    if (not isinstance(location, str) or len(location) > 2048
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in location)
            or "\\" in location):
        raise UnsafeTarget("Redirect location contains unsupported characters or is too long.")
    joined = urljoin(current_url, location)
    parsed = urlsplit(joined)
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower().rstrip(".") != expected_host.lower():
        raise UnsafeTarget("Redirect leaves the verified HTTPS origin; it was not followed.")
    try:
        redirect_port = parsed.port
    except ValueError as exc:
        raise UnsafeTarget("Redirect contains an invalid port.") from exc
    if parsed.username or parsed.password or redirect_port not in (None, 443):
        raise UnsafeTarget("Redirect contains unsupported authority information.")
    path = parsed.path or "/"
    query = parsed.query[:512]
    if len(path) > 512 or any(ord(ch) < 32 or ord(ch) == 127 for ch in path + query) or "\\" in path + query:
        raise UnsafeTarget("Redirect path or query contains unsupported characters.")
    return urlunsplit(("https", expected_host, path, query, ""))
