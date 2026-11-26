import dns.exception
import dns.resolver
from apps.assets.domain_validation import validate_public_addresses, UnsafeTarget


def resolve_and_validate(hostname: str) -> list[str]:
    """Resolve absolute A/AAAA records with bounded DNS timeouts, then reject unsafe sets."""
    fqdn = hostname.rstrip(".") + "."
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    addresses = set()
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(
                fqdn,
                record_type,
                lifetime=2.5,
                search=False,
                raise_on_no_answer=False,
            )
        except dns.resolver.NXDOMAIN as exc:
            raise UnsafeTarget("The target hostname does not exist in DNS.") from exc
        except dns.exception.DNSException as exc:
            raise UnsafeTarget("DNS resolution could not be completed safely.") from exc
        if answer.rrset:
            for record in answer:
                addresses.add(record.address)
    return validate_public_addresses(addresses)
