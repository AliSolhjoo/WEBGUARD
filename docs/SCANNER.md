# Passive scanner reference — WEBGUARD 2.0

## Implemented checks

| ID | Check | Current behavior |
|---|---|---|
| WG-HTTP-001 | HTTPS availability | Validates a TLS handshake to the verified hostname. |
| WG-HTTP-002 | HTTP to HTTPS redirect | Requires the observed HTTP redirect to explicitly target the same verified host over HTTPS and the HTTPS probe to succeed. |
| WG-TLS-001 | TLS certificate expiry | Reads expiry from a verified TLS peer; flags expired or less-than-30-day validity. |
| WG-TLS-002 | Negotiated TLS version | Records the negotiated version; flags obsolete SSL/TLS versions if negotiated. It does not enumerate every supported version/cipher. |
| WG-HDR-001 | Content-Security-Policy | Checks for a CSP header. |
| WG-HDR-002 | Strict-Transport-Security | Requires HSTS on HTTPS with a `max-age` of at least 15,768,000 seconds. |
| WG-HDR-003 | X-Content-Type-Options | Requires exactly `nosniff`. |
| WG-HDR-004 | Referrer-Policy | Accepts recognized privacy-conscious values and checks the last recognized policy in a comma-separated list. |
| WG-HDR-005 | Permissions-Policy | Checks for a policy header. It does not fully parse every browser feature directive. |
| WG-HDR-006 | Clickjacking protection | Accepts X-Frame-Options DENY/SAMEORIGIN or a restrictive CSP `frame-ancestors`; rejects wildcard and malformed `'none'` combinations. |
| WG-HDR-007 | CSP unsafe script directives | Checks the effective script source for `unsafe-inline` and `unsafe-eval`. |
| WG-COOKIE-001 | Cookie attributes | Reviews observed root response Set-Cookie metadata for Secure, HttpOnly and SameSite. Cookie values are never retained. |
| WG-DNS-001 | SPF record | Looks for SPF TXT at the apex domain; lookup errors are not reported as missing records. |
| WG-DNS-002 | DMARC record | Looks for DMARC TXT at `_dmarc.<hostname>`. |
| WG-DNS-003 | SPF strictness | Flags multiple SPF records, permissive `+all`/`?all`/`all`, and missing/non-terminal all mechanisms. |
| WG-DNS-004 | DMARC enforcement | Reports whether `p=quarantine` or `p=reject` is configured. |
| WG-DNS-005 | CAA record | Observes whether one or more CAA records exist. It does not evaluate every issuance policy edge case. |
| WG-CONTENT-001 | Mixed content references | Parses at most 64 KiB of origin-root HTML/XHTML and flags absolute HTTP resource references. |
| WG-CONTENT-002 | Public technology disclosure | Flags basic server/version, X-Powered-By, generator and source-map indicators without storing raw header values or HTML. |

An outcome of `fail` creates a Finding. `pass`, `info` and `error` outcomes remain in the scan check results. A DNS timeout is an unknown/error result, not evidence that a record is absent.

## Network scope and limits

- The asset must be a verified public DNS hostname and belong to an active workspace.
- A and AAAA lookups are absolute (no resolver search suffix) and bounded. Every answer is validated; the entire set is rejected if any address is non-global, private, loopback, link-local, multicast, reserved or unspecified. More than eight unique addresses are rejected.
- Each connection resolves and validates the hostname again, then connects to a selected validated IP. HTTPS uses the original hostname for SNI and certificate hostname validation. Environment proxy settings are not used.
- Only ports 80 and 443 are accepted.
- The origin probe sends `HEAD` to `/` and follows at most three redirects only if the target is the exact same hostname, HTTPS and standard port 443. Redirect paths and queries are length-bounded and reject control characters/backslashes.
- A separate, single `GET` may sample only `https://<verified-host>/` when HTTPS is reachable. It does not follow redirects, uses `Accept-Encoding: identity`, and reads at most 65,537 bytes (64 KiB plus one byte to determine truncation). Only HTML/XHTML is decoded. The body is held transiently in memory and is not persisted in the database, report, audit log or notification.
- DNS TXT and CAA records are limited to apex TXT, `_dmarc` TXT and apex CAA. No arbitrary record type lookup is performed.
- Per-connection timeout, total scan budget and redirect count are capped by constants/environment values. The scanner queue allows at most three pending/running scans per organization; the local worker processes one at a time.

## Severity and score

Severity is application triage, not CVSS. The score is:

```text
score = max(0, 100 - sum(weight of failed checks))
critical = 10, high = 8, medium = 5, low = 2, informational = 0
```

This score is only a trend indicator for comparing the same asset over time. It is not a probability of compromise, compliance score or proof that a site is safe.

## Known blind spots

- Only the origin root is checked. Application routes, APIs, subdomains, authenticated pages and user-specific workflows are not covered.
- Cookie attributes are observed only from the root response and may not represent session cookies on authenticated routes.
- `HEAD` behavior can differ from `GET`; HTML sampling is bounded and only observes the root response without following GET redirects.
- Mixed-content parsing is a simple HTML attribute sample and does not execute JavaScript, parse CSS fully or discover resources loaded dynamically.
- TLS inspection records the protocol negotiated by the default Python context; it is not a full protocol/cipher enumeration.
- Header and DNS checks indicate configuration, not exploitation. They can have false positives/negatives and require manual confirmation.
- SPF/DMARC/CAA lookups do not prove mail deliverability or complete DNS-policy correctness.
