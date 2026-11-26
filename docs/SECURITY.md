# Security model and threat boundaries — WEBGUARD 2.0

## Intended use

WEBGUARD is intended only for domains the operator owns or is explicitly authorized to assess. DNS TXT verification proves control of the DNS zone at verification time, not legal permission to test every third-party service hosted there. Do not assess third-party targets without written authorization.

The scanner is passive and bounded. It does not exploit vulnerabilities, guess credentials, bypass authentication, submit form data, execute JavaScript, download arbitrary files, crawl route trees, discover subdomains, scan ports or run payloads.

## Scanner controls

1. **Hostname-only scope:** the asset model accepts a normalized fully qualified hostname, not a URL/path/port, wildcard or literal IP. Local/reserved suffixes are rejected.
2. **DNS verification:** the scanner is queued only for a verified asset. The challenge is a random token under `_webguard-verify.<hostname>`.
3. **Private-address denial:** all A/AAAA answers are validated together; any private/non-global/special address blocks the scan.
4. **DNS pinning:** the scanner re-resolves and validates immediately before each TCP connection and connects to the validated IP. HTTPS still verifies certificate hostname and SNI for the registered hostname.
5. **Redirect policy:** only same-host HTTPS redirects on standard port 443 can be followed; count is capped at three. Redirect input rejects controls/backslashes and bounds path/query length.
6. **Methods and request scope:** origin probes use HEAD on `/`; only ports 80/443 are used. A separate GET may sample only the verified HTTPS origin root. The GET does not follow redirects.
7. **Response limits:** content-type must be HTML/XHTML, compression is disabled for the sample, and at most 64 KiB is retained transiently. Raw response bodies and raw cookie values are not stored.
8. **Evidence minimization:** cookie names and flags are stored; sensitive query values and raw technology header values are not persisted in findings. HTML-derived indicators store only boolean/count/limited host indicators.
9. **Queue controls:** passive profile only, maximum three active jobs per organization, serial local worker, bounded timeouts.

## Application controls

- Password validation enforces Django validators and a 12-character minimum.
- JWT access tokens are short-lived; refresh rotation and blacklist are enabled. Logout checks refresh-token ownership.
- Login, registration, scan creation and assistant routes have scoped throttling.
- Organization data is scoped in list/detail queries; finding assignment requires a non-viewer member of the same workspace.
- PDF downloads, assistant requests, notifications and scan comparison are tenant-scoped.
- Notification data is limited to its recipient and active organization.
- Audit entries omit credentials, bearer tokens, raw HTML and cookie values.
- Django sends baseline security headers; production mode enables HTTPS-related settings when configured.

## Explicit limitations and residual risks

- This build stores frontend JWTs in browser `sessionStorage`. This is acceptable only for local development or a trusted demo; a same-origin script injection can expose a token. Before external production, replace it with a reviewed Secure/HttpOnly/SameSite cookie or BFF session and CSRF design.
- Scanner process has outbound network access. Before production, isolate it on a dedicated worker host/segment and enforce egress firewall rules that deny internal, management, metadata and control-plane networks even if application checks regress.
- DNS can change between checks. Re-resolution, whole-set validation and IP pinning reduce but do not remove all infrastructure/network risks.
- The local worker is a single-process database queue. It is not designed for multiple concurrent workers on SQLite, high availability or distributed scheduling.
- SQLite is for local development, not multi-user production. Use PostgreSQL, backups, monitoring and tested recovery.
- Application audit rows are not tamper-proof against database administrators. Use external append-only logging/SIEM for evidentiary requirements.
- The offline security advisor is deterministic rule-based guidance. It is not generative AI, a substitute for an expert, or proof of exploitability.
- WEBGUARD's score is a heuristic, not CVSS or a compliance certification.

## Production checklist

- [ ] Independent security review and authorized penetration test of WEBGUARD itself.
- [ ] Dedicated isolated scanner worker and egress firewall.
- [ ] PostgreSQL with TLS, least-privilege role, encrypted backups and restore test.
- [ ] Strong production secrets from a secret manager; `DEBUG=false`; exact hosts and origins.
- [ ] TLS reverse proxy, HTTPS, reviewed proxy headers, HSTS after readiness.
- [ ] Replace sessionStorage JWTs with HttpOnly/Secure/SameSite cookie or BFF session and CSRF review.
- [ ] MFA/SSO for administrators, account recovery controls and audit alerting.
- [ ] Formal authorization record/renewal/revocation beyond DNS TXT proof.
- [ ] Queue quotas, worker supervision, health monitoring and safe retry/dead-letter strategy.
- [ ] External append-only logs and retention policy.
- [ ] Dependency scanning, patch management, SBOM and vulnerability response process.
- [ ] Document privacy/retention rules for domain and assessment evidence.
