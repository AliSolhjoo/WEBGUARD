# WEBGUARD 2.2.0

**WEBGUARD** is a bilingual, defensive web-security assessment workspace for domains that the operator owns or is explicitly authorized to assess. It combines DNS ownership challenges, bounded passive HTTP/TLS/DNS observations, evidence-backed findings, remediation workflow, trends, scan comparison, bilingual PDF reporting and an offline rule-based security advisor.

> **Authorization boundary:** A DNS TXT challenge demonstrates control of the relevant DNS zone at verification time; it is not legal authorization for every service hosted by that domain. Only assess assets you own or have written permission to test. WEBGUARD is not an exploit scanner or a penetration-testing certification tool.

## Highlights

- **Bilingual interface:** English (LTR) and Persian (RTL), persistent language selection, localized labels and dates.
- **Identity and workspace:** registration, login, refresh-token rotation, logout/revocation, owner/admin/analyst/viewer roles and tenant-scoped data.
- **Asset inventory:** hostname-only registration, random DNS TXT ownership challenge and verified-scope enforcement. The verification modal explains how to publish the TXT record, handles relative DNS host fields, and shows resolver errors inline instead of silently remaining pending.
- **Passive scanner:** bounded root-level HTTP/HTTPS `HEAD` probes; same-host HTTPS redirects only; public DNS address validation and IP-pinned sockets; TLS certificate/protocol observations; security headers; cookie attribute metadata; SPF, DMARC and CAA lookups.
- **Bounded content checks:** one HTTPS `GET` to the verified origin root may read at most 64 KiB of HTML/XHTML. It is not a crawler, it does not follow this GET's redirects, and the raw HTML is never stored. The sample is used only for mixed-content references and limited public technology-disclosure indicators.
- **Findings management:** severity, status, assignment, remediation notes and audit trail.
- **Security intelligence:** 30-day activity trends, latest score trend and same-asset scan comparison (new/resolved/persistent check identifiers).
- **Offline security advisor:** deterministic remediation guidance derived from check identifiers and stored evidence. It is not an LLM and does not call external services.
- **Reports:** PDF report generated in the selected English or Persian language. Persian PDF output requires a Unicode Persian/Arabic font plus `arabic-reshaper` and `python-bidi`.
- **Notifications:** per-user, per-workspace scan completion/failure notifications.
- **Personalization Studio:** per-user themes (Midnight/Graphite/Light), six accent palettes, font and text scale, density, corner shape, compact/expanded sidebar, page width, reduced motion, customizable dashboard widget visibility/order and one/two-column layout, hideable/reorderable sidebar navigation within its existing sections, and portable per-user visual profiles. Includes analyst/executive/minimal presets and versioned JSON import/export.
- **Local worker:** database-backed single-process queue. No Docker, WSL, Redis or cloud account is required for local development.

## Technology

| Layer | Technology |
|---|---|
| API | Python 3.12+, Django 5.2, Django REST Framework |
| Auth | SimpleJWT with short-lived access tokens and refresh rotation/blacklist |
| Database | SQLite for local development; PostgreSQL option for deployment |
| DNS / network | dnspython, Python sockets and TLS |
| PDF | ReportLab; optional RTL shaping dependencies for Persian |
| Frontend | React 19, TypeScript, Vite, Lucide icons and custom responsive CSS |
| Tests | pytest, pytest-django, coverage, frontend TypeScript/Vite build |

## Windows quick start

Requirements: Python **3.12+**, Node.js **20+**, npm, and network access for the first dependency installation.

1. Extract the ZIP to a writable folder, for example `C:\Users\<you>\Desktop\WEBGUARD`.
2. Open PowerShell in the project root (the folder containing `backend`, `frontend`, `scripts` and `START_WEBGUARD.bat`).
3. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1
```

The setup script creates `.venv`, installs backend/frontend dependencies, creates `.env` from `.env.example` if needed, creates initial migrations, migrates the SQLite database and runs Django's system check.

4. Start all three local services:

```powershell
.\scripts\dev.ps1
```

Or double-click `START_WEBGUARD.bat` in the project root after setup.

| Service | Address |
|---|---|
| Frontend | http://127.0.0.1:5173 (launcher may select 5174–5180 if busy) |
| Backend | http://127.0.0.1:8000 |
| Health | http://127.0.0.1:8000/health/ |
| OpenAPI | http://127.0.0.1:8000/api/schema/ |
| Swagger | http://127.0.0.1:8000/api/docs/ |
| ReDoc | http://127.0.0.1:8000/api/redoc/ |
| Django admin | http://127.0.0.1:8000/admin/ |

Create the first account through the registration screen. It creates the first organization and assigns the owner role. Keep the worker terminal open; queued assessments remain pending until `run_scan_worker` processes them. Open **Personalization studio** in the sidebar to tailor the interface and dashboard.

## Manual start

Terminal 1 — API:

```powershell
Set-Location .\backend
..\.venv\Scripts\Activate.ps1
python manage.py runserver 127.0.0.1:8000
```

Terminal 2 — worker:

```powershell
Set-Location .\backend
..\.venv\Scripts\Activate.ps1
python manage.py run_scan_worker
```

Terminal 3 — frontend:

```powershell
Set-Location .\frontend
npm run dev
```

## Verify a domain and run an assessment

1. Register/sign in.
2. Open **Assets** and register a hostname only, e.g. `example.com` (no scheme, path, port or IP address).
3. Open its verification challenge. Publish the exact TXT record at your authoritative DNS provider:
   - Name: `_webguard-verify.<domain>`
   - Type: `TXT`
   - Value: `webguard-verification=<unique-token>`
4. Wait for DNS propagation and click **Verify DNS record**.
5. Open **Assessments**, select the verified asset and queue a passive scan.
6. Keep the scanner worker running. Review the 19 check results and associated findings after completion.
7. Use **Compare** to compare a completed scan with the previous completed scan for the same asset.
8. Update finding status/assignee/notes, open the **Security assistant** for offline remediation guidance, and generate a Persian or English PDF report.

## Personalization

Open **Personalization studio** from the sidebar. Changes apply immediately and are saved in browser storage under the signed-in user's ID; they do not alter organization data, scanner scope, or authorization. Export the current visual/dashboard profile as JSON to move it to another browser, or import an existing WEBGUARD preferences file. The dashboard can be rebuilt by hiding/showing and reordering cards. Sidebar items can also be hidden and reordered within their existing sections; Overview and Personalization remain available so users can always recover their layout. On mobile, the dashboard always returns to one column and compact navigation expands to keep labels accessible.

Run the isolated preferences tests from `frontend/` with `npm run test:preferences`. The root `scripts/test.ps1` also runs this suite before the frontend build.

## Test and validation

Run the full local validation after setup:

```powershell
.\scripts\test.ps1
```

It runs Django `check`, migration drift check, pytest with coverage and the frontend production build. If any stage fails, the script stops and reports the failing stage.

Also run individual commands when debugging:

```powershell
Set-Location .\backend
..\.venv\Scripts\python.exe -m pytest
..\.venv\Scripts\python.exe manage.py check
..\.venv\Scripts\python.exe manage.py makemigrations --check --dry-run
Set-Location ..\frontend
npm run build
```

See `docs/TESTING.md` for the exact coverage boundaries and `IMPLEMENTATION_STATUS.md` for validation that was possible in the build environment used to prepare this ZIP.

## Operational and security notes

- Scanner scope is limited to a verified public hostname, ports 80/443, bounded DNS records and a small origin-root HTML sample.
- A/AAAA lookup results are validated as a set; any non-global/private/reserved answer blocks the target. TCP connections are pinned to a validated address, while TLS still verifies the original hostname/SNI.
- Redirects must remain on the exact verified hostname, use HTTPS and standard port 443. Redirect count is capped at three.
- HTML sampling sends one GET only to `https://<verified-host>/`, reads at most 65,537 bytes to detect truncation, persists no body, and does not follow redirect paths.
- No form submission, authentication flow, file download, exploit payload, brute force, arbitrary crawling, subdomain discovery or port scanning is included.
- The scanner worker is serial and local. Use a dedicated isolated worker host and restrictive egress firewall before any external deployment.
- JWT access/refresh tokens are stored in browser `sessionStorage` in this development build. Do not expose this configuration to untrusted networks. Move to Secure/HttpOnly/SameSite cookies or a backend-for-frontend with a reviewed CSRF model before production.
- SQLite is for local development and one worker only. Use PostgreSQL, backups, monitoring, external append-only logs, hardened secrets and a formal deployment architecture for production.
- The posture score is a transparent WEBGUARD heuristic, not CVSS, a compliance score or a guarantee of safety.
- The offline advisor is deterministic guidance, not a language model or vulnerability exploit confirmation.

Read `docs/SECURITY.md` before any deployment and complete its production checklist. This repository is an advanced defensive application, not a security certification; obtain an independent security review before commercial use.
