# WEBGUARD 2.0 — implementation and verification status

## Included capabilities

- Django/DRF API, custom user model, password validation, JWT access/refresh, refresh rotation/blacklist, logout ownership check and scoped throttles.
- Organization workspace with owner/admin/analyst/viewer roles and one-workspace-per-user model.
- Hostname normalization, DNS TXT ownership verification and verified-asset-only assessment queue.
- Bounded passive scanner with absolute A/AAAA resolution, public IP validation, IP-pinned sockets, TLS hostname/SNI verification, same-host HTTPS-only redirect checks and capped time/redirect budgets.
- Nineteen stable scanner checks covering HTTP/HTTPS, TLS, security headers, clickjacking/CSP, cookie flags, SPF/DMARC/CAA and bounded root HTML mixed-content/technology-disclosure signals.
- One same-origin HTTPS root GET may read at most 64 KiB of HTML in memory only. The GET does not follow redirects and the raw body is not persisted.
- Finding workflow with status, workspace assignee and remediation notes; audit trail records changes.
- Same-asset scan comparison (new/resolved/persistent check IDs and heuristic score change), 30-day activity/score trends and recipient-scoped notifications.
- Bilingual frontend and bilingual PDF reports; stored report language controls subsequent download output.
- Offline deterministic security advisor with English/Persian remediation rules for all supported scanner check IDs. It makes no external model/API call.
- Responsive React/TypeScript UI, one-click Windows launcher, PowerShell setup/dev/test scripts and documentation.

## Checks executed in the packaging environment

Latest reproducible checks:

- Pure Python unit suite: **55 passed** (domain and redirect safety, network policy with mocked DNS/socket, scanner check logic, scoring and offline assistant rules).
- Python bytecode compilation (`python -m compileall -q backend`): passed.
- TypeScript/TSX syntax transpilation: **4 files passed** using the installed TypeScript compiler API. This is syntax validation only, not a strict project type-check.
- CSS parser: **539 top-level rules, 0 parse errors**.
- Translation-key coverage check: all 218 direct literal `t()` calls in `App.tsx` were checked against the Persian dictionary (386 entries); no missing keys were found.
- English ReportLab smoke test with an in-memory scan-shaped fixture: passed; output began with `%PDF-` and was 2,743 bytes.
- Archive integrity and SHA-256 are checked when the final ZIP is created.

## Checks not executable in this packaging environment

The build environment does not include Django, Django REST Framework, pytest-django, React/Vite dependencies, `arabic-reshaper` or `python-bidi`, and package-registry access was unavailable. Therefore the following are **not claimed as passed here**:

- Full Django/pytest-django integration suite, including API and database worker tests.
- Django `manage.py check`, migration generation/drift check and real database integration.
- Strict TypeScript type-check (`tsc -b`) and Vite production build.
- Persian PDF rendering smoke test (requires RTL shaping modules and an installed Persian/Arabic font).
- Browser end-to-end tests against a live local Django/Vite runtime.

Run `scripts/setup.ps1` then `scripts/test.ps1` on Windows to install dependencies, create/migrate the local database, run the complete backend test suite and build the frontend. Fix any environment-specific failure reported there before treating the application as fully validated.

## Important deployment boundary

This is an advanced defensive product build, not a penetration test and not a production security certification. The browser currently stores JWTs in sessionStorage; move to a reviewed Secure/HttpOnly/SameSite cookie or BFF session before exposing the app to untrusted networks. Isolate the scanner process with egress controls, use PostgreSQL and backups, enable production HTTPS/secrets, and conduct an independent security review before commercial deployment.


## Patch 2.0.1 — 2026-11-25

- Removed 15 duplicate Persian translation keys that caused Vite `Duplicate key` warnings. The Persian translation object now has 395 unique entries and no duplicate keys.
- Fixed the domain-verification UX: verification errors are caught and shown inside the modal; the modal stays open only so the user can correct the DNS record and retry, and the UI clearly states that DNS publication must be done at the authoritative DNS provider before clicking Verify.
- Added guidance for DNS providers that append the zone name automatically (use `_webguard-verify` as the relative host in that case).
- Added distinct API responses for missing TXT records (HTTP 400) and DNS resolver timeouts/unavailability (HTTP 503).
- Added integration tests for missing TXT and DNS timeout responses. Django integration tests could not be executed in this packaging environment because Django/DRF are not installed.
- Python bytecode compilation passed; TypeScript/TSX syntax parsing, translation duplicate check, and the pure domain-safety test suite were run separately. Full Vite build and full Django tests still require installing project dependencies on the Windows workstation.


## Patch 2.1.0 — Personalization Studio

- Added a complete Personalization Studio reachable from the sidebar.
- Added Midnight, Graphite and Light themes; six accent colors; three density modes; system/Segoe UI/Tahoma font choices; small/standard/large text scale; sharp/balanced/rounded corners; expanded/compact sidebar; standard/wide content canvas; and reduced-motion preference.
- Added a dashboard builder with one/two-column wide-screen layout, visibility toggles, empty-dashboard recovery action, and persistent up/down widget ordering. The dashboard falls back to a single column on narrow screens.
- Added analyst, executive and minimal profile presets, live visual preview, reset-to-default confirmation, JSON export and versioned/allow-listed JSON import (maximum file size 128 KiB).
- Preferences are isolated by authenticated user ID in browser localStorage; they are not transmitted to the backend and do not affect role permissions or security data.
- Added nine Node built-in tests for defaults, allowed values, invalid input normalization, dashboard widget ordering/visibility, import/export round trip, schema validation, unknown-field rejection and per-user storage isolation.
- `npm run test:preferences`: **9 passed** at the 2.1.0 patch baseline using Node's built-in test runner and the TypeScript compiler API.
- `preferences.ts` strict standalone TypeScript check passed; App/i18n/main/API/preferences/Vite source TS/TSX syntax transpilation passed; CSS parser found zero syntax errors.
- Full React strict project type-check, Vite production build and browser interaction tests were not run in this packaging environment because npm dependency installation stalled at the package registry. Run `npm install`, `npm run test:preferences`, and `npm run build` on the Windows workstation before pushing this release.


## Patch 2.2.0 — Extended Personalization

- Added user-controlled sidebar visibility and ordering within the existing Workspace, Security and Administration groups. Overview is protected as a recovery route; the Personalization Studio remains permanently available. These settings only change navigation presentation and never change API permissions.
- Added import/export persistence for navigation settings, plus safe normalization of unknown, missing and duplicate navigation identifiers.
- Updated curated Analyst, Executive and Minimal profiles to include matching sidebar layouts.
- Expanded the preference test suite to 14 tests covering all visual/layout modes, sidebar visibility/order/recovery and a complete 23,328-combination matrix for theme, accent, density, font, text scale, corners, sidebar, content width, dashboard columns and reduced-motion state.
- `npm run test:preferences`: **14 passed**. Standalone strict TypeScript validation for `preferences.ts` passed; TS/TSX syntax validation passed for six source/config files; CSS parsing reported 814 rules and 0 parse errors; all 272 static translation calls in `App.tsx` had Persian translations.
- Browser-based visual regression and live Vite build still require the React/Vite package installation on the target Windows system. `npm install` in the packaging environment failed because `registry.npmjs.org` could not be resolved (`EAI_AGAIN`); this is an environment/network limitation and not a reported application build result.
