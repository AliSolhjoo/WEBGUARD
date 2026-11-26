# WEBGUARD Frontend

The WEBGUARD frontend is a responsive React + TypeScript workspace built with Vite and Lucide icons.

## Included screens

- Overview: security posture, asset coverage, risk distribution and recent assessments.
- Assets: add hostnames, view DNS ownership challenges, search the inventory, launch a passive assessment, and remove an asset after confirmation.
- Assessments: queue passive checks, review status/history, cancel active work, inspect check evidence and remediation guidance.
- Findings: filter by severity/workflow status, search by domain/check/title, review technical evidence, assign remediation to a workspace member, add remediation notes and update workflow state.
- Security insights: review 30-day scan activity, security-score history and open finding distribution.
- Security assistant: receive offline, deterministic remediation plans in English or Persian, grounded in a stored check result.
- Assessments: compare a completed scan with the previous completed scan for the same asset to identify new, resolved and persistent check IDs.
- Reports: generate and download organization-scoped English or Persian PDF reports.
- Team & access: view workspace members and add existing users when the current role permits it.
- Notifications: receive per-user notifications when scans complete, are blocked or fail.
- Audit trail: view administrative audit events.
- Personalization Studio: choose Midnight/Graphite/Light themes, six accent colors, density, font, text size, corner shape, sidebar width, content width and reduced-motion mode. Rebuild the Overview dashboard by enabling, hiding and reordering widgets and choosing one/two columns. The sidebar can also hide unused pages and reorder items within their existing sections; Overview and Personalization remain available as recovery routes.
- Curated analyst/executive/minimal profiles, instant preview, reset, and versioned JSON import/export. Preferences are saved separately for each signed-in user in this browser.

The UI uses a local system-font stack and does not depend on external font services. Layouts are provided for desktop, tablet and mobile. Viewer-only users see read-only controls; the backend remains the source of truth for authorization.

## Languages

The interface supports English (`EN`) and Persian (`فارسی`). The selector is available before and after sign-in and remembers the selection in browser local storage. Persian mode switches the application to RTL and uses Persian locale date formatting; English mode switches back to LTR. Technical evidence such as domains, email addresses, HTTP headers, identifiers and raw JSON remains unchanged. PDF reports support the selected language at creation time. Persian PDF generation requires the optional RTL shaping packages and a Unicode Persian/Arabic font; see `../docs/LOCALIZATION.md`.

## Development

Requirements: Node.js 20+ and npm.

```powershell
cd .\frontend
npm install
npm run dev
```

Vite serves the UI at `http://127.0.0.1:5173` and proxies `/api` to the local Django API at `http://127.0.0.1:8000`.

Run the isolated personalization preference suite:

```powershell
npm run test:preferences
```

For a production bundle:

```powershell
npm run build
```

The frontend requires the Django API to be running for authentication and workspace data. Run the root-level `scripts/setup.ps1` and `scripts/dev.ps1` for the complete local environment.
