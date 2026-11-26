# Architecture — WEBGUARD 2.0

## Design choice

WEBGUARD is a **modular monolith**: one Django/DRF API with bounded domain modules, a React/TypeScript SPA, and a separate Django management-command worker that shares the database queue. The local setup intentionally avoids Docker, WSL and Redis. The worker boundary can later be replaced with a dedicated queue/worker architecture when the deployment requirements justify it.

## Component map

```text
Browser (React + TypeScript)
        |
        | /api/v1 (JWT)
        v
Django + DRF
  |-- accounts         Registration, login, tokens
  |-- organizations    Workspace membership and roles
  |-- assets           Hostname inventory and DNS verification
  |-- scans            Scan jobs, checks, findings, comparison
  |-- scanner          DNS safety, pinned probes, passive check registry
  |-- reports          English/Persian PDF generation and downloads
  |-- audit            Audit events and recipient-scoped notifications
        |
        +---- SQLite (local) / PostgreSQL (deployment)
        ^
        |
Django scan worker (one local process)
  |-- claims pending job
  |-- revalidates verified asset and organization state
  |-- validates all DNS A/AAAA responses and pins TCP destination
  |-- bounded HEAD probes on HTTP/HTTPS root (80/443)
  |-- optional one HTTPS GET to origin root; HTML/XHTML read capped at 64 KiB
  |-- never follows the content GET redirect; never persists raw body
  |-- persists 19 standardized outcomes, findings, audit and notification
```

## Important data boundaries

- `Organization` owns `Asset` records; `Membership` grants a user a role in one workspace.
- `Scan` belongs to one asset and records requester and lifecycle.
- `ScanCheck` stores the outcome for each stable check ID.
- `Finding` is attached to a failed check result and stores workflow status, assignee and remediation notes. Historical findings remain attached to their original scan.
- `SecurityReport` is tied to a completed scan and stores the selected language. PDF output is generated from persisted results at download time.
- `Notification` is scoped to both a recipient and organization.
- `AuditLog` records security-relevant events without storing passwords, bearer tokens, raw response bodies or cookie values.

All API object queries are scoped to the authenticated user's active organization. Multi-workspace switching is not implemented.

## Queue model

A `Scan` row is the queue record. `run_scan_worker` polls pending scans, conditionally changes a pending row to running, and executes one job at a time. Cancellation uses a conditional database update; the worker checks state before storing results so a cancelled scan does not later become completed. A worker must be running for queued assessments to progress. SQLite is acceptable for one local worker only.

## Scanner boundaries

Network access is isolated in `apps/scanner/network.py`; scope validation is in `apps/assets/domain_validation.py` and DNS policy in `apps/scanner/safety.py`. The scanner uses absolute A/AAAA resolution, rejects any non-global answer, pins the TCP connection to an approved IP and preserves the registered hostname for TLS SNI/verification. Redirects must stay on the exact verified host over HTTPS and are capped. A separate content sample targets only the origin root and reads at most 64 KiB of HTML/XHTML.

Checks live in `apps/scanner/checks.py` and return a common `Outcome`. New checks must consume only the smallest required observation and preserve the scope, timeout and evidence-minimization controls.

## Analysis and reporting

The risk score is a transparent WEBGUARD heuristic and must never be labeled CVSS. Scan comparison uses stable check IDs and only completed scans of the same asset. The security advisor is deterministic offline guidance keyed by check IDs; it does not call a language model or modify target systems. PDF report language is stored per report; Persian output needs RTL shaping modules and an installed Unicode Persian font.
