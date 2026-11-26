# API reference — WEBGUARD 2.0

Base path: `/api/v1/`. Schema: `/api/schema/`; Swagger: `/api/docs/`; ReDoc: `/api/redoc/`. Protected routes require `Authorization: Bearer <access-token>`.

## Authentication

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register/` | Create a user and first organization owner; return JWT pair. |
| POST | `/auth/login/` | Obtain access/refresh tokens using email and password. |
| POST | `/auth/refresh/` | Rotate/refresh access token. |
| POST | `/auth/logout/` | Blacklist the authenticated user's refresh token. |
| GET | `/auth/me/` | Current account and primary organization. |

Registration example:

```json
{
  "email": "analyst@example.com",
  "password": "use-a-unique-long-passphrase-123",
  "full_name": "Security Analyst",
  "organization_name": "Example Security Team"
}
```

## Organization and dashboard

| Method | Path | Purpose |
|---|---|---|
| GET | `/organization/` | Current organization and role. |
| GET | `/organization/members/` | List organization members. |
| POST | `/organization/members/` | Add/update an existing account role (owner/admin only). |
| GET | `/dashboard/overview/` | Counts, findings distribution, recent scans and latest heuristic score. |
| GET | `/dashboard/trends/` | Last 30-day activity, score history and open findings by severity. |

## Assets

| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/assets/` | List or add hostname. |
| GET / DELETE | `/assets/{id}/` | Read/delete an asset in the current organization. |
| GET / POST | `/assets/{id}/verification/` | Read DNS TXT challenge or verify that challenge. |

POST `/assets/`: `{ "domain": "example.com" }`. URL schemes, paths, ports, wildcards, credentials, reserved/local hostnames and IP literals are rejected. Verification GET returns the exact TXT `record_name`, `record_type` and `expected_value`; do not publish the token anywhere except the authoritative TXT record.

## Assessments and findings

| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/scans/` | List assessments or queue a passive scan. |
| GET / POST | `/scans/{id}/` | Read result/checks or cancel pending/running scan. |
| GET | `/scans/{id}/comparison/` | Compare a completed scan with the previous completed scan for the same asset. |
| GET | `/findings/` | List tenant findings; optional `status`, `severity`, `asset`, `q` filters. |
| PATCH | `/findings/{id}/` | Update status, notes and `assigned_to` (workspace member ID or null). |

Queue payload: `{ "asset": 1, "profile": "passive" }`. Only verified assets and the passive profile are accepted. A local scanner worker must be running.

Finding update example:

```json
{
  "status": "open",
  "assigned_to": 12,
  "notes": "Review CSP in the staging environment before deployment."
}
```

A viewer cannot be assigned remediation work. The assignee must belong to the current workspace.

## Offline security advisor

| Method | Path | Purpose |
|---|---|---|
| POST | `/assistant/analyze/` | Generate deterministic rule-based remediation for a tenant finding. |

Payload: `{ "finding_id": 7, "language": "fa" }`. `language` is `en` or `fa`. No external AI endpoint is called. Response includes impact, steps, validation criteria, stored evidence and limitations.

## Reports, notifications and audit

| Method | Path | Purpose |
|---|---|---|
| GET / POST | `/reports/` | List reports or generate a PDF for a completed scan. |
| GET | `/reports/{id}/download/` | Authenticated, organization-scoped PDF download. |
| GET | `/notifications/` | Current user's notification list and unread count. |
| POST | `/notifications/{id}/read/` | Mark the current user's notification read. |
| DELETE | `/notifications/{id}/` | Delete the current user's notification. |
| GET | `/audit-logs/` | Recent organization audit events (owner/admin only). |

Report creation payload: `{ "scan": 7, "language": "fa" }`. A report stores its language at generation time; later UI language changes do not change an existing report.

## Health and error behavior

`GET /health/` is a public liveness route. Errors use standard DRF JSON responses. All object reads/writes are scoped to the authenticated user's single workspace. Multi-workspace switching is not implemented in this release.
