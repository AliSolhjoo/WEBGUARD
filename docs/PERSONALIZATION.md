# WEBGUARD Personalization Studio

## Overview

The Personalization Studio provides user-level interface preferences without changing security data, scan policy, organization settings, or role-based permissions.

## Available controls

- Themes: Midnight, Graphite, and Light.
- Accent colors: Blue, Cyan, Violet, Emerald, Rose, and Amber.
- Density: Compact, Comfortable, and Spacious.
- Sidebar: Expanded or Compact. On tablet/mobile, the sidebar expands to retain readable navigation labels.
- Content width: Standard or Wide.
- Corner shape: Sharp, Balanced, or Rounded.
- Text size: Small, Standard, or Large.
- Font family: System, Segoe UI, or Tahoma (availability depends on the operating system).
- Reduced motion preference.
- Dashboard widget visibility, ordering, and one/two-column layout (mobile remains one column).
- Sidebar navigation visibility and ordering within the existing Workspace, Security and Administration groups. Overview is kept visible as a recovery route; the Personalization Studio is always available. Ordering is constrained within the existing navigation groups so the group structure remains predictable.
- Curated profiles: Security Analyst, Executive, and Minimal.
- Export/import as a versioned JSON preferences file and reset to defaults.

## Persistence and privacy

Preferences are stored in browser `localStorage`, scoped by the authenticated WEBGUARD user ID. They are not sent to the backend and do not modify organization-level configuration. Users may export the JSON file to carry settings to another browser/device. Import accepts only the current schema version and normalizes all values against explicit allow-lists. Unknown fields are ignored; the JSON file cannot execute code or change server configuration.

If browser storage is unavailable or full, the current tab continues using in-memory preferences, but persistence may not be available. Clearing browser storage also clears locally saved customization.

## Responsive behavior

The dashboard column selection applies on wide screens. At tablet/mobile breakpoints, the dashboard uses one column. Compact navigation is expanded on tablet/mobile so labels remain available. The settings screen itself stacks into one column on narrow screens.

## Validation

Run from `frontend/`:

```powershell
npm run test:preferences
npm run build
```

The Node built-in test suite verifies default profiles, every supported visual/layout mode, the complete allowed appearance-combination matrix, dashboard widget allow-lists/order normalization, sidebar visibility/order and recovery behavior, schema-version rejection, round-trip serialization, unknown-field rejection and per-user persistence isolation.
