# WEBGUARD localization

WEBGUARD supports English (`en`) and Persian (`fa`). The language selector is available on authentication and workspace screens. Selection is persisted in browser local storage under `webguard-language`.

## Frontend behavior

- English uses LTR and `en-US` date/time formatting.
- Persian uses RTL layout, a Persian-friendly system font stack and `fa-IR` date/time formatting.
- Navigation, forms, filters, findings workflow, notifications, scan comparison, insights, assistant guidance and report controls are translated.
- Hostnames, email addresses, IDs, header names, DNS values, check IDs and raw JSON evidence are intentionally preserved as technical data.

## PDF reports

PDF reports support the language selected at report creation (`language: en | fa`). The selected language is stored on the `SecurityReport` record and determines the output when the report is downloaded later.

Persian PDF output requires:

- `arabic-reshaper`
- `python-bidi`
- A Unicode Persian/Arabic TrueType font. The generator looks for Tahoma or Arial on Windows and Noto Sans Arabic/DejaVu Sans on common Linux paths.

These Python packages are installed by `scripts/setup.ps1` through `backend/requirements.txt`. If a Persian font is not found, report generation returns a clear server error; install Tahoma/Arial or configure an available Unicode font path before using Persian PDF generation. Technical identifiers and evidence values remain unmodified; fixed labels, check descriptions and remediation text are localized.

## Adding translations

Add the English source key to `src/i18n.tsx` usage through `t('English source text')` and add its Persian translation to the `fa` dictionary. Keep API enum values and CSS class names canonical; translate only display labels. Also add tests for important server-generated notification/PDF text when adding backend output.
