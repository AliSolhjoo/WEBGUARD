# Testing and verification

## Full local validation (Windows)

After `scripts/setup.ps1` has installed dependencies and created migrations/database, run from the repository root:

```powershell
.\scripts\test.ps1
```

The script stops on the first failure and executes:

1. `python manage.py check`
2. `python manage.py makemigrations --check --dry-run`
3. `coverage run -m pytest`
4. `coverage report -m`
5. `npm run build` (strict TypeScript check plus Vite production bundle)

## Test groups

- `test_domain_safety.py`: hostname normalization, reserved host rejection, public/private address validation and redirect safety.
- `test_network_policy.py`: DNS resolution policy, pinned destination, TLS hostname/SNI, same-host redirect cap.
- `test_security_checks.py`: stable check registry, headers, cookies, SPF/DMARC/CAA, mixed content and disclosure evidence minimization.
- `test_risk.py`: heuristic scoring.
- `test_assistant_rules.py`: offline guidance for every scanner check ID and English/Persian behavior.
- `test_scanner_runner.py`: worker state transitions, cancellation and origin-root-only content sampling.
- `test_api_security.py`: authentication, tenant isolation, role enforcement, finding assignment, comparison, notifications, assistant and report language.
- `test_pdf_report.py`: PDF byte output (English; Persian rendering also requires RTL/font dependencies).

All network/DNS behavior in unit tests is mocked. Automated tests do not send probes to arbitrary live targets.

## Build environment boundary

The ZIP assembly environment may not have Django/DRF or frontend npm packages installed and may not have network access to package registries. A successful pure-unit or syntax check is not a substitute for `pytest-django`, Django system/migration checks, strict TypeScript checking or a Vite production build. The implementation status file records exactly which checks were executable during packaging. The Windows `setup.ps1` installs dependencies, and `test.ps1` is the required final validation on the target machine.
