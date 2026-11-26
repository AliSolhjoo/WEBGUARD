$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $Python)) { throw 'Virtual environment not found. Run setup.ps1 first.' }
Push-Location (Join-Path $Root 'backend')
try {
    & $Python manage.py check
    if ($LASTEXITCODE -ne 0) { throw 'Django system check failed.' }
    & $Python manage.py makemigrations --check --dry-run
    if ($LASTEXITCODE -ne 0) { throw 'Migration consistency check failed.' }
    & $Python -m coverage run -m pytest
    if ($LASTEXITCODE -ne 0) { throw 'Backend test suite failed.' }
    & $Python -m coverage report -m
    if ($LASTEXITCODE -ne 0) { throw 'Coverage report failed.' }
} finally { Pop-Location }
Push-Location (Join-Path $Root 'frontend')
try {
    & npm run test:preferences
    if ($LASTEXITCODE -ne 0) { throw 'Frontend preferences test suite failed.' }
    & npm run build
    if ($LASTEXITCODE -ne 0) { throw 'Frontend production build failed.' }
} finally { Pop-Location }
Write-Host 'Backend tests and frontend production build completed.' -ForegroundColor Green
