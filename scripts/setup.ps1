$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Python = Get-Command python -ErrorAction SilentlyContinue
$Node = Get-Command node -ErrorAction SilentlyContinue
$Npm = Get-Command npm -ErrorAction SilentlyContinue

if (-not $Python) { throw 'Python was not found. Install Python 3.12 or newer and add it to PATH.' }
if (-not $Node -or -not $Npm) { throw 'Node.js and npm are required. Install Node.js 20+ and reopen PowerShell.' }

$PythonVersion = & python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) { throw 'Could not execute Python. Verify the Python installation and PATH.' }
$Parts = $PythonVersion.Split('.')
if ([int]$Parts[0] -lt 3 -or ([int]$Parts[0] -eq 3 -and [int]$Parts[1] -lt 12)) { throw "Python 3.12+ is required; found $PythonVersion" }

$NodeVersion = (& node -p "process.versions.node").Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not execute Node.js. Verify the installation and PATH.' }
$NodeMajor = [int]($NodeVersion.Split('.')[0])
if ($NodeMajor -lt 20) { throw "Node.js 20+ is required; found $NodeVersion" }

$VenvPython = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $VenvPython)) {
    Write-Host '[1/5] Creating Python virtual environment...' -ForegroundColor Cyan
    & python -m venv (Join-Path $Root '.venv')
    if ($LASTEXITCODE -ne 0) { throw 'Python virtual environment creation failed.' }
}

Write-Host '[2/5] Installing backend dependencies...' -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'pip upgrade failed.' }
& $VenvPython -m pip install -r (Join-Path $Root 'backend\requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Backend dependency installation failed.' }

Write-Host '[3/5] Installing frontend dependencies...' -ForegroundColor Cyan
Push-Location (Join-Path $Root 'frontend')
try { & npm install; if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency installation failed.' } } finally { Pop-Location }

if (-not (Test-Path (Join-Path $Root '.env'))) {
    Copy-Item (Join-Path $Root '.env.example') (Join-Path $Root '.env')
    Write-Host 'Created .env from .env.example.' -ForegroundColor Yellow
}

Write-Host '[4/5] Creating database migrations and applying them...' -ForegroundColor Cyan
Push-Location (Join-Path $Root 'backend')
try {
    & $VenvPython manage.py makemigrations accounts organizations assets scans reports audit
    if ($LASTEXITCODE -ne 0) { throw 'Django makemigrations failed.' }
    & $VenvPython manage.py migrate
    if ($LASTEXITCODE -ne 0) { throw 'Django migrations failed.' }
    & $VenvPython manage.py check
    if ($LASTEXITCODE -ne 0) { throw 'Django system check failed.' }
} finally { Pop-Location }

Write-Host '[5/5] Setup completed.' -ForegroundColor Green
Write-Host 'Next: run .\scripts\dev.ps1 to open API, worker and frontend terminals.'
