$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$VenvPython = Join-Path $Root '.venv\Scripts\python.exe'
if (-not (Test-Path $VenvPython)) { throw 'Virtual environment not found. Run .\scripts\setup.ps1 first.' }
if (-not (Test-Path (Join-Path $Root 'frontend\node_modules'))) { throw 'Frontend dependencies not found. Run .\scripts\setup.ps1 first.' }

$Backend = Join-Path $Root 'backend'
$Frontend = Join-Path $Root 'frontend'
$ApiCommand = "Set-Location '$Backend'; & '$VenvPython' manage.py runserver 127.0.0.1:8000"
$WorkerCommand = "Set-Location '$Backend'; & '$VenvPython' manage.py run_scan_worker"
$FrontendCommand = "Set-Location '$Frontend'; npm run dev"

Start-Process powershell.exe -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $ApiCommand) | Out-Null
Start-Sleep -Seconds 2
Start-Process powershell.exe -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $WorkerCommand) | Out-Null
Start-Process powershell.exe -ArgumentList @('-NoExit', '-ExecutionPolicy', 'Bypass', '-Command', $FrontendCommand) | Out-Null
Write-Host 'WEBGUARD services launched in separate PowerShell windows.' -ForegroundColor Green
Write-Host 'Frontend: http://127.0.0.1:5173'
Write-Host 'API health: http://127.0.0.1:8000/health/'
Write-Host 'Django admin: http://127.0.0.1:8000/admin/'
