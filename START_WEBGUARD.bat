@echo off
setlocal EnableExtensions EnableDelayedExpansion
set "ROOT=%~dp0"
set "WEBGUARD_ROOT=%ROOT%"
title WEBGUARD Launcher

rem Child service modes: the same BAT is reused to open dedicated console windows.
if /I "%~1"=="api" goto RUN_API
if /I "%~1"=="worker" goto RUN_WORKER
if /I "%~1"=="frontend" goto RUN_FRONTEND

cls
echo ============================================================
echo                  WEBGUARD - LOCAL LAUNCHER
echo ============================================================
echo.
echo Project: %ROOT%
echo.

if not exist "%ROOT%.venv\Scripts\python.exe" (
    echo [ERROR] Python virtual environment was not found.
    echo Run this once from the project folder:
    echo     powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
    goto MAIN_ERROR
)
if not exist "%ROOT%frontend\node_modules\vite" (
    echo [ERROR] Frontend dependencies were not found.
    echo Run this once from the project folder:
    echo     powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1
    goto MAIN_ERROR
)
if not exist "%ROOT%backend\manage.py" (
    echo [ERROR] backend\manage.py was not found. Keep this BAT in the WEBGUARD root folder.
    goto MAIN_ERROR
)

rem Check whether the WEBGUARD API is already healthy.
powershell.exe -NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:8000/health/'; if ($r.StatusCode -eq 200) { exit 0 } } catch {}; exit 1" >nul 2>&1
if not errorlevel 1 (
    echo [OK] Backend API is already running on port 8000.
) else (
    call :CHECK_PORT 8000
    if "!PORT_FREE!"=="0" (
        echo [ERROR] Port 8000 is occupied by another application, and WEBGUARD API did not answer its health check.
        echo Close the application using port 8000, then click this file again.
        goto MAIN_ERROR
    )
    echo [START] Starting Backend API...
    start "WEBGUARD API" "%ComSpec%" /k ""%~f0" api"
)

rem Avoid starting a duplicate scanner worker.
powershell.exe -NoProfile -Command "$p = Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^python(w)?\.exe$' -and $_.CommandLine -match 'run_scan_worker' }; if ($p) { exit 1 } else { exit 0 }" >nul 2>&1
if errorlevel 1 (
    echo [OK] A scanner worker is already running.
) else (
    echo [START] Starting Scanner Worker...
    start "WEBGUARD Scanner Worker" "%ComSpec%" /k ""%~f0" worker"
)

rem Reuse a Vite process belonging to this project, if one is already listening.
set "FRONTEND_PORT="
for /f "usebackq delims=" %%P in (`powershell.exe -NoProfile -Command "$root = [System.IO.Path]::GetFullPath($env:WEBGUARD_ROOT).TrimEnd('\'); $items = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -ge 5173 -and $_.LocalPort -le 5180 }; foreach ($item in $items) { $proc = Get-CimInstance Win32_Process -Filter ('ProcessId = ' + $item.OwningProcess) -ErrorAction SilentlyContinue; if ($proc -and $proc.CommandLine -like ('*' + $root + '\frontend\*') -and $proc.CommandLine -match 'vite') { Write-Output $item.LocalPort; break } }" 2^>nul`) do set "FRONTEND_PORT=%%P"

if defined FRONTEND_PORT (
    echo [OK] WEBGUARD Frontend is already running on port !FRONTEND_PORT!.
) else (
    rem Pick the first available port; this avoids the common 5173-in-use error.
    for %%P in (5173 5174 5175 5176 5177 5178 5179 5180) do (
        if not defined FRONTEND_PORT (
            call :CHECK_PORT %%P
            if "!PORT_FREE!"=="1" set "FRONTEND_PORT=%%P"
        )
    )
    if not defined FRONTEND_PORT (
        echo [ERROR] No free frontend port found between 5173 and 5180.
        goto MAIN_ERROR
    )
    echo [START] Starting Frontend on port !FRONTEND_PORT!...
    start "WEBGUARD Frontend" "%ComSpec%" /k ""%~f0" frontend !FRONTEND_PORT!"
)

echo.
echo Waiting briefly for services to initialize...
timeout /t 4 /nobreak >nul
start "" "http://127.0.0.1:!FRONTEND_PORT!"
echo.
echo ============================================================
echo WEBGUARD launch request completed.
echo Frontend: http://127.0.0.1:!FRONTEND_PORT!
echo API:      http://127.0.0.1:8000
echo Swagger:  http://127.0.0.1:8000/api/docs/
echo.
echo Keep the API, Worker and Frontend windows open while using WEBGUARD.
echo Close those service windows to stop the application.
echo ============================================================
echo.
pause
exit /b 0

:CHECK_PORT
set "PORT_FREE=0"
powershell.exe -NoProfile -Command "if (Get-NetTCPConnection -LocalPort %~1 -State Listen -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }" >nul 2>&1
if errorlevel 1 exit /b 0
set "PORT_FREE=1"
exit /b 0

:RUN_API
cd /d "%ROOT%backend"
echo Starting WEBGUARD API at http://127.0.0.1:8000 ...
"%ROOT%.venv\Scripts\python.exe" manage.py runserver 127.0.0.1:8000
echo.
echo WEBGUARD API process stopped.
pause
exit /b

:RUN_WORKER
cd /d "%ROOT%backend"
echo Starting WEBGUARD Scanner Worker ...
"%ROOT%.venv\Scripts\python.exe" manage.py run_scan_worker
echo.
echo WEBGUARD Scanner Worker stopped.
pause
exit /b

:RUN_FRONTEND
cd /d "%ROOT%frontend"
echo Starting WEBGUARD Frontend at http://127.0.0.1:%~2 ...
call npm.cmd run dev -- --host 127.0.0.1 --port %~2
echo.
echo WEBGUARD Frontend process stopped.
pause
exit /b

:MAIN_ERROR
echo.
echo WEBGUARD could not be started. Fix the message above and click this file again.
echo.
pause
exit /b 1
