@echo off
REM ==================================================================
REM   VELD VALIDATOR (ENDORSE-ONLY)
REM
REM   Runs a full P2P node that ENDORSES blocks as a registered
REM   validator. It does NOT mine: no proof-of-work, no 1 GB dataset,
REM   low CPU and memory. You earn a share of the endorsement pool
REM   instead of block rewards.
REM
REM   Want to mine AND endorse (earn both)? Run "Start Mining.bat"
REM   instead -- a registered validator that mines endorses its own
REM   blocks automatically.
REM
REM   Do NOT run this at the same time as "Start Mining.bat" -- they
REM   share the same data directory and port. Pick one.
REM
REM   To become a validator (custodial-bond model):
REM     1. Register from the wallet's Validators page. Registering BONDS
REM        the production minimum (10,000 VELD) from your spendable balance
REM        into the protocol custody vault -- the bond IS the
REM        registration, there is no separate "stake" step.
REM     2. Keep a small SPENDABLE balance for endorsement fees. Each
REM        endorsement is a tiny fee-paying transaction; a validator with
REM        zero spendable balance silently cannot endorse.
REM     3. Keep this node running 24/7 to earn endorsement rewards.
REM     4. The 100-block operation cooldown must pass before deregistration.
REM        After deregistration, the bond remains slashable through the full
REM        43,200-block (90-day) finality evidence horizon (measured from
REM        the last counted finality vote when later) and returns at the first
REM        480-block settlement boundary strictly after that horizon.
REM        Ordinary endorsement double-signing confiscates 50%; conflicting
REM        locked-finality votes confiscate 100% (25% reporter, 75% burn).
REM        Run ONE instance per validator key.
REM ==================================================================
setlocal DisableDelayedExpansion EnableExtensions
REM Preserve the install path as data before delayed expansion is enabled.
REM Inline PowerShell reads it from the environment so apostrophes and other
REM PowerShell metacharacters in a Windows profile/install path stay inert.
set "_VELD_INSTALL_DIR=%~dp0"
if "%_VELD_INSTALL_DIR:~-1%"=="\" set "_VELD_INSTALL_DIR=%_VELD_INSTALL_DIR:~0,-1%"
setlocal EnableDelayedExpansion
REM UTF-8 codepage for non-ASCII install paths.
chcp 65001 >nul
cd /d "%~dp0"

REM -- Fleet anchor: a validator with no anchor peer would stall out of the box.
REM    Seed the fleet anchor IPs by default so the node joins the mesh. Operators
REM    can override by setting VELD_FLEET_ANCHOR_IPS before launch.
if not defined VELD_FLEET_ANCHOR_IPS set "VELD_FLEET_ANCHOR_IPS=5.78.107.166,5.78.97.56,5.78.127.51"

set CLIENT_VERSION=3.0.0
title Veld Validator v%CLIENT_VERSION% (endorse-only)

echo.
echo ============================================================
echo   VELD VALIDATOR v%CLIENT_VERSION% ^(endorse-only^)
echo   Where value is earned.
echo ============================================================
echo.
echo   NOTE: This node endorses blocks as a validator and does NOT
echo         mine. To mine AND endorse, run "Start Mining.bat" instead.
echo         Do not run both - they share the same data folder.
echo.

REM --- Binary sanity check -------------------------------------
if not exist "%~dp0bin\veld-node.exe" (
    echo   ERROR: bin\veld-node.exe is missing.
    echo   Redownload the client from https://veld.network
    echo.
    pause
    exit /b 1
)
for %%F in ("%~dp0bin\veld-node.exe") do if %%~zF LSS 1000000 (
    echo   ERROR: bin\veld-node.exe looks truncated ^(under 1 MB^).
    echo   Your download is corrupted. Redownload from https://veld.network
    echo.
    pause
    exit /b 1
)

REM --- SHA256 integrity check (ALL files, not just the exe) ---
REM Extended to every file in SHA256SUMS.txt
REM (bat launchers, binaries, README) to close the swap-the-bat attack
REM vector. See Start Mining.bat for full rationale.
REM missing SHA256SUMS.txt now fails loud (was: silent skip).
if not exist "%~dp0SHA256SUMS.txt" (
    echo.
    echo   [integrity] FAILED. SHA256SUMS.txt is missing from this package.
    echo   Re-download from https://veld.network/downloads/VeldClient-Windows-x64.zip
    echo   DO NOT run unverified binaries.
    echo.
    pause
    exit /b 1
)
if not exist "%~dp0SHA256SUMS.txt.sig" (
    echo.
    echo   [integrity] FAILED. Detached release signature is missing.
    echo   This package is unsigned and will not be executed.
    echo.
    pause
    exit /b 1
)
set "_VELD_SIGCHECK=%TEMP%\veld-release-check-%RANDOM%-%RANDOM%.txt"
"%~dp0bin\veld-node.exe" --verify-release "%~dp0SHA256SUMS.txt" "%~dp0SHA256SUMS.txt.sig" >"!_VELD_SIGCHECK!" 2>nul
if errorlevel 1 goto v_package_signature_failed
powershell -NoProfile -ExecutionPolicy Bypass -Command "$x=@(Get-Content -LiteralPath $env:_VELD_SIGCHECK); if($x.Count -ne 1 -or $x[0] -cne 'RELEASE-SIGNATURE-VALID'){exit 1}"
if errorlevel 1 goto v_package_signature_failed
del /Q "!_VELD_SIGCHECK!" >nul 2>nul
echo   [integrity] release signature: VALID ^(pinned key^)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$l=@(Get-Content -LiteralPath (Join-Path $env:_VELD_INSTALL_DIR 'SHA256SUMS.txt')); $v=@($l | Where-Object { $_.StartsWith('# release-version=') }); if ($l.Count -lt 2 -or $l[0] -cne '# veld-release-manifest-v1' -or $v.Count -ne 1 -or $v[0] -cne '# release-version=%CLIENT_VERSION%') { exit 1 }"
if errorlevel 1 (
    echo   [integrity] FAILED. Signed manifest version does not match this launcher.
    pause
    exit /b 1
)
echo   [integrity] signed release version: %CLIENT_VERSION%
echo   [integrity] verifying every file in SHA256SUMS.txt ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$bad=$false; $n=0; foreach ($line in Get-Content -LiteralPath (Join-Path $env:_VELD_INSTALL_DIR 'SHA256SUMS.txt')) { if ($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$') { $exp=$matches[1].ToLower(); $p=Join-Path $env:_VELD_INSTALL_DIR ($matches[2].Trim()); if (Test-Path -LiteralPath $p) { $got=(Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower(); if ($got -ne $exp) { Write-Host ('   MISMATCH: ' + $matches[2].Trim()); Write-Host ('     expected=' + $exp); Write-Host ('     actual  =' + $got); $bad=$true } else { $n++ } } else { Write-Host ('   MISSING: ' + $matches[2].Trim()); $bad=$true } } }; if ($bad) { Write-Host ''; Write-Host '   [integrity] FAILED. Your package has been modified or partially downloaded.'; Write-Host '   Re-download from https://veld.network and verify SHA256SUMS.txt against the'; Write-Host '   .zip.sha256 hosted OUT-OF-BAND at veld.network/downloads/VeldClient-Windows-x64.zip.sha256.'; Write-Host '   DO NOT run an unverified package.'; exit 1 } else { Write-Host ('   [integrity] OK: ' + $n + ' files verified.') }"
if errorlevel 1 (
    echo.
    pause
    exit /b 1
)
goto v_package_signature_ok
:v_package_signature_failed
del /Q "!_VELD_SIGCHECK!" >nul 2>nul
echo.
echo   [integrity] FAILED. Release signature is invalid.
echo   Refusing to trust package hashes or execute this client.
echo.
pause
exit /b 1
:v_package_signature_ok

REM Signed mandatory-version check. Validator mode does not self-install while
REM running; it refuses a known-stale binary and directs the operator to the
REM signed package/update path.
echo   [update] checking signed release manifest ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Check -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal
if errorlevel 2 goto v_update_required
if errorlevel 1 echo   [update] Signed feed unavailable; continuing with the locally verified client.
goto v_update_ok
:v_update_required
echo.
echo   [update] A newer signed client is required. Validator will not start.
echo   Download the signed package or run Start Mining.bat to install it.
echo.
pause
exit /b 1
:v_update_ok

REM --- Clock-drift reminder -------------------------------------
REM Endorsements are signed over a block height + hash; a drifted
REM clock can make the node reject the very tip it should endorse.
echo   [clock] If endorsement fails with clock-drift errors, run
echo           'w32tm /resync' in an Administrator Command Prompt.
echo.
if not exist "veld-data" mkdir veld-data
if exist "%~dp0veld-data\.force-update" del /Q "%~dp0veld-data\.force-update" 2>nul
start "veld-update-watcher" /B powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Watch -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal

REM --- Already-running detection (scoped to THIS directory) ----
REM Warn only when veld-node.exe is already running from THIS directory.
REM Killing every instance system-wide could corrupt other instances'
REM LevelDB WAL. Use PowerShell because wmic is absent on current Windows.
for /f "usebackq tokens=*" %%p in (`powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter 'Name=\"veld-node.exe\"' | Where-Object { $_.CommandLine -like ('*' + $env:_VELD_INSTALL_DIR + '*') } | Select-Object -ExpandProperty ProcessId" 2^>nul`) do (
    echo.
    echo   WARNING: veld-node.exe is already running from this folder ^(PID %%p^).
    echo   Close the other window first, or press Ctrl+C to cancel.
    echo.
    pause
)

REM --- Privacy networking: Tor-only (v2.7.32) ------------------
echo   [network] This validator runs PRIVATE via Tor: all peer traffic is
echo             routed through Tor and you are reachable only as a .onion,
echo             so your home IP is never exposed. RPC 8334 stays localhost.
echo             The official Tor is fetched once and checksum-verified.
echo.
REM The signed release package must contain the Tor helper. Never download or
REM replace executable support code outside the authenticated updater.
if not exist "%~dp0tor-setup.ps1" goto :v_tor_failed
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Join-Path $env:_VELD_INSTALL_DIR 'tor-setup.ps1'; $expected='4314c8a9dadf50dec8f40a34ad1bdce82e091faca3c6708fb99ec78d7e3369eb'; if((Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() -cne $expected){Write-Host '   [tor] signed Tor helper hash mismatch.'; exit 1}"
if errorlevel 1 goto :v_tor_failed
echo   [tor] setting up private networking ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tor-setup.ps1" "%~dp0veld-data"
if errorlevel 1 goto :v_tor_failed
goto :v_tor_ok
:v_tor_failed
echo.
echo   [tor] Could not start Tor - not starting, to avoid exposing your IP.
echo   Re-run this launcher to retry.
echo.
pause
exit /b 1
:v_tor_ok
echo.
echo   [validator-check] Before endorsement rewards flow, you must ALSO:
echo             1. Register on the wallet's Validators page. Registering
echo                BONDS the production minimum (10,000 VELD) from your
echo                spendable balance
echo                into the protocol custody vault - there is no separate
echo                staking step.
echo             2. Keep a small spendable balance for endorsement fees.
echo             3. Keep this window running 24/7.
echo             The 100-block operation cooldown must pass before deregister.
echo             After deregistration the bond remains slashable for the full
echo             43,200-block ^(90-day^) finality evidence horizon ^(measured
echo             from the last counted finality vote when later^) and returns
echo             at the first 480-block boundary strictly after that horizon.
echo             An endorsement double-sign confiscates 50%%; a conflicting
echo             locked-finality vote confiscates 100%% ^(25%% reporter,
echo             75%% burn^). Run just ONE instance per validator key.
echo             Until you register, this binary runs as a plain mining node
echo             - harmless, but earns no endorsement rewards.
echo.

REM hardcoded --connect args removed (see Start Mining.bat
REM for full rationale). The in-binary seeder.h list is the durable peer-discovery
REM source; freezing DNS names into the .bat creates a multi-decade stranding risk.
"%~dp0bin\veld-node.exe" --endorse --tor-only --datadir "%~dp0veld-data"

echo.
echo Node stopped.
pause
endlocal
