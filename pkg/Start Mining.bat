@echo off
REM ==================================================================
REM   VELD DESKTOP MINING + VALIDATOR CLIENT
REM
REM   One binary (veld-node.exe) runs both the full node and the mining
REM   + endorsement loop. On first launch you will be asked how to set
REM   up your miner's reward address:
REM
REM     [1] Resume previous session
REM     [2] Log in from a keyfile (.veld-keys)
REM     [3] Log in with a different VELD wallet (paste private key)
REM     [4] Create a brand-new wallet
REM
REM   This is NOT a wallet. To send, receive, or stake VELD, use
REM   the web wallet at https://wallet.veld.network
REM ==================================================================
setlocal DisableDelayedExpansion EnableExtensions
REM Preserve the install path as data before delayed expansion is enabled.
REM Inline PowerShell reads it from the environment so apostrophes and other
REM PowerShell metacharacters in a Windows profile/install path stay inert.
set "_VELD_INSTALL_DIR=%~dp0"
if "%_VELD_INSTALL_DIR:~-1%"=="\" set "_VELD_INSTALL_DIR=%_VELD_INSTALL_DIR:~0,-1%"
setlocal EnableDelayedExpansion
REM Force UTF-8 codepage so non-ASCII install paths don't break findstr.
chcp 65001 >nul
cd /d "%~dp0"

REM -- Fleet anchor (mining gate): a fresh download has no anchor peer and would
REM    HALT mining ("[mining] HALTED: no anchor peer connected"). Seed the fleet
REM    anchor IPs by default so mining works out of the box. Operators can still
REM    override by setting VELD_FLEET_ANCHOR_IPS before launch.
if not defined VELD_FLEET_ANCHOR_IPS set "VELD_FLEET_ANCHOR_IPS=5.78.107.166,5.78.97.56,5.78.127.51"

REM --- Interrupted-update recovery --------------------------------
REM The updater keeps a fixed, signed-tree transaction journal beside this
REM launcher.  Recover it before reading the manifest or executing the node;
REM a power loss during per-file promotion must never strand a mixed release.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Recover -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal
if errorlevel 1 (
    echo.
    echo   [update] FAILED to recover an interrupted signed update.
    echo   Do not run this mixed install. Re-run this launcher or
    echo   download a fresh client from https://veld.network/downloads/
    echo.
    pause
    exit /b 1
)

REM -- CLIENT VERSION -----------------------------------------------
REM   Bump this string EVERY TIME a new Windows client zip is published.
REM   Format: MAJOR.MINOR.PATCH (strict semantic versioning).
REM   It's displayed in the welcome banner so users can confirm they're
REM   on the current release at a glance.
set CLIENT_VERSION=3.0.3
title Veld Desktop Mining Client v%CLIENT_VERSION%

echo.
echo ============================================================
echo   VELD DESKTOP MINING + VALIDATOR CLIENT  v%CLIENT_VERSION%
echo   Where value is earned.
echo ============================================================
echo.

REM --- Binary sanity check -------------------------------------
REM Refuse to launch if the binary is missing, zero-byte, or wrong.
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
REM Verify every file listed in SHA256SUMS.txt, including the launchers,
REM binaries, and README. The authoritative
REM SHA256SUMS.txt hash lives at veld.network/downloads/*.sha256
REM (out-of-band). Users who land via Discord/Telegram links
REM should independently fetch that .sha256 and compare.
REM previously this check used `if exist` and silently
REM skipped the entire integrity verification when SHA256SUMS.txt was missing
REM (e.g., partial extraction, archive tool corruption, malicious removal).
REM Users would unknowingly launch unverified binaries. Now: missing SHA256SUMS
REM is a fail-loud condition that halts launch.
if not exist "%~dp0SHA256SUMS.txt" (
    echo.
    echo   [integrity] FAILED. SHA256SUMS.txt is missing from this package.
    echo   This means either:
    echo     1. The .zip was extracted incompletely or with the wrong tool
    echo     2. The package has been tampered with
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
if errorlevel 1 goto package_signature_failed
powershell -NoProfile -ExecutionPolicy Bypass -Command "$x=@(Get-Content -LiteralPath $env:_VELD_SIGCHECK); if($x.Count -ne 1 -or $x[0] -cne 'RELEASE-SIGNATURE-VALID'){exit 1}"
if errorlevel 1 goto package_signature_failed
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
goto package_signature_ok
:package_signature_failed
del /Q "!_VELD_SIGCHECK!" >nul 2>nul
echo.
echo   [integrity] FAILED. Release signature is invalid.
echo   Refusing to trust package hashes or execute this client.
echo.
pause
exit /b 1
:package_signature_ok

REM --- Update check (interactive Y/N - required to mine) -----------
REM An outdated client running against a post-consensus-change network can
REM disconnects, mines orphan blocks, or worst-case forks the chain.
REM Updates are now MANDATORY - the launcher will not continue if a
REM newer client is available. v2.7.15: the launcher now ASKS (Y/N) and
REM shows the changelog on the prompt; declining (N) exits without mining
REM (you cannot mine on a stale client). A background watcher
REM (spawned below) re-checks every hour while the client runs and
REM triggers exit code 77 (mandatory restart) if the server
REM publishes a newer build mid-session. The launcher catches 77
REM and re-runs itself, which forces install on next startup.
echo   [update] checking for newer client ...
REM v2.7.87: update discovery is authenticated before any remote hash is
REM trusted.  veld-update.ps1 requires SHA256SUMS.txt.sig to verify against
REM the release key pinned in the currently installed veld-node.exe.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Check -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal
if errorlevel 2 goto do_update
if errorlevel 1 echo   [update] Signed update feed unavailable; keeping the currently verified client.
goto skip_update
:do_update
echo.
echo   ============================================================
echo   A newer Veld client is available.
echo   ============================================================
echo.
echo   What's new in this update:
echo   ------------------------------------------------------------
echo   The signed updater verified the new release manifest and changelog.
echo   Full release notes: https://veld.network
echo   ------------------------------------------------------------
echo.
echo   Updating is REQUIRED to mine. An outdated client is rejected by
echo   the network ^(genesis / consensus mismatch^) and earns no rewards.
echo.
set "_upd="
set /p "_upd=   Update now? (Y/N): "
if /I "!_upd!"=="Y"   goto do_install
if /I "!_upd!"=="YES" goto do_install
echo.
echo   ============================================================
echo   Update declined. This client will NOT mine until it is
echo   updated. Re-run Start Mining.bat and choose Y when ready.
echo   ============================================================
echo.
pause
exit /b 1

:do_install
echo.
echo   [update] Downloading and installing the new client ...
echo   [update] (Press Ctrl+C now to cancel and quit. The changelog
echo            will be shown on the new launcher's welcome screen.)
echo.
REM v2.7.88: the verified package is moved into a fixed transaction journal.
REM A hidden PowerShell commit process waits for this cmd PID to exit, backs
REM up the complete old signed tree, atomically replaces each file, promotes
REM the signed manifest last, rehashes the live tree, and only then relaunches.
REM Any error rolls back; any power loss is recovered at the top of this file.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Install -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal
if errorlevel 1 goto update_failed
goto signed_update_complete
:signed_update_complete
echo.
echo   ============================================================
echo   [update] Package authenticated. This window will now close;
echo   [update] the transactional installer will commit, verify, and
echo   [update] reopen the signed client. If it doesn't, double-click
echo   [update] Start Mining.bat to recover or resume safely.
echo   ============================================================
echo.
timeout /t 3 /nobreak >nul 2>nul
REM Full 'exit' (not 'exit /b') so the launching window closes in EVERY
REM mode -- including when started from an existing cmd prompt. 'exit /b'
REM only closed it under cmd /c (double-click); an interactive parent cmd
REM lingered, so the relaunch VBS would wait its full parent-PID-poll
REM ceiling before reopening (the delay + old window staying open the
REM operator saw). With full 'exit' the cmd dies in ~3s and the poll
REM exits immediately via its `If Not alive` branch.
exit 0

:update_failed
echo.
echo   [update] Update FAILED. Cannot launch an outdated client
echo   [update] against a newer network - refusing to start mining.
echo   [update] Manually download from https://veld.network/downloads/
echo   [update] and re-run Start Mining.bat
echo.
pause
exit /b 1

:skip_update

REM v2.7.5: show the local CHANGES.txt to the user. Updates are
REM mandatory + automatic so the user never sees what changed during
REM the install itself; printing the (short) local file every launch
REM keeps them informed before mining starts. Reads from the bundled
REM pkg/CHANGES.txt that just got copied during install.
if not exist "%~dp0CHANGES.txt" goto after_changelog
echo.
echo   ------------------------------------------------------------
echo   What's new in this release:
echo   ------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $t=Get-Content -Raw -LiteralPath (Join-Path $env:_VELD_INSTALL_DIR 'CHANGES.txt'); $L=$t -split '\r?\n'; $s=0; for($i=0;$i -lt $L.Count;$i++){ if($L[$i] -match '^-{10,}'){ $s=$i; break } }; $v=@(); for($i=0;$i -lt $L.Count;$i++){ if($L[$i] -match '^v[0-9]'){ $v+=$i } }; $e=if($v.Count -ge 2){$v[1]}else{$L.Count}; $b=$L[$s..($e-1)]; while($b.Count -gt 0 -and ($b[-1].Trim() -eq '' -or $b[-1] -match '^-{10,}$')){ $b=$b[0..($b.Count-2)] }; $b | ForEach-Object { Write-Host $_ } } catch {}"
echo   ------------------------------------------------------------
echo.
:after_changelog

REM -- Network mode: PRIVATE by default.  The separately named clearnet
REM    launcher is the only supported opt-out and must set VELD_CLEARNET=1.
REM    A missing, empty, false, or legacy VELD_TOR value always stays on Tor.
if not exist "%~dp0veld-data" mkdir "%~dp0veld-data"

REM Prefer the official signed snapshot when it is newer. The node keeps RPC,
REM inbound P2P, explorer, and mining disabled until an independent background
REM sync from genesis reaches the exact same tip and state digest.
set "SYNCFLAG=--snapshot-bootstrap"

REM Clearnet requires an exact affirmative opt-in supplied by
REM "Start Mining (Clearnet).bat".  Never fail open or infer consent merely
REM because a privacy variable is absent.
if /I "!VELD_CLEARNET!"=="1" goto :net_clearnet

echo.
echo   ------------------------------------------------------------
echo   Network: PRIVATE by default ^(Tor^).
echo   ------------------------------------------------------------
echo   All peer traffic is routed through Tor and you are reachable only
echo   as a .onion - your home IP is never exposed. Wallet keys and RPC
echo   stay localhost-only. The official Tor is downloaded once and
echo   verified against a pinned checksum ^(nothing is bundled^).
echo   Want max speed instead ^(exposes your IP^)? Run
echo   "Start Mining (Clearnet).bat".
echo.
REM The signed release package must contain the Tor helper. Never download or
REM replace executable support code from a launcher outside the signed updater.
if not exist "%~dp0tor-setup.ps1" (
  echo    [tor] signed Tor helper is missing.
  goto :tor_failed
)
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=Join-Path $env:_VELD_INSTALL_DIR 'tor-setup.ps1'; $expected='4314c8a9dadf50dec8f40a34ad1bdce82e091faca3c6708fb99ec78d7e3369eb'; if((Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLower() -cne $expected){Write-Host '   [tor] signed Tor helper hash mismatch.'; exit 1}"
if errorlevel 1 goto :tor_failed
echo   [tor] setting up private networking ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tor-setup.ps1" "%~dp0veld-data"
if errorlevel 1 goto :tor_failed
set "NETFLAG=--tor-only"
goto :net_done

:tor_failed
echo.
echo   ============================================================
echo   [tor] Could not start Tor, so your IP is NOT protected.
echo   Mining is paused to avoid exposing you. Options:
echo     - Re-run "Start Mining.bat" to retry ^(transient network or AV^).
echo     - Run "Start Mining (Clearnet).bat" to mine over clearnet
echo       ^(faster, but publishes your IP^).
echo   ============================================================
echo.
pause
exit /b 1

:net_clearnet
echo.
echo   ------------------------------------------------------------
echo   Network: CLEARNET ^(your IP is visible to peers^)
echo   ------------------------------------------------------------
echo.
set "NETFLAG=--reachable"

:net_done


REM --- Already-running detection (scoped to THIS directory) ----
REM Detect only instances launched from this installation directory.
for /f "usebackq tokens=*" %%p in (`powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter 'Name=\"veld-node.exe\"' | Where-Object { $_.CommandLine -like ('*' + $env:_VELD_INSTALL_DIR + '*') } | Select-Object -ExpandProperty ProcessId" 2^>nul`) do (
    echo.
    echo   WARNING: veld-node.exe is already running ^(PID %%p^).
    echo   Close the other window first, or press Ctrl+C to cancel.
    echo.
    pause
)

REM -- Background mandatory-update watcher -----------------------
REM The watcher accepts only a release-signed manifest verified by the pinned
REM key. A missing/invalid signature cannot force a restart or provide a hash.
REM On a real signed version change it writes veld-data\.force-update; the node
REM observes that sentinel and shuts down cleanly before the launcher restarts.
if exist "%~dp0veld-data\.force-update" del /Q "%~dp0veld-data\.force-update" 2>nul
start "veld-update-watcher" /B powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-update.ps1" -Mode Watch -InstallDir "%_VELD_INSTALL_DIR%" -Distribution Terminal

REM Restart loop. veld-node.exe must not be a
REM run-once process for a 24/7 mining client. Crashes (LevelDB
REM IO, network glitches, OOM, unhandled exceptions) would
REM otherwise leave the user with a dead window and no mining
REM rewards. Wrap the exe in a controlled restart loop with
REM exponential backoff (1s, 5s, 15s, 30s, 60s, 60s...). User
REM can break out with Ctrl+C twice (first interrupts the exe,
REM second exits the loop before the next restart).
set _restart_count=0
set _restart_delay=1
:restart_loop
echo.
echo   [start] Launching veld-node.exe ^(attempt #!_restart_count!^)
echo.
REM v2.7.5: silence the vendored-pin selftest print on stderr so the
REM welcome screen stays clean; the selftest still runs internally and
REM aborts the process if vendored.h has been tampered with.
set VELD_QUIET_SELFTEST=1
"%~dp0bin\veld-node.exe" --mine !NETFLAG! !SYNCFLAG! --datadir "%~dp0veld-data"
set _exit_code=!ERRORLEVEL!

echo.
echo   [stopped] veld-node.exe exited with code !_exit_code!.

REM v2.7.2 - mandatory-update flag set by background watcher.
REM If present, treat as exit code 77 regardless of actual code.
if exist "%~dp0veld-data\.force-update" (
    del /Q "%~dp0veld-data\.force-update" 2>nul
    echo   [restart] Mandatory client update detected by background watcher.
    goto :relaunch_for_update
)
REM Exit code 77 = veld-node requested mandatory update.
if !_exit_code! EQU 77 (
    echo   [restart] Mandatory update requested by client.
    goto :relaunch_for_update
)
if !_exit_code! EQU 0 (
    echo   [stopped] Clean exit ^(Ctrl+C or shutdown^). Not restarting.
    goto :user_stop
)
REM Ctrl+C against the node yields the Windows control-C status code
REM (-1073741510 / 0xC000013A) when the node is torn down by the default
REM console handler instead of exiting 0. Treat that as a deliberate user
REM stop -- NOT a crash to restart. Without this the loop would relaunch
REM the node after the user pressed Ctrl+C and answered N to "Terminate
REM batch job (Y/N)?", and the window would never close.
if !_exit_code! EQU -1073741510 goto :user_stop
if !_exit_code! EQU 3221225786  goto :user_stop
REM Exit code 75 = node requested clean restart (chain replay handles it).
REM Exit code 76 is reserved for a snapshot/background-validation mismatch that
REM requires explicit operator recovery. Signed snapshot imports are quarantined
REM until independent genesis IBD matches exactly.
if !_exit_code! EQU 75 (
    echo   [restart] Clean restart requested.
    set _restart_count=0
    set _restart_delay=1
    goto :restart_loop
)
if !_exit_code! EQU 76 (
    echo   [stopped] Validation recovery requires operator inspection.
    echo   [stopped] No chain data was moved and no snapshot was imported.
    goto :final_exit
)
echo   [restart] Crash detected. Restarting in !_restart_delay!s ^(Ctrl+C to abort^)...
timeout /t !_restart_delay! /nobreak >nul
if errorlevel 1 (
    echo   [restart] User aborted restart.
    goto :user_stop
)
set /a _restart_count+=1
if !_restart_count! GEQ 1   set _restart_delay=5
if !_restart_count! GEQ 3   set _restart_delay=15
if !_restart_count! GEQ 5   set _restart_delay=30
if !_restart_count! GEQ 10  set _restart_delay=60
goto :restart_loop

REM -- Mandatory-update relaunch (single, parens-free hand-off) -----
REM Re-launch this same launcher in a fresh window so the startup
REM version-check installs the update, then close THIS window.
REM Use full 'exit' so the current command window closes in every launch mode.
REM The fresh window's own
REM install path (:do_install) does the file copy + relaunch.
:relaunch_for_update
echo   [restart] Re-launching to install the update ...
start "Veld Mining Client" "%~dp0Start Mining.bat"
exit 0

REM -- Clean user stop (Ctrl+C / graceful shutdown) ----------------
REM Close the window without a 'pause'. A deliberate stop should not
REM leave a dead window the user has to dismiss. Full 'exit' so an
REM interactive parent cmd is torn down too rather than lingering at
REM "Terminate batch job (Y/N)?".
:user_stop
echo.
echo Mining stopped.
exit 0

REM -- Error/abort exit --------------------------------------------
REM Reserved for unexpected fall-through. Keeps the 'pause' so any
REM diagnostic text above stays readable before the window closes.
:final_exit
echo.
echo Mining stopped.
pause
endlocal
