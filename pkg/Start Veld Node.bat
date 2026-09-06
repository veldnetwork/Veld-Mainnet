@echo off
setlocal EnableExtensions
title Veld Node

set "VELD_HOME=%~dp0"
set "VELD_INSTALL_DIR=%VELD_HOME:~0,-1%"
set "VELD_NODE=%VELD_HOME%bin\veld-node.exe"
set "VELD_WINDOWED=%VELD_HOME%Veld Node.exe"
set "VELD_MANIFEST=%VELD_HOME%SHA256SUMS.txt"
set "VELD_SIGNATURE=%VELD_HOME%SHA256SUMS.txt.sig"
set "VELD_UPDATER=%VELD_HOME%veld-update.ps1"

REM Mining work admission requires at least one explicitly configured outbound
REM anchor. Keep the established terminal-client defaults while allowing an
REM operator to replace the complete set before launch.
if not defined VELD_FLEET_ANCHOR_IPS set "VELD_FLEET_ANCHOR_IPS=5.78.107.166,5.78.97.56,5.78.127.51"

if not exist "%VELD_NODE%" goto :missing
if not exist "%VELD_WINDOWED%" goto :missing
if not exist "%VELD_MANIFEST%" goto :missing
if not exist "%VELD_SIGNATURE%" goto :missing
if not exist "%VELD_UPDATER%" goto :missing

powershell -NoProfile -ExecutionPolicy Bypass -File "%VELD_UPDATER%" -Mode Recover -InstallDir "%VELD_INSTALL_DIR%"
if errorlevel 1 (
    echo.
    echo   Veld Node could not recover an interrupted signed update.
    echo   Re-run this launcher or download a fresh client from https://veld.network.
    echo.
    pause
    exit /b 1
)

set "VELD_CHECK=%TEMP%\veld-node-gui-verify-%RANDOM%-%RANDOM%.txt"
"%VELD_NODE%" --verify-release "%VELD_MANIFEST%" "%VELD_SIGNATURE%" >"%VELD_CHECK%" 2>nul
if errorlevel 1 (
    del /q "%VELD_CHECK%" >nul 2>nul
    echo.
    echo   Veld Node could not verify this package's release signature.
    echo   Re-download the client from https://veld.network.
    echo.
    pause
    exit /b 1
)
del /q "%VELD_CHECK%" >nul 2>nul

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$root=[IO.Path]::GetFullPath($env:VELD_HOME); $bad=$false; $seen=@{};" ^
  "foreach($line in Get-Content -LiteralPath $env:VELD_MANIFEST){" ^
  "if($line -match '^([0-9a-fA-F]{64})\s+\*?(.+)$'){" ^
  "$rel=$matches[2].Trim().Replace('/','\'); $seen[$rel]=$true; $path=[IO.Path]::GetFullPath((Join-Path $root $rel));" ^
  "if(-not $path.StartsWith($root,[StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $path -PathType Leaf)){ $bad=$true; break };" ^
  "$got=(Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant();" ^
  "if($got -ne $matches[1].ToLowerInvariant()){ $bad=$true; break }}};" ^
  "foreach($need in @('bin\veld-node.exe','bin\veld-wallet.exe','Veld Node.exe','Start Veld Node.bat','veld-update.ps1','tor-setup.ps1','CHANGES.txt')){" ^
  "if(-not $seen.ContainsKey($need)){ $bad=$true; break }}; if($bad){exit 1}"
if errorlevel 1 (
    echo.
    echo   Veld Node found a missing or modified package file.
    echo   Re-download the client from https://veld.network.
    echo.
    pause
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%VELD_UPDATER%" -Mode Check -InstallDir "%VELD_INSTALL_DIR%"
if errorlevel 2 goto :update_available
if errorlevel 1 echo   [update] Signed update feed unavailable; keeping this verified client.
goto :launch

:update_available
echo.
echo   A signed Veld Node update is required before mining.
echo.
set /P "VELD_UPDATE_CHOICE=Install the update now? [Y/N]: "
if /I not "%VELD_UPDATE_CHOICE%"=="Y" (
    echo   Update declined. Mining was not started.
    pause
    exit /b 1
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%VELD_UPDATER%" -Mode Install -InstallDir "%VELD_INSTALL_DIR%"
if errorlevel 1 (
    echo.
    echo   The signed update could not be installed. No unverified files were launched.
    pause
    exit /b 1
)
exit /b 0

:launch

start "" /D "%VELD_HOME%" "%VELD_WINDOWED%" --clearnet --node "%VELD_NODE%" --datadir "%VELD_HOME%veld-data"
exit /b 0

:missing
echo.
echo   Veld Node is missing a required signed package file.
echo   Re-download the complete client from https://veld.network.
echo.
pause
exit /b 1
