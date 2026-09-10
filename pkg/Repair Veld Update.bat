@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Repair Veld Update
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0veld-repair.ps1"
set "REPAIR_EXIT=%errorlevel%"
if not "%REPAIR_EXIT%"=="0" pause
exit /b %REPAIR_EXIT%
