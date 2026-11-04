# ==========================================================================
#  tor-watchdog.ps1 - stop the Veld tor.exe for THIS folder when the miner ends
#
#  Spawned (detached, hidden) by tor-setup.ps1 and bound to the LAUNCHER
#  console's process id. tor.exe is started detached so it can serve the node
#  during mining; without this watchdog it would linger after the client is
#  closed. We watch the LAUNCHER (not the node) so we survive the node's
#  crash-restart loop, and we match tor by THIS folder's path so a user's
#  separate Tor Browser is never touched. Fires on Ctrl+C, window-close, or
#  a normal exit alike.
# ==========================================================================
param(
  [Parameter(Mandatory=$true)][string]$DataDir,
  [Parameter(Mandatory=$true)][int]$LauncherPid
)
$ErrorActionPreference = 'SilentlyContinue'
$tordir = Join-Path $DataDir 'tor'

# 1. Wait until the launcher console exits (any reason).
while (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $LauncherPid)) { Start-Sleep -Seconds 2 }

# 2. Grace: a mandatory-update relaunch opens a fresh launcher window which
#    reuses the same tor. Give it a moment, then only stop tor if NO node for
#    this folder is (re)starting - otherwise we would kill the new session's tor.
Start-Sleep -Seconds 4
$node = Get-CimInstance Win32_Process -Filter "Name='veld-node.exe'" |
        Where-Object { $_.CommandLine -like ("*" + $DataDir + "*") } | Select-Object -First 1
if ($node) { return }

# 3. No node left - stop the tor.exe we started for THIS folder.
Get-CimInstance Win32_Process -Filter "Name='tor.exe'" |
  Where-Object { $_.CommandLine -like ("*" + $tordir + "*") } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
