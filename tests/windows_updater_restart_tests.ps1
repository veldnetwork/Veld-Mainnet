param([string]$Updater)
$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $Updater) { $Updater = Join-Path $Root 'pkg\veld-update.ps1' }
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Updater, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'updater failed PowerShell parsing' }
foreach ($name in @('Relaunch-InstalledClient', 'Wait-ForParentExit')) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    }, $true)
    if ($null -eq $functionAst) { throw ('missing function: ' + $name) }
    Invoke-Expression $functionAst.Extent.Text
}
$checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
$script:verificationFails = $false
$script:omitLauncher = $false
$script:launched = 0
$script:verified = $false
function Get-VerifiedInstalled {
    $script:verified = $false
    if ($script:verificationFails) { throw 'fixture package verification failed' }
    $script:verified = $true
    $entries = @{}
    if (-not $script:omitLauncher) {
        $entries['Veld Node.exe'] = 'fixture'
        $entries['Start Veld Node.bat'] = 'fixture'
        $entries['Start Mining.bat'] = 'fixture'
    }
    return [pscustomobject]@{Entries = $entries}
}
function Start-Process {
    param($FilePath, $ArgumentList, $WorkingDirectory, $WindowStyle)
    Check $script:verified 'restart occurred before installed-package verification'
    Check ($WorkingDirectory -ceq $InstallDir) 'restart lost the install directory'
    if ($Distribution -eq 'Node') {
        Check ($FilePath -ceq (Join-Path $InstallDir 'Veld Node.exe')) 'node update restart re-entered the interactive launcher'
        Check ($WindowStyle -ceq 'Hidden') 'automatic restart opened a command window'
    } else {
        Check ($FilePath -ceq (Join-Path $env:SystemRoot 'System32\cmd.exe')) 'terminal restart did not use the system command interpreter'
        Check ($WindowStyle -ceq 'Normal') 'interactive terminal launcher is hidden'
    }
    $script:launched++
    $start = @{FilePath=$FilePath; WorkingDirectory=$WorkingDirectory; WindowStyle='Hidden'; PassThru=$true}
    if ($ArgumentList) { $start.ArgumentList = $ArgumentList }
    $process = Microsoft.PowerShell.Management\Start-Process @start
    if (-not $process.WaitForExit(10000)) { $process.Kill(); throw 'fixture child did not finish' }
    Check ($process.ExitCode -eq 0) 'fixture child failed'
    $process.Dispose()
}
function Expect-NoLaunch([scriptblock]$Action, [string]$Description) {
    $before = $script:launched; $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Check $rejected ($Description + ' was accepted')
    Check ($script:launched -eq $before) ($Description + ' started a process')
}
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) ('veld-restart-' + [guid]::NewGuid().ToString('N'))
$originalLauncher = $env:VELD_UPDATE_RESTART_LAUNCHER
$originalData = $env:VELD_UPDATE_NODE_DATA_DIR
[IO.Directory]::CreateDirectory($TempRoot) | Out-Null
try {
    $InstallDir = Join-Path $TempRoot 'Veld %PATH% ! & (3.1.10)'
    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    Add-Type -OutputAssembly (Join-Path $InstallDir 'Veld Node.exe') -OutputType ConsoleApplication -TypeDefinition @"
using System;
using System.IO;
public class RestartFixture {
    public static int Main(string[] args) {
        File.WriteAllLines("restart-node.txt", args);
        return 0;
    }
}
"@
    [IO.File]::WriteAllText((Join-Path $InstallDir 'Start Veld Node.bat'), "@echo off" + [Environment]::NewLine + "echo PROMPT>wrong-launcher.txt" + [Environment]::NewLine + "exit /b 17" + [Environment]::NewLine)
    [IO.File]::WriteAllText((Join-Path $InstallDir 'Start Mining.bat'), "@echo off" + [Environment]::NewLine + "echo terminal>restart-terminal.txt" + [Environment]::NewLine + "exit /b 0" + [Environment]::NewLine)
    $env:VELD_UPDATE_RESTART_LAUNCHER = 'preserve-parent-value'
    $Distribution = 'Node'
    $PrimaryLauncher = 'Veld Node.exe'
    $env:VELD_UPDATE_NODE_DATA_DIR = $null
    Relaunch-InstalledClient
    Check ([IO.File]::ReadAllText((Join-Path $InstallDir 'restart-node.txt')).Length -eq 0) 'restart forced a default data directory'
    Check (-not (Test-Path -LiteralPath (Join-Path $InstallDir 'wrong-launcher.txt'))) 'automatic restart entered the interactive launcher'
    foreach ($data in @((Join-Path $TempRoot ('Custom %PATH% ! & ' + [char]0x00e9 + [char]0x65e5)), [IO.Path]::GetPathRoot($TempRoot))) {
        $env:VELD_UPDATE_NODE_DATA_DIR = $data
        Relaunch-InstalledClient
        $arguments = [IO.File]::ReadAllLines((Join-Path $InstallDir 'restart-node.txt'))
        Check ($arguments.Count -eq 2 -and $arguments[0] -ceq '--datadir' -and $arguments[1] -ceq $data) 'restart changed or expanded the exact custom data directory'
    }
    Check ($env:VELD_UPDATE_RESTART_LAUNCHER -ceq 'preserve-parent-value') 'restart changed the parent environment'
    $Distribution = 'Terminal'
    $PrimaryLauncher = 'Start Mining.bat'
    Relaunch-InstalledClient
    Check ([IO.File]::ReadAllText((Join-Path $InstallDir 'restart-terminal.txt')).Trim() -ceq 'terminal') 'Terminal restart did not execute Start Mining.bat'
    foreach ($kind in @('Node','Terminal')) {
        $Distribution = $kind
        $script:verificationFails = $true
        Expect-NoLaunch { Relaunch-InstalledClient } ('unverified ' + $kind + ' package')
        $script:verificationFails = $false; $script:omitLauncher = $true
        Expect-NoLaunch { Relaunch-InstalledClient } ($kind + ' manifest missing restart executable')
        $script:omitLauncher = $false
    }
    # Exercise both sides of the deadline without sleeping for 90 seconds.
    $script:clock = [datetime]'2026-01-01T00:00:00Z'
    $script:exitAt = $script:clock.AddSeconds(45)
    function Get-Date { return $script:clock }
    function Start-Sleep { param($Milliseconds); $script:clock = $script:clock.AddMilliseconds($Milliseconds) }
    function Get-Process { param($Id, $ErrorAction); if ($script:clock -lt $script:exitAt) { return @{Id=$Id} } }
    Wait-ForParentExit 424242
    Check ($script:clock -eq $script:exitAt) 'handoff did not wait for bounded shutdown and GUI cleanup'
    $started = $script:clock; $script:exitAt = $started.AddHours(1)
    $rejected = $false
    try { Wait-ForParentExit 424242 } catch { $rejected = $true }
    Check ($rejected -and ($script:clock-$started).TotalSeconds -eq 90) 'stuck parent wait is not bounded'
    Write-Output ('PASS windows_updater_restart_tests checks=' + $checks)
}
finally {
    $env:VELD_UPDATE_RESTART_LAUNCHER = $originalLauncher
    $env:VELD_UPDATE_NODE_DATA_DIR = $originalData
    Write-Output ('Fixture directory: ' + $TempRoot)
}
