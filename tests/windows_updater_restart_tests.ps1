$ErrorActionPreference = 'Stop'
$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $Root 'pkg\veld-update.ps1'), [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'updater failed PowerShell parsing' }
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Relaunch-InstalledClient'
}, $true)
if ($null -eq $functionAst) { throw 'restart function is missing' }
Invoke-Expression $functionAst.Extent.Text

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
        $entries['Start Veld Node.bat'] = 'fixture'
        $entries['Start Mining.bat'] = 'fixture'
    }
    return [pscustomobject]@{Entries = $entries}
}
function Start-Process {
    param($FilePath, $ArgumentList, $WorkingDirectory, $WindowStyle)
    Check $script:verified 'restart occurred before installed-package verification'
    Check ($FilePath -ceq (Join-Path $env:SystemRoot 'System32\cmd.exe')) `
        'restart did not use the system command interpreter'
    Check ($WindowStyle -ceq 'Normal') 'interactive launcher is hidden'
    Check ($WorkingDirectory -ceq $InstallDir) 'restart lost the install directory'
    $script:launched++
    # Run only the harmless fixture batch, in a hidden process. Production
    # arguments and inherited environment are exercised without starting Veld.
    $process = Microsoft.PowerShell.Management\Start-Process `
        -FilePath $FilePath -ArgumentList $ArgumentList `
        -WorkingDirectory $WorkingDirectory -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(10000)) {
        $process.Kill()
        throw 'fixture batch did not finish'
    }
    Check ($process.ExitCode -eq 0) 'fixture batch failed'
    $process.Dispose()
}
function Expect-NoLaunch([scriptblock]$Action, [string]$Description) {
    $before = $script:launched; $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Check $rejected ($Description + ' was accepted')
    Check ($script:launched -eq $before) ($Description + ' started a process')
}

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('veld-restart-' + [guid]::NewGuid().ToString('N'))
$originalLauncher = $env:VELD_UPDATE_RESTART_LAUNCHER
[IO.Directory]::CreateDirectory($TempRoot) | Out-Null
try {
    # Literal percent sequences must not turn into environment expansion;
    # ampersands, parentheses and exclamation marks are ordinary path bytes.
    $InstallDir = Join-Path $TempRoot 'Veld %PATH% ! & (3.0.7)'
    [IO.Directory]::CreateDirectory($InstallDir) | Out-Null
    [IO.File]::WriteAllText((Join-Path $InstallDir 'Start Veld Node.bat'),
        "@echo off`r`necho node>restart-node.txt`r`nexit /b 0`r`n")
    [IO.File]::WriteAllText((Join-Path $InstallDir 'Start Mining.bat'),
        "@echo off`r`necho terminal>restart-terminal.txt`r`nexit /b 0`r`n")
    $env:VELD_UPDATE_RESTART_LAUNCHER = 'preserve-parent-value'
    $PrimaryLauncher = 'Veld Node.exe'
    $Distribution = 'Node'
    Relaunch-InstalledClient
    Check ([IO.File]::ReadAllText((Join-Path $InstallDir 'restart-node.txt')).Trim() -ceq 'node') `
        'Node restart did not execute Start Veld Node.bat'
    Check ($env:VELD_UPDATE_RESTART_LAUNCHER -ceq 'preserve-parent-value') `
        'restart changed the parent environment'
    $Distribution = 'Terminal'
    $PrimaryLauncher = 'Start Mining.bat'
    Relaunch-InstalledClient
    Check ([IO.File]::ReadAllText((Join-Path $InstallDir 'restart-terminal.txt')).Trim() -ceq 'terminal') `
        'Terminal restart did not execute Start Mining.bat'
    $script:verificationFails = $true
    Expect-NoLaunch { Relaunch-InstalledClient } 'unverified installed package'
    $script:verificationFails = $false; $script:omitLauncher = $true
    Expect-NoLaunch { Relaunch-InstalledClient } 'manifest missing restart launcher'
    Write-Output ('PASS windows_updater_restart_tests checks=' + $checks)
}
finally {
    $env:VELD_UPDATE_RESTART_LAUNCHER = $originalLauncher
    # Retain only fixture files under the resolved test root for diagnosis.
    Write-Output ('Fixture directory: ' + $TempRoot)
}
