param(
    [Parameter(Mandatory=$true)][string]$PreviousPackage,
    [Parameter(Mandatory=$true)][string]$RepairPackage,
    [Parameter(Mandatory=$true)][string]$Output,
    [string]$Updater
)
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($Updater)) {
    $Updater=Join-Path $PSScriptRoot '..\pkg\veld-update.ps1'
}
$InstallDir=[IO.Path]::GetFullPath($Output)
if (Test-Path -LiteralPath $InstallDir) { throw 'A fresh disposable installation is required' }
[IO.Directory]::CreateDirectory($InstallDir)|Out-Null
foreach ($item in Get-ChildItem -LiteralPath $PreviousPackage -Force) {
    Copy-Item -LiteralPath $item.FullName -Destination $InstallDir -Recurse
}
$Node=Join-Path $InstallDir 'bin\veld-node.exe'
$ReleaseVerifier=Join-Path ([IO.Path]::GetFullPath($RepairPackage)) 'bin\veld-node.exe'
$LocalManifest=Join-Path $InstallDir 'SHA256SUMS.txt'
$LocalSignature=$LocalManifest+'.sig'
$Transaction=Join-Path $InstallDir '.veld-update-transaction'
$MaxManifestDownloadBytes=8MB
$Distribution='Node';$PrimaryLauncher='Veld Node.exe'
$RequiredPackageFiles=@('bin/veld-node.exe','bin/veld-wallet.exe','Veld Node.exe',
    'Start Veld Node.bat','veld-update.ps1','tor-setup.ps1','CHANGES.txt')
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Updater parse failure' }
foreach ($function in $ast.FindAll({param($n)
    $n -is [Management.Automation.Language.FunctionDefinitionAst]
},$true)) {
    . ([scriptblock]::Create($function.Extent.Text))
}
function Wait-ForParentExit([int]$ProcessId) {
    if ($ProcessId -ne 424242) { throw 'Unexpected fixture parent' }
}
$script:relaunches=0
function Relaunch-InstalledClient {
    $verified=Get-VerifiedInstalled
    $script:relaunchVersion=$verified.Version.Text
    $script:relaunches++
}
$data=Join-Path $InstallDir 'veld-data'
[IO.Directory]::CreateDirectory($data)|Out-Null
$preserved=@{
    'veld-data\chain-preserve.txt'='saved history fixture'
    'veld-data\miner.key'='opaque encrypted identity fixture'
    'node-gui.conf'="mining_threads=15`nsync=full`nremote_monitoring=1`n"
    'remote-monitor.dat'='opaque protected pairing fixture'
}
foreach ($name in $preserved.Keys) {
    [IO.File]::WriteAllText((Join-Path $InstallDir $name),$preserved[$name])
}
$before=Get-VerifiedInstalled
$expected=Read-ReleaseVersion (Join-Path $RepairPackage 'SHA256SUMS.txt')
if ((Compare-ReleaseVersion $expected $before.Version) -le 0) {
    throw 'Repair fixture must contain a newer signed release'
}
$tampered=Join-Path $data 'tampered-manifest.txt'
[IO.File]::WriteAllText($tampered,[IO.File]::ReadAllText($LocalManifest)+"# altered`n")
if (Verify-ReleaseSignature $tampered $LocalSignature) { throw 'Tampered manifest was accepted' }
$stage=Join-Path $Transaction 'stage'
[IO.Directory]::CreateDirectory($stage)|Out-Null
foreach ($item in Get-ChildItem -LiteralPath $RepairPackage -Force) {
    Copy-Item -LiteralPath $item.FullName -Destination $stage -Recurse
}
Write-TransactionState 'HANDOFF'
Invoke-TransactionCommit 424242
$after=Get-VerifiedInstalled
if ($after.Version.Text -cne $expected.Text -or $script:relaunches -ne 1 -or
    $script:relaunchVersion -cne $expected.Text) { throw 'Repair did not commit and relaunch the signed version' }
foreach ($name in $preserved.Keys) {
    if ([IO.File]::ReadAllText((Join-Path $InstallDir $name)) -cne $preserved[$name]) {
        throw ('Repair changed persistent state: '+$name)
    }
}
if (Test-Path -LiteralPath $Transaction) { throw 'Completed repair left a transaction behind' }
$runtime=@(& $Node --version 2>$null)
if ($LASTEXITCODE -ne 0 -or ($runtime -join ' ') -notlike ('*'+$expected.Text+'*')) {
    throw 'Repaired node cannot start from the installed runtime'
}
@{result='PASS';before=$before.Version.Text;after=$after.Version.Text;
    fresh_verifier_used=$true;tampered_manifest_rejected=$true;
    state_preserved=$true;native_startup=$true;relaunches=$script:relaunches} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $data 'repair-test-result.json')
Write-Host ('PASS: signed repair '+$before.Version.Text+' to '+$after.Version.Text+' with fresh verifier')
