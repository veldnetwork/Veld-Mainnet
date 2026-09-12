param([string]$Updater,
      [string]$Output, [switch]$Baseline)
$ErrorActionPreference='Stop'
if ([string]::IsNullOrWhiteSpace($Updater)) {
    $Updater = Join-Path $PSScriptRoot '..\pkg\veld-update.ps1'
}
if (!$Output -or (Test-Path -LiteralPath $Output)) { throw 'A new disposable output directory is required' }
$InstallDir=[IO.Path]::GetFullPath($Output)
[IO.Directory]::CreateDirectory($InstallDir)|Out-Null
$Transaction=Join-Path $InstallDir '.veld-update-transaction'
$MaxManifestDownloadBytes=8MB
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater parse failure'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)) {
    . ([scriptblock]::Create($f.Extent.Text))
}
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Threading;
public class TemporaryFileLock : IDisposable {
    FileStream stream;
    Timer timer;
    public TemporaryFileLock(string path, int releaseAfterMs) {
        stream = File.Open(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(releaseAfterMs>0) timer=new Timer(_=>Dispose(),null,releaseAfterMs,Timeout.Infinite);
    }
    public void Dispose() {
        var value=Interlocked.Exchange(ref stream,null);
        if(value!=null)value.Dispose();
        var clock=Interlocked.Exchange(ref timer,null);
        if(clock!=null)clock.Dispose();
    }
}
'@
$results=@()
function Need([bool]$ok,[string]$why){if(!$ok){throw $why}}
$source=Join-Path $InstallDir 'source.txt';$destination=Join-Path $InstallDir 'installed.txt'
[IO.File]::WriteAllText($source,'new signed bytes');[IO.File]::WriteAllText($destination,'old signed bytes')
$expected=(Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLower()
$locked=[TemporaryFileLock]::new($destination,1600)
$clock=[Diagnostics.Stopwatch]::StartNew();$failure=''
try{Install-FileAtomic $source $destination $expected}catch{$failure=$_.Exception.Message}finally{$locked.Dispose()}
if($Baseline){
    Need ($failure.Length -gt 0) 'Baseline did not reproduce file-lock failure'
    Need ([IO.File]::ReadAllText($destination) -ceq 'old signed bytes') 'Baseline changed the blocked destination'
    @{baseline_reproduced=$true;elapsed_ms=$clock.ElapsedMilliseconds;error=$failure}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $InstallDir 'result.json')
    Write-Host 'REPRODUCED: transient lock aborts the released updater';exit 0
}
Need (!$failure) ('Transient file lock did not recover: '+$failure)
Need ((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLower() -ceq $expected) 'Retry did not install exact bytes'
$results+=@{case='transient lock';ms=$clock.ElapsedMilliseconds;result='PASS'}
$locked=[TemporaryFileLock]::new($destination,0);$clock.Restart()
try{Install-FileAtomic $source $destination $expected}finally{$locked.Dispose()}
Need ($clock.ElapsedMilliseconds -lt 1200) 'Already correct locked file was unnecessarily replaced'
$results+=@{case='locked unchanged file';result='PASS'}
[IO.File]::WriteAllText($source,'tampered source');$rejected=$false
try{Install-FileAtomic $source $destination $expected}catch{$rejected=$true}
Need $rejected 'Idempotence skipped source verification'
Need ((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLower() -ceq $expected) 'Corrupt source changed destination'
$results+=@{case='source tampering';result='PASS'}
$locked=[TemporaryFileLock]::new($destination,0);$clock.Restart();$failure=''
$newHash=(Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash.ToLower()
try{Install-FileAtomic $source $destination $newHash}catch{$failure=$_.Exception.Message}finally{$locked.Dispose()}
Need ($failure -like '*Windows is still locking*') 'Permanent lock did not explain recovery'
Need ($clock.Elapsed.TotalSeconds -lt 19) 'File retry was unbounded'
Need ((Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLower() -ceq $expected) 'Permanent lock changed old bytes'
$results+=@{case='permanent lock';ms=$clock.ElapsedMilliseconds;result='PASS'}
$lock=Open-InstallLock
try{
    $refused=$false;try{$second=Open-InstallLock;$second.Dispose()}catch{$refused=$true}
    Need $refused 'Second updater acquired the same installation'
    [IO.Directory]::CreateDirectory($Transaction)|Out-Null
    Write-TransactionState 'PREPARED';Remove-TransactionTree
    $refused=$false;try{$second=Open-InstallLock;$second.Dispose()}catch{$refused=$true}
    Need $refused 'Transaction cleanup released installation ownership'
}finally{$lock.Dispose()}
$lock=Open-InstallLock;$lock.Dispose()
$results+=@{case='installation ownership across cleanup';result='PASS'}
foreach($name in @('veld-data/db/CURRENT','wallet-data/wallet.dat','node-gui.conf','remote-monitor.dat','remote-trust.dat','remote-unlock.dat','miner.key','full-ibd.receipt','.veld-update.lock')) {
    $manifest=Join-Path $InstallDir 'test-manifest.txt'
    [IO.File]::WriteAllText($manifest,"# veld-release-manifest-v1`n# release-version=9.9.9`n"+('a'*64)+' *'+$name+"`n",[Text.UTF8Encoding]::new($false))
    $refused=$false;try{Read-Manifest $manifest|Out-Null}catch{$refused=$_.Exception.Message -like '*persistent user state*'}
    Need $refused ('Manifest could overwrite '+$name)
    $results+=@{case=('protected '+$name);result='PASS'}
}
$Mode='Commit';Write-UpdateResult 'failed' 'Fixture failure: installation preserved'
$saved=Get-Content -LiteralPath (Join-Path $InstallDir 'update-last-result.json') -Raw|ConvertFrom-Json
Need ($saved.status -eq 'failed' -and $saved.phase -eq 'Commit') 'Detached commit failure was not retained'
$results+=@{case='durable outcome';result='PASS'}
@{result='PASS';cases=$results}|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $InstallDir 'result.json')
Write-Host ('PASS updater durability cases='+$results.Count)
