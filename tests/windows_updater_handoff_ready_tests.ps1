param([Parameter(Mandatory=$true)][string]$Updater,
      [Parameter(Mandatory=$true)][string]$Output,
      [ValidateSet('ready','slow-cleanup','child-exit','child-timeout')][string]$Case='ready')
$ErrorActionPreference='Stop'
$Updater=[IO.Path]::GetFullPath($Updater);$Output=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $Output){throw 'Fresh output directory required'}
[IO.Directory]::CreateDirectory($Output)|Out-Null
$InstallDir=Join-Path $Output 'install';[IO.Directory]::CreateDirectory($InstallDir)|Out-Null
$Transaction=Join-Path $InstallDir '.veld-update-transaction';[IO.Directory]::CreateDirectory($Transaction)|Out-Null
$Distribution='Node';$Mode='Install';$HandoffEvent=''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater parse failure'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
 . ([scriptblock]::Create($f.Extent.Text))
}
$script:ObservedChild=$null
function Start-Process {
 param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
 if($WindowStyle -cne 'Hidden' -or -not $PassThru){throw 'Unexpected helper launch options'}
 if($Case -eq 'child-exit'){$ArgumentList='-NoProfile -Command "exit 47"'}
 if($Case -eq 'child-timeout'){$ArgumentList='-NoProfile -Command "Start-Sleep -Seconds 60"'}
 $child=Microsoft.PowerShell.Management\Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -PassThru -RedirectStandardOutput $RedirectStandardOutput -RedirectStandardError $RedirectStandardError
 $script:ObservedChild=@{id=$child.Id;started=$child.StartTime}
 return $child
}
$InstallLock=Open-InstallLock;$TransactionLock=Open-TransactionLock
Write-TransactionState 'PREPARED';$TransactionOwned=$true
$outcome=@{case=$Case;updater_sha256=(Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLower();scope='Native Windows named-event handshake, exclusive locks, complete Commit entry; no GUI, production installation, mining or laptop execution.'}
try {
 if($Case -eq 'slow-cleanup'){
  $source=[IO.File]::ReadAllText($Updater)
  $cleanup=$source.LastIndexOf('    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue', $source.LastIndexOf('    Start-CommitHandoff $parentPid $PSCommandPath'))
  if($cleanup -lt 0){throw 'No cleanup before helper startup'}
  Start-Sleep -Seconds 35
  if($null -ne $script:ObservedChild){throw 'Helper started during cleanup'}
  $outcome.cleanup_before_child=$true
 }
 $timer=[Diagnostics.Stopwatch]::StartNew();$failure=''
 try{Start-CommitHandoff $PID $Updater}catch{$failure=$_.Exception.Message}
 $outcome.ready_wait_seconds=$timer.Elapsed.TotalSeconds;$outcome.error=$failure
 if($Case -in @('ready','slow-cleanup')){
  if($failure){throw $failure}
  foreach($op in @('Open-InstallLock','Open-TransactionLock')){
   $blocked=$false
   try{$unexpected=& $op;$unexpected.Dispose()}catch{$blocked=$true}
   if(-not $blocked){throw ('Helper did not own '+$op+' at readiness')}
  }
  if($null -ne $script:InstallLock -or $null -ne $script:TransactionLock -or $script:TransactionOwned){throw 'Install retained transaction ownership'}
  $outcome.child_owns_both_locks=$true;$outcome.handoff_ready=$true
 }elseif($Case -eq 'child-exit'){
  if($failure -notlike '*exited before readiness (code 47)*'){throw ('Missing early failure: '+$failure)}
  $outcome.handoff_ready=$false
 }else{
  if($failure -notlike '*did not become ready*' -or $timer.Elapsed.TotalSeconds -gt 40){throw ('Unbounded/incorrect timeout: '+$failure)}
  $outcome.handoff_ready=$false
 }
 $HandoffEvent='Local\untrusted-event';$rejected=$false
 try{Signal-CommitHandoff}catch{$rejected=$true}
 if(-not $rejected){throw 'Invalid handoff event accepted'}
 $outcome.invalid_event_refused=$true;$outcome.status='PASS_HANDOFF_READY'
}finally{
 # Stop only this fixture's helper, while its real parent is still alive.
 if($null -ne $script:ObservedChild){
  $p=Get-Process -Id $script:ObservedChild.id -ErrorAction SilentlyContinue
  if($null -ne $p -and $p.StartTime -eq $script:ObservedChild.started){$p.Kill();$p.WaitForExit();$p.Dispose()}
 }
 if($null -ne $script:InstallLock){$script:InstallLock.Dispose()}
 if($null -ne $script:TransactionLock){$script:TransactionLock.Dispose()}
 if(-not $outcome.status){$outcome.status='FAILED'}
 $outcome|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $Output 'result.json')
}
Write-Host ('PASS_HANDOFF_READY '+$Case)
