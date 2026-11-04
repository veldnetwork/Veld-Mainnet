param([Parameter(Mandatory=$true)][string]$Updater,
      [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Updater=[IO.Path]::GetFullPath($Updater);$Output=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $Output){throw 'Fresh output directory required'}
[IO.Directory]::CreateDirectory($Output)|Out-Null
$InstallDir=Join-Path $Output 'install';[IO.Directory]::CreateDirectory($InstallDir)|Out-Null
$Transaction=Join-Path $InstallDir '.veld-update-transaction';[IO.Directory]::CreateDirectory($Transaction)|Out-Null
$TempRoot=Join-Path $Output 'temporary-download';[IO.Directory]::CreateDirectory($TempRoot)|Out-Null
$Distribution='Node';$Mode='Install';$HandoffEvent=''
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater parse failure'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){. ([scriptblock]::Create($f.Extent.Text))}
$text=[IO.File]::ReadAllText($Updater)
$start=$text.LastIndexOf("    Write-TransactionState 'PREPARED'")
$end=$text.IndexOf("    exit 0`n}",$start)
if($end -lt 0){$end=$text.IndexOf("    exit 0`r`n}",$start)}
if($start -lt 0 -or $end -lt 0){throw 'Install handoff tail not found'}
$tail=$text.Substring($start,$end-$start)+'    exit 0'
$script:ObservedChild=$null;$script:CleanupFinished=$false
function Get-CimInstance {
 param($ClassName,$Filter)
 if($ClassName -cne 'Win32_Process' -or $Filter -cne ('ProcessId='+$PID)){throw 'Unexpected parent lookup'}
 # This fixture remains alive as the application parent until final cleanup.
 return @{ParentProcessId=$PID}
}
function Start-Process {
 param($FilePath,$ArgumentList,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
 if(-not $script:CleanupFinished){throw 'Child started before slow cleanup completed'}
 $begin=$ArgumentList.IndexOf('-File "')+7;$finish=$ArgumentList.IndexOf('" -Mode Commit',$begin)
 if($begin -lt 7 -or $finish -lt $begin){throw 'Unexpected child arguments'}
 $ArgumentList=$ArgumentList.Substring(0,$begin)+$Updater+$ArgumentList.Substring($finish)
 $p=Microsoft.PowerShell.Management\Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -PassThru -RedirectStandardOutput $RedirectStandardOutput -RedirectStandardError $RedirectStandardError
 $script:ObservedChild=[Diagnostics.Process]::GetProcessById($p.Id);$null=$script:ObservedChild.Handle
 return $p
}
function Remove-Item {
 param($LiteralPath,[switch]$Recurse,[switch]$Force,$ErrorAction)
 if($LiteralPath -cne $TempRoot){throw 'Unexpected cleanup path'}
 Start-Sleep -Seconds 35
 if($null -ne $script:ObservedChild){throw 'Commit already launched during delayed cleanup'}
 Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse -Force
 $script:CleanupFinished=$true
}
$InstallLock=Open-InstallLock;$TransactionLock=Open-TransactionLock;$TransactionOwned=$true
$clock=[Diagnostics.Stopwatch]::StartNew()
try{& ([scriptblock]::Create($tail))}
finally{
 $report=@{status='FAILED';elapsed_seconds=$clock.Elapsed.TotalSeconds;scope='Exact production Install handoff tail and complete Commit entry; native child, event and file locks. Explicit delayed-cleanup fault; fixture parent replaces GUI. No mining or production access.';updater_sha256=(Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLower()}
 try{
  if($null -eq $script:ObservedChild -or $script:ObservedChild.HasExited){throw 'Installer authorized shutdown without a live commit helper'}
  if($null -ne $InstallLock -or $null -ne $TransactionLock -or $TransactionOwned){throw 'Installer retained ownership'}
  foreach($op in @('Open-InstallLock','Open-TransactionLock')){
   $blocked=$false;try{$lock=& $op;$lock.Dispose()}catch{$blocked=$true}
   if(-not $blocked){throw ('Commit did not own '+$op)}
  }
  $report.status='PASS_INSTALL_HANDOFF';$report.cleanup_before_child=$true;$report.live_helper_owns_both_locks=$true
 }finally{
  if($null -ne $script:ObservedChild){if(-not $script:ObservedChild.HasExited){$script:ObservedChild.Kill();$script:ObservedChild.WaitForExit()};$script:ObservedChild.Dispose()}
  if($null -ne $InstallLock){$InstallLock.Dispose()};if($null -ne $TransactionLock){$TransactionLock.Dispose()}
  $report|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'result.json')
 }
}
