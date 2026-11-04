param([Parameter(Mandatory=$true)][string]$Updater,
      [Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
$Updater=[IO.Path]::GetFullPath($Updater)
$Output=[IO.Path]::GetFullPath($Output)
if(Test-Path -LiteralPath $Output){throw 'Fresh output directory required'}
[IO.Directory]::CreateDirectory($Output)|Out-Null
$InstallDir=Join-Path $Output 'install'
[IO.Directory]::CreateDirectory($InstallDir)|Out-Null
$Transaction=Join-Path $InstallDir '.veld-update-transaction'
[IO.Directory]::CreateDirectory($Transaction)|Out-Null
$TempRoot=Join-Path $Output 'temporary-download'
[IO.Directory]::CreateDirectory($TempRoot)|Out-Null
$Distribution='Node';$Mode='Install'
$LocalManifest=Join-Path $InstallDir 'SHA256SUMS.txt'
$LocalSignature=$LocalManifest+'.sig'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater parse failure'}
foreach($f in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$false)){
 . ([scriptblock]::Create($f.Extent.Text))
}
$source=[IO.File]::ReadAllText($Updater)
$start=$source.LastIndexOf('    $parentPid = (Get-CimInstance')
$end=$source.IndexOf("    exit 0`n}",$start)
if($end -lt 0){$end=$source.IndexOf("    exit 0`r`n}",$start)}
if($start -lt 0 -or $end -lt 0){throw 'Unique complete Install handoff tail not found'}
$tail=$source.Substring($start,$end-$start)+'    exit 0'
$InstallLock=Open-InstallLock
$TransactionLock=Open-TransactionLock
Write-TransactionState 'PREPARED'
$TransactionOwned=$true
$script:CommitProcess=$null
$clock=[Diagnostics.Stopwatch]::StartNew()
function Start-Process {
 param($FilePath,$ArgumentList,$WindowStyle)
 if($ArgumentList -notlike '*-Mode Commit*'){throw 'Unexpected child'}
 # Bind the extracted Install tail to the actual unchanged released helper.
 $begin=$ArgumentList.IndexOf('-File "')+7
 $finish=$ArgumentList.IndexOf('" -Mode Commit',$begin)
 $ArgumentList=$ArgumentList.Substring(0,$begin)+$Updater+$ArgumentList.Substring($finish)
 $script:CommitProcess=Microsoft.PowerShell.Management\Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Output 'commit.stdout.log') -RedirectStandardError (Join-Path $Output 'commit.stderr.log')
 $null=$script:CommitProcess.Handle
 return $script:CommitProcess
}
function Remove-Item {
 param($LiteralPath,[switch]$Recurse,[switch]$Force,$ErrorAction)
 if($LiteralPath -cne $TempRoot){throw 'Unexpected cleanup path'}
 # Explicit fault: slow antivirus/filesystem cleanup while Install owns its lock.
 Start-Sleep -Seconds 35
 $script:CommitProcess.Refresh()
 $dead=$script:CommitProcess.HasExited
 if($dead){$script:CommitProcess.WaitForExit()}
 $exitCode=if($dead){$script:CommitProcess.ExitCode}else{$null}
 $result=@{case='slow post-spawn cleanup';released_updater_sha256=(Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLower();child_exited_before_handoff_returns=$dead;child_exit_code=$exitCode;installer_lock_still_owned=($null -ne $InstallLock);transaction_state=Read-TransactionState;elapsed_seconds=$clock.Elapsed.TotalSeconds;scope='Real Windows processes and exclusive file locks, released complete Commit entry and exact Install tail. Deliberately delayed cleanup; no real GUI, mining, wallet or laptop execution.'}
 $result|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $Output 'result.json')
 if(-not $dead -or $exitCode -ne 1){throw 'Expected released lock-timeout failure not reproduced'}
 Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Recurse -Force
}
& ([scriptblock]::Create($tail))
