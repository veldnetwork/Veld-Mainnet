param(
    [string]$Updater = (Join-Path $PSScriptRoot '..\pkg\veld-update.ps1'),
    [Parameter(Mandatory=$true)][string]$Output,
    [switch]$Baseline
)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Output){throw 'Fresh fixture required'}
[IO.Directory]::CreateDirectory($Output)|Out-Null
$InstallDir=[IO.Path]::GetFullPath($Output);$Distribution='Node'
Add-Type -OutputAssembly (Join-Path $InstallDir 'Veld Node.exe') -OutputType WindowsApplication -TypeDefinition @'
using System;using System.IO;using System.Threading;
public class RelaunchProcessFixture {
 public static int Main(){
  string record=Environment.GetEnvironmentVariable("VELD_QA_RELAUNCH_RECORD");
  int count=File.Exists(record)?File.ReadAllLines(record).Length:0;
  File.AppendAllText(record,System.Diagnostics.Process.GetCurrentProcess().Id+Environment.NewLine);
  string mode=Environment.GetEnvironmentVariable("VELD_QA_RELAUNCH_MODE");
  if(mode=="exit" || (mode=="transient" && count<2))return 17;
  Thread.Sleep(60000);return 0;
 }
}
'@
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($Updater,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'Updater parse failure'}
$fn=$ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'Relaunch-InstalledClient'},$true)
if($fn.Count -ne 1){throw 'Ambiguous function'}
. ([scriptblock]::Create($fn[0].Extent.Text))
function Get-VerifiedInstalled {return @{Entries=@{'Veld Node.exe'='explicit fixture'}}}
# Only the fixture executable is allowed to be terminated below. The production
# signature gate is covered by separate signed-package transaction tests.
$oldRecord=$env:VELD_QA_RELAUNCH_RECORD;$oldMode=$env:VELD_QA_RELAUNCH_MODE;$oldData=$env:VELD_UPDATE_NODE_DATA_DIR
$env:VELD_UPDATE_NODE_DATA_DIR=$null
$results=@()
try{
 foreach($mode in @('exit','transient','stay')){
  $record=Join-Path $InstallDir ($mode+'.txt');$env:VELD_QA_RELAUNCH_RECORD=$record;$env:VELD_QA_RELAUNCH_MODE=$mode
  $errorText='';$clock=[Diagnostics.Stopwatch]::StartNew()
  try{Relaunch-InstalledClient}catch{$errorText=$_.Exception.Message}
  Start-Sleep -Milliseconds 500
  $ids=@(Get-Content -LiteralPath $record)
  $alive=@()
  foreach($childId in $ids){$p=Get-Process -Id ([int]$childId) -ErrorAction SilentlyContinue;if($p -and $p.Path -eq (Join-Path $InstallDir 'Veld Node.exe')){$alive+=$p}}
  if($Baseline){if($mode -ne 'exit' -or $errorText -or $alive.Count -ne 0 -or $ids.Count -ne 1){throw 'Baseline did not reproduce false successful relaunch'}}
  elseif($mode -eq 'exit'){if($errorText -notlike '*did not stay open after 3 starts*' -or $ids.Count -ne 3 -or $alive.Count -ne 0){throw 'Permanent early exit not bounded/reported'}}
  elseif($errorText -or $alive.Count -ne 1 -or $ids.Count -ne $(if($mode -eq 'transient'){3}else{1})){throw ('Incorrect recovery: '+$mode+' '+$errorText)}
  $results+=@{case=$mode;starts=$ids.Count;alive=$alive.Count;error=$errorText;seconds=$clock.Elapsed.TotalSeconds}
  foreach($p in $alive){$p.Kill();$p.WaitForExit();$p.Dispose()}
  if($Baseline){break}
 }
 @{status='PASS';baseline=[bool]$Baseline;updater_sha256=(Get-FileHash -LiteralPath $Updater -Algorithm SHA256).Hash.ToLower();cases=$results;scope='Actual Windows process creation/lifetime; package verification explicitly replaced for the inert fixture executable. No owner GUI, keys, mining or production paths.'}|ConvertTo-Json -Depth 5|Set-Content -Encoding UTF8 -LiteralPath (Join-Path $InstallDir 'result.json')
}finally{
 foreach($record in Get-ChildItem -LiteralPath $InstallDir -Filter '*.txt'){
  foreach($childId in Get-Content -LiteralPath $record.FullName){$p=Get-Process -Id ([int]$childId) -ErrorAction SilentlyContinue;if($p -and $p.Path -eq (Join-Path $InstallDir 'Veld Node.exe')){$p.Kill();$p.WaitForExit();$p.Dispose()}}
 }
 $env:VELD_QA_RELAUNCH_RECORD=$oldRecord;$env:VELD_QA_RELAUNCH_MODE=$oldMode;$env:VELD_UPDATE_NODE_DATA_DIR=$oldData
}
