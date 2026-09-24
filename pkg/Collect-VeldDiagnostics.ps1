param([string]$InstallRoot=$PSScriptRoot,[string]$OutputDirectory=[Environment]::GetFolderPath('Desktop'))
$ErrorActionPreference='Stop'
$report=[ordered]@{schema=1;collected_utc=[DateTime]::UtcNow.ToString('o');read_only=$true;scope='Veld updater and Windows application lifecycle; no wallet, keys, tokens, or configuration contents'}
$root=[IO.Path]::GetFullPath($InstallRoot)
$report.install=[ordered]@{found=(Test-Path -LiteralPath (Join-Path $root 'SHA256SUMS.txt'));files=@();outcome=$null}
foreach($name in @('Veld Node.exe','bin\veld-node-gui.exe','bin\veld-node.exe','bin\veld-pool-client.exe','SHA256SUMS.txt','veld-update.ps1','pkg\veld-update.ps1')) {
 $file=Join-Path $root $name
 if(Test-Path -LiteralPath $file -PathType Leaf) {
  $item=Get-Item -LiteralPath $file
  if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-eq 0) {
   $report.install.files+=@{name=$name;bytes=$item.Length;sha256=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant();modified_utc=$item.LastWriteTimeUtc.ToString('o')}
  }
 }
}
$outcome=Join-Path $root 'update-last-result.json'
if((Test-Path -LiteralPath $outcome -PathType Leaf)-and (Get-Item -LiteralPath $outcome).Length -le 8192) {
 try {
  $parsed=Get-Content -LiteralPath $outcome -Raw|ConvertFrom-Json
  $report.install.outcome=@{}
  foreach($key in @('schema','status','phase','time','version')) {if($null-ne $parsed.$key){$report.install.outcome[$key]=$parsed.$key}}
 }catch{$report.install.outcome=@{error='Unreadable update result'}}
}
$report.processes=@(Get-Process -ErrorAction SilentlyContinue |Where-Object {$_.ProcessName -match '^veld-(node|node-gui|pool-client)$|^Veld Node$'} |ForEach-Object {
 $started=$null;try{$started=$_.StartTime.ToUniversalTime().ToString('o')}catch{}
 @{name=$_.ProcessName;id=$_.Id;started_utc=$started;responding=$_.Responding}
})
$report.events=@();$report.event_errors=@()
foreach($spec in @(@{LogName='Application';Id=@(1000,1001,1002);StartTime=(Get-Date).AddDays(-7)},@{LogName='System';Id=@(1,12,13,41,1074);StartTime=(Get-Date).AddDays(-7)})) {
 try {
  foreach($event in @(Get-WinEvent -FilterHashtable $spec -MaxEvents 1000 -ErrorAction Stop)) {
   $message=[string]$event.Message
   if($spec.LogName-eq 'Application' -and $message -notmatch '(?i)veld[- ](node|pool-client)'){continue}
   if($spec.LogName-eq 'System' -and $event.ProviderName -notmatch '^Microsoft-Windows-(Kernel-Power|Kernel-General|Power-Troubleshooter)$|^User32$'){continue}
   $exe=[regex]::Match($message,'(?i)(?:veld-(?:node-gui|node|pool-client)|Veld Node)\.exe').Value
   $exception=[regex]::Match($message,'(?i)Exception code:\s*(0x[0-9a-f]+)').Groups[1].Value
   $report.events+=@{utc=$event.TimeCreated.ToUniversalTime().ToString('o');id=$event.Id;provider=$event.ProviderName;application=$exe;exception_code=$exception}
  }
 }catch{$report.event_errors+=@{log=$spec.LogName;error='No matching events or access unavailable'}}
}
# Export recognized updater messages only, never arbitrary log lines or paths.
$report.updater_messages=@()
$state=Join-Path $env:LOCALAPPDATA 'Veld\Node'
$paths=@((Join-Path $state 'update-install.log'),(Join-Path $state 'update-check.log'),(Join-Path $root 'update-commit.log'),(Join-Path $root 'update-commit-error.log'))
foreach($path in $paths) {
 if(!(Test-Path -LiteralPath $path -PathType Leaf)){continue}
 $item=Get-Item -LiteralPath $path
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){continue}
 $counts=@{}
 foreach($line in @(Get-Content -LiteralPath $path -Tail 250)) {
  foreach($pattern in @('another updater/recovery process owns the install transaction','Durable install handoff is ready','Update helper stopped before it was ready','Update helper did not become ready','Signed package verified','Update failed','rollback','Signature verification failed','ABORT:')) {
   if($line -match [regex]::Escape($pattern)){$counts[$pattern]=1+[int]$counts[$pattern]}
  }
 }
 $report.updater_messages+=@{file=$item.Name;bytes=$item.Length;modified_utc=$item.LastWriteTimeUtc.ToString('o');recognized_messages=$counts}
}
$output=[IO.Path]::GetFullPath($OutputDirectory)
if(!(Test-Path -LiteralPath $output -PathType Container)){throw 'Output folder must already exist.'}
$destination=Join-Path $output ('Veld-diagnostics-'+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'.json')
if(Test-Path -LiteralPath $destination){throw 'Diagnostic file already exists.'}
$report|ConvertTo-Json -Depth 8|Set-Content -LiteralPath $destination -Encoding UTF8
Write-Output ('Saved '+$destination+'. Nothing was uploaded or changed in Veld.')
