param([string]$InstallDir)
$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($PSScriptRoot).TrimEnd('\')
$node = Join-Path $root 'bin\veld-node.exe'
$manifest = Join-Path $root 'SHA256SUMS.txt'
$signature = Join-Path $root 'SHA256SUMS.txt.sig'

try {
    # The fresh complete package supplies its own pinned native verifier.
    # Repair never edits a manifest, disables verification, or touches keys.
    $verified = @(& $node --verify-release $manifest $signature 2>&1)
    if ($LASTEXITCODE -ne 0 -or ($verified -join "`n").Trim() -cne 'RELEASE-SIGNATURE-VALID') {
        throw 'The repair package signature could not be verified. Download the complete package again.'
    }
    if ((Get-Item -LiteralPath $manifest).Length -gt 8MB) {throw 'Repair manifest exceeds its size limit'}
    $seen = @{}
    foreach ($line in Get-Content -LiteralPath $manifest) {
        if ($line.StartsWith('#')) {continue}
        if ($line -cnotmatch '^([0-9a-f]{64}) \*(.+)$') {throw 'Repair manifest has a malformed entry'}
        $hash = $Matches[1]; $relative = $Matches[2]
        if ($relative.Contains('\') -or $relative.StartsWith('/') -or
            $relative.Contains(':') -or $relative.Split('/') -contains '..' -or
            $relative.Split('/') -contains '.' -or $relative -like 'veld-data/*' -or
            $seen.ContainsKey($relative)) {throw 'Repair manifest contains an unsafe or duplicate path'}
        $seen[$relative] = $true
        $path = [IO.Path]::GetFullPath((Join-Path $root $relative))
        if (!$path.StartsWith($root+'\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Repair path escaped the package'}
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {throw 'Repair file is not regular'}
        if ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) {
            throw ('Repair package file failed verification: '+$relative)
        }
    }
    foreach ($required in @('bin/veld-node.exe','Veld Node.exe','veld-update.ps1','veld-repair.ps1','Repair Veld Update.bat')) {
        if (!$seen.ContainsKey($required)) {throw ('Incomplete repair package: '+$required)}
    }
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        Add-Type -AssemblyName System.Windows.Forms
        $picker = [Windows.Forms.FolderBrowserDialog]::new()
        try {
            $picker.Description = 'Select your existing Veld folder containing Veld Node.exe and veld-data. Your chain and wallet stay in this folder.'
            $picker.ShowNewFolderButton = $false
            if ($picker.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) {exit 0}
            $InstallDir = $picker.SelectedPath
        } finally {$picker.Dispose()}
    }
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    if ($InstallDir -ieq $root) {throw 'Select the existing installation, not the newly extracted repair package.'}
    foreach ($name in @('Veld Node.exe','bin\veld-node.exe','SHA256SUMS.txt','SHA256SUMS.txt.sig')) {
        if (!(Test-Path -LiteralPath (Join-Path $InstallDir $name) -PathType Leaf)) {
            throw 'That folder is not an existing Veld Node installation.'
        }
    }
    # Close only processes whose executable path matches the selected install.
    # A node gets the same graceful event used by its own Stop button.
    $guiPath = Join-Path $InstallDir 'Veld Node.exe'
    $nodePath = Join-Path $InstallDir 'bin\veld-node.exe'
    foreach ($info in Get-CimInstance Win32_Process -Filter "name='Veld Node.exe'") {
        if ($info.ExecutablePath -ine $guiPath) {continue}
        $process = Get-Process -Id $info.ProcessId -ErrorAction Stop
        if (!$process.CloseMainWindow() -or !$process.WaitForExit(15000)) {
            throw 'Close the Veld app in the selected folder, then run repair again.'
        }
    }
    foreach ($info in Get-CimInstance Win32_Process -Filter "name='veld-node.exe'") {
        if ($info.ExecutablePath -ine $nodePath) {continue}
        $process = Get-Process -Id $info.ProcessId -ErrorAction Stop
        $stop = [Threading.EventWaitHandle]::OpenExisting('Local\VeldNodeShutdown-'+$info.ProcessId)
        try {$stop.Set() | Out-Null} finally {$stop.Dispose()}
        if (!$process.WaitForExit(30000)) {throw 'The node is still stopping. Run repair after it has stopped.'}
    }
    Write-Host '   [repair] Using the fresh signed updater. Your existing data folder is retained.'
    & (Join-Path $root 'veld-update.ps1') -Mode Install -InstallDir $InstallDir -Distribution Node
    exit $LASTEXITCODE
} catch {
    Write-Host ('   [repair] Could not finish: '+$_.Exception.Message)
    exit 1
}
