param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Check', 'Install', 'Watch', 'Commit', 'Recover')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [int]$ParentPid = 0,
    [ValidateSet('Node', 'Terminal')]
    [string]$Distribution = 'Node'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Net.Http
Add-Type -AssemblyName System.IO.Compression
$InstallDir = [IO.Path]::GetFullPath($InstallDir)
$installRoot = [IO.Path]::GetPathRoot($InstallDir)
if ($InstallDir.Length -gt $installRoot.Length) {
    $InstallDir = $InstallDir.TrimEnd('\')
}
if (-not [IO.Directory]::Exists($InstallDir)) {
    Write-Host '   [update] ABORT: install directory does not exist'
    exit 1
}
$Base = 'https://veld.network/downloads'
$RemoteManifestName = if ($Distribution -eq 'Terminal') {
    'VeldTerminalClient-SHA256SUMS.txt'
} else { 'SHA256SUMS.txt' }
$RemoteSignatureName = $RemoteManifestName + '.sig'
$RemoteZipName = if ($Distribution -eq 'Terminal') {
    'VeldTerminalClient-Windows-x64.zip'
} else { 'VeldClient-Windows-x64.zip' }
$RemoteZipShaName = $RemoteZipName + '.sha256'
$RemoteZipShaSignatureName = $RemoteZipShaName + '.sig'
$RemoteChangesName = if ($Distribution -eq 'Terminal') {
    'VeldTerminalClient-CHANGES.txt'
} else { 'CHANGES.txt' }
$PrimaryLauncher = if ($Distribution -eq 'Terminal') {
    'Start Mining.bat'
} else { 'Veld Node.exe' }
$RequiredPackageFiles = if ($Distribution -eq 'Terminal') {
    @('bin/veld-node.exe', 'veld-update.ps1', 'Start Mining.bat',
      'Start Mining (Clearnet).bat', 'Start Validator.bat', 'tor-setup.ps1',
      'tor-watchdog.ps1', 'CHANGES.txt')
} else {
    @('bin/veld-node.exe', 'bin/veld-node-gui.exe', 'bin/veld-wallet.exe',
      'Veld Node.exe', 'veld-update.ps1', 'Start Veld Node.bat')
}
$Node = Join-Path $InstallDir 'bin\veld-node.exe'
$LocalManifest = Join-Path $InstallDir 'SHA256SUMS.txt'
$LocalSignature = Join-Path $InstallDir 'SHA256SUMS.txt.sig'
$Transaction = Join-Path $InstallDir '.veld-update-transaction'

$MaxManifestDownloadBytes = 8MB
$MaxSignatureDownloadBytes = 64KB
$MaxChecksumDownloadBytes = 16KB
$MaxChangelogDownloadBytes = 8MB
$MaxReleaseArchiveBytes = 256MB
$MaxReleaseArchiveEntries = 4096
$MaxReleaseEntryBytes = 256MB
$MaxReleaseExpandedBytes = 512MB

function Abort-Update([string]$Message) {
    Write-Host ('   [update] ABORT: ' + $Message)
    exit 1
}

function Fetch([string]$Name, [string]$Destination) {
    $maximum = switch -CaseSensitive ($Name) {
        $RemoteManifestName { $MaxManifestDownloadBytes; break }
        $RemoteSignatureName { $MaxSignatureDownloadBytes; break }
        $RemoteChangesName { $MaxChangelogDownloadBytes; break }
        $RemoteZipShaName { $MaxChecksumDownloadBytes; break }
        $RemoteZipShaSignatureName { $MaxSignatureDownloadBytes; break }
        $RemoteZipName { $MaxReleaseArchiveBytes; break }
        default { throw ('download route has no byte policy: ' + $Name) }
    }
    if ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) {
        throw ('download destination already exists: ' + $Destination)
    }

    $handler = $null
    $client = $null
    $request = $null
    $response = $null
    $stream = $null
    $output = $null
    $deadline = $null
    $created = $false
    try {
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.AutomaticDecompression = [Net.DecompressionMethods]::None
        $client = [Net.Http.HttpClient]::new($handler, $true)
        $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
        $deadline = [Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(30))
        $uri = [Uri]::new($Base + '/' + $Name)
        if ($uri.Scheme -cne 'https' -or -not $uri.IsAbsoluteUri) {
            throw 'release downloads require an absolute HTTPS URI'
        }
        $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
        $response = $client.SendAsync(
            $request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
            $deadline.Token).GetAwaiter().GetResult()
        $status = [int]$response.StatusCode
        if ($status -ge 300 -and $status -lt 400) {
            throw ('release download redirect refused: HTTP ' + $status)
        }
        if (-not $response.IsSuccessStatusCode) {
            throw ('release download failed: HTTP ' + $status)
        }
        $declared = $response.Content.Headers.ContentLength
        if ($null -ne $declared -and [uint64]$declared -gt [uint64]$maximum) {
            throw ('declared download length exceeds route cap: ' + $Name)
        }

        # CreateNew is deliberately after the header check: an oversized
        # Content-Length is rejected before any destination or body transfer.
        $output = [IO.FileStream]::new(
            $Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
            [IO.FileShare]::None, 65536,
            [IO.FileOptions]::WriteThrough -bor [IO.FileOptions]::SequentialScan)
        $created = $true
        $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
        $buffer = [byte[]]::new(65536)
        [uint64]$received = 0
        while ($true) {
            $count = $stream.ReadAsync(
                $buffer, 0, $buffer.Length,
                $deadline.Token).GetAwaiter().GetResult()
            if ($count -eq 0) { break }
            if ($received -gt [uint64]$maximum -or
                [uint64]$count -gt ([uint64]$maximum - $received)) {
                throw ('download body exceeds route cap: ' + $Name)
            }
            $output.Write($buffer, 0, $count)
            $received += [uint64]$count
        }
        if ($received -eq 0) { throw ('empty download: ' + $Name) }
        $output.Flush($true)
    }
    catch {
        if ($null -ne $output) { $output.Dispose(); $output = $null }
        if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
        if ($created) {
            [IO.File]::Delete($Destination)
        }
        throw
    }
    finally {
        if ($null -ne $output) { $output.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
        if ($null -ne $request) { $request.Dispose() }
        if ($null -ne $deadline) { $deadline.Dispose() }
        if ($null -ne $client) { $client.Dispose() }
        elseif ($null -ne $handler) { $handler.Dispose() }
    }
}

function Expand-BoundedReleaseArchive([string]$Archive, [string]$Destination) {
    if ([IO.Directory]::Exists($Destination) -or [IO.File]::Exists($Destination)) {
        throw 'release archive destination already exists'
    }
    [IO.Directory]::CreateDirectory($Destination) | Out-Null
    $root = [IO.Path]::GetFullPath($Destination).TrimEnd('\') + '\'
    $archiveStream = $null
    $zip = $null
    try {
        $archiveStream = [IO.FileStream]::new(
            $Archive, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read, 65536,
            [IO.FileOptions]::SequentialScan)
        $zip = [IO.Compression.ZipArchive]::new(
            $archiveStream, [IO.Compression.ZipArchiveMode]::Read, $false)
        if ($zip.Entries.Count -eq 0 -or
            $zip.Entries.Count -gt $MaxReleaseArchiveEntries) {
            throw 'release archive entry count exceeds policy'
        }
        $seen = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase)
        [uint64]$declaredTotal = 0
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ([string]::IsNullOrWhiteSpace($name) -or $name.Contains('\') -or
                $name.Contains([char]0) -or $name.StartsWith('/') -or
                $name -match '^[A-Za-z]:' -or
                ($name.Split('/') -contains '..') -or
                ($name.Split('/') -contains '.')) {
                throw ('unsafe release archive path: ' + $name)
            }
            $isDirectory = $name.EndsWith('/')
            $relative = $name.TrimEnd('/').Replace('/', '\')
            if (-not $seen.Add($relative)) {
                throw ('duplicate release archive path: ' + $name)
            }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            $windowsAttributes = ($entry.ExternalAttributes -band 0xFFFF)
            if ($unixType -eq 0xA000 -or
                ($windowsAttributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ('release archive contains a link/reparse entry: ' + $name)
            }
            if (-not $isDirectory) {
                if ([uint64]$entry.Length -gt [uint64]$MaxReleaseEntryBytes) {
                    throw ('release archive entry exceeds policy: ' + $name)
                }
                if ($declaredTotal -gt [uint64]$MaxReleaseExpandedBytes -or
                    [uint64]$entry.Length -gt
                        ([uint64]$MaxReleaseExpandedBytes - $declaredTotal)) {
                    throw 'release archive expanded size exceeds policy'
                }
                $declaredTotal += [uint64]$entry.Length
            }
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if (-not $target.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) {
                throw ('release archive path escapes destination: ' + $name)
            }
        }

        [uint64]$actualTotal = 0
        $buffer = [byte[]]::new(65536)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $relative = $name.TrimEnd('/').Replace('/', '\')
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $relative))
            if ($name.EndsWith('/')) {
                [IO.Directory]::CreateDirectory($target) | Out-Null
                continue
            }
            $parent = [IO.Path]::GetDirectoryName($target)
            [IO.Directory]::CreateDirectory($parent) | Out-Null
            $input = $null
            $file = $null
            try {
                $input = $entry.Open()
                $file = [IO.FileStream]::new(
                    $target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
                    [IO.FileShare]::None, 65536,
                    [IO.FileOptions]::WriteThrough -bor [IO.FileOptions]::SequentialScan)
                [uint64]$entryBytes = 0
                while ($true) {
                    $count = $input.Read($buffer, 0, $buffer.Length)
                    if ($count -eq 0) { break }
                    if ($entryBytes -gt [uint64]$MaxReleaseEntryBytes -or
                        [uint64]$count -gt
                            ([uint64]$MaxReleaseEntryBytes - $entryBytes) -or
                        $actualTotal -gt [uint64]$MaxReleaseExpandedBytes -or
                        [uint64]$count -gt
                            ([uint64]$MaxReleaseExpandedBytes - $actualTotal)) {
                        throw 'release archive expansion exceeded policy while streaming'
                    }
                    $file.Write($buffer, 0, $count)
                    $entryBytes += [uint64]$count
                    $actualTotal += [uint64]$count
                }
                if ($entryBytes -ne [uint64]$entry.Length) {
                    throw ('release archive entry length mismatch: ' + $name)
                }
                $file.Flush($true)
            }
            finally {
                if ($null -ne $file) { $file.Dispose() }
                if ($null -ne $input) { $input.Dispose() }
            }
        }
        if ($actualTotal -ne $declaredTotal) {
            throw 'release archive expanded length mismatch'
        }
    }
    catch {
        if ($null -ne $zip) { $zip.Dispose(); $zip = $null }
        if ($null -ne $archiveStream) { $archiveStream.Dispose(); $archiveStream = $null }
        if ([IO.Directory]::Exists($Destination)) {
            [IO.Directory]::Delete($Destination, $true)
        }
        throw
    }
    finally {
        if ($null -ne $zip) { $zip.Dispose() }
        if ($null -ne $archiveStream) { $archiveStream.Dispose() }
    }
}

function Read-CanonicalLines([string]$Path, [string]$Description,
                             [uint64]$MaximumBytes) {
    $stream = $null
    $reader = $null
    try {
        $stream = [IO.FileStream]::new(
            $Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::Read, 65536, [IO.FileOptions]::SequentialScan)
        if ($stream.Length -eq 0) {
            throw ($Description + ' is empty')
        }
        if ([uint64]$stream.Length -gt $MaximumBytes) {
            throw ($Description + ' exceeds its byte limit')
        }

        # Check the byte-level canonical form without retaining a complete raw
        # copy.  Keep this stream open for decoding so the checked file cannot
        # be replaced between validation and parsing on Windows.
        $buffer = [byte[]]::new(65536)
        [byte]$lastByte = 0
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            for ($offset = 0; $offset -lt $count; $offset++) {
                if ($buffer[$offset] -eq 13) {
                    throw ($Description + ' is not canonical LF text')
                }
            }
            $lastByte = $buffer[$count - 1]
        }
        if ($lastByte -ne 10) {
            throw ($Description + ' is not canonical LF text')
        }

        $stream.Position = 0
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $reader = [IO.StreamReader]::new(
            $stream, $utf8, $false, 4096, $true)
        while (($line = $reader.ReadLine()) -ne $null) {
            Write-Output $line
        }
    }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $stream) { $stream.Dispose() }
    }
}

function Read-Manifest([string]$Path) {
    $lines = @(Read-CanonicalLines $Path 'signed manifest' `
        $MaxManifestDownloadBytes)
    if ($lines.Count -lt 3 -or $lines[0] -cne '# veld-release-manifest-v1' -or
        $lines[1] -notmatch '^# release-version=(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw 'signed manifest schema/version is not canonical'
    }
    $entries = @{}
    $previous = $null
    foreach ($line in $lines[2..($lines.Count - 1)]) {
        if ($line -notmatch '^([0-9a-f]{64}) \*([^\r\n]+)$') {
            throw 'malformed signed manifest line'
        }
        $sha = $matches[1]
        $rel = $matches[2]
        if ($rel.StartsWith('/') -or $rel.Contains('\') -or
            ($rel -split '/') -contains '..' -or ($rel -split '/') -contains '.' -or
            $rel -notmatch '^[A-Za-z0-9._ ()/-]+$') {
            throw ('unsafe signed manifest path: ' + $rel)
        }
        if ($null -ne $previous -and
            [StringComparer]::Ordinal.Compare($previous, $rel) -ge 0) {
            throw 'signed manifest paths are not strictly sorted'
        }
        if ($entries.ContainsKey($rel)) { throw ('duplicate manifest path: ' + $rel) }
        $entries[$rel] = $sha
        $previous = $rel
    }
    if ($entries.Count -eq 0) { throw 'signed manifest contains no files' }
    return $entries
}

function Read-ReleaseVersion([string]$Path) {
    $lines = @(Read-CanonicalLines $Path 'signed manifest' `
        $MaxManifestDownloadBytes)
    if ($lines.Count -lt 3 -or $lines[0] -cne '# veld-release-manifest-v1') {
        throw 'missing or invalid signed release-manifest schema'
    }
    if (-not $lines[1].StartsWith('# release-version=')) {
        throw 'signed manifest release version is not the canonical second line'
    }
    $text = $lines[1].Substring('# release-version='.Length)
    if ($text -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$') {
        throw ('signed manifest has malformed release version: ' + $text)
    }
    $major = 0; $minor = 0; $patch = 0
    if (-not [int]::TryParse($matches[1], [ref]$major) -or
        -not [int]::TryParse($matches[2], [ref]$minor) -or
        -not [int]::TryParse($matches[3], [ref]$patch)) {
        throw 'signed release version component is out of range'
    }
    return [pscustomobject]@{
        Text = $text; Major = $major; Minor = $minor; Patch = $patch
    }
}

function Compare-ReleaseVersion($A, $B) {
    foreach ($field in @('Major', 'Minor', 'Patch')) {
        if ($A.$field -lt $B.$field) { return -1 }
        if ($A.$field -gt $B.$field) { return 1 }
    }
    return 0
}

function Read-ZipChecksum([string]$Path, [string]$ExpectedVersion) {
    $lines = @(Read-CanonicalLines $Path 'signed zip checksum' `
        $MaxChecksumDownloadBytes)
    if ($lines.Count -ne 3 -or $lines[0] -cne '# veld-release-zip-v1' -or
        $lines[1] -cne ('# release-version=' + $ExpectedVersion)) {
        throw 'zip checksum metadata/version does not match the signed release manifest'
    }
    $recordPattern = '^([0-9a-f]{64}) \*' + [regex]::Escape($RemoteZipName) + '$'
    if ($lines[2] -notmatch $recordPattern) {
        throw 'malformed signed zip checksum record'
    }
    return $matches[1]
}

function Assert-LocalManifestAndNode([hashtable]$Files) {
    if (-not $Files.ContainsKey('bin/veld-node.exe')) {
        throw 'local manifest has no bin/veld-node.exe entry'
    }
    if (-not (Test-Path -LiteralPath $Node)) {
        throw 'local veld-node.exe is missing'
    }
    $actualLocal = (Get-FileHash -Algorithm SHA256 -LiteralPath $Node).Hash.ToLower()
    if ($actualLocal -ne $Files['bin/veld-node.exe']) {
        throw 'local node hash does not match the installed signed manifest'
    }
}

function Assert-EqualVersionManifestIdentity([string]$RemotePath, [string]$LocalPath) {
    $remoteDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $RemotePath).Hash
    $localDigest = (Get-FileHash -Algorithm SHA256 -LiteralPath $LocalPath).Hash
    if ($remoteDigest -cne $localDigest) {
        throw 'equal signed version has different manifest bytes (release equivocation refused)'
    }
}

function Verify-ReleaseSignature([string]$Manifest, [string]$Signature) {
    if (-not (Test-Path -LiteralPath $Node)) { return $false }
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $output = @(& $Node --verify-release $Manifest $Signature 2>$null |
        ForEach-Object { $_.ToString() })
    $code = $LASTEXITCODE
    $ErrorActionPreference = $saved
    return ($code -eq 0 -and $output.Count -eq 1 -and
        $output[0] -ceq 'RELEASE-SIGNATURE-VALID')
}

function Download-SignedManifest([string]$Directory) {
    $manifest = Join-Path $Directory 'SHA256SUMS.txt'
    $signature = Join-Path $Directory 'SHA256SUMS.txt.sig'
    Fetch $RemoteManifestName $manifest
    Fetch $RemoteSignatureName $signature
    if (-not (Verify-ReleaseSignature $manifest $signature)) {
        throw 'release manifest is unsigned or invalid against the pinned release key'
    }
    return $manifest
}

function Assert-SafeInstallPath([string]$Path, [string]$Description) {
    $root = $InstallDir
    $full = [IO.Path]::GetFullPath($Path)
    $prefix = if ($root.EndsWith('\')) { $root } else { $root + '\' }
    $isRoot = $full.Equals($root, [StringComparison]::OrdinalIgnoreCase)
    if (-not $isRoot -and
        -not $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw ($Description + ' escapes the install directory')
    }
    $rootItem = Get-Item -LiteralPath $root -Force
    if (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'install directory is a reparse point'
    }
    if ($isRoot) { return $full }
    $relative = $full.Substring($prefix.Length)
    $parts = @($relative.Split([char]'\'))
    $cursor = $root
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ($parts[$i].Length -eq 0) { throw ($Description + ' has an empty path component') }
        $cursor = Join-Path $cursor $parts[$i]
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw ($Description + ' traverses a reparse point: ' + $cursor)
            }
            if ($i -lt ($parts.Count - 1) -and -not $item.PSIsContainer) {
                throw ($Description + ' traverses a non-directory: ' + $cursor)
            }
        }
    }
    return $full
}

function Assert-RegularFile([string]$Path, [string]$Description) {
    if (-not [IO.File]::Exists($Path)) { throw ($Description + ' is missing') }
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or
        (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw ($Description + ' is not a regular non-reparse file')
    }
}

function Ensure-SafeParent([string]$Path, [string]$Description) {
    $safe = Assert-SafeInstallPath $Path $Description
    $parent = Split-Path -Parent $safe
    if (-not [IO.Directory]::Exists($parent)) {
        [IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    Assert-SafeInstallPath $parent ($Description + ' parent') | Out-Null
    return $safe
}

function Copy-Durable([string]$Source, [string]$Destination) {
    Assert-RegularFile $Source 'transaction source file'
    if ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) {
        throw ('transaction destination already exists: ' + $Destination)
    }
    $sourceStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read)
    try {
        $destinationStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew,
            [IO.FileAccess]::Write, [IO.FileShare]::None)
        try {
            $sourceStream.CopyTo($destinationStream)
            $destinationStream.Flush($true)
        }
        finally { $destinationStream.Dispose() }
    }
    finally { $sourceStream.Dispose() }
}

function Replace-FileAtomic([string]$Pending, [string]$Destination) {
    # Windows PowerShell 5.1 rejects a null backup path for File.Replace even
    # though newer .NET runtimes permit it. Use a same-directory temporary
    # backup so replacement remains atomic on the destination volume, then
    # remove the backup after the new file is durable.
    $backup = $Destination + '.veld-replace-' + [guid]::NewGuid().ToString('N') + '.bak'
    try {
        if ([IO.File]::Exists($backup) -or [IO.Directory]::Exists($backup)) {
            throw ('atomic replacement backup already exists: ' + $backup)
        }
        [IO.File]::Replace($Pending, $Destination, $backup, $true)
    }
    finally {
        if ([IO.File]::Exists($backup)) {
            [IO.File]::Delete($backup)
        }
    }
}

function Install-FileAtomic([string]$Source, [string]$Destination, [string]$ExpectedSha) {
    $safeDestination = Ensure-SafeParent $Destination 'signed install destination'
    $pending = $safeDestination + '.veld-update-' + [guid]::NewGuid().ToString('N') + '.new'
    try {
        Copy-Durable $Source $pending
        $pendingSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $pending).Hash.ToLower()
        if ($pendingSha -ne $ExpectedSha) { throw 'pending install copy changed hash' }
        if ([IO.File]::Exists($safeDestination)) {
            Assert-RegularFile $safeDestination 'existing install destination'
            Replace-FileAtomic $pending $safeDestination
        }
        elseif ([IO.Directory]::Exists($safeDestination)) {
            throw 'signed install destination is a directory'
        }
        else {
            [IO.File]::Move($pending, $safeDestination)
        }
        $installedSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $safeDestination).Hash.ToLower()
        if ($installedSha -ne $ExpectedSha) { throw 'installed file changed hash after promotion' }
    }
    finally {
        if ([IO.File]::Exists($pending)) {
            Remove-Item -LiteralPath $pending -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-InstalledFile([string]$Path) {
    $safe = Assert-SafeInstallPath $Path 'obsolete signed install path'
    if ([IO.Directory]::Exists($safe)) { throw 'obsolete signed file became a directory' }
    if ([IO.File]::Exists($safe)) {
        Assert-RegularFile $safe 'obsolete signed install file'
        [IO.File]::Delete($safe)
    }
}

function Write-TransactionState([string]$State) {
    if ($State -notmatch '^(PREPARED|HANDOFF|BACKED_UP|APPLYING|COMMITTED|ROLLED_BACK)$') {
        throw 'invalid update transaction state'
    }
    $statePath = Join-Path $Transaction 'state'
    $pending = Join-Path $Transaction ('state.' + [guid]::NewGuid().ToString('N') + '.new')
    $bytes = [Text.Encoding]::ASCII.GetBytes($State + "`n")
    $stream = [IO.File]::Open($pending, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    if ([IO.File]::Exists($statePath)) {
        Replace-FileAtomic $pending $statePath
    }
    else {
        [IO.File]::Move($pending, $statePath)
    }
}

function Read-TransactionState() {
    $statePath = Join-Path $Transaction 'state'
    Assert-RegularFile $statePath 'update transaction state'
    $raw = [IO.File]::ReadAllBytes($statePath)
    $text = [Text.Encoding]::ASCII.GetString($raw)
    $valid = @('PREPARED', 'HANDOFF', 'BACKED_UP', 'APPLYING', 'COMMITTED', 'ROLLED_BACK')
    if ($text.Length -lt 2 -or $text[$text.Length - 1] -ne "`n" -or
        $valid -cnotcontains $text.Substring(0, $text.Length - 1)) {
        throw 'update transaction state is malformed'
    }
    return $text.Substring(0, $text.Length - 1)
}

function Open-TransactionLock() {
    $lockPath = Join-Path $Transaction 'active.lock'
    Assert-SafeInstallPath $lockPath 'update transaction lock' | Out-Null
    if ([IO.File]::Exists($lockPath)) {
        Assert-RegularFile $lockPath 'update transaction lock'
    }
    elseif ([IO.Directory]::Exists($lockPath)) {
        throw 'update transaction lock is a directory'
    }
    try {
        return [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    }
    catch { throw 'another updater/recovery process owns the install transaction' }
}

function Get-VerifiedPackage([string]$Stage) {
    $safeStage = Assert-SafeInstallPath $Stage 'update stage'
    $stageItem = Get-Item -LiteralPath $safeStage -Force
    if (-not $stageItem.PSIsContainer -or
        (($stageItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'update stage is not a regular directory'
    }
    $manifestPath = Join-Path $safeStage 'SHA256SUMS.txt'
    $signaturePath = Join-Path $safeStage 'SHA256SUMS.txt.sig'
    Assert-RegularFile $manifestPath 'staged signed manifest'
    Assert-RegularFile $signaturePath 'staged detached signature'
    if (-not (Verify-ReleaseSignature $manifestPath $signaturePath)) {
        throw 'staged manifest signature is invalid against the pinned release key'
    }
    $entries = Read-Manifest $manifestPath
    $version = Read-ReleaseVersion $manifestPath
    foreach ($required in $RequiredPackageFiles) {
        if (-not $entries.ContainsKey($required)) {
            throw ('signed package is missing required updater component: ' + $required)
        }
    }
    $files = @{}
    foreach ($item in Get-ChildItem -LiteralPath $safeStage -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('package contains a reparse point: ' + $item.FullName)
        }
        if ($item.PSIsContainer) { continue }
        $rel = $item.FullName.Substring($safeStage.Length).TrimStart('\').Replace('\','/')
        if ($rel -eq 'SHA256SUMS.txt' -or $rel -eq 'SHA256SUMS.txt.sig') { continue }
        if ($files.ContainsKey($rel)) { throw ('duplicate package path: ' + $rel) }
        $files[$rel] = $item.FullName
    }
    if ($files.Count -ne $entries.Count) {
        throw 'package file set does not match the signed manifest'
    }
    foreach ($rel in $entries.Keys) {
        if (-not $files.ContainsKey($rel)) { throw ('signed file missing: ' + $rel) }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $files[$rel]).Hash.ToLower()
        if ($got -ne $entries[$rel]) { throw ('signed hash mismatch: ' + $rel) }
    }
    return [pscustomobject]@{
        Root = $safeStage; Manifest = $manifestPath; Signature = $signaturePath
        Entries = $entries; Files = $files; Version = $version
    }
}

function Get-VerifiedInstalled() {
    Assert-SafeInstallPath $LocalManifest 'installed manifest' | Out-Null
    Assert-SafeInstallPath $LocalSignature 'installed signature' | Out-Null
    Assert-SafeInstallPath $Node 'installed release verifier' | Out-Null
    Assert-RegularFile $Node 'installed veld-node.exe'
    Assert-RegularFile $LocalManifest 'installed signed manifest'
    Assert-RegularFile $LocalSignature 'installed detached signature'
    if (-not (Verify-ReleaseSignature $LocalManifest $LocalSignature)) {
        throw 'installed release manifest signature is missing or invalid'
    }
    $entries = Read-Manifest $LocalManifest
    $version = Read-ReleaseVersion $LocalManifest
    foreach ($rel in $entries.Keys) {
        $path = Join-Path $InstallDir ($rel.Replace('/','\'))
        Assert-SafeInstallPath $path ('installed signed file ' + $rel) | Out-Null
        Assert-RegularFile $path ('installed signed file ' + $rel)
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower()
        if ($got -ne $entries[$rel]) { throw ('installed signed hash mismatch: ' + $rel) }
    }
    # Mutable chain/wallet data may live below the installation root, but code
    # must be an exact subset of the signed release. Reject executable drift
    # such as bin/bin/veld-node.exe instead of silently blessing the tree just
    # because every manifest-listed file still matches.
    $codeExtensions = @('.exe', '.dll', '.ps1', '.bat', '.cmd', '.com', '.scr')
    foreach ($item in Get-ChildItem -LiteralPath $InstallDir -Recurse -Force -File) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('installed tree contains a reparse point: ' + $item.FullName)
        }
        if ($item.FullName.StartsWith($Transaction + '\',
                [StringComparison]::OrdinalIgnoreCase)) { continue }
        $rel = $item.FullName.Substring($InstallDir.Length).TrimStart('\').Replace('\','/')
        if ($rel.StartsWith('veld-data/', [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($rel -eq 'SHA256SUMS.txt' -or $rel -eq 'SHA256SUMS.txt.sig') { continue }
        if ($codeExtensions -contains $item.Extension.ToLowerInvariant() -and
            -not $entries.ContainsKey($rel)) {
            throw ('unmanifested executable file in installed tree: ' + $rel)
        }
    }
    return [pscustomobject]@{ Entries = $entries; Version = $version }
}

function Backup-Installed($Installed) {
    $backup = Join-Path $Transaction 'backup'
    if (Test-Path -LiteralPath $backup) { throw 'update backup path already exists' }
    [IO.Directory]::CreateDirectory($backup) | Out-Null
    foreach ($rel in $Installed.Entries.Keys) {
        $source = Join-Path $InstallDir ($rel.Replace('/','\'))
        $destination = Join-Path $backup ($rel.Replace('/','\'))
        $parent = Split-Path -Parent $destination
        [IO.Directory]::CreateDirectory($parent) | Out-Null
        Copy-Durable $source $destination
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash.ToLower()
        if ($got -ne $Installed.Entries[$rel]) { throw ('backup hash mismatch: ' + $rel) }
    }
    foreach ($name in @('SHA256SUMS.txt', 'SHA256SUMS.txt.sig')) {
        $source = Join-Path $InstallDir $name
        $destination = Join-Path $backup $name
        Copy-Durable $source $destination
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $source).Hash -cne
            (Get-FileHash -Algorithm SHA256 -LiteralPath $destination).Hash) {
            throw ('backup changed ' + $name)
        }
    }
    Write-TransactionState 'BACKED_UP'
}

function Apply-VerifiedPackage($Package, $OldEntries) {
    Write-TransactionState 'APPLYING'
    foreach ($rel in $OldEntries.Keys) {
        if (-not $Package.Entries.ContainsKey($rel)) {
            Remove-InstalledFile (Join-Path $InstallDir ($rel.Replace('/','\')))
        }
    }
    $ordinary = @($Package.Entries.Keys | Where-Object {
        $_ -cne 'veld-update.ps1' -and $_ -cne $PrimaryLauncher
    } | Sort-Object)
    $ordered = @($ordinary)
    $ordered += 'veld-update.ps1'
    $ordered += $PrimaryLauncher
    foreach ($rel in $ordered) {
        $destination = Join-Path $InstallDir ($rel.Replace('/','\'))
        Install-FileAtomic $Package.Files[$rel] $destination $Package.Entries[$rel]
        Write-Host ('   [update]  + ' + $rel)
    }
    $signatureSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package.Signature).Hash.ToLower()
    Install-FileAtomic $Package.Signature $LocalSignature $signatureSha
    $manifestSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $Package.Manifest).Hash.ToLower()
    # Promote the signed manifest last: it is the installed-version identity,
    # and must not name the new tree until every signed payload byte is live.
    Install-FileAtomic $Package.Manifest $LocalManifest $manifestSha
    $installed = Get-VerifiedInstalled
    if ((Compare-ReleaseVersion $installed.Version $Package.Version) -ne 0 -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $LocalManifest).Hash -cne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $Package.Manifest).Hash) {
        throw 'post-install signed version/manifest identity check failed'
    }
    Write-TransactionState 'COMMITTED'
}

function Rollback-Transaction() {
    $backup = Join-Path $Transaction 'backup'
    $stage = Join-Path $Transaction 'stage'
    $backupManifest = Join-Path $backup 'SHA256SUMS.txt'
    $backupSignature = Join-Path $backup 'SHA256SUMS.txt.sig'
    $stageManifest = Join-Path $stage 'SHA256SUMS.txt'
    Assert-RegularFile $backupManifest 'rollback manifest'
    Assert-RegularFile $backupSignature 'rollback signature'
    Assert-RegularFile $stageManifest 'rollback staged manifest'
    $oldEntries = Read-Manifest $backupManifest
    $newEntries = Read-Manifest $stageManifest
    foreach ($rel in $newEntries.Keys) {
        if (-not $oldEntries.ContainsKey($rel)) {
            Remove-InstalledFile (Join-Path $InstallDir ($rel.Replace('/','\')))
        }
    }
    foreach ($rel in $oldEntries.Keys) {
        $source = Join-Path $backup ($rel.Replace('/','\'))
        $destination = Join-Path $InstallDir ($rel.Replace('/','\'))
        Install-FileAtomic $source $destination $oldEntries[$rel]
    }
    $signatureSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $backupSignature).Hash.ToLower()
    Install-FileAtomic $backupSignature $LocalSignature $signatureSha
    $manifestSha = (Get-FileHash -Algorithm SHA256 -LiteralPath $backupManifest).Hash.ToLower()
    Install-FileAtomic $backupManifest $LocalManifest $manifestSha
    Get-VerifiedInstalled | Out-Null
    Write-TransactionState 'ROLLED_BACK'
}

function Remove-TransactionTree() {
    if (-not (Test-Path -LiteralPath $Transaction)) { return }
    Assert-SafeInstallPath $Transaction 'update transaction' | Out-Null
    $rootItem = Get-Item -LiteralPath $Transaction -Force
    if (-not $rootItem.PSIsContainer -or
        (($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        throw 'update transaction path is not a regular directory'
    }
    foreach ($item in Get-ChildItem -LiteralPath $Transaction -Recurse -Force) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('update transaction contains a reparse point: ' + $item.FullName)
        }
    }
    Remove-Item -LiteralPath $Transaction -Recurse -Force
}

function Wait-ForParentExit([int]$ProcessId) {
    if ($ProcessId -le 0) { throw 'commit handoff has no valid parent process id' }
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return }
        Start-Sleep -Milliseconds 200
    }
    throw 'launcher did not exit within the update handoff deadline'
}

function Relaunch-InstalledClient() {
    $launcher = Join-Path $InstallDir $PrimaryLauncher
    if (Test-Path -LiteralPath $launcher) {
        Start-Process -FilePath 'explorer.exe' -ArgumentList ('"' + $launcher + '"') | Out-Null
    }
}

function Invoke-TransactionRecovery() {
    if (-not (Test-Path -LiteralPath $Transaction)) { return }
    $lock = Open-TransactionLock
    try {
        $state = Read-TransactionState
        switch ($state) {
            'APPLYING' {
                Rollback-Transaction
                Write-Host '   [update] Interrupted update rolled back to the last signed release.'
            }
            'COMMITTED' {
                try { Get-VerifiedInstalled | Out-Null }
                catch {
                    Rollback-Transaction
                    Write-Host '   [update] Incomplete committed update rolled back to the last signed release.'
                }
            }
            'ROLLED_BACK' { Get-VerifiedInstalled | Out-Null }
            'PREPARED' { }
            'HANDOFF' { }
            'BACKED_UP' { }
            default { throw 'unrecognized update recovery state' }
        }
    }
    finally { $lock.Dispose() }
    Remove-TransactionTree
}

function Invoke-TransactionCommit([int]$LauncherPid) {
    $lock = Open-TransactionLock
    $committed = $false
    $rolledBack = $false
    $discardPrepared = $false
    $failure = $null
    try {
        if ((Read-TransactionState) -cne 'HANDOFF') {
            throw 'update transaction is not in handoff state'
        }
        Wait-ForParentExit $LauncherPid
        $package = Get-VerifiedPackage (Join-Path $Transaction 'stage')
        $installed = Get-VerifiedInstalled
        if ((Compare-ReleaseVersion $package.Version $installed.Version) -le 0) {
            throw 'commit package is not strictly newer than the installed signed release'
        }
        Backup-Installed $installed
        Apply-VerifiedPackage $package $installed.Entries
        $committed = $true
    }
    catch {
        $failure = $_.Exception.Message
        try {
            $state = Read-TransactionState
            if ($state -ceq 'APPLYING' -or $state -ceq 'BACKED_UP') {
                Rollback-Transaction
                $rolledBack = $true
            }
            elseif ($state -ceq 'COMMITTED') {
                $committed = $true
            }
            elseif ($state -ceq 'PREPARED' -or $state -ceq 'HANDOFF') {
                # No live install path is mutated before APPLYING is durable.
                $discardPrepared = $true
            }
        }
        catch {
            $failure = 'update failed and rollback requires manual recovery: ' + $failure +
                '; rollback error: ' + $_.Exception.Message
        }
    }
    finally { $lock.Dispose() }
    if ($committed -or $rolledBack -or $discardPrepared) {
        Remove-TransactionTree
    }
    if ($null -ne $failure -and -not $committed) {
        throw ('update transaction failed: ' + $failure)
    }
    Relaunch-InstalledClient
}

if ($Mode -eq 'Recover') {
    try {
        Invoke-TransactionRecovery
        exit 0
    }
    catch {
        Write-Host ('   [update] RECOVERY FAILED: ' + $_.Exception.Message)
        exit 1
    }
}

if ($Mode -eq 'Commit') {
    try {
        Invoke-TransactionCommit $ParentPid
        exit 0
    }
    catch {
        Write-Host ('   [update] COMMIT FAILED: ' + $_.Exception.Message)
        try { Relaunch-InstalledClient } catch { }
        exit 1
    }
}

if (Test-Path -LiteralPath $Transaction) {
    Abort-Update 'an update transaction needs recovery before feed access'
}

if ($Mode -eq 'Watch') {
    try { Get-VerifiedInstalled | Out-Null }
    catch { Abort-Update ('installed release verification failed: ' + $_.Exception.Message) }
    $deadline = (Get-Date).AddHours(24)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3600
        $watchTemp = Join-Path $env:TEMP ('veld-update-watch-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $watchTemp -Force | Out-Null
        try {
            $watchManifest = Download-SignedManifest $watchTemp
            $remoteWatch = Read-Manifest $watchManifest
            $remoteWatchVersion = Read-ReleaseVersion $watchManifest
            $verifiedWatch = Get-VerifiedInstalled
            $localWatch = $verifiedWatch.Entries
            $localWatchVersion = $verifiedWatch.Version
            if (-not $remoteWatch.ContainsKey('bin/veld-node.exe')) {
                throw 'remote signed manifest has no bin/veld-node.exe entry'
            }
            foreach ($required in $RequiredPackageFiles) {
                if (-not $remoteWatch.ContainsKey($required)) {
                    throw ('remote signed manifest has no required ' + $Distribution +
                           ' package entry: ' + $required)
                }
            }
            $watchComparison = Compare-ReleaseVersion $remoteWatchVersion $localWatchVersion
            if ($watchComparison -lt 0) {
                throw ('signed feed rollback refused: remote ' + $remoteWatchVersion.Text +
                       ' < installed ' + $localWatchVersion.Text)
            }
            if ($watchComparison -eq 0 -and
                $remoteWatch['bin/veld-node.exe'] -ne $localWatch['bin/veld-node.exe']) {
                throw 'equal signed version has a different node hash (release equivocation refused)'
            }
            if ($watchComparison -eq 0) {
                Assert-EqualVersionManifestIdentity $watchManifest $LocalManifest
            }
            if ($watchComparison -gt 0) {
                $sentinel = Join-Path $InstallDir 'veld-data\.force-update'
                Set-Content -LiteralPath $sentinel `
                    -Value $remoteWatchVersion.Text -Encoding ASCII
                Remove-Item -LiteralPath $watchTemp -Recurse -Force -ErrorAction SilentlyContinue
                exit 0
            }
        }
        catch {
            # Fail closed: an unavailable/unsigned feed never creates the
            # mandatory-update sentinel and never supplies an artifact hash.
        }
        Remove-Item -LiteralPath $watchTemp -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

$TempRoot = Join-Path $env:TEMP ('veld-update-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $TempRoot | Out-Null
if (((Get-Item -LiteralPath $TempRoot -Force).Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'update temporary directory is a reparse point'
}
$TransactionLock = $null
$TransactionOwned = $false

try {
    $remoteManifest = Download-SignedManifest $TempRoot
    $remoteSignature = Join-Path $TempRoot 'SHA256SUMS.txt.sig'
    $remote = Read-Manifest $remoteManifest
    $remoteVersion = Read-ReleaseVersion $remoteManifest
    if (-not $remote.ContainsKey('bin/veld-node.exe')) {
        throw 'signed manifest has no bin/veld-node.exe entry'
    }
    foreach ($required in $RequiredPackageFiles) {
        if (-not $remote.ContainsKey($required)) {
            throw ('signed manifest has no required ' + $Distribution +
                   ' package entry: ' + $required)
        }
    }

    $verifiedLocal = Get-VerifiedInstalled
    $local = $verifiedLocal.Entries
    $localVersion = $verifiedLocal.Version
    $comparison = Compare-ReleaseVersion $remoteVersion $localVersion
    if ($comparison -lt 0) {
        throw ('signed feed rollback refused: remote ' + $remoteVersion.Text +
               ' < installed ' + $localVersion.Text)
    }
    if ($comparison -eq 0 -and
        $remote['bin/veld-node.exe'] -ne $local['bin/veld-node.exe']) {
        throw 'equal signed version has a different node hash (release equivocation refused)'
    }
    if ($comparison -eq 0) {
        Assert-EqualVersionManifestIdentity $remoteManifest $LocalManifest
    }

    if ($Mode -eq 'Check') {
        if ($comparison -gt 0) {
            Write-Host ''
            Write-Host '   ============================================================'
            Write-Host '   [update] A signed newer Veld client is available.'
            Write-Host ('   [update] Installed version: ' + $localVersion.Text)
            Write-Host ('   [update] Remote version:    ' + $remoteVersion.Text)
            if ($remote.ContainsKey('CHANGES.txt')) {
                $remoteChanges = Join-Path $TempRoot 'CHANGES.txt'
                Fetch $RemoteChangesName $remoteChanges
                $changesHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $remoteChanges).Hash.ToLower()
                if ($changesHash -ne $remote['CHANGES.txt']) {
                    throw 'published changelog does not match the signed release manifest'
                }
                Write-Host ''
                Get-Content -LiteralPath $remoteChanges -TotalCount 24 | ForEach-Object {
                    Write-Host ('   ' + $_)
                }
            }
            Write-Host '   ============================================================'
            Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
            exit 2
        }
        Write-Host ('   [update] Client ' + $localVersion.Text + ' is up to date (signed manifest verified).')
        Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        exit 0
    }

    # Install is permitted only for a strictly greater signed version. An old
    # valid signature is not freshness, and equal-version replacement is not a
    # release channel.
    if ($comparison -eq 0) {
        Write-Host ('   [update] No install: signed version ' + $remoteVersion.Text + ' is already installed.')
        Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
        exit 0
    }

    $zip = Join-Path $TempRoot $RemoteZipName
    $zipSha = Join-Path $TempRoot $RemoteZipShaName
    $zipShaSignature = Join-Path $TempRoot $RemoteZipShaSignatureName
    Fetch $RemoteZipShaName $zipSha
    Fetch $RemoteZipShaSignatureName $zipShaSignature
    if (-not (Verify-ReleaseSignature $zipSha $zipShaSignature)) {
        throw 'zip checksum is unsigned or invalid against the pinned release key'
    }
    $declared = Read-ZipChecksum $zipSha $remoteVersion.Text
    # The checksum has been authenticated before the untrusted archive is even
    # downloaded. The bounded streaming extractor below independently enforces
    # entry, per-file, total expansion, link, duplicate, and traversal limits.
    Fetch $RemoteZipName $zip
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash.ToLower()
    if ($actual -ne $declared) { throw 'zip checksum mismatch' }

    $stage = Join-Path $TempRoot 'stage'
    Expand-BoundedReleaseArchive $zip $stage
    $stageManifest = Join-Path $stage 'SHA256SUMS.txt'
    $stageSignature = Join-Path $stage 'SHA256SUMS.txt.sig'
    if (-not (Test-Path -LiteralPath $stageManifest)) { throw 'package has no manifest' }
    if (-not (Test-Path -LiteralPath $stageSignature)) { throw 'package has no detached signature' }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $stageManifest).Hash -ne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $remoteManifest).Hash) {
        throw 'package manifest differs from the release-signed manifest'
    }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $stageSignature).Hash -ne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $remoteSignature).Hash) {
        throw 'package signature differs from the published release signature'
    }

    $actualFiles = @{}
    foreach ($item in Get-ChildItem -LiteralPath $stage -Recurse -File) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw ('package contains a reparse point: ' + $item.FullName)
        }
        $rel = $item.FullName.Substring($stage.Length).TrimStart('\').Replace('\','/')
        if ($rel -eq 'SHA256SUMS.txt' -or $rel -eq 'SHA256SUMS.txt.sig') { continue }
        $actualFiles[$rel] = $item.FullName
    }
    if ($actualFiles.Count -ne $remote.Count) {
        throw 'package file set does not match the signed manifest'
    }
    foreach ($rel in $remote.Keys) {
        if (-not $actualFiles.ContainsKey($rel)) { throw ('signed file missing: ' + $rel) }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $actualFiles[$rel]).Hash.ToLower()
        if ($got -ne $remote[$rel]) { throw ('signed hash mismatch: ' + $rel) }
    }
    foreach ($rel in $actualFiles.Keys) {
        if (-not $remote.ContainsKey($rel)) { throw ('unsigned extra file in package: ' + $rel) }
    }
    foreach ($required in $RequiredPackageFiles) {
        if (-not $actualFiles.ContainsKey($required)) {
            throw ('signed package is missing required updater component: ' + $required)
        }
    }

    # The fixed transaction directory is both a process-wide install lock and
    # a reboot-surviving recovery journal.  Nothing in the live install is
    # mutated by this process; a child commit process waits for the running
    # launcher to exit, backs up the complete old signed tree, and promotes
    # every new file atomically with rollback on any error.
    if (Test-Path -LiteralPath $Transaction) {
        throw 'another update transaction already exists'
    }
    New-Item -ItemType Directory -Path $Transaction -ErrorAction Stop | Out-Null
    $TransactionOwned = $true
    Assert-SafeInstallPath $Transaction 'new update transaction' | Out-Null
    $TransactionLock = Open-TransactionLock
    $transactionStage = Join-Path $Transaction 'stage'
    Move-Item -LiteralPath $stage -Destination $transactionStage
    $transactionPackage = Get-VerifiedPackage $transactionStage
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $transactionPackage.Manifest).Hash -cne
        (Get-FileHash -Algorithm SHA256 -LiteralPath $remoteManifest).Hash) {
        throw 'transaction stage lost the release-signed manifest identity'
    }
    Write-TransactionState 'PREPARED'
    $parentPid = (Get-CimInstance Win32_Process -Filter ('ProcessId=' + $PID)).ParentProcessId
    if ($parentPid -le 0) { throw 'cannot identify the launcher process for safe handoff' }
    $commitArguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath +
        '" -Mode Commit -InstallDir "' + $InstallDir + '" -ParentPid ' + $parentPid +
        ' -Distribution ' + $Distribution
    Start-Process -FilePath 'powershell.exe' -ArgumentList $commitArguments `
        -WindowStyle Hidden | Out-Null
    Write-TransactionState 'HANDOFF'
    $TransactionLock.Dispose()
    $TransactionLock = $null
    $TransactionOwned = $false
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host '   [update] Signed package verified. Durable install handoff is ready.'
    exit 0
}
catch {
    Write-Host ('   [update] FAILED: ' + $_.Exception.Message)
    if ($null -ne $TransactionLock) {
        $TransactionLock.Dispose()
        $TransactionLock = $null
    }
    if ($TransactionOwned) {
        try { Remove-TransactionTree } catch { }
    }
    Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}
