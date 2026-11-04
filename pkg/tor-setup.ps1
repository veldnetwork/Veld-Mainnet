# ==========================================================================
#  tor-setup.ps1 - Veld tor-only privacy networking
#
#  Fetches the OFFICIAL Tor (hash-pinned, verified before it is ever run),
#  writes a torrc with a static v3 hidden service fronting the node P2P port,
#  starts Tor, and waits for it to finish bootstrapping. Called by the Veld
#  launchers before the node starts with --tor-only.
#
#  We do NOT ship tor.exe inside the package (it trips antivirus heuristics
#  when bundled next to a miner). Instead we fetch the official binary once
#  and verify it against a pinned SHA-256, so a hijacked mirror cannot
#  substitute a different binary. Exit 0 = Tor bootstrapped and ready.
# ==========================================================================
param([Parameter(Mandatory=$true)][string]$DataDir)
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
Add-Type -AssemblyName System.Net.Http
$TOR_MAX_ARCHIVE_BYTES = 256MB
$TOR_MAX_EXTRACTED_EXE_BYTES = 64MB
$TOR_EXTRACT_TIMEOUT_SECONDS = 60

function Get-BoundedHttpsFile([string]$UriText, [string]$Destination,
                              [uint64]$MaximumBytes, [int]$TimeoutSeconds) {
  if ([IO.File]::Exists($Destination) -or [IO.Directory]::Exists($Destination)) {
    throw 'Tor download destination already exists'
  }
  $uri = [Uri]::new($UriText)
  if (-not $uri.IsAbsoluteUri -or $uri.Scheme -cne 'https') {
    throw 'Tor downloads require an absolute HTTPS URI'
  }
  $handler = $null; $client = $null; $request = $null; $response = $null
  $stream = $null; $output = $null; $deadline = $null; $created = $false
  try {
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $handler.AutomaticDecompression = [Net.DecompressionMethods]::None
    $client = [Net.Http.HttpClient]::new($handler, $true)
    $client.Timeout = [Threading.Timeout]::InfiniteTimeSpan
    $deadline = [Threading.CancellationTokenSource]::new(
      [TimeSpan]::FromSeconds($TimeoutSeconds))
    $request = [Net.Http.HttpRequestMessage]::new([Net.Http.HttpMethod]::Get, $uri)
    $response = $client.SendAsync(
      $request, [Net.Http.HttpCompletionOption]::ResponseHeadersRead,
      $deadline.Token).GetAwaiter().GetResult()
    $status = [int]$response.StatusCode
    if ($status -ge 300 -and $status -lt 400) {
      throw ('Tor download redirect refused: HTTP ' + $status)
    }
    if (-not $response.IsSuccessStatusCode) {
      throw ('Tor download failed: HTTP ' + $status)
    }
    $declared = $response.Content.Headers.ContentLength
    if ($null -ne $declared -and [uint64]$declared -gt $MaximumBytes) {
      throw 'Tor archive declared length exceeds policy'
    }
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
      if ($received -gt $MaximumBytes -or
          [uint64]$count -gt ($MaximumBytes - $received)) {
        throw 'Tor archive body exceeds policy'
      }
      $output.Write($buffer, 0, $count)
      $received += [uint64]$count
    }
    if ($received -eq 0) { throw 'empty Tor archive download' }
    $output.Flush($true)
  }
  catch {
    if ($null -ne $output) { $output.Dispose(); $output = $null }
    if ($null -ne $stream) { $stream.Dispose(); $stream = $null }
    if ($created) { [IO.File]::Delete($Destination) }
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

function Get-TrustedSystemTarExecutable() {
  # Resolve from operating-system special folders, never from the process
  # current directory, PATH, or attacker-controlled environment variables.
  $windowsDirectory = [IO.Path]::GetFullPath(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)).TrimEnd('\')
  $systemDirectory = [IO.Path]::GetFullPath(
    [Environment]::SystemDirectory).TrimEnd('\')
  if (-not [IO.Path]::IsPathRooted($windowsDirectory) -or
      -not [IO.Path]::IsPathRooted($systemDirectory) -or
      -not [IO.Path]::GetDirectoryName($systemDirectory).Equals(
        $windowsDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Windows system directory identity is invalid'
  }
  foreach ($directory in @($windowsDirectory, $systemDirectory)) {
    $item = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Windows system directory is missing or is a reparse point'
    }
  }

  $extractor = [IO.Path]::GetFullPath((Join-Path $systemDirectory 'tar.exe'))
  if (-not [IO.Path]::IsPathRooted($extractor) -or
      -not [IO.Path]::GetDirectoryName($extractor).Equals(
        $systemDirectory, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'trusted Tor extractor path is not canonical'
  }
  $extractorItem = Get-Item -LiteralPath $extractor -Force -ErrorAction Stop
  if ($extractorItem.PSIsContainer -or $extractorItem.Length -eq 0 -or
      ($extractorItem.Attributes -band
        [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'trusted Windows tar executable is missing or unsafe'
  }
  return $extractor
}

function Expand-BoundedTorExecutable([string]$Extractor, [string]$Archive,
                                     [string]$Destination,
                                     [uint64]$MaximumBytes,
                                     [int]$TimeoutSeconds) {
  if ($MaximumBytes -eq 0 -or $TimeoutSeconds -le 0) {
    throw 'invalid Tor extraction policy'
  }
  if ([IO.File]::Exists($Destination) -or
      [IO.Directory]::Exists($Destination)) {
    throw 'Tor extraction destination already exists'
  }
  if (-not [IO.File]::Exists($Archive) -or
      $Archive.IndexOfAny([char[]]@([char]0, [char]10, [char]13, [char]34)) -ge 0) {
    throw 'unsafe Tor archive path'
  }
  $trustedExtractor = Get-TrustedSystemTarExecutable
  if (-not [IO.Path]::IsPathRooted($Extractor) -or
      -not [IO.Path]::GetFullPath($Extractor).Equals(
        $trustedExtractor, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Tor extraction requires the trusted Windows system tar executable'
  }

  $process = $null
  $output = $null
  $started = $false
  $created = $false
  $clock = [Diagnostics.Stopwatch]::StartNew()
  try {
    $output = [IO.FileStream]::new(
      $Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write,
      [IO.FileShare]::None, 65536,
      [IO.FileOptions]::WriteThrough -bor [IO.FileOptions]::SequentialScan)
    $created = $true

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $trustedExtractor
    $start.Arguments = '-xOzf "' + $Archive + '" tor/tor.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $false
    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) { throw 'could not start Tor archive extraction' }
    $started = $true

    $buffer = [byte[]]::new(65536)
    [uint64]$received = 0
    while ($true) {
      $remaining = [int][Math]::Floor(
        ($TimeoutSeconds * 1000.0) - $clock.Elapsed.TotalMilliseconds)
      if ($remaining -le 0) { throw 'Tor archive extraction deadline exceeded' }
      $read = $process.StandardOutput.BaseStream.ReadAsync(
        $buffer, 0, $buffer.Length)
      if (-not $read.Wait($remaining)) {
        throw 'Tor archive extraction deadline exceeded'
      }
      $count = $read.GetAwaiter().GetResult()
      if ($count -eq 0) { break }
      if ($received -gt $MaximumBytes -or
          [uint64]$count -gt ($MaximumBytes - $received)) {
        throw 'Tor executable expansion exceeds policy'
      }
      $output.Write($buffer, 0, $count)
      $received += [uint64]$count
    }
    if ($received -eq 0) { throw 'Tor archive produced an empty executable' }

    $remaining = [int][Math]::Floor(
      ($TimeoutSeconds * 1000.0) - $clock.Elapsed.TotalMilliseconds)
    if ($remaining -le 0 -or -not $process.WaitForExit($remaining)) {
      throw 'Tor archive extraction deadline exceeded'
    }
    if ($process.ExitCode -ne 0) { throw 'Tor archive extraction failed' }
    $output.Flush($true)
  }
  catch {
    if ($started -and $null -ne $process) {
      try {
        if (-not $process.HasExited) {
          $process.Kill()
          [void]$process.WaitForExit(5000)
        }
      } catch { }
    }
    if ($null -ne $output) { $output.Dispose(); $output = $null }
    if ($created) { [IO.File]::Delete($Destination) }
    throw
  }
  finally {
    if ($null -ne $output) { $output.Dispose() }
    if ($null -ne $process) { $process.Dispose() }
    $clock.Stop()
  }
}

# The node deliberately refuses to import secrets or identity files from a
# directory that grants access to any principal other than the current user.
# Tor's Windows defaults add SYSTEM and the current logon SID to newly-created
# hidden-service files, so normalize the bundled Tor tree to the same
# owner-only ACL used by the Veld datadir. Tor runs as this user and retains
# full access.
function Set-VeldOwnerOnlyAcl([string]$Path, [bool]$IsDirectory) {
  $sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
  if ($IsDirectory) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
               [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetAccessRuleProtection($true, $false)
  $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $sid,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    $inherit,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow)
  [void]$acl.AddAccessRule($rule)
  if ($IsDirectory) {
    [System.IO.Directory]::SetAccessControl($Path, $acl)
  } else {
    [System.IO.File]::SetAccessControl($Path, $acl)
  }
}

function Protect-VeldOwnerOnlyTree([string]$Root) {
  if (-not (Test-Path -LiteralPath $Root)) { return }
  Set-VeldOwnerOnlyAcl $Root $true
  Get-ChildItem -LiteralPath $Root -Force -Recurse -ErrorAction Stop | ForEach-Object {
    Set-VeldOwnerOnlyAcl $_.FullName $_.PSIsContainer
  }
}

# Pinned to an exact official Tor Expert Bundle (Tor 15.0.15, Windows x86_64).
# SELF-HOSTED on veld.network as the primary source: the Tor Project DELETES
# superseded versions from dist.torproject.org the moment a new release ships,
# which 404'd the pinned URL and broke tor-only mode. veld.network mirrors the
# byte-identical, hash-pinned bundle so upstream version churn can never break
# it. The Tor archive (which keeps old versions) is a fallback. The SHA-256 is
# verified before the binary is ever run, so no mirror can substitute a
# different binary.
$TOR_URLS   = @(
  'https://veld.network/downloads/tor-expert-bundle-windows-x86_64-15.0.15.tar.gz',
  'https://archive.torproject.org/tor-package-archive/torbrowser/15.0.15/tor-expert-bundle-windows-x86_64-15.0.15.tar.gz'
)
$TOR_SHA256 = '8d3daf579192f3f128c0f42553dd994c640501b4b98682216d807c88004f7a96'

$tgz = $null
$tmpx = $null
try {
  $tordir  = Join-Path $DataDir 'tor'
  $torexe  = Join-Path $tordir  'tor.exe'
  $torrc   = Join-Path $tordir  'torrc'
  $tordata = Join-Path $tordir  'data'
  $hsdir   = Join-Path $tordir  'hs'
  $notice  = Join-Path $tordir  'notice.log'
  $marker  = Join-Path $tordir  '.tor-pinned'
  New-Item -ItemType Directory -Force -Path $tordir,$tordata | Out-Null

  # 1. Fetch and hash-verify the official Tor (only if not already pinned-OK).
  $cur = ''
  if ((Test-Path $torexe) -and (Test-Path $marker)) { $cur = (Get-Content $marker -ErrorAction SilentlyContinue) }
  if ($cur -ne $TOR_SHA256) {
    Write-Host '  [tor] fetching the official Tor (one-time, hash-pinned) ...'
    try {
      $systemTar = Get-TrustedSystemTarExecutable
    } catch {
      Write-Host ('  [tor] ERROR: trusted Windows tar.exe is unavailable (' +
        $_.Exception.Message + ').')
      exit 2
    }
    $tgz = Join-Path $env:TEMP ('veld-tor-' + [guid]::NewGuid().ToString('N').Substring(0,8) + '.tar.gz')
    # Try each source in order; accept the first that downloads AND matches the
    # pinned SHA-256. A 404 / network error on one source falls through to the
    # next instead of aborting tor-only mode.
    $fetched = $false
    foreach ($u in $TOR_URLS) {
      try {
        Get-BoundedHttpsFile $u $tgz $TOR_MAX_ARCHIVE_BYTES 180
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $tgz).Hash.ToLower()
        if ($got -eq $TOR_SHA256) { $fetched = $true; break }
        Write-Host ('  [tor] ' + $u + ' returned an unexpected file (sha ' + $got.Substring(0,16) + '...); trying next source ...')
        Remove-Item -Force $tgz -ErrorAction SilentlyContinue
      } catch {
        Write-Host ('  [tor] ' + $u + ' unavailable (' + $_.Exception.Message + '); trying next source ...')
        Remove-Item -Force $tgz -ErrorAction SilentlyContinue
      }
    }
    if (-not $fetched) {
      Write-Host '  [tor] ERROR: could not fetch a hash-valid Tor bundle from any source - refusing to run.'
      exit 3
    }
    $tmpx = Join-Path $env:TEMP ('veld-torx-' + [guid]::NewGuid().ToString('N').Substring(0,8))
    New-Item -ItemType Directory -Path $tmpx | Out-Null
    if (((Get-Item -LiteralPath $tmpx -Force).Attributes -band
          [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw 'Tor extraction directory is a reparse point'
    }
    # The archive is byte-for-byte pinned before decompression.  Stream only
    # the required member through a parent-owned pipe into a CreateNew file;
    # enforce the expansion ceiling and deadline before bytes reach the final
    # Tor installation path.
    $src = Join-Path $tmpx 'tor.exe'
    Expand-BoundedTorExecutable $systemTar $tgz $src `
      $TOR_MAX_EXTRACTED_EXE_BYTES $TOR_EXTRACT_TIMEOUT_SECONDS
    if (-not (Test-Path $src)) { Write-Host '  [tor] ERROR: tor.exe not found in bundle.'; exit 4 }
    $srcItem = Get-Item -LiteralPath $src -Force
    if (($srcItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $srcItem.PSIsContainer -or $srcItem.Length -eq 0 -or
        [uint64]$srcItem.Length -gt [uint64]$TOR_MAX_EXTRACTED_EXE_BYTES) {
      throw 'Tor archive produced an unsafe or oversized executable'
    }
    Copy-Item -Force $src $torexe
    Set-Content -Path $marker -Value $TOR_SHA256 -Encoding ASCII
    Remove-Item -Recurse -Force $tmpx -ErrorAction SilentlyContinue
    Remove-Item -Force $tgz -ErrorAction SilentlyContinue
    Write-Host '  [tor] verified and installed.'
  }

  # 2. torrc: SOCKS out plus a persistent v3 hidden service to local P2P 8333.
  #    LongLivedPorts plus KeepalivePeriod keep circuits warm so block
  #    propagation rides an already-open circuit (minimal added latency).
  $lines = @(
    '# Veld tor-only privacy mode (auto-generated; do not edit).',
    'SocksPort 9050',
    ('DataDirectory "' + $tordata.Replace('\','/') + '"'),
    ('HiddenServiceDir "' + $hsdir.Replace('\','/') + '"'),
    'HiddenServicePort 8333 127.0.0.1:8333',
    'HiddenServiceVersion 3',
    'KeepalivePeriod 30',
    'LongLivedPorts 8333',
    ('Log notice file ' + $notice.Replace('\','/'))
  )
  Set-Content -Path $torrc -Value $lines -Encoding ASCII
  Protect-VeldOwnerOnlyTree $tordir

  # 3. Start tor if not already running from this folder.
  $running = Get-CimInstance Win32_Process -Filter "Name='tor.exe'" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*$tordir*" }
  if (-not $running) {
    Remove-Item -Force $notice -ErrorAction SilentlyContinue
    Start-Process -FilePath $torexe -ArgumentList ('-f "' + $torrc + '"') -WindowStyle Hidden
    Write-Host '  [tor] starting and bootstrapping (first run can take 30-60s) ...'
  }

  # 4. Wait for the bootstrap-complete line.
  $deadline = (Get-Date).AddSeconds(180)
  while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    if (Test-Path $notice) {
      if (Select-String -Path $notice -Pattern 'Bootstrapped 100' -Quiet -ErrorAction SilentlyContinue) {
        $onion = ''
        $hf = Join-Path $hsdir 'hostname'
        if (Test-Path $hf) { $onion = (Get-Content $hf -ErrorAction SilentlyContinue | Select-Object -First 1) }
        if (-not $onion -or $onion -notmatch '^[a-z2-7]{56}\.onion$') {
          continue
        }
        Protect-VeldOwnerOnlyTree $hsdir
        Write-Host ('  [tor] ready. You are reachable as: ' + $onion)
        # Bind a detached watchdog to the launcher console (our parent process)
        # so the tor.exe we started - which is intentionally detached so it can
        # serve the node during mining - is stopped when the client is closed
        # (Ctrl+C, window-close, or normal exit) instead of lingering.
        try {
          $lp = (Get-CimInstance Win32_Process -Filter ("ProcessId=" + $PID) -ErrorAction SilentlyContinue).ParentProcessId
          $wd = Join-Path (Split-Path -Parent $DataDir) 'tor-watchdog.ps1'
          if ($lp -and (Test-Path $wd)) {
            Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File',$wd,'-DataDir',$DataDir,'-LauncherPid',$lp) | Out-Null
            Write-Host '  [tor] cleanup watchdog armed (tor stops when you close the client).'
          }
        } catch {}
        exit 0
      }
    }
  }
  Write-Host '  [tor] ERROR: Tor did not finish bootstrapping in time.'
  exit 5
} catch {
  Write-Host ('  [tor] ERROR: ' + $_.Exception.Message)
  exit 1
} finally {
  if ($null -ne $tmpx -and [IO.Directory]::Exists($tmpx)) {
    [IO.Directory]::Delete($tmpx, $true)
  }
  if ($null -ne $tgz -and [IO.File]::Exists($tgz)) {
    [IO.File]::Delete($tgz)
  }
}
