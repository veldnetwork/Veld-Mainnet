param(
  [ValidateSet('Ensure', 'Status')]
  [string]$Mode = 'Ensure',
  [switch]$RetryNow
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$RuleName = 'Veld Node P2P (TCP 8333)'
$P2PPort = '8333'
$TcpProtocol = 6
$InboundDirection = 1
$AllowAction = 1
$AllFirewallProfiles = 7
$RetryDelay = [TimeSpan]::FromDays(30)

function Get-CanonicalLocalPath([string]$Path) {
  if ([string]::IsNullOrWhiteSpace($Path) -or
      $Path.IndexOfAny([char[]]@([char]0, [char]10, [char]13, [char]34)) -ge 0) {
    throw 'Unsafe executable path.'
  }

  $full = [IO.Path]::GetFullPath($Path)
  if (-not [IO.Path]::IsPathRooted($full) -or $full.StartsWith('\\')) {
    throw 'The automatic firewall setup requires a local installation.'
  }
  return $full
}

function Get-GuiPreference([string]$ConfigPath, [string]$Name) {
  if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $null }
  $prefix = $Name + '='
  foreach ($line in [IO.File]::ReadAllLines($ConfigPath)) {
    if ($line.StartsWith($prefix, [StringComparison]::Ordinal)) {
      return $line.Substring($prefix.Length).Trim()
    }
  }
  return $null
}

function Get-NamedFirewallRules {
  try {
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $found = @()
    foreach ($rule in $policy.Rules) {
      if ([string]::Equals([string]$rule.Name, $RuleName,
                           [StringComparison]::Ordinal)) {
        $found += $rule
      }
    }
    return @($found)
  } catch {
    return @()
  }
}

function Test-AnyAddress([object]$Value) {
  $text = [string]$Value
  return [string]::IsNullOrWhiteSpace($text) -or $text -eq '*'
}

function Test-ExactFirewallRule([object]$Rule, [string]$NodePath) {
  try {
    $application = Get-CanonicalLocalPath ([string]$Rule.ApplicationName)
    return $Rule.Enabled -eq $true -and
      [int]$Rule.Protocol -eq $TcpProtocol -and
      [string]$Rule.LocalPorts -eq $P2PPort -and
      [int]$Rule.Direction -eq $InboundDirection -and
      [int]$Rule.Action -eq $AllowAction -and
      [int]$Rule.Profiles -eq $AllFirewallProfiles -and
      $Rule.EdgeTraversal -eq $false -and
      (Test-AnyAddress $Rule.LocalAddresses) -and
      (Test-AnyAddress $Rule.RemoteAddresses) -and
      (Test-AnyAddress $Rule.RemotePorts) -and
      [string]::IsNullOrWhiteSpace([string]$Rule.ServiceName) -and
      ([string]::IsNullOrWhiteSpace([string]$Rule.InterfaceTypes) -or
       [string]$Rule.InterfaceTypes -eq 'All') -and
      [string]::Equals($application, $NodePath,
                       [StringComparison]::OrdinalIgnoreCase)
  } catch {
    return $false
  }
}

function Test-ExactFirewallConfiguration([object[]]$Rules,
                                         [string]$NodePath) {
  foreach ($rule in $Rules) {
    if (Test-ExactFirewallRule $rule $NodePath) { return $true }
  }
  return $false
}

function Read-AttemptState([string]$StateFile) {
  try {
    if (-not (Test-Path -LiteralPath $StateFile -PathType Leaf)) { return $null }
    return Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
  } catch {
    return $null
  }
}

function Write-AttemptState([string]$StateFile, [string]$NodePath,
                            [string]$Result) {
  try {
    $directory = Split-Path -Parent $StateFile
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $payload = [ordered]@{
      schema = 1
      result = $Result
      program = $NodePath
      port = [int]$P2PPort
      attempted_utc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Compress
    $pending = $StateFile + '.new'
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($pending, $payload + [Environment]::NewLine, $utf8)
    Move-Item -LiteralPath $pending -Destination $StateFile -Force
  } catch {
    # Reachability state is advisory and must never stop the node.
  }
}

function Test-BackoffActive([object]$State, [string]$NodePath) {
  if ($null -eq $State -or $RetryNow) { return $false }
  try {
    if (-not [string]::Equals([string]$State.program, $NodePath,
                              [StringComparison]::OrdinalIgnoreCase) -or
        [string]$State.result -ne 'deferred') {
      return $false
    }
    $last = [DateTime]::Parse([string]$State.attempted_utc,
                              [Globalization.CultureInfo]::InvariantCulture,
                              [Globalization.DateTimeStyles]::RoundtripKind)
    return ([DateTime]::UtcNow - $last.ToUniversalTime()) -lt $RetryDelay
  } catch {
    return $false
  }
}

function Invoke-FirewallSetup([string]$NodePath, [bool]$UpdateExisting) {
  $netsh = Join-Path $env:SystemRoot 'System32\netsh.exe'
  if (-not (Test-Path -LiteralPath $netsh -PathType Leaf)) { return $false }

  $arguments = @('advfirewall', 'firewall')
  if ($UpdateExisting) {
    $arguments += @('set', 'rule', ('name="' + $RuleName + '"'), 'new')
  } else {
    $arguments += @('add', 'rule', ('name="' + $RuleName + '"'))
  }
  $arguments += 'description="Inbound Veld peer traffic only; RPC and web ports remain local."'
  $arguments += @(
    'dir=in',
    'action=allow',
    ('program="' + $NodePath + '"'),
    'protocol=TCP',
    ('localport=' + $P2PPort),
    'remoteport=any',
    'localip=any',
    'remoteip=any',
    # A user who explicitly enables public reachability may still have their
    # trusted LAN classified as Public by Windows.  Keep the exception narrow
    # (the exact node binary and P2P port only) while applying it consistently
    # to whichever network profile is active.
    'profile=domain,private,public',
    'interfacetype=any',
    'edge=no',
    'enable=yes'
  )

  try {
    $process = Start-Process -FilePath $netsh -ArgumentList $arguments `
      -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    return $process.ExitCode -eq 0
  } catch {
    return $false
  }
}

try {
  $packageRoot = Get-CanonicalLocalPath (Split-Path -Parent $PSCommandPath)
  $nodePath = Get-CanonicalLocalPath (Join-Path $packageRoot 'bin\veld-node.exe')
  if (-not (Test-Path -LiteralPath $nodePath -PathType Leaf)) { exit 3 }

  $stateRoot = Join-Path $env:LOCALAPPDATA 'Veld\Node'
  $stateFile = Join-Path $stateRoot 'reachability-v1.json'
  $configFile = Join-Path $stateRoot 'node-gui.conf'

  # Tor-only and explicitly outbound-only configurations never request a
  # clearnet firewall exception.
  if ((Get-GuiPreference $configFile 'tor') -eq '1' -or
      (Get-GuiPreference $configFile 'reachable') -eq '0') {
    exit 0
  }

  $rules = @(Get-NamedFirewallRules)
  if (Test-ExactFirewallConfiguration $rules $nodePath) {
    if ($Mode -eq 'Ensure') {
      Write-AttemptState $stateFile $nodePath 'installed'
    }
    exit 0
  }
  if ($Mode -eq 'Status') { exit 2 }

  $state = Read-AttemptState $stateFile
  if (Test-BackoffActive $state $nodePath) { exit 0 }

  $updated = Invoke-FirewallSetup $nodePath ($rules.Count -gt 0)
  $rules = @(Get-NamedFirewallRules)
  if ($updated -and (Test-ExactFirewallConfiguration $rules $nodePath)) {
    Write-AttemptState $stateFile $nodePath 'installed'
    exit 0
  }

  # A declined UAC request or unsupported policy leaves the node in its safe
  # outbound-only mode. Delay the next automatic request to avoid prompt loops.
  Write-AttemptState $stateFile $nodePath 'deferred'
  exit 0
} catch {
  exit 0
}
