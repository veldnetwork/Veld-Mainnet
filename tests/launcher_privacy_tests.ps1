$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
$defaultLauncher = Join-Path $root 'pkg\Start Mining.bat'
$clearnetLauncher = Join-Path $root 'pkg\Start Mining (Clearnet).bat'
$default = [IO.File]::ReadAllText($defaultLauncher)
$clearnet = [IO.File]::ReadAllText($clearnetLauncher)
$checks = 0

function Assert-Condition([bool]$Condition, [string]$Message) {
    $script:checks++
    if (-not $Condition) { throw "FAIL: $Message" }
}

$gate = 'if /I "!VELD_CLEARNET!"=="1" goto :net_clearnet'
Assert-Condition ($default.Contains($gate)) 'exact clearnet opt-in gate is present'
Assert-Condition (-not $default.Contains('if not defined VELD_TOR goto :net_clearnet')) 'legacy fail-open gate is absent'
Assert-Condition ($default.Contains('set "NETFLAG=--tor-only"')) 'private path selects tor-only'
Assert-Condition ($default.Contains(':tor_failed')) 'Tor setup failure has a terminal branch'
$torFailure = $default.Substring($default.IndexOf(':tor_failed'))
Assert-Condition ($torFailure.Contains('exit /b 1')) 'Tor failure refuses launch'
Assert-Condition ($default.IndexOf($gate) -lt $default.IndexOf('set "NETFLAG=--tor-only"')) 'gate precedes private launch flag'
Assert-Condition ($default.IndexOf('set "NETFLAG=--tor-only"') -lt $default.LastIndexOf(':net_clearnet')) 'private path precedes clearnet label'
Assert-Condition ($clearnet.Contains('set "VELD_CLEARNET=1"')) 'named clearnet launcher opts out explicitly'
Assert-Condition ($clearnet.Contains('call "%~dp0Start Mining.bat"')) 'named clearnet launcher delegates to signed main launcher'

$cases = @{
    ''      = 'tor'
    '0'     = 'tor'
    'false' = 'tor'
    'true'  = 'tor'
    '01'    = 'tor'
    'yes'   = 'tor'
    '1 '    = 'tor'
    '1'     = 'clearnet'
}
foreach ($entry in $cases.GetEnumerator()) {
    $actual = if ($entry.Key.Equals('1', [StringComparison]::OrdinalIgnoreCase)) {
        'clearnet'
    } else {
        'tor'
    }
    Assert-Condition ($actual -eq $entry.Value) "privacy selection for '$($entry.Key)'"
}

Write-Output "PASS launcher_privacy_tests checks=$checks default=tor exact_opt_out=1"
