$ErrorActionPreference = 'Stop'

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TorSetup = Join-Path $Root 'pkg\tor-setup.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $TorSetup, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Tor setup failed PowerShell parsing' }
$resolverAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-TrustedSystemTarExecutable'
}, $true)
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Expand-BoundedTorExecutable'
}, $true)
if ($null -eq $resolverAst) { throw 'trusted system tar resolver not found' }
if ($null -eq $functionAst) { throw 'bounded Tor extraction function not found' }
Invoke-Expression $resolverAst.Extent.Text
Invoke-Expression $functionAst.Extent.Text

$source = [IO.File]::ReadAllText($TorSetup)
$resolverSource = $resolverAst.Extent.Text
$functionSource = $functionAst.Extent.Text
$torSetupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $TorSetup).Hash.ToLower()
$checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Expect-Rejected([scriptblock]$Action, [string]$Destination,
                         [string]$Description) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Check $rejected ($Description + ' was accepted')
    Check (-not [IO.File]::Exists($Destination)) `
        ($Description + ' left a partial executable')
}

Check ($source -notmatch '&\s+tar\.exe\s+-xzf') `
    'Tor setup retains child-controlled filesystem extraction'
Check ($source -notmatch 'Get-Command\s+tar\.exe' -and
       $functionSource -notmatch 'FileName\s*=\s*[''"]tar\.exe[''"]') `
    'Tor setup still resolves tar.exe through current-directory/PATH search'
foreach ($required in @(
    '[Environment]::SystemDirectory',
    '[Environment+SpecialFolder]::Windows',
    '[IO.FileAttributes]::ReparsePoint',
    "Join-Path `$systemDirectory 'tar.exe'"
)) {
    Check ($resolverSource.Contains($required)) `
        ('trusted Tor extractor resolver missing: ' + $required)
}
Check ($source -match 'TOR_MAX_EXTRACTED_EXE_BYTES\s*=\s*64MB' -and
       $source -match 'TOR_EXTRACT_TIMEOUT_SECONDS') `
    'Tor extraction production ceiling/deadline is missing'
foreach ($required in @(
    '$start.FileName = $trustedExtractor',
    'FileMode]::CreateNew', 'RedirectStandardOutput = $true',
    'StandardOutput.BaseStream.ReadAsync', '$MaximumBytes - $received',
    'WaitForExit($remaining)', '$process.Kill()',
    '[IO.File]::Delete($Destination)'
)) {
    Check ($functionSource.Contains($required)) `
        ('Tor extraction boundary missing: ' + $required)
}
Check ($source -match
       'Expand-BoundedTorExecutable\s+\$systemTar\s+\$tgz\s+\$src[\s\S]*TOR_MAX_EXTRACTED_EXE_BYTES[\s\S]*TOR_EXTRACT_TIMEOUT_SECONDS') `
    'production Tor install does not invoke the bounded extractor'
Check ($source.IndexOf('if ($got -eq $TOR_SHA256)') -lt
       $source.IndexOf('Expand-BoundedTorExecutable $systemTar $tgz')) `
    'Tor archive is expanded before its SHA-256 pin is accepted'
foreach ($launcherName in @('Start Mining.bat', 'Start Validator.bat')) {
    $launcher = [IO.File]::ReadAllText((Join-Path $Root ('pkg\' + $launcherName)))
    Check ($launcher.Contains("`$expected='$torSetupHash'")) `
        ($launcherName + ' does not pin the exact final Tor setup helper')
}

$Tar = Get-TrustedSystemTarExecutable
Check ([IO.Path]::IsPathRooted($Tar) -and
       [IO.Path]::GetDirectoryName($Tar).Equals(
         [IO.Path]::GetFullPath([Environment]::SystemDirectory).TrimEnd('\'),
         [StringComparison]::OrdinalIgnoreCase)) `
    'trusted Tor extractor is not the absolute Windows system tar executable'
$tarItem = Get-Item -LiteralPath $Tar -Force
Check (-not $tarItem.PSIsContainer -and $tarItem.Length -gt 0 -and
       ($tarItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) `
    'trusted Tor extractor is missing, empty, or a reparse point'
$TempRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('veld tor stream ' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($TempRoot) | Out-Null
try {
    $fixture = Join-Path $TempRoot 'fixture'
    $torFolder = Join-Path $fixture 'tor'
    [IO.Directory]::CreateDirectory($torFolder) | Out-Null
    $expected = [byte[]]::new(65536)
    for ($index = 0; $index -lt $expected.Length; $index++) {
        $expected[$index] = [byte]($index % 251)
    }
    [IO.File]::WriteAllBytes((Join-Path $torFolder 'tor.exe'), $expected)
    $archive = Join-Path $TempRoot 'valid bundle.tar.gz'
    & $Tar -czf $archive -C $fixture 'tor/tor.exe'
    Check ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($archive)) `
        'could not create valid Tor archive fixture'

    $valid = Join-Path $TempRoot 'valid-tor.exe'
    Expand-BoundedTorExecutable $Tar $archive $valid $expected.Length 10
    Check ([IO.File]::Exists($valid)) 'valid Tor member was not extracted'
    Check ([IO.FileInfo]::new($valid).Length -eq $expected.Length) `
        'exact-maximum Tor member length changed'
    Check ((Get-FileHash -Algorithm SHA256 -LiteralPath $valid).Hash -ceq
           (Get-FileHash -Algorithm SHA256 -LiteralPath `
              (Join-Path $torFolder 'tor.exe')).Hash) `
        'streamed Tor member bytes changed'

    $oversized = Join-Path $TempRoot 'oversized-tor.exe'
    Expect-Rejected {
        Expand-BoundedTorExecutable $Tar $archive $oversized `
            ($expected.Length - 1) 10
    } $oversized 'one-byte expansion overflow'

    $emptyFixture = Join-Path $TempRoot 'empty-fixture'
    $emptyTor = Join-Path $emptyFixture 'tor'
    [IO.Directory]::CreateDirectory($emptyTor) | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $emptyTor 'tor.exe'), [byte[]]::new(0))
    $emptyArchive = Join-Path $TempRoot 'empty.tar.gz'
    & $Tar -czf $emptyArchive -C $emptyFixture 'tor/tor.exe'
    Check ($LASTEXITCODE -eq 0) 'could not create empty Tor fixture'
    $emptyOutput = Join-Path $TempRoot 'empty-tor.exe'
    Expect-Rejected {
        Expand-BoundedTorExecutable $Tar $emptyArchive $emptyOutput 1024 10
    } $emptyOutput 'empty Tor member'

    $missingFixture = Join-Path $TempRoot 'missing-fixture'
    [IO.Directory]::CreateDirectory($missingFixture) | Out-Null
    [IO.File]::WriteAllText((Join-Path $missingFixture 'other'), 'x')
    $missingArchive = Join-Path $TempRoot 'missing.tar.gz'
    & $Tar -czf $missingArchive -C $missingFixture 'other'
    Check ($LASTEXITCODE -eq 0) 'could not create missing-member fixture'
    $missingOutput = Join-Path $TempRoot 'missing-tor.exe'
    Expect-Rejected {
        Expand-BoundedTorExecutable $Tar $missingArchive $missingOutput 1024 10
    } $missingOutput 'missing Tor member'

    $existing = Join-Path $TempRoot 'existing-tor.exe'
    [IO.File]::WriteAllText($existing, 'preserve')
    $existingRejected = $false
    try { Expand-BoundedTorExecutable $Tar $archive $existing 65536 10 }
    catch { $existingRejected = $true }
    Check $existingRejected 'preexisting extraction destination was accepted'
    Check ([IO.File]::ReadAllText($existing) -ceq 'preserve') `
        'preexisting extraction destination changed'

    # A controlled tar.exe writes a sentinel immediately when executed. Put it
    # in both the process current directory and at the front of PATH, then prove
    # extraction still uses the explicitly validated Windows system binary.
    $fakeFolder = Join-Path $TempRoot 'fake-tar'
    [IO.Directory]::CreateDirectory($fakeFolder) | Out-Null
    $fakeTar = Join-Path $fakeFolder 'tar.exe'
    $fakeSource = @'
#include <cstdlib>
#include <fstream>
int main() {
    const char* sentinel = std::getenv("VELD_FAKE_TAR_SENTINEL");
    if (sentinel != nullptr && sentinel[0] != '\0') {
        std::ofstream(sentinel, std::ios::binary) << "executed";
    }
    return 99;
}
'@
    $fakeCpp = Join-Path $fakeFolder 'fake-tar.cpp'
    [IO.File]::WriteAllText($fakeCpp, $fakeSource,
        [Text.UTF8Encoding]::new($false))
    $compiler = @(
        (Get-Command clang++.exe -ErrorAction SilentlyContinue).Source,
        (Get-Command g++.exe -ErrorAction SilentlyContinue).Source,
        'C:\msys64\clang64\bin\clang++.exe'
    ) | Where-Object { $_ -and [IO.File]::Exists($_) } | Select-Object -First 1
    if (-not $compiler) { throw 'no C++ compiler available for kill fixture' }
    & $compiler -std=c++20 -O2 -static $fakeCpp -o $fakeTar
    Check ($LASTEXITCODE -eq 0 -and [IO.File]::Exists($fakeTar)) `
        'could not build malicious extractor fixture'
    $sentinel = Join-Path $TempRoot 'shadow-executed'
    $env:VELD_FAKE_TAR_SENTINEL = $sentinel
    $previousNativeDirectory = [Environment]::CurrentDirectory
    $previousPath = $env:PATH
    Push-Location $fakeFolder
    [Environment]::CurrentDirectory = $fakeFolder
    $env:PATH = $fakeFolder + [IO.Path]::PathSeparator + $previousPath
    try {
        $shadowOutput = Join-Path $TempRoot 'shadow-safe-tor.exe'
        Expand-BoundedTorExecutable $Tar $archive $shadowOutput 65536 10
        Check ([IO.File]::Exists($shadowOutput) -and
               (Get-FileHash -Algorithm SHA256 -LiteralPath $shadowOutput).Hash -ceq
               (Get-FileHash -Algorithm SHA256 -LiteralPath `
                  (Join-Path $torFolder 'tor.exe')).Hash) `
            'trusted extractor did not produce canonical bytes under shadowing'
    }
    finally {
        $env:PATH = $previousPath
        [Environment]::CurrentDirectory = $previousNativeDirectory
        Pop-Location
        Remove-Item Env:VELD_FAKE_TAR_SENTINEL -ErrorAction SilentlyContinue
    }
    Check (-not [IO.File]::Exists($sentinel)) `
        'same-directory/PATH tar.exe shadow was executed'

    $untrustedOutput = Join-Path $TempRoot 'untrusted-tor.exe'
    Expect-Rejected {
        Expand-BoundedTorExecutable $fakeTar $archive $untrustedOutput 65536 10
    } $untrustedOutput 'explicit non-system Tor extractor'

    Write-Output ('PASS daybreak_tor_stream_extract_tests checks=' + $checks)
}
finally {
    if ([IO.Directory]::Exists($TempRoot)) {
        try { [IO.Directory]::Delete($TempRoot, $true) }
        catch { Write-Warning ('fixture cleanup deferred: ' + $_.Exception.Message) }
    }
}
