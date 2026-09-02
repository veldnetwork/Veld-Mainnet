$ErrorActionPreference = 'Stop'

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Updater = Join-Path $Root 'pkg\veld-update.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $Updater, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'updater failed PowerShell parsing' }

$functionNames = @(
    'Read-CanonicalLines', 'Read-Manifest', 'Read-ReleaseVersion',
    'Read-ZipChecksum'
)
foreach ($name in $functionNames) {
    $functionAst = $ast.Find({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $name
    }, $true)
    if ($null -eq $functionAst) { throw ('updater function not found: ' + $name) }
    Invoke-Expression $functionAst.Extent.Text
}

$canonicalAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-CanonicalLines'
}, $true).Extent.Text
$manifestAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-Manifest'
}, $true).Extent.Text
$versionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-ReleaseVersion'
}, $true).Extent.Text
$checksumAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Read-ZipChecksum'
}, $true).Extent.Text

$MaxManifestDownloadBytes = 8MB
$MaxChecksumDownloadBytes = 16KB
$RemoteZipName = 'VeldClient-Windows-x64.zip'
$Utf8 = [Text.UTF8Encoding]::new($false, $true)
$checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
function Expect-Rejected([scriptblock]$Action, [string]$Description) {
    $rejected = $false
    try { & $Action } catch { $rejected = $true }
    Check $rejected ($Description + ' was accepted')
}
function Write-Utf8([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, $Utf8)
}

Check ($canonicalAst -notmatch 'ReadAllBytes|ReadAllText|GetString|\.Split\(') `
    'canonical metadata reader retains a complete raw/text duplicate'
Check ($canonicalAst -match '\$stream\.Length' -and
       $canonicalAst -match '\$MaximumBytes' -and
       $canonicalAst -match 'StreamReader') `
    'canonical metadata reader lacks pre-decode byte ceiling or streaming decode'
Check ($manifestAst -match 'MaxManifestDownloadBytes' -and
       $versionAst -match 'MaxManifestDownloadBytes') `
    'manifest readers are not bound to the 8 MiB route ceiling'
Check ($checksumAst -match 'MaxChecksumDownloadBytes') `
    'checksum reader is not bound to the 16 KiB route ceiling'

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('veld-updater-metadata-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($TempRoot) | Out-Null
try {
    $manifest = Join-Path $TempRoot 'MANIFEST.tsv'
    $manifestText = "# veld-release-manifest-v1`n" +
        "# release-version=3.0.0`n" +
        (('a' * 64) + " *bin/veld-node.exe`n")
    Write-Utf8 $manifest $manifestText
    $manifestLength = [uint64]([IO.FileInfo]::new($manifest).Length)

    $lines = @(Read-CanonicalLines $manifest 'signed manifest' $manifestLength)
    Check ($lines.Count -eq 3) 'exact-ceiling metadata line count changed'
    Check ($lines[0] -ceq '# veld-release-manifest-v1') `
        'exact-ceiling metadata first line changed'
    Expect-Rejected {
        Read-CanonicalLines $manifest 'signed manifest' ($manifestLength - 1)
    } 'metadata one byte over ceiling'

    $files = Read-Manifest $manifest
    Check ($files.Count -eq 1 -and
           $files['bin/veld-node.exe'] -ceq ('a' * 64)) `
        'valid manifest did not parse'
    $version = Read-ReleaseVersion $manifest
    Check ($version.Text -ceq '3.0.0' -and $version.Major -eq 3) `
        'valid release version did not parse'

    $checksum = Join-Path $TempRoot 'VeldClient-Windows-x64.zip.sha256'
    $checksumText = "# veld-release-zip-v1`n" +
        "# release-version=3.0.0`n" +
        (('b' * 64) + " *$RemoteZipName`n")
    Write-Utf8 $checksum $checksumText
    Check ((Read-ZipChecksum $checksum '3.0.0') -ceq ('b' * 64)) `
        'valid checksum metadata did not parse'

    $crlf = Join-Path $TempRoot 'crlf.txt'
    [IO.File]::WriteAllBytes($crlf, $Utf8.GetBytes("a`r`n"))
    Expect-Rejected { Read-CanonicalLines $crlf 'fixture' 16 } `
        'CRLF metadata'

    $unterminated = Join-Path $TempRoot 'unterminated.txt'
    [IO.File]::WriteAllBytes($unterminated, $Utf8.GetBytes('a'))
    Expect-Rejected { Read-CanonicalLines $unterminated 'fixture' 16 } `
        'unterminated metadata'

    $invalidUtf8 = Join-Path $TempRoot 'invalid-utf8.txt'
    [IO.File]::WriteAllBytes($invalidUtf8, [byte[]](0xC3, 0x28, 0x0A))
    Expect-Rejected { Read-CanonicalLines $invalidUtf8 'fixture' 16 } `
        'invalid UTF-8 metadata'

    $empty = Join-Path $TempRoot 'empty.txt'
    [IO.File]::WriteAllBytes($empty, [byte[]]::new(0))
    Expect-Rejected { Read-CanonicalLines $empty 'fixture' 16 } `
        'empty metadata'

    Write-Output ('PASS daybreak_updater_metadata_boundary_tests checks=' +
        $checks)
}
finally {
    if ([IO.Directory]::Exists($TempRoot)) {
        [IO.Directory]::Delete($TempRoot, $true)
    }
}
