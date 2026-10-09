$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression

$Root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Updater = Join-Path $Root 'pkg\veld-update.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $Updater, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'updater failed PowerShell parsing' }
$functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Expand-BoundedReleaseArchive'
}, $true)
if ($null -eq $functionAst) { throw 'bounded archive function not found' }
Invoke-Expression $functionAst.Extent.Text
$canonicalAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-CanonicalDirectoryPath'
}, $true)
if ($null -eq $canonicalAst) { throw 'canonical directory function not found' }
Invoke-Expression $canonicalAst.Extent.Text
$mapAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-ReleaseFileMap'
}, $true)
if ($null -eq $mapAst) { throw 'release file map function not found' }
Invoke-Expression $mapAst.Extent.Text
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class UpdaterShortPathFixture {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern uint GetShortPathName(string path, StringBuilder result, uint capacity);
}
'@

$MaxReleaseArchiveEntries = 4
$MaxReleaseEntryBytes = 8
$MaxReleaseExpandedBytes = 12
$checks = 0
function Check([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}

function New-FixtureZip([string]$Path, [array]$Entries) {
    $stream = [IO.FileStream]::new(
        $Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None)
    $zip = $null
    try {
        $zip = [IO.Compression.ZipArchive]::new(
            $stream, [IO.Compression.ZipArchiveMode]::Create, $false)
        foreach ($item in $Entries) {
            $entry = $zip.CreateEntry([string]$item.Name)
            if ($null -ne $item.ExternalAttributes) {
                $entry.ExternalAttributes = [int]$item.ExternalAttributes
            }
            if ($null -ne $item.Body) {
                $entryStream = $entry.Open()
                try {
                    $bytes = [Text.Encoding]::UTF8.GetBytes([string]$item.Body)
                    $entryStream.Write($bytes, 0, $bytes.Length)
                } finally {
                    $entryStream.Dispose()
                }
            }
        }
    } finally {
        if ($null -ne $zip) { $zip.Dispose() }
        $stream.Dispose()
    }
}

function Expect-Rejected([string]$Archive, [string]$Stage,
                         [string]$Description) {
    $rejected = $false
    try {
        Expand-BoundedReleaseArchive $Archive $Stage
    } catch {
        $rejected = $true
    }
    Check $rejected ($Description + ' was accepted')
    Check (-not [IO.Directory]::Exists($Stage)) `
        ($Description + ' left a partial extraction tree')
}

$TempRoot = Join-Path ([IO.Path]::GetTempPath()) `
    ('veld-updater-archive-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($TempRoot) | Out-Null
try {
    $valid = Join-Path $TempRoot 'valid.zip'
    New-FixtureZip $valid @(
        [pscustomobject]@{Name='a.txt'; Body='12345678'; ExternalAttributes=$null},
        [pscustomobject]@{Name='dir/'; Body=$null; ExternalAttributes=$null},
        [pscustomobject]@{Name='dir/b.txt'; Body='1234'; ExternalAttributes=$null}
    )
    $validStage = Join-Path $TempRoot 'valid-stage'
    Expand-BoundedReleaseArchive $valid $validStage
    Check ([IO.File]::ReadAllText((Join-Path $validStage 'a.txt')) -ceq '12345678') `
        'exact per-entry maximum changed'
    Check ([IO.File]::ReadAllText((Join-Path $validStage 'dir\b.txt')) -ceq '1234') `
        'exact total maximum changed'
    Check ((Get-ChildItem -LiteralPath $validStage -File -Recurse).Count -eq 2) `
        'valid archive file set changed'
    $shortBuffer = [Text.StringBuilder]::new(32768)
    Check ([UpdaterShortPathFixture]::GetShortPathName($validStage, $shortBuffer, 32768) -gt 0) `
        'short-path lookup failed'
    $shortStage = $shortBuffer.ToString()
    $canonicalStage = Get-CanonicalDirectoryPath $shortStage
    $relativeNames = @(Get-ChildItem -LiteralPath $canonicalStage -File -Recurse | ForEach-Object {
        $_.FullName.Substring($canonicalStage.Length).TrimStart('\').Replace('\','/')
    })
    Check ($relativeNames.Count -eq 2 -and $relativeNames -contains 'a.txt' -and
        $relativeNames -contains 'dir/b.txt') 'short temporary path changed package membership'
    if ($shortStage -cne $canonicalStage) {
        $legacyNames = @(Get-ChildItem -LiteralPath $shortStage -File -Recurse | ForEach-Object {
            $_.FullName.Substring($shortStage.Length).TrimStart('\').Replace('\','/')
        })
        Check ($legacyNames -notcontains 'a.txt') 'legacy short-path refusal was not reproduced'
        Write-Output 'PASS real Windows short-path package membership regression'
    } else { Write-Output 'Short alias unavailable on this filesystem; canonical membership passed' }
    $shortFiles = Get-ReleaseFileMap $shortStage
    Check ($shortFiles.Count -eq 2 -and $shortFiles.ContainsKey('a.txt') -and
        $shortFiles.ContainsKey('dir/b.txt')) 'file map changed short-path membership'
    $longFiles = Get-ReleaseFileMap ($canonicalStage + '\')
    Check ($longFiles.Count -eq 2 -and $longFiles['a.txt'] -ceq $shortFiles['a.txt']) `
        'trailing separator changed package membership'
    [IO.File]::WriteAllText((Join-Path $canonicalStage 'SHA256SUMS.txt'), 'fixture metadata')
    [IO.File]::WriteAllText((Join-Path $canonicalStage 'SHA256SUMS.txt.sig'), 'fixture signature')
    Check ((Get-ReleaseFileMap $shortStage).Count -eq 2) 'root metadata counted as payload'
    $hidden = Join-Path $canonicalStage 'hidden.txt'
    [IO.File]::WriteAllText($hidden, 'not in manifest')
    [IO.File]::SetAttributes($hidden, [IO.FileAttributes]::Hidden)
    $withHidden = Get-ReleaseFileMap $shortStage
    Check ($withHidden.Count -eq 3 -and $withHidden.ContainsKey('hidden.txt')) `
        'hidden extra payload escaped exact file-set verification'

    $traversal = Join-Path $TempRoot 'traversal.zip'
    New-FixtureZip $traversal @(
        [pscustomobject]@{Name='../escape'; Body='x'; ExternalAttributes=$null})
    Expect-Rejected $traversal (Join-Path $TempRoot 'traversal-stage') 'traversal entry'
    Check (-not [IO.File]::Exists((Join-Path $TempRoot 'escape'))) `
        'traversal wrote outside stage'

    $duplicate = Join-Path $TempRoot 'duplicate.zip'
    New-FixtureZip $duplicate @(
        [pscustomobject]@{Name='File.txt'; Body='a'; ExternalAttributes=$null},
        [pscustomobject]@{Name='file.txt'; Body='b'; ExternalAttributes=$null})
    Expect-Rejected $duplicate (Join-Path $TempRoot 'duplicate-stage') 'case-fold duplicate'

    $entryBomb = Join-Path $TempRoot 'entry-bomb.zip'
    New-FixtureZip $entryBomb @(
        [pscustomobject]@{Name='large'; Body='123456789'; ExternalAttributes=$null})
    Expect-Rejected $entryBomb (Join-Path $TempRoot 'entry-bomb-stage') 'oversized entry'

    $totalBomb = Join-Path $TempRoot 'total-bomb.zip'
    New-FixtureZip $totalBomb @(
        [pscustomobject]@{Name='one'; Body='1234567'; ExternalAttributes=$null},
        [pscustomobject]@{Name='two'; Body='123456'; ExternalAttributes=$null})
    Expect-Rejected $totalBomb (Join-Path $TempRoot 'total-bomb-stage') 'total expansion'

    $many = Join-Path $TempRoot 'many.zip'
    New-FixtureZip $many @(
        [pscustomobject]@{Name='1'; Body=''; ExternalAttributes=$null},
        [pscustomobject]@{Name='2'; Body=''; ExternalAttributes=$null},
        [pscustomobject]@{Name='3'; Body=''; ExternalAttributes=$null},
        [pscustomobject]@{Name='4'; Body=''; ExternalAttributes=$null},
        [pscustomobject]@{Name='5'; Body=''; ExternalAttributes=$null})
    Expect-Rejected $many (Join-Path $TempRoot 'many-stage') 'entry-count overflow'

    $symlink = Join-Path $TempRoot 'symlink.zip'
    New-FixtureZip $symlink @(
        [pscustomobject]@{
            Name='link'; Body='target';
            ExternalAttributes=[int](0xA1FF0000)
        })
    Expect-Rejected $symlink (Join-Path $TempRoot 'symlink-stage') 'symlink entry'

    $empty = Join-Path $TempRoot 'empty.zip'
    New-FixtureZip $empty @()
    Expect-Rejected $empty (Join-Path $TempRoot 'empty-stage') 'empty archive'

    $malformed = Join-Path $TempRoot 'malformed.zip'
    [IO.File]::WriteAllBytes($malformed, [byte[]](1,2,3,4,5))
    Expect-Rejected $malformed (Join-Path $TempRoot 'malformed-stage') 'malformed archive'

    $existingStage = Join-Path $TempRoot 'existing-stage'
    [IO.Directory]::CreateDirectory($existingStage) | Out-Null
    [IO.File]::WriteAllText((Join-Path $existingStage 'sentinel'), 'preserve')
    $existingRejected = $false
    try { Expand-BoundedReleaseArchive $valid $existingStage }
    catch { $existingRejected = $true }
    Check $existingRejected 'preexisting archive destination was accepted'
    Check ([IO.File]::ReadAllText((Join-Path $existingStage 'sentinel')) -ceq 'preserve') `
        'preexisting archive destination changed'

    Write-Output ('PASS updater_archive_tests checks=' + $checks)
} finally {
    if ([IO.Directory]::Exists($TempRoot)) {
        try { [IO.Directory]::Delete($TempRoot, $true) }
        catch { Write-Warning ('fixture cleanup deferred: ' + $_.Exception.Message) }
    }
}
