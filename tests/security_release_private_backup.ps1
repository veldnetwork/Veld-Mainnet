param(
    [Parameter(Mandatory=$true)][string]$Source,
    [Parameter(Mandatory=$true)][string]$Destination,
    [Parameter(Mandatory=$true)][string]$FixtureRoot
)
$ErrorActionPreference = 'Stop'
function AccessFingerprint($Acl) {
    $rules = @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
        "$($_.IdentityReference.Value)|$([int]$_.AccessControlType)|$([int]$_.FileSystemRights)|$([int]$_.InheritanceFlags)|$([int]$_.PropagationFlags)|$($_.IsInherited)"
    })
    return ($rules -join "`n")
}
$rootPath = (Resolve-Path -LiteralPath $FixtureRoot).ProviderPath.TrimEnd('\') + '\'
$sourcePath = (Resolve-Path -LiteralPath $Source).ProviderPath.TrimEnd('\')
$destinationPath = [IO.Path]::GetFullPath($Destination).TrimEnd('\')
if (!$sourcePath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
    !$destinationPath.StartsWith($rootPath, [StringComparison]::OrdinalIgnoreCase) -or
    $sourcePath -eq $destinationPath -or
    (Test-Path -LiteralPath $destinationPath)) {
    throw 'Backup requires distinct fixture-contained paths and a new destination.'
}
$sourceItem = Get-Item -LiteralPath $sourcePath
if (!$sourceItem.PSIsContainer -or ($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Backup source must be a real directory.'
}
$entries = @(Get-ChildItem -LiteralPath $sourcePath -Recurse -Force)
if (@($entries | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
    throw 'Fixture backup does not follow reparse points.'
}
[IO.Directory]::CreateDirectory($destinationPath) | Out-Null
Set-Acl -LiteralPath $destinationPath -AclObject (Get-Acl -LiteralPath $sourcePath)
foreach ($entry in @(Get-ChildItem -LiteralPath $sourcePath -Force)) {
    Copy-Item -LiteralPath $entry.FullName -Destination $destinationPath -Recurse
}
foreach ($entry in $entries) {
    $relative = $entry.FullName.Substring($sourcePath.Length).TrimStart('\')
    $targetPath = Join-Path $destinationPath $relative
    Set-Acl -LiteralPath $targetPath -AclObject (Get-Acl -LiteralPath $entry.FullName)
    $sourceAcl = Get-Acl -LiteralPath $entry.FullName
    $targetAcl = Get-Acl -LiteralPath $targetPath
    # Windows may add the auto-inheritance bookkeeping bit during Set-Acl.
    # Verify the actual owner, group, protection and every ACE instead.
    if ($sourceAcl.Owner -ne $targetAcl.Owner -or $sourceAcl.Group -ne $targetAcl.Group -or
        $sourceAcl.AreAccessRulesProtected -ne $targetAcl.AreAccessRulesProtected -or
        (AccessFingerprint $sourceAcl) -ne (AccessFingerprint $targetAcl)) {
        throw "Backup ACL mismatch: $relative"
    }
}
Write-Output "PASS private backup: $($entries.Count) entries with matching ACLs"
