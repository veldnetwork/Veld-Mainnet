param(
    [Parameter(Mandatory = $true)]
    [string]$Node
)

$ErrorActionPreference = 'Stop'

$nodePath = (Resolve-Path -LiteralPath $Node).Path
$tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$testRoot = Join-Path $tempRoot (
    'veld-keyfile-migration-' + [guid]::NewGuid().ToString('N'))
$process = $null
$previousPassphrase = $env:VELD_VAULT_PASSPHRASE

try {
    New-Item -ItemType Directory -Path $testRoot | Out-Null
    $resolvedTestRoot = (Resolve-Path -LiteralPath $testRoot).Path
    if (-not $resolvedTestRoot.StartsWith(
            $tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing an unsafe test path: $resolvedTestRoot"
    }

    $env:VELD_VAULT_PASSPHRASE = (
        'Local-Interop-Test-' + [guid]::NewGuid().ToString('N') + '!7a')
    $createOutput = & $nodePath --create-miner-key --datadir $resolvedTestRoot 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "The node could not create the initial key bundle: $createOutput"
    }

    $minerPath = Join-Path $resolvedTestRoot 'miner.key'
    $portable = @(Get-ChildItem -LiteralPath $resolvedTestRoot `
        -Filter '*.veld-keys' -File)
    if (-not (Test-Path -LiteralPath $minerPath) -or $portable.Count -ne 1) {
        throw 'Initial key bundle did not contain exactly one portable keyfile.'
    }
    $minerHash = (Get-FileHash -Algorithm SHA256 `
        -LiteralPath $minerPath).Hash
    if ((Get-FileHash -Algorithm SHA256 `
            -LiteralPath $portable[0].FullName).Hash -ne $minerHash) {
        throw 'Initial miner.key and portable keyfile bytes differ.'
    }

    Move-Item -LiteralPath $portable[0].FullName `
        -Destination ($portable[0].FullName + '.legacy-test-backup')

    $stdoutPath = Join-Path $resolvedTestRoot 'node.stdout.log'
    $stderrPath = Join-Path $resolvedTestRoot 'node.stderr.log'
    $process = Start-Process -FilePath $nodePath -PassThru `
        -WindowStyle Hidden `
        -ArgumentList @('--datadir', $resolvedTestRoot, '--mine', '--no-prompt') `
        -RedirectStandardOutput $stdoutPath `
        -RedirectStandardError $stderrPath

    $deadline = [DateTime]::UtcNow.AddSeconds(35)
    $migrated = $null
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Milliseconds 250
        $candidate = @(Get-ChildItem -LiteralPath $resolvedTestRoot `
            -Filter '*.veld-keys' -File -ErrorAction SilentlyContinue)
        if ($candidate.Count -eq 1) {
            $migrated = $candidate[0]
            break
        }
        if ($process.HasExited) {
            break
        }
    }

    if ($null -eq $migrated) {
        $details = @(
            Get-Content -LiteralPath $stdoutPath -ErrorAction SilentlyContinue
            Get-Content -LiteralPath $stderrPath -ErrorAction SilentlyContinue
        ) -join "`n"
        throw "Legacy sign-in did not publish a portable keyfile.`n$details"
    }
    if ((Get-FileHash -Algorithm SHA256 `
            -LiteralPath $migrated.FullName).Hash -ne $minerHash) {
        throw 'Migrated portable keyfile bytes differ from miner.key.'
    }
    if (@(Get-ChildItem -LiteralPath $resolvedTestRoot `
            -Filter '*.veld-keys' -File).Count -ne 1) {
        throw 'Legacy sign-in generated more than one portable keyfile.'
    }

    Write-Output 'PASS windows_node_keyfile_migration_process_tests checks=5'
} finally {
    if ($null -ne $process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    $env:VELD_VAULT_PASSPHRASE = $previousPassphrase
    if (Test-Path -LiteralPath $testRoot) {
        $resolvedCleanup = (Resolve-Path -LiteralPath $testRoot).Path
        if (-not $resolvedCleanup.StartsWith(
                $tempRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            -not ([System.IO.Path]::GetFileName($resolvedCleanup)).StartsWith(
                'veld-keyfile-migration-',
                [System.StringComparison]::Ordinal)) {
            throw "Refusing an unsafe cleanup path: $resolvedCleanup"
        }
        [System.IO.Directory]::Delete($resolvedCleanup, $true)
    }
}
