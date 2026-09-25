# Verify a Veld release

A release has three distinct identities: its tagged source, the source used
for its binary build, and the actual downloaded package. Check all three;
a green development-branch check is not a signature on a downloaded binary.

## Establish the verifier's trust

Use a previously verified Veld node or a verifier built from independently
reviewed, pinned source. Do not use the executable inside a newly downloaded,
unverified package as the sole verifier of that same package.

The release key is in [release_pubkey.h](../include/crypto/release_pubkey.h).
For the 3.2.7 source, the SHA-256 fingerprint of its decoded 1,952-byte public
key is:

```text
d08731f74b27b61ecbecd54785adbbf918732b06af39978b4b88894821a8771d
```

Confirm the trust anchor independently before first installation. Publishing
a key beside a package does not independently establish the publisher's identity.
The release key and snapshot key are different trust anchors.

## Authenticate the records

Open the [versioned 3.2.7 release](https://github.com/veldnetwork/Veld-Mainnet/releases/tag/v3.2.7).
Download `RELEASE-IDENTITY-3.2.7.json`, `RELEASE-ASSETS-SHA256.txt`, their `.sig`
files, and the intended package and its corresponding checksum records. Keep
GUI and terminal packages in separate directories; do not interchange their
manifests or mix files from different releases.

Veld uses raw ML-DSA-65 signatures over the double-SHA-256 payload digest,
not OpenPGP signatures. The existing node command verifies this format against
its compiled release key and exits before normal node startup.

On Linux, replace the verifier path with your independently trusted executable:

```sh
set -eu
VERIFIER=/absolute/path/to/trusted/veld-node
"$VERIFIER" --verify-release RELEASE-IDENTITY-3.2.7.json RELEASE-IDENTITY-3.2.7.json.sig
"$VERIFIER" --verify-release RELEASE-ASSETS-SHA256.txt RELEASE-ASSETS-SHA256.txt.sig
```

On Windows, use PowerShell and explicitly check each native exit code:

```powershell
$ErrorActionPreference = 'Stop'
$Verifier = 'C:\Path\To\Trusted\bin\veld-node.exe'
$Records = @('RELEASE-IDENTITY-3.2.7.json', 'RELEASE-ASSETS-SHA256.txt')
foreach ($Record in $Records) {
    & $Verifier --verify-release $Record ($Record + '.sig')
    if ($LASTEXITCODE -ne 0) {
        throw "Release signature verification failed: $Record"
    }
}
```

Require exit code zero and `RELEASE-SIGNATURE-VALID`. A missing record, unreadable
file, invalid signature, unexpected release identity, or failed hash check is
a stop condition, not a warning to bypass. Do not edit signed records to fix
line endings or formatting before verification.

## Check the payload and its source

After authenticating the asset checksum record, compute the downloaded archive's
SHA-256 and compare it with that archive's exact entry. For example, PowerShell's
`Get-FileHash -Algorithm SHA256 -LiteralPath .\downloaded-package.zip` computes a
hash; the command alone does not establish that it matches a trusted value.

On Linux, after downloading every file named in the authenticated record:

```sh
sha256sum --check --strict RELEASE-ASSETS-SHA256.txt
```

Do not use an ignore-missing option and interpret the result as verification of
all assets. For a selected package, explicitly verify that package's entry and
report the limited scope. Before running a package, authenticate its internal
`SHA256SUMS.txt.sig` with the trusted verifier, check every named payload hash,
and enforce the package's membership rules. The existing launchers and updater
perform package validation; do not remove or disable those checks.

Read the authenticated release identity and compare its declared version,
source commit/tree, and package identities with the intended release. Verify
any source archive against that exact Git tree, including file membership and
executable modes. See [source identity](source-identity.md) and
[build instructions](../BUILDING.md). Hash equality establishes byte identity;
a successful build under a different toolchain is not a claim of reproducibility.

## Record the result accurately

Keep the verified release version, source identity, package hashes, verifier
trust basis, commands, exit codes, platform, and test results. Distinguish
signature/hash verification from operating-system signature checks, interactive
Windows testing, network health, and custody qualification. Neither a valid
release signature nor passing CI is a comprehensive security certification.
