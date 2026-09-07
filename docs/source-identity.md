# Source and release identity

## Identify a checkout

`main` contains ongoing maintenance. Release branches describe release source;
signed package manifests identify the binaries actually distributed. These
identities are related but are not interchangeable.

Record the commit, tree, and working-tree status before building:

```sh
git rev-parse HEAD
git rev-parse HEAD^{tree}
git status --short
python3 scripts/verify-pqc-provenance.py
```

The [production controllers](../BUILDING.md) require a clean checkout, record
the commit and tree, and check source identity again after linking. Archive
builds require explicit source commit and tree values. Check those values
against the corresponding Git objects; declaring a value does not prove the
archive matches it.

Verify downloaded binaries using the official package manifest and signature.
Building from source does not grant the official release signature. Different
toolchains or paths can produce different binary hashes.

## Network identity

The public network is `veld-public-mainnet-v2`, using protocol version `2` and
state digest schema `VELD_STATE_DIGEST_v8`. Its compiled genesis fingerprint is:

```text
880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b
```

Definitions are in [network identity](../include/network/network_identity.h),
[constants](../include/core/constants.h), and [version](../include/core/version.h).
Client release numbers do not replace these chain identifiers.

## Historical mainnet launch

The 3.0.0 BUILD-02 launch record identifies:

| Field | Value |
| --- | --- |
| Release ID | `VELD-3.0.0-BUILD-02-03388b12-c540616f` |
| Launch source commit | `03388b12f8125ac0f321984730a9906064f48f62` |
| Launch source tree | `c540616f288fe38fffa1ce061598425b6e53fcbc` |
| Combined build digest | `7dcf10fa5d879e383c32693665265f9e8fcbcd90ca6540c7a31cae29b7536612` |

The original publication manifest and launch-equivalence records describe
that historical release. They do not describe the current maintenance tree.
Their unchanged records remain in the
[original public launch commit](https://github.com/veldnetwork/Veld-Mainnet/tree/138c919f5ec817a9e6cdc8750750e6bf7b08698f),
including its
[source identity](https://github.com/veldnetwork/Veld-Mainnet/blob/138c919f5ec817a9e6cdc8750750e6bf7b08698f/SOURCE_IDENTITY.md)
and [file manifest](https://github.com/veldnetwork/Veld-Mainnet/blob/138c919f5ec817a9e6cdc8750750e6bf7b08698f/PUBLICATION_SOURCE_MANIFEST.tsv).
