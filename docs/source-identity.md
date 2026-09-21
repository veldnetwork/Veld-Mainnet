# Source and release identity

## Identify a checkout

`main` contains ongoing maintenance. Release tags and branches identify source;
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

## Veld 3.2.2

Binary-build commit: `1f77a67365ff9c3c36dae2a624feb35615446202`.
Binary-build tree: `97898f972e3a6eb0cce2caf86475afa5e4988bc6`.
The [corresponding source archive](https://veld.network/downloads/Veld-3.2.2-source.tar.gz)
preserves that exact build input. The public release tag also contains this
documentation and hosted presentation follow-up and must not be called the binary-build commit.

Windows GUI ZIP SHA-256:
`69d050d03c7a3ea9ef5823593b5cb0f8fbc24b59c251427e3f5167dc9ac21ffc`.
Signed package manifest SHA-256:
`cdd11c0329b37faf643d5ac19bc000f66104c842756e6c220ac72520c935be89`.
Verify detached signatures as well as hashes. The signed release identity
retains its preparation-time state; subsequent runtime checks are documented
separately in [qualification scope](release-3.2.2-qualification.md).

## Veld 3.2.1

The signed production binaries use commit `1c693db24de71e71bc45b26958da03340d847f5c`
and tree `9fb5c2ea6824a661c5d36cee2eae8ddbea798426`.
The [corresponding source archive](https://veld.network/downloads/Veld-3.2.1-source.tar.gz)
contains that exact binary-build tree. The release source tag includes later
web and documentation corrections; it is not falsely identified as the binary
build input. Those later changes do not modify the signed Windows package.

GUI ZIP SHA-256: `5593cf53016edd9cff16e86639aed2ba567769d9a11861267ff80e58d22b7c7c`.
Verify the [signed release identity](https://veld.network/downloads/RELEASE-IDENTITY-3.2.1.json),
package manifest, ZIP checksum and their detached signatures.
The identity's preparation-time qualification state is retained; subsequent
runtime evidence is listed separately in the release qualification document.

Activation is block **9,500**. Stale 6,200 and unpublished 9,000 proposals are
superseded. Existing history retains its original rules.

## Veld 3.1.8

The `v3.1.8` tag identifies the mining timestamp and near-miss reliability
release. Its [signed release identity](https://veld.network/downloads/RELEASE-IDENTITY-3.1.8.json)
binds the source commit and tree to the package hashes. The
[source archive](https://veld.network/downloads/Veld-3.1.8-source.tar.gz)
is generated from that commit. Verify the detached release-assets signature
and package manifest before installing the client.

## Veld 3.1.7

The `v3.1.7` tag identifies the consolidated reliability source. The
[release identity record](https://veld.network/downloads/RELEASE-IDENTITY-3.1.7.json)
binds its exact commit and tree to the distributed package hashes. The
[corresponding source archive](https://veld.network/downloads/Veld-3.1.7-source.tar.gz)
is generated from that commit. Verify the detached release manifest signature
and individual payload hashes before installing downloaded artifacts.

## Veld 3.1.6

The `v3.1.6` tag identifies the source used for the distributed Windows client
and Linux fleet build. The [release identity record](https://veld.network/downloads/RELEASE-IDENTITY-3.1.6.json)
binds that source to the signed packages. Documentation and hosted web changes
on `main` do not replace the tagged source or existing signed binaries.

| Field | Value |
| --- | --- |
| Source commit | `1ddcb449c651748463a4f066c4d5fec6e5e1a623` |
| Source tree | `ea76d61d2439a312fd9ea1317645fe6bb39b9634` |
| Windows GUI ZIP SHA-256 | `01fe6745793a07190b899750638f3b148a946accdf4614728502ea6c85fe4b51` |
| Windows terminal ZIP SHA-256 | `4760d5ce8ceda6a35a5eebe21cd31e6eff6fcfa2dfbe2ccd72bbc5f6b823502e` |

The [source archive](https://veld.network/downloads/Veld-3.1.6-source.tar.gz)
is published with the package checksums and detached Veld signatures.

## Veld 3.1.1

The `v3.1.1` release tag and
[release identity record](https://veld.network/downloads/RELEASE-IDENTITY-3.1.1.json)
identify the checkpoint update. The record binds the source commit and tree to
the distributed artifacts. The
[corresponding source archive](https://veld.network/downloads/Veld-3.1.1-source.tar.gz)
is published beside the signed package. The release was qualified and
published on 8 September 2026. Later documentation changes on `main` do not
change the tagged source or signed artifacts.

| Field | Value |
| --- | --- |
| Source commit | `8cfb6595c1fc0ad67d0e50ca2050423a2e513505` |
| Source tree | `3478d00949dc3790de213fda26c5ad9543529f31` |
| Windows ZIP SHA-256 | `2b70f2891dcee5d2eaa960671bc5c596cc85611b30667bbcbc7bc8e9ebeeab26` |

## Veld 3.1.0

The `v3.1.0` tag pins the source used for the Windows client and fleet build.
Release-status documentation on `main` was updated after publication; it does
not change the tagged source or signed binaries.

| Field | Value |
| --- | --- |
| Source commit | `26b8aad93144fd7387c566882186f8d7d295ca69` |
| Source tree | `4af87d9294f87f91e4858855995133ebaeea48bd` |
| Windows ZIP SHA-256 | `0368590531009a29b6dc7ac68b755d3033459687ea04d53022107493ffa6be87` |

The [corresponding source archive](https://veld.network/downloads/Veld-3.1.0-source.tar.gz)
and [release identity](https://veld.network/downloads/RELEASE-IDENTITY-3.1.0.json)
are published beside the signed client. The package contains its payload
manifest and Veld release signature. These signatures are separate from
Windows Authenticode.

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
