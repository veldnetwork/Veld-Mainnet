# Veld

Veld is a CPU-mined blockchain with a maximum supply of 21 million VELD,
staking, ML-DSA-65 transaction signatures, and a bonded validator finality
layer. This repository contains the node, wallet, validator, mining portal,
and public web applications for `veld-public-mainnet-v2`.

[Website and downloads](https://veld.network/) ·
[Explorer](https://explorer.veld.network/) ·
[Wallet](https://wallet.veld.network/) ·
[Portal](https://portal.veld.network/)

## Getting started

- **Run a client:** download the signed Windows package from
  [veld.network](https://veld.network/), extract it, and open
  `Start Veld Node.bat`. See the [operator guide](docs/operations/README.md).
- **Build from source:** follow [BUILDING.md](BUILDING.md).
- **Explore the implementation:** start with the
  [architecture guide](docs/architecture.md) and [documentation index](docs/README.md).
- **Contribute:** read [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [test guide](tests/README.md). Report vulnerabilities through
  [SECURITY.md](SECURITY.md).

## Releases and network identity

**3.1.8** keeps mining timestamps current on slow workers and permits retries
after unsuccessful near-miss submissions. It includes the connection and
updater reliability fixes, preserves saved settings and chain data, and removes
the separate update-repair launcher. See the [release notes](docs/release-notes.md)
and [download the signed client](https://veld.network/#download).

The stake minimum is **500 VELD**. Co-mining eligibility requires **1,000 VELD**
staked under the mining address; validator registration uses a separate bond.
The existing mainnet consensus rules and checkpoint authority are unchanged.

The [`v3.1.8` tag](https://github.com/veldnetwork/Veld-Mainnet/tree/v3.1.8)
identifies the published release source. Signed package manifests identify
the distributed binaries. `main` may contain later maintenance and documentation updates. [CHANGELOG.md](CHANGELOG.md)
distinguishes hosted updates from packaged changes.

| Property | Value |
| --- | --- |
| Network | `veld-public-mainnet-v2` |
| Protocol version | `2` |
| Proof of work | VeldHash, CPU mining |
| Maximum supply | 21,000,000 VELD |
| State digest schema | `VELD_STATE_DIGEST_v8` |
| Genesis fingerprint | `880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b` |

The [source identity guide](docs/source-identity.md) explains how to identify a
checkout, verify release inputs, and inspect the original mainnet launch record.

## Source layout

| Directory | Contents |
| --- | --- |
| [src/](src/) | Node, wallet, Windows launcher, validator, key utility, and portal entry points |
| [include/](include/) | Consensus, chainstate, networking, mining, wallet, and platform modules |
| [tests/](tests/) | Unit tests, process tests, web checks, and deterministic fixtures |
| [build/](build/) | Linux and Windows production build controllers |
| [scripts/](scripts/) | Dependency verification, WASM tooling, and topology collection |
| [pkg/](pkg/) | Client launchers, updater, web overlays, and reverse-proxy configuration |
| [resources/](resources/) | Application icons and Windows resource files |
| [website/](website/) | Homepage, hosted Explorer pages, display scripts, and service workers |
| [docs/](docs/) | Developer, operator, release, and security documentation |
| [vendor/](vendor/) | Pinned third-party cryptography and provenance records |

## Security and licensing

Review the [security model](docs/security/threat-model.md) before operating a
node or integrating btcVELD. Signed packages authenticate a release; they do
not constitute a security certification.

Veld-authored source is licensed under [AGPL-3.0-only](LICENSE). Dependencies
retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Branding is covered separately by [TRADEMARKS.md](TRADEMARKS.md).
