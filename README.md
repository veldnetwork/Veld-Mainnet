# Veld

Veld is a CPU-mined blockchain with a maximum supply of 21 million VELD,
staking, ML-DSA-65 transaction signatures, and a bonded validator finality
layer. This repository contains the node, wallet, validator, mining portal,
and public web applications for `veld-public-mainnet-v2`.

[Website and downloads](https://veld.network/) ·
[Explorer](https://explorer.veld.network/) ·
[Wallet](https://wallet.veld.network/) ·
[Portal](https://portal.veld.network/) ·
[Pool](https://pool.veld.network/)

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

**Veld Node 3.2.1 is published. Update before block 9,500.**

The Windows client includes Pool and Solo modes, CPU controls, private pool
account viewing, improved window/scroll recovery, and signed automatic updates.
Use [pool.veld.network](https://pool.veld.network/) with your own payout address.
Pool members never provide private keys or a personal stake.

At block **9,500**, the release enables opt-in SHA-384 key destinations, removes
the aggregate ordinary-stake prerequisite for validator registration, and uses
a flat **0.30%** AMM swap fee in both directions. Historical validation remains
unchanged. The validator's own **10,000 VELD bond**, individual eligibility,
governance, finality, and seven-validator btcVELD requirements remain separate.

Ordinary staking starts at **500 VELD**. Co-mining still requires **1,000 VELD**
staked by the participating economic identity. The public pool is not yet
participating in mainnet co-mining; its separately funded identity is required.
Pool lottery winnings and ordinary staking yield are shared when earned.

Automatic updates are opt-in and check hourly while the app is open. Preserve
wallet backups, chain data, worker accounts and signing journals. Selected
testers already using a different signed 3.2.1 package must install the final
package manually; equal-version manifest conflicts are intentionally refused.

The signed binaries were built from commit
`1c693db24de71e71bc45b26958da03340d847f5c`, tree
`9fb5c2ea6824a661c5d36cee2eae8ddbea798426`. The release source tag also includes
subsequent documented web and documentation corrections. Those changes do not
alter the signed binaries. See [source identity](docs/source-identity.md),
[release notes](docs/release-notes.md), and [qualification scope](docs/release-3.2.1-qualification.md).

Publication is not a comprehensive security clearance or btcVELD custody
activation. Exact qualification results and remaining work are distinguished
from implemented features.

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
