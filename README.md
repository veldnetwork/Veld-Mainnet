# Veld

Veld is a CPU-mined blockchain with a maximum supply of 21 million VELD,
staking, ML-DSA-65 transaction signatures, and a bonded validator finality
layer. This repository contains the node, wallet, validator, mining pool,
portal, btcVELD services, and public web applications for `veld-public-mainnet-v2`.

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
- **Mine in a pool:** follow the [pool mining guide](docs/operations/pool-mining.md).
- **Explore the implementation:** start with the
  [architecture guide](docs/architecture.md) and [documentation index](docs/README.md).
- **Contribute:** read [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [test guide](tests/README.md). Report vulnerabilities through
  [SECURITY.md](SECURITY.md).

## Releases and network identity

Pool and Solo modes remain available. Pool members use their own payout address
without providing a private key or personal stake. See
[pool.veld.network](https://pool.veld.network/) for setup and private account views.

Enable **Settings → Release and updates → Automatic updates** in Veld Node.
Checks run hourly while the app is open. Read the
[update guide](docs/operations/automatic-updates.md) for mining resume and
recovery behavior.

Release tags and signed packages retain their original identities. Ongoing
maintenance on `main` does not replace released binaries. See
[source identity](docs/source-identity.md) for exact commits and hashes.

Publication is not a comprehensive security clearance or btcVELD custody
activation. Full economic and custody qualification remain separately tracked.

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
| [pool/](pool/) | Worker gateway, coordinator, accounting, restricted signing, dashboards, and qualification |
| [swap/](swap/) | btcVELD issuance, redemption, reserves, witness, relay, and custody services |
| [tests/](tests/) | Unit tests, process tests, web checks, and deterministic fixtures |
| [build/](build/) | Linux and Windows production build controllers |
| [scripts/](scripts/) | Dependency verification, WASM tooling, and topology collection |
| [pkg/](pkg/) | Client launchers, updater, web overlays, and reverse-proxy configuration |
| [resources/](resources/) | Application icons and Windows resource files |
| [website/](website/) | Homepage, hosted Explorer pages, display scripts, and service workers |
| [docs/](docs/) | Developer, operator, release, and security documentation |
| [vendor/](vendor/) | Pinned third-party cryptography and provenance records |
| [third_party_licenses/](third_party_licenses/) | Dependency license texts |

## Security and licensing

Review the [security model](docs/security/threat-model.md) before operating a
node or integrating btcVELD. Signed packages authenticate a release; they do
not constitute a security certification.

Veld-authored source is licensed under [AGPL-3.0-only](LICENSE). Dependencies
retain their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Branding is covered separately by [TRADEMARKS.md](TRADEMARKS.md).
