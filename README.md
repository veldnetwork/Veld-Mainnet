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

- **Run a client:** download the signed Windows or Linux package from
  [veld.network](https://veld.network/). See the
  [operator guide](docs/operations/README.md) for installation and launch steps.
- **Build from source:** follow [BUILDING.md](BUILDING.md).
- **Mine in a pool:** follow the [pool mining guide](docs/operations/pool-mining.md).
- **Explore the implementation:** start with the
  [architecture guide](docs/architecture.md) and [documentation index](docs/README.md).
- **Contribute:** read [CONTRIBUTING.md](CONTRIBUTING.md) and the
  [test guide](tests/README.md). Report vulnerabilities through
  [SECURITY.md](SECURITY.md).

## Releases and network identity

The signed [3.3.4 release](https://github.com/veldnetwork/Veld-Mainnet/releases/tag/v3.3.4)
was published on November 12, 2026. **Upgrade before mainnet block 34,750.**
Block height controls activation; November 13 at noon Denver/MST is an estimate.

- Validator registration falls to 5,000 VELD. Finality uses five eligible keys,
  capped weights, maturity, snapshots, warm-up and a strict greater-than-two-thirds quorum.
- Native transaction fees go entirely to miners permanently. Exchange trading
  fees and AMM liquidity-provider fees are separate.
- A 20,000 VELD rewards-vault target can increase payouts within the existing
  8% cycle limit. It is not a locked reserve or a guaranteed payout.
- Halvings begin at blocks 700,801 and 1,401,601. Co-mining retires at the first;
  ordinary subsidies then split 60% miners / 20% vault / 20% validators.
- Excess bonds require an owner-signed request and the full evidence window.
  Existing bond principal does not return automatically.

See the [activation and snapshot boundaries](docs/release-3.3.4-activation.md),
[release notes](docs/release-notes.md), and [whitepaper](docs/WHITEPAPER.md).
The btcVELD seven-validator gate, ten-vote protocol-upgrade minimum, and
100-block reorganization rejection horizon remain separate requirements.

Production appchain hosting remains paused. The developer workspace uses a
separate, valueless testnet; native 3.3.4 does not launch production contracts.

Solo and Pool modes are supported by the client. The official production pool
is currently stopped; check its status before connecting. Pool members use their own payout address
without providing a private key or personal stake. See
[pool.veld.network](https://pool.veld.network/) for setup and private account views.

Enable **Settings → Release and updates → Automatic updates** in Veld Node.
Checks run hourly while the app is open. Read the
[update guide](docs/operations/automatic-updates.md) for mining resume and
recovery behavior.

Release tags and signed packages retain their original identities. Ongoing
maintenance on `main` does not replace released binaries. See
[source identity](docs/source-identity.md) for exact commits and hashes.
See the [release verification guide](docs/release-verification.md) for
signature and package checks.

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
