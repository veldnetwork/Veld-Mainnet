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

**Veld Node 3.2.2 is published. Update before block 9,500.**

This maintenance release improves native Pool-page scrolling, uses charcoal
controls, preserves per-device reward accounts, and reports current pool mining
through the portal. Work requests use bounded 256-nonce batches; transient
template-publication races request a fresh, fully validated candidate.

Pool and Solo modes remain available. Pool members use their own payout address
without providing a private key or personal stake. See
[pool.veld.network](https://pool.veld.network/) for setup and private account views.

The block **9,500** upgrade remains unchanged: opt-in SHA-384 key destinations
with ML-DSA-65 signatures, removal of the aggregate ordinary-stake validator
registration prerequisite, and a flat **0.30%** AMM swap fee in both directions.
The validator's individual **10,000 VELD bond**, eligibility, governance,
finality, and seven-validator btcVELD requirements remain separate.
Ordinary staking starts at **500 VELD**; co-mining eligibility remains
**1,000 VELD** for the participating economic identity. Mainnet pool co-mining
is not yet operator-funded. Pool lottery winnings and ordinary staking yield
are shared when earned; operator-contributed principal remains separate.

Automatic updates are opt-in and check hourly while the app is open. An actual
public 3.2.1-to-3.2.2 automatic update resumed pool mining without another
passphrase and preserved the saved account. That check triggered the normal
startup check by re-enabling the preference; it did not measure a full elapsed
hour. The earlier 3.2.0-to-3.2.1 solo-resume result is recorded separately.

The signed binaries use commit `1f77a67365ff9c3c36dae2a624feb35615446202`,
tree `97898f972e3a6eb0cce2caf86475afa5e4988bc6`. This public-source follow-up
adds documentation and hosted presentation assets; it does not change the signed package. See
[source identity](docs/source-identity.md), [release notes](docs/release-notes.md),
and [qualification scope](docs/release-3.2.2-qualification.md).

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
