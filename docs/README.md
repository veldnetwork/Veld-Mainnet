# Documentation

## Development

- [Build from source](../BUILDING.md): platforms, production roles, and build identity.
- [Architecture](architecture.md): entry points and module responsibilities.
- [Testing](../tests/README.md): test groups, dependencies, and local execution.
- [Contributing](../CONTRIBUTING.md): patch scope, coding style, and review.
- [Source identity](source-identity.md): commits, release inputs, and launch records.
- [Pool implementation](../pool/README.md): gateway, work verification, accounting, and signing.
- [btcVELD implementation](../swap/README.md): issuance, reserves, redemption, and custody services.

## Operations

- [Running Veld](operations/README.md): launchers, node roles, and updates.
- [Node health](operations/node-health.md): synchronization, peers, and state consistency.
- [Pool mining](operations/pool-mining.md): Windows setup, account access, and reward balances.
- [Pool service operations](operations/pool-candidate.md): architecture, accounting, and recovery.
- [Pool installation](../pkg/pool/README.md): service configuration, identity separation, and shutdown.
- [Pool administration](../pkg/pool/ADMIN.md): authenticated operator controls.
- [Release notes](release-notes.md): client changes and upgrade requirements.
- [Automatic updates](operations/automatic-updates.md): opt-in, mining resume, and recovery limits.
- [Changelog](../CHANGELOG.md): versioned changes and unreleased maintenance.

## Qualification

- [3.2.2 qualification](release-3.2.2-qualification.md): released artifact checks and remaining coverage.
- [3.2.1 qualification](release-3.2.1-qualification.md): earlier release evidence and limits.
- [Native pool qualification](../pool/qualification/README.md): disposable chain, funded payments, and platform checks.
- [Public pool website](pool-public-website.md): account privacy, public projections, and browser checks.

## Security and protocol

- [Protocol whitepaper](WHITEPAPER.md): network design, economics, and activation.
- [Upgrade at block 9,500](consensus/upgrade-9500.md): destinations, validator registration, and AMM fees.
- [SHA-384 destinations](sha384-destinations.md): encoding, authorization, and migration.
- [AMM fee policy](amm-market-fee-candidate.md): market pricing, fee treatment, and analysis limits.
- [Upgrade at block 3,840](consensus/upgrade-3840.md): ASERT, staking, and compatibility.
- [Coinbase accounting](consensus/coinbase-policy.md): subsidy and fee policy.

- [Security policy](../SECURITY.md): private vulnerability reporting.
- [Threat model](security/threat-model.md): assets, trust boundaries, and limitations.
- [Consensus upgrade at height 2,880](security/consensus-upgrade.md): activation and replay rules.
- [Explorer resource limits](security/explorer-resource-limits.md): block-page memory accounting.
- [Dependency provenance](../vendor/pqc/provenance/README.md): cryptographic inputs and verification.

## btcVELD

- [System design](btcVELD-DEX-design.md): service roles and Bitcoin-backed token flows.
- [Custody security](btcVELD-custody-security.md): signing authority, spending policy, and recovery.
- [AMM design](btcVELD-AMM-design.md): liquidity and swap execution.
- [Issuer chain binding](../swap/deploy/ISSUER-CHAIN-BINDING.md): intended-chain and authority checks.
- [Issuer and witness runbook](../swap/deploy/MINT-SIGNER-WITNESS-RUNBOOK.md): reservation and reconciliation requirements.
- [Activation runbook](../swap/deploy/GO-LIVE.md): prerequisites for separately authorized operations.

The implementation determines consensus behavior. Documentation describes the
source in this checkout; live service state and installed client versions must
be checked independently.
