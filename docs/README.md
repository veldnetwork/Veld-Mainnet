# Documentation

## Development

- [Build from source](../BUILDING.md): platforms, production roles, and build identity.
- [Architecture](architecture.md): entry points and module responsibilities.
- [Testing](../tests/README.md): test groups, dependencies, and local execution.
- [Contributing](../CONTRIBUTING.md): patch scope, coding style, and review.
- [Source identity](source-identity.md): commits, release inputs, and launch records.

## Operations

- [Running Veld](operations/README.md): launchers, node roles, and updates.
- [Node health](operations/node-health.md): synchronization, peers, and state consistency.
- [Release notes](release-notes.md): 3.1.3 update guidance and compatibility.
- [Changelog](../CHANGELOG.md): source changes and pending client changes.

## Security and protocol

- [Protocol whitepaper](WHITEPAPER.md): network design, economics, and activation.
- [Upgrade at block 3,840](consensus/upgrade-3840.md): ASERT, staking, and compatibility.
- [Coinbase accounting](consensus/coinbase-policy.md): subsidy and fee policy.

- [Security policy](../SECURITY.md): private vulnerability reporting.
- [Threat model](security/threat-model.md): assets, trust boundaries, and limitations.
- [Consensus upgrade at height 2,880](security/consensus-upgrade.md): activation and replay rules.
- [Explorer resource limits](security/explorer-resource-limits.md): block-page memory accounting.
- [Dependency provenance](../vendor/pqc/provenance/README.md): cryptographic inputs and verification.

The implementation determines consensus behavior. Documentation describes the
source in this checkout; live service state and installed client versions must
be checked independently.
