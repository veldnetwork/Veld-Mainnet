# Veld 3.1.0

Released on 8 September 2026 for `veld-public-mainnet-v2`, after the
block-2,880 upgrade and sustained fleet chain agreement were verified.

[Download the signed Windows client](https://veld.network/downloads/VeldClient-Windows-x64-3.1.0.zip)
or inspect the [release source](https://github.com/veldnetwork/Veld-Mainnet/tree/v3.1.0).

## Mining efficiency

- Reduce scratchpad and dataset initialization overhead while preserving the
  exact VeldHash output and cryptographic byte stream.
- Reduce integer square-root work without changing its result.
- Preserve the exact header used by each worker during timestamp refreshes.
- Retain completed hash counts when a search is canceled and finish the
  progress sampler before publishing the final total.
- Detect available Windows physical cores for worker defaults and presets,
  with a conservative fallback when topology is unavailable.
- Apply the supported 1–64 worker range consistently across the client and
  portal. Portal adjustments use the saved count for the next node start.

A worker is a software thread. Logical processors can run additional workers,
but more workers do not always improve throughput because they share CPU and
memory resources. Tune each machine independently. Presets use physical cores;
custom counts allow additional logical threads within the supported limit.

## Multiple machines

Retain the independent random search origins introduced in 3.0.9. Each computer
runs its own miner, including when machines share a payout address. Portal
pairing provides monitoring and controls; it does not pool the machines' work.
Regression coverage includes different worker counts and independent processes.

## Compatibility and updating

Coinbase allocation, staking eligibility, difficulty rules, protocol version 2,
genesis, addresses, and existing data directories are unchanged. The consensus
upgrade remains at block 2,880. This release includes the earlier snapshot
restart and signed updater repairs. Existing wallet styling is preserved.

Use the signed updater to install 3.1.0. Retain chain data and wallet backups.
The updater's signature and version checks remain in force.
See the [changelog](../CHANGELOG.md) for changes and the
[upgrade specification](security/consensus-upgrade.md) for activation rules.

## Verification

Windows and Linux hashing passed all 28 frozen mainnet vectors from 3.0.9.
Mining solution, cancellation, concurrent search, worker-policy, and portable
checks passed. The fleet's low-memory verification build also matched all
28 vectors and refused mining commands.

Release signatures and downloaded artifact hashes were verified after website
publication. These checks establish the tested release behavior and artifact
identity; they are not a guarantee of error-free software. See
[source and release identity](source-identity.md) for the exact commit, tree,
and download checksum.
