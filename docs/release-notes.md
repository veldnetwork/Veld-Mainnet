# Veld 3.1.0

Prepared for `veld-public-mainnet-v2`. Publication is held until the scheduled
block-2,880 upgrade has passed and the fleet's chain agreement is verified.

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

Use the signed updater when the release becomes available. Retain chain data
and wallet backups. The updater's signature and version checks remain in force.
See the [changelog](../CHANGELOG.md) for changes and the
[upgrade specification](security/consensus-upgrade.md) for activation rules.
