# Veld 3.1.1

Checkpoint authority replacement and verified historical pinning for
`veld-public-mainnet-v2`.

## Checkpoint protection

This client enforces the verified block at height **2,800**. The pin participates
in block admission, replay, synchronization, and reorganization anchoring.
Independent fleet nodes confirmed the historical hash beyond the existing
100-block reorganization horizon.

The public-mainnet client also trusts a replacement ML-DSA-65 signing key for
the official checkpoint feed. The original encrypted signing key was preserved,
but its unlock credential could not be recovered. The replacement keystore,
saved unlock credential, signatures, and encrypted recovery backup were verified
locally. Private signing material remains outside the fleet and public source.

Downloaded checkpoint records remain advisory. They cannot move the compiled
pin or replace proof-of-work, transaction, state, or snapshot validation. See
[checkpoints and chain validation](checkpoints.md) for the pin, public-key
fingerprints, and compatibility details.

## Updating and compatibility

Use the signed updater or the [official Windows download](https://veld.network/#download).
Keep existing chain data and wallet backups. Upgrading an already synchronized
client does not require deleting its data or starting again from genesis.

Existing 3.1.0 clients do not trust signatures from the replacement checkpoint
key and do not contain this historical pin. Install 3.1.1 to receive both changes.
Older clients continue ordinary chain validation; the feed remains advisory.

The existing chain, mining algorithm, reward allocation, staking eligibility,
difficulty rules, addresses, and protocol version 2 remain unchanged. This
release retains the mining improvements in 3.1.0 and the upgrade activated at
block 2,880. It does not schedule a new activation height.

Release qualification covers checkpoint verification and rejection cases,
compiled-pin boundaries, Windows and Linux builds, compiled genesis identity,
production hash vectors, release signatures, and the signed updater handoff.
Published artifacts are identified by their signed manifests and the
[release identity record](https://veld.network/downloads/RELEASE-IDENTITY-3.1.1.json).
See [source identity](source-identity.md) and the [changelog](../CHANGELOG.md).
