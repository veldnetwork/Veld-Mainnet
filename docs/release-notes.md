# Veld 3.0.8

Released September 6, 2026, for `veld-public-mainnet-v2`.

## Upgrade before block 2,880

Miners and node operators must install compatible software before block 2,880.
This release includes the consensus changes introduced in 3.0.6:

- Certified finality retention and durable anchor authorization.
- Validator principal settlement after applicable evidence horizons.
- Stake-floor enforcement for new registrations, while existing validator
  obligations remain enforceable.
- Governance votes bound to proposal creation identity and voting round.

Open and timelocked governance rounds restart under the new authorization
rules at activation. Completed proposals retain their terminal status. The
[upgrade specification](security/consensus-upgrade.md) describes replay and
migration behavior.

Network identity, protocol version 2, genesis, address encoding, and existing
data directories remain compatible. Preserve wallet backups and chain data.
After activation, older consensus software is not a compatible rollback.

## Snapshot restart recovery

3.0.8 fixes startup when a node has advanced beyond its original signed
snapshot while independent background validation is still running.

Startup verifies the snapshot at its original height, retains the independent
validation target and saved progress, and validates subsequent blocks. Mining
and endorsing remain paused until independent validation completes. Retain
existing data and verification markers when updating.

## Windows updater

The 3.0.7 updater correction is included. GUI clients restart through the signed
`Start Veld Node.bat` launcher after verifying the installed package. Terminal
clients retain `Start Mining.bat`. The updater in the currently installed
version controls the first upgrade's restart.

Download the complete signed client from [veld.network](https://veld.network/).
The updater's signature and version checks remain in force.

## Source maintenance

Hosted wallet, Explorer, and portal updates can be published independently of
client packages. `main` also contains native changes awaiting the next client
release. See the [changelog](../CHANGELOG.md) for that distinction and earlier
release history, and [source identity](source-identity.md) for verification.
