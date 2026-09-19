# Native custody service qualification

The native custody adapter is restricted to disposable networks. It is not an
activated public custody system or the completed managed Windows Node feature.
Exactly three of five community keys remain required; fleet keys are excluded.

`veld_payout_signerd.py` accepts the versioned `native_custody` configuration only
through explicit initialization of a new private commitment database. Normal
startup refuses missing, inconsistent or partially initialized authority. Each
request independently verifies the pinned native chain, finalized CIA1 intent,
Bitcoin chain and unspent reserve, complete descriptor, exact transaction,
member position and fee limits. Durable intent commitment precedes signing.
Cached signatures retain the original transaction and cannot release an input
reservation merely because time has passed.

`veld_redeemd.py --collect-native-payout` requires five distinct pinned member
keys and collects a usable three-signature result. It continues past unusable
responses, tries bounded three-member subsets, and requires Bitcoin Core
finalization and mempool acceptance. The separate Bitcoin fee sponsor must have
zero custody signing authority. The command returns signed bytes without
broadcasting. Normal native tip advancement is permitted only while the exact
authorization, reserve input and finalized ancestry remain unchanged.

`veld_redeemd.py --prepare-native-settlement` independently checks the confirmed
Bitcoin transaction, canonical block, Merkle inclusion, direct parent identities,
native authorization and reserve accounting before preparing a fee-only CST1
carrier. It preserves the exact parent bytes bound by CIA1 while comparing each
parent's non-witness transaction with Bitcoin Core. It does not mint, authorize a
timeout-only refund, sign a native carrier or broadcast either transaction.

Retirement must consume the original reserve edge on Bitcoin and reach the
required independently verified confirmation and native-finality boundaries.
The native honor window also applies. Retained complete payout signatures are
not erased or treated as expired; their Bitcoin input must become unusable before
principal is restored. Contradictory terminal history freezes the proposal.

The inactive node proposal checks custody semantics at mempool entry using a
stable chain frame and disposable module snapshots. Already-terminal settlements
are refused as new mempool entries, while historical block replay retains its
existing idempotent behavior. The public-release build refuses the experimental
custody relay signing macro.

Private qualification uses actual Bitcoin Core wallets, ML-DSA native validators,
signer entry points and CLI adapters. Five wallets on one host do not establish
five independent operators. The test chain has distinct consensus parameters;
passing it does not qualify a production Node binary or public activation.

Remaining product work includes the durable broadcasting/settlement scheduler,
funded C1 migration, Windows private-state and key-principal integration, installer
and update recovery, independent operator qualification and full audit coverage.
The current POSIX authority store is not Windows-qualified. The managed process
runner's Job Object is a resource/lifetime control, not custody-key isolation.
