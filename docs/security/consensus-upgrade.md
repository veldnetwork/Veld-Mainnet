# Consensus upgrade at block 2,880

This specification describes the upgrade included in Veld 3.0.6 and later
for `veld-public-mainnet-v2`. Activation is fixed in the consensus code at
block 2,880. The rules below preserve historical replay before activation.

## Shared activation and replay contract

H=2880 is a settlement/epoch boundary (six intervals of 480 in the mainnet
profile). There is no runtime or per-node override. Default module tests exercise
2880; an explicitly supplied test H=960 remains a regression control requiring
`VELD_TEST_HOOKS` and is rejected in public builds. Zero remains the disabled sentinel.
Historical consensus checks and digest encodings remain unchanged below H.

Node startup rebuilds modules from canonical blocks: `ReplayChain` resets the
validator, governance, finality, and anchor states before replay. Governance
proposal identities are collected during this historical replay but are not added
to the old digest or old authorization rules. Derived governance KV alone is not a
post-upgrade bootstrap or replay contract; the node does not call `LoadFromKV`.
Old rows without canonical creation identities cannot authorize migrated votes.
Canonical snapshots and alternate-branch snapshots include the new value fields.

Nodes must run compatible software before activation. Historical blocks
retain their original validation rules. See the [release notes](../release-notes.md)
for update guidance.

## Finality carrier and durable floors

The selected design delays new permanent anchor authorization until a later valid
certificate covers the earlier certificate's carrier in its authenticated target
prefix. `record` remains the latest canonical certificate and voting source;
`certified_carrier_record` supplies anchor authorization after H. A second digest
version commits this additional state. Existing pre-H records and exact durable
floors are grandfathered; this cannot reconcile an already divergent history.

For post-H certificates, the early reorg gate protects the authenticated target
prefix. A necessary second gate runs only after full alternate-module validation,
before validation-only success or durable block publication: the alternative must
contain the exact old target and retain a validated certificate at that target or
a higher one. Missing retention wiring fails closed. This postcondition is not a
replacement for cryptographic certificate validation. Existing VLF1 durable-floor
encoding and exact pins remain unchanged. A new pin's authorization carrier is
already inside the latest authenticated target prefix, so carrier-only transport
does not create a new premature durable floor.

Tradeoff: fresh permanent anchor promotion waits for later carrier certification.
Valid alternate transport still needs a fully validated certificate in its branch
history. The migration does not persist detached certificates in a new database.

## Principal and outstanding slash evidence

`principal_settled_at` is terminal consensus state. Historical settlement boundaries
strictly below H are grandfathered as already paid; a boundary equal to H is unpaid
and enters the new schedule. There is no clawback, fabricated debt, or repayment
of completed principal. Historical economic loss remains unrecoverable.

Unpaid principal uses the first settlement boundary strictly after the maximum of
the applicable ordinary/exit evidence horizon, the last recorded finality vote's
horizon, and the end of every retained frozen epoch containing the validator plus
the finality evidence window. Widened arithmetic prevents wraparound. Epoch-end
accounting deliberately includes votes absent from canonical certificates and may
hold collateral up to 19 additional blocks beyond the last scheduled checkpoint.

The parent schedule is consumed before current-block evidence changes the bond's
class. Both slash paths, clean re-entry, inactive-record pruning, and the vault RPC
use the same principal state. An unpaid principal is displayed as held even at its
scheduled height until the canonical settlement transition consumes it.

Existing deterministic reporter allocation is retained: ordinary evidence uses
the existing tuple order; equivocation settlements use the recorded equivocation
reporter. This introduces no new multi-reporter split. Yield escrow retains its
existing independent terminal-tranche settlement rules; the extended hold applies
to principal. Validator digest v8 commits terminal principal state; pre-H v7 is
unchanged.

## Registration floor and existing obligations

At and after H, the liquid-stake floor gates REGISTER only. Deregistration,
endorsement, ordinary slash, and finality-equivocation operations retain their
other existing authorization and eligibility checks. Below H the historical gate
still applies to all operations. Canonical and alternate module ordering continues
to apply staking before updating the validator registry's total stake.

The legacy RPC `system_active` remains the registration-floor indicator. The new
`existing_operations_active` capability allows the bundled validator daemon to
continue its registered-validator loop below the floor after migration. Missing
capability fields preserve old-node behavior. The UI and Explorer distinguish
continued operation from paused registration; the daemon still checks registration
before reaching finality or endorsement production.

## Governance authorization

Both supported proposal forms derive creation identity from a domain-separated
commitment to chain identity, canonical transaction ID, and output index. The
transaction ID commits the complete marker, including legacy ignored timestamp
bytes. Sequential proposal numbers remain presentation identifiers.

At H, OPEN and TIMELOCKED proposals restart as OPEN with empty votes and tallies,
no old timelock, and a fresh full voting duration from H. Original creation height
is retained; terminal proposals remain terminal. Old per-proposal vote cooldowns
are cleared. This explicitly removes pending legacy voting approvals.

The vote identity commits creation identity and round start. Post-H authorization
uses a versioned V2 marker and challenge binding proposal number, vote identity,
choice, and signed height. The consensus parser, RPC builder, and wallet intent
builder share this contract. Legacy signatures are never reinterpreted as V2.
Before H, legacy authorization and digest bytes remain unchanged. Versioned
serialization keeps the strict final votes-array layout and rejects missing or
unknown identity metadata. The upgraded digest includes creation and round state.

At the last block before H, preparation requests using next-block rules pause until
the migration has actually run. A proposal or round change between display and
preparation requires refresh; signing is not silently rebound to new content.

## Implementation and testing

- [Activation constant](../../include/consensus/security_upgrade.h)
- [Finality state](../../include/consensus/finality_state.h)
- [Validator state](../../include/consensus/validators.h)
- [Governance state](../../include/consensus/governance.h)
- [Migration tests](../../tests/security_consensus_migration_tests.cpp)
- [Historical compatibility tests](../../tests/security_consensus_legacy_compat.cpp)

Module tests cover migration boundaries and legacy behavior. They do not
establish live network adoption or replace full replay and restart checks
for a release.
