# RTP1 service migration contract

Status: implementation and qualification incomplete. This document does not
enable minting, enroll signers or replace an existing custody authority.

## Native and service boundary

The native fresh-reserve profile accepts recipient-bound RTP1 mint proofs.
`inspectrtp1mint` checks an exact unsigned transaction against one fully validated
Veld/Bitcoin state without signing it or mutating that state. Its result identifies
the chain, tip, reserve predecessor, supply, deposit outpoint, recipient, amount
and custody hashes. `swap/rtp1_mint_policy.py` validates this result against the
operator's independent pins and rechecks the branch. Its bounded stdin decoder
uses the native mint policy with that exact prior state.

These functions are not yet the issuer/witness service workflow. The current
`veld_signerd.py` and `veld_wt_reserve.py` main paths still use the MNP/C1 protocol.
Their existing custody, allocation, authority, heartbeat and recovery gates must
remain closed rather than being bypassed for RTP1.

## Required issuer transition

1. Require an independently reviewed chain and custody configuration, the existing
   single active issuer and independent witness. A coordinator cannot supply or
   replace these pins.
2. Authenticate the full unsigned transaction, every raw parent, each referenced
   value/script, the fee and exact recipient. Retain the complete native prepared
   transaction and reserve context. The old two-field prepared file is
   incompatible with the current keygen and must not reach the signing boundary.
3. Obtain a fresh native RTP1 inspection and an independently verified witness
   reservation for the exact template hash, Bitcoin deposit and custody epoch.
   Persist the receipt and immutable input lease before signing can begin.
4. Derive the detached signing intent from those independently verified facts,
   including the complete operation identity and fee limits. Never authorize a
   coordinator-supplied intent merely because it is well formed.
5. Persist the exact prepared evidence and authorized intent. Persist `SIGNING`
   before the randomized transaction-signature attempt. Recheck the native state,
   witness gate and emergency stop at the irreversible boundary.
6. Persist the signed bytes before acknowledging them to the witness; release
   them only after the witness's durable exact-byte commit. A retry returns those
   same bytes. A missing or uncertain signing result requires reconciliation,
   not a fresh randomized signature or a released input lease.

Authorizing a detached intent is not permission to sign a payout and does not
replace the three-of-five Bitcoin custody policy.

## Required witness transition

The witness must independently validate the native inspection and Bitcoin reserve
transition, including the actual direct parents, canonical finality, exact
recipient commitment and confirmed successor reserve. A DEPOSIT predecessor can
already be spent by the verified rollover; deleting the old `gettxout` check
without verifying that exact successor is unsafe.

Version the receipt and durable ledger. Bind each reservation to the exact chain,
custody epoch, reserve predecessor, deposit, amount, recipient, proof hash and
unsigned template hash. Keep one immutable liability identity across retries and
coordinator restarts. Preserve conservative capacity accounting for every
reserved, signed, unacknowledged or uncertain carrier. Missing or stale independent
observations refuse new liability; they never justify dropping an existing one.

Commit verification must use the reservation's retained native context to decode
the exact original template. A consumed mint cannot pass a fresh-issuance check;
that is not evidence that its signed bytes may be forgotten. Confirmed and
reorganized outcomes require canonical native effect records plus the matching
Bitcoin reserve history before any liability is retired.

## Existing MNP/C1 liabilities

Inventory every issuer, witness, allocation and signing-stage journal before
changing its schema. Retain originals and exact signed bytes. Reconcile both
operators' views against the same canonical native/Bitcoin state. Missing history,
inconsistent epochs, uncertain signatures and unresolved liabilities stop migration.

C1F1 already inserts its funding outpoint into the shared nullifier accumulator;
MNP2 consumes the funded reservation without inserting it again. RTP1 OPEN/DEPOSIT
performs a nonmembership insertion. Relabeling a funded C1 record as an RTP1 record
therefore does not preserve its state transition. Existing funded reservations
need an explicit compatible completion or retirement rule with native accounting
and rollback tests. Do not erase their nullifiers, reset reservation counters,
assume an empty ledger, or reuse their Bitcoin backing to make migration pass.

Existing signed payout/refund material also survives software rollback and key
rotation. Migration must retain or cryptographically retire that authority before
releasing backing or restoring token principal. An elapsed timeout is insufficient.

## Qualification

Run complete issuer-to-witness-to-keygen-to-node transactions, with actual
signatures and independent local chain views, for OPEN, DEPOSIT, cached retry,
confirmation, reorganization, restart and restored ledgers. Exercise interruption
at every durable write and acknowledgement boundary. Compare reserve, circulating
supply, pending mint liability and redemption principal before and after each
case. Verify stale context and conflicting reservations refuse without mutation.

Component signing and private native-chain receipts do not qualify this service
migration. Production configuration, historical-liability evidence, independent
operators and funded activation remain separate requirements.
