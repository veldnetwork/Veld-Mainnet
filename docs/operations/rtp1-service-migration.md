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

`inspect-rtp1-backing-stdin` now derives the deposit, reserve successor, direct
parent transaction identities, recipient and operation from the same native
classifier. `swap/rtp1_backing_evidence.py` compares these facts with the native
inspection and an independently pinned Bitcoin Core view. Core must confirm the
exact transaction and block, input parents, output value and script, and an
unspent successor including mempool spends. The composed inspection repeats the
entire native inspection after the Bitcoin work. Its evidence hash is an
integrity binding, not a witness signature or an authority grant.

The backing boundary passed an actual private Core deposit with144 confirmations,
block invalidation and reconsideration. Linux and Windows keygen builds decoded
that proof and produced independently verified issuer input signatures offline.
Those earlier fixtures did not perform native mint admission. A subsequent
private-network run exercised the actual issuer, witness, watchtower, heartbeat
receiver and native RPC entry points for OPEN and DEPOSIT, with Bitcoin Core
requiring three custody signatures and native seven-validator finality. The
private node profile differs from the public production profile; this does not
qualify production activation or five independent operators.

The issuer and witness entry points now dispatch versioned RTP1 requests through
`swap/rtp1_service_runtime.py`. Activation is restricted to explicitly pinned
disposable Veld profiles and Bitcoin regtest. The versioned journal binds exact
requests, independent backing, signed witness receipts and exact carrier bytes.
Existing authority, protected-file, process-lock, heartbeat and restoration gates
remain enforced. Production RTP1 service activation stays closed.

Descriptor validation remains network-specific: mainnet requires the reviewed
account xpubs at `86h/0h/0h`; an explicitly selected Bitcoin test network requires
account tpubs at `86h/1h/0h`. Both require the same fixed NUMS internal key, one
three-of-five leaf and five distinct public keys. Core independently derives
every script. Actual Core tests verified all 1,000 entries and refused an altered
final script; default mainnet validation refused the test descriptor.

The issuer's native evidence/signing boundary has been updated. Its existing C1
and MNP service paths now retrieve complete parent transactions from their own
node, use the keyless `prepare-signing-stdin` command to authenticate the exact
inputs and fee, and authorize a detached intent before recording `SIGNING`.
The input's independently resolved block height is retained. Parent retrieval
uses that exact height and verifies its canonical block and raw transaction hash,
so old inputs do not depend on a recent-history scan. New evidence and inspection
metadata use the same genesis hash representation as native RPC; existing signing
domain constants and genesis bytes are unchanged.
Prepared evidence, intent and exact signed output survive a retry. An uncertain
transaction-signing attempt is never repeated. Legacy signing stages require
reconciliation. Fresh policy and emergency-stop checks run again at the key
boundary. The RTP1 adapter uses this same durable signing boundary.

Actual native evidence, intent and input-signature checks have passed on Windows
and Linux with disposable credentials. The POSIX issuer staging/recovery path was
also exercised with the real keygen. Windows bounded execution uses a Job Object
and an explicit inherited-handle list. It is not a custody-key isolation boundary;
the complete managed Windows custody worker remains unimplemented.

## Implemented disposable lifecycle

The issuer requests `rtp1_reserve`, verifies the independent ML-DSA receipt and
persists it before attempting an issuer signature. Both operators retain the
exact template, reserve predecessor and deposit identity. The issuer rechecks
current backing, emergency stop, authority, solvency and witness state at its key
boundary. It releases signed bytes only after an exact durable witness commit.
The witness uses retained native context and the keyless
`verify-signed-carrier-stdin` command to verify every input signature at commit.
The issuer performs the same cryptographic verification for newly signed,
retained and witness-recovered bytes. Revalidation counts the current reservation
once alongside every other unresolved liability; it never releases capacity by
substituting a zero mint amount.

The guarded watchtower adapter compares coherent native supply, unsettled
redemption principal and reserve accounting with a bounded Core inventory. It
checks each confirmed output against the full pinned descriptor and an unspent
view that includes mempool spends. Both journals reconcile canonical confirmations
before cached status or commitment responses. A failed one-shot watchtower cycle
returns failure to its caller rather than a successful process status.

Lost acknowledgements retry the same bytes. An issuer restored to a retained
reservation can recover the exact committed payload from its witness without
another randomized signature. Missing or contradictory history refuses; neither
operator resets it automatically. Canonical native mint effects and independently
confirmed Bitcoin inclusion settle pending accounting. Reorganization reinstates
the pending liability without deleting signatures or receipts.

`--initialize-rtp1-state` inventories and hashes only recognized empty legacy
journals, leaves their originals unchanged, and writes the activation marker
last. Both exact empty issuer formats are supported, including the format written
by `--initialize-authority-state`. Existing funded or signed C1 state, partial
initialization and signing-stage history refuse migration. Enabling the RTP1
configuration closes legacy issuance and allocation routes under the same lock.

The earlier two-journal cryptographic fixture simulated the native view. The
subsequent private native run admitted OPEN and DEPOSIT through the actual service
entry points and recognized their canonical effects. It also refused a forged
carrier and emergency-stop retries, recovered witness bytes with issuer decryption
unavailable, and restored pending liability during an actual Bitcoin invalidation.
Restoring the Bitcoin branch reconciled both journals without another mint.
The resulting issued tokens passed native AMM seed, add, both swap directions
and liquidity removal with unchanged circulating supply.
Historical-liability migration and independent operators remain unqualified. The
bounded journal retains all records; archival, simultaneous operator backup
rollback and every physical write-interruption boundary require further testing.

## Required issuer transition

1. Require an independently reviewed chain and custody configuration, the existing
   single active issuer and independent witness. A coordinator cannot supply or
   replace these pins.
2. Authenticate the full unsigned transaction, every raw parent, each referenced
   value/script, the fee and exact recipient. Retain the complete native prepared
   transaction and reserve context. The evidence builder and existing issuer
   staging now enforce this boundary. RTP1 service orchestration must retain it.
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
