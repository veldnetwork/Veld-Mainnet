# C1 WRAP admission and allocation ceremony

This runbook covers the public issuer-WRAP allocator. It does not authorize a
custody descriptor, an owner key, or a WORM service. Those are ceremony inputs,
not source-tree defaults.

## Hard prerequisites

1. The node RPC must expose authoritative `peg_unlocked=true`,
   `mint_live=true`, and `completion_live=true` for the next launch candidate.
   Fresh-genesis policy opens these before finality or Bitcoin-anchor
   promotion. After a later finality stall, `mint_live=false` closes new
   admissions, C1R1/C1E1, direct MNP1, MSPV, and address reveal, while
   `completion_live=true` permits only exact C1C1/C1F1/MNP2 recovery for an
   allocation already in the required canonical state. A missing field fails
   closed; no service may infer completion authority from `peg_unlocked` alone.
2. The compiled issuer maximum per mint must be at least 10,000 sats and its
   static custody ceiling must exactly equal the owner-signed C1 policy.
   Current source, schema, and policy agree on the owner-confirmed
   1,000,000,000-sat shared absolute ceiling; the sustained-work ladder still
   supplies the lower effective headroom. Startup fails before returning an
   address if either the per-mint or aggregate check is false.
3. A custody descriptor/manifest ceremony must pin scripts for the complete
   range 0-10,999. Indices 0-999 are operator-reserved; the public Core cursor
   must begin at 1,000. Never manufacture or copy addresses from this example.
4. Select the external monotonic/WORM authority under C4. Install independent
   absolute-argv archive hooks on the coordinator and isolated signer. Before
   either service replaces terminal raw bytes with a bounded tombstone, its
   hook must durably archive the exact record, read it back, verify the same
   SHA-256, and return the exact acknowledgement required by the source. The
   acknowledgement must identify S3-style object lock mode `COMPLIANCE` and a
   retention deadline at least ten years after archive time. Missing, stale,
   mismatched, governance-mode, short-retention, or unverifiable receipts are
   hard stops; local pruning is not an archive substitute.

## Sign and install the one policy artifact

1. Copy `swap/deploy/c1-wrap-capacity.example.json` outside the source tree.
2. Replace only `archive_authority_id` with the C4 ceremony identity. For the
   initial record keep `record_sequence=1`, the zero predecessor, and public
   end 10,999. Validate against the supplied schema.
3. Sign the exact JSON bytes with the owner ML-DSA-65 key. Install the identical
   JSON, detached signature hex, and owner public-key hex on allocator and
   witness hosts. Mode/ownership must satisfy their fail-closed readers.
4. Compare the SHA-256 reported by the allocator health response with the hash
   returned by the allocation witness. Any mismatch is a HALT, never a rollout
   warning.
5. This C1R1/C1E1/C1C1/C1F1/MNP2 state is committed by D_tokens v7 and changes
   block validity for reservation carriers. Deploy only from a fresh genesis
   with all nodes on the same binary; it is not a version-bump migration for an
   existing chain state.
6. Install `veld_c1_reservationd.py` on the custody coordinator and configure
   `c1-reservationd-config.example.json`. Its signer command must be a dedicated
   SSH forced-command identity reaching `veld_signerd.py` on the isolated issuer
   box. The issuer key never exists on the coordinator or wrap host. Add the
   `c1_reservation_authority` stanza from `signer-config.example.json` so the
   isolated signer independently rechecks the allocation witness and its own
   authenticated Veld node before signing every C1 phase. Configure its
   `durable_archive_command` separately from the coordinator's
   `terminal_archive_command`; both must pass the archive contract above.

Do **not** activate a public-range successor with this release. The signed
policy schema intentionally permits a later monotonically linked successor,
but both allocator and witness currently fail closed with
`C1_RANGE_ROTATION_REQUIRED` if its end exceeds 10,999. The fixed 100,000-row /
64 MiB journals cannot safely be pruned using the present whole-file checkpoint
hook: doing so would discard exact old-request replay, random-index no-reuse,
lifetime principal/destination aggregates, and the event-chain authority.

A later release may enable a range successor only after an audited F4 protocol
adds all of the following on both hosts: exact full-record/event WORM store and
readback SHA-256; `COMPLIANCE` retention of at least ten years; an authenticated
keyed lookup/index committed by the monotonic checkpoint (request id, descriptor
index, principal, destination, and consensus sequence); canonical terminal
height/hash proof strictly deeper than 100 blocks; crash-idempotent store-before-
delete rotation; and fail-closed replay, rollback, unavailable-archive, and
tamper tests. At that point the successor still increments `record_sequence`,
links `previous_policy_sha256`, raises only the end, and deploys with the exact
expanded ceremony-pinned descriptor manifest. No index is ever reused.

## One-shot ledgers

Initialize the witness allocation ledger and allocator journal only after the
descriptor, signed policy, Core cursor, and WORM authority have been recorded.
Arm each `allow_initial_*` flag for one initialization invocation, including
`allow_initial_state_creation` for the C1 coordinator. The programs write and
externally checkpoint their empty ledgers, then intentionally stop; disarm every
flag before normal service startup. The coordinator checkpoints every prepared
unsigned carrier, randomized signed bytes, and broadcast attempt with a
monotonic sequence/hash. A missing or rolled-back existing state is a
reconciliation incident; never reinitialize it.

For the coordinator, run this only on its local service host—not through the
public `/wrap` route or SSH forced-command key:

```sh
VELD_C1_RESERVATIOND_CONFIG=/etc/veld/c1-reservationd.json \
  /opt/veld/swap/veld_c1_reservationd.py --initialize
```

Archive the returned checkpoint acknowledgement, set
`allow_initial_state_creation=false`, and only then enable the forced command.
A normal stdin allocation request never creates missing state.

## Runtime behavior and drills

- A client requests the current 600-second beacon, computes the 24-bit puzzle,
  and signs the beacon/nonce/canonical WRAP request with its ML-DSA-65 key.
  Work from the prior beacon is rejected.
- A new request is journaled and independently witnessed without disclosing its
  Bitcoin locator. The coordinator prepares, isolated-signs, fsyncs, and
  broadcasts exact C1R1 bytes. After C1R1 is 101-deep it does the same for C1E1.
  Only after C1E1 itself is 101-deep may `/wrap` return the exact address. HTTP
  202 means canonicalization is pending and must contain no address or script.
  If descriptor allocation advances but C1R1 never becomes canonical, the
  coordinator closes that exact next sequence with C1C1; it never reassigns the
  sequence or Bitcoin index.
- C1R1 subtracts its amount from issuer headroom and from the shared
  1,000,000,000-sat MSPV occupancy ceiling. After the disclosed script receives
  the exact admitted Bitcoin amount, C1F1 opens the commitment and proves the
  exact confirmed funding output plus current sparse nonmembership. Its strict
  consensus transition consumes the outpoint and makes the lease funded without
  issuing btcVELD. The matching root-neutral MNP2 then credits the recipient and
  erases the funded lease. Unreserved MNP1 minting still uses ordinary issuer
  headroom.
- During a later finality stall, stop new admission and never disclose a newly
  revealable address. Continue exact C1C1 closure for a missing next sequence,
  exact C1F1 for an already-exposed allocation within its consensus funding
  window, and exact MNP2 for an already-funded allocation. Re-read the
  authoritative candidate tuple before preparation and again at the isolated
  signer. A malformed completion carrier, changed tip, stale CFP1 root,
  mismatched commitment/opening, wrong outpoint, or noncanonical lifecycle is a
  hard refusal, not a reason to fall back to direct MNP1.
- The allocator and witness independently enforce 5 allocations per epoch,
  200 per UTC day, 5,000,000 sats per principal and destination, a 10,000-sat
  minimum, and public indices 1,000-10,999. Capacity refusal is explicit
  `AT_CAPACITY` and never evicts an existing allocation.
- The wall-clock seven-day private-intent timeout applies before exposure. An
  undisclosed intent may retire and its finite C1R1 lease expires by block
  height. The public funding term begins when C1E1 reaches 101 confirmations and
  spans exactly 3,360 Veld heights. `/wrap` returns consensus-derived
  `send_starts_height`, a conservative `recommended_send_cutoff_height`, the
  last `funding_accepts_through_height`, `funding_expires_height`, and current
  height—not the private pre-reveal deadline. An unfunded lease is pruned after
  expiry and its capacity releases; a funded lease persists until exact MNP2.
  After the safe send cutoff the API enters `RECOVERY_ONLY`, reveals no new send
  instruction, and does not promise automatic minting for a Bitcoin payment
  made after consensus has pruned the unfunded lease.
- New admissions stop when row or byte use reaches 90%. Existing funding/mint
  lifecycle writes may consume the reserved final 10%; at 100% the service
  hard-stops cleanly.
- Bitcoin tip age is `ALERT` at 3,600 seconds and `RECOVERY_ONLY` at 7,200.
  Recovery-only forbids new allocations while exact retries and existing mint
  lifecycle reconciliation remain available.

Archive and retain the signed policy bytes, detached signature, both reported
hashes, descriptor/manifest hashes, first and last public index tests, boundary
test output, coordinator sequence/hash backups, exact signed bytes for every C1
phase, CFP1 inputs, MNP2 bytes, and every WORM store/readback acknowledgement.
Drill a lost signer reply, lost broadcast reply, restart, shallow reorg before
and after each 101-deep boundary, C1R1 expiry before exposure, unfunded C1E1
expiry, C1F1 rollback and recovery, MNP2 rollback, archive refusal at the 90%
and 100% boundaries, and finality-liveness pause/resume. A GO report must label
missing RPC fields, descriptor expansion, owner signatures, actual WORM
receipts, or keys as external ceremony blockers; source code must not fabricate
that evidence.
