# WRAP descriptor-allocation capacity and recovery

## Launch status

The launch custody descriptor has two deliberately separate manifest domains.
The compiled consensus/SPV prefix remains exactly `[0,999]`: index 0 is
permanently reserved for permissionless SPV minting and indices 1-999 remain
operator-reserved.  The C1 operational manifest and coordinator wallet cover
exactly `[0,10999]`, with public `/wrap` allocation beginning at index 1000.
The old allocator called `getnewaddress` for every accepted/retried request; an
unauthenticated client or a lost HTTP response could therefore burn the finite
range without creating a valid allocation.

Production now fails closed unless every field under the
`public_capacity_policy_version: 1` block in `veld_wrapd.config.json` is
explicit. Example numbers are proposed resource/availability values, not owner
approval and not peg economics. Starting the old non-journaled development
allocator now also requires the conspicuous
`development_only_allow_unsafe_allocator: true` escape hatch; omission can no
longer expose it accidentally.

## Implemented invariants

- A first request carries a wallet-persisted random 128-bit `request_id` and a
  stateless SHA-256 admission proof. The proof is bound to request ID, exact
  VELD destination, exact amount, timestamp and nonce.
- The allocation journal derives Core's exact next descriptor address and
  fsyncs a `reserved` intent **before** calling `getnewaddress`.
- If the process, disk publication, proxy, or HTTP response dies, an exact retry
  compares Core's `next` index with the intent. It either performs the one
  authorized advance or adopts that exact already-advanced address. It never
  allocates a replacement.
- After Core advances, journal version 2 persists an `allocated` boundary and
  invokes a dedicated SSH forced command on the independent watchtower. The
  address is returned only after that host fsyncs the exact immutable allocation
  in `wrap-allocation-authority.json`; a witness outage leaves it unavailable but
  consumes no additional index. The mint-signer SSH key cannot register records.
- Concurrent identical requests serialize through the journal and all receive
  the same result. A request ID reused with different immutable fields fails.
  The 128-bit request ID is also a retry capability, so a mobile IP change does
  not strand an otherwise exact retry.
- Principal and destination accounting remains replay-stable across retries,
  but its amount ceiling equals the shared custody ceiling and is not a
  narrower per-user cap.
- Public issuance halts before the configured reserve of descriptor indices.
  `/health` reports the Core `next` index, public indices remaining and whether
  the reserve threshold is reached.
- The journal is bounded, strict JSON in an owner-only directory, written by
  fsync + atomic rename + directory fsync. Linked, permissive, duplicate,
  malformed, conflicting or oversized records fail startup.
- Journal indices must form one contiguous history, and Core's live descriptor
  cursor must be the one exact next value implied by it (or one of the two
  states around a final durable intent). Manual address issuance, Core rollback,
  a mismatched wallet restore, skipped indices and duplicate-index reuse fail
  startup, health and allocation. Every persisted BTC address is rederived from
  its exact descriptor index at startup; an issued-address retry also rechecks
  the exact script and VELD-recipient label before returning it.
- A pending durable intent blocks all unrelated allocation until its exact
  retry/reconciliation completes. External/manual use of `getnewaddress` is
  detected as an allocator-authority violation.
- The process holds an owner-only nonblocking OS lock derived from the journal
  path before reconciliation. A second daemon—even on another TCP port—cannot
  become a concurrent allocator for the same journal.
- A missing journal never silently becomes a fresh production allocator.
  First creation is a one-shot ceremony: temporarily set
  `allow_initial_allocation_store_creation: true`; the service creates and
  fsyncs the empty journal, then intentionally exits. Set it back to `false`
  before the service is allowed to run. Leaving the flag true once a journal
  exists also fails startup.

The desktop stores the pending request ID before contacting the service, mines
the advertised work in event-loop-sized batches, verifies the returned request
ID, and clears the pending marker only after a valid response. An unresolved
request cannot be overwritten by changing account or amount; it must be retried
exactly. Admission timestamps use the service clock and restart before expiry,
so local clock skew and a longer proof search do not strand the request. A
received same-origin rejection may release the local pending marker only when
the journal explicitly returns `request_recorded: false`; lost/unknown replies
and durable intents remain exact-retry-only.

## Operator rules

1. Only `veld_wrapd` may call `getnewaddress` on this wallet after activation.
2. Back up `allocations.json` and the independent
   `wrap-allocation-authority.json` with the descriptor wallet and swap/peg
   records. Never restore one without exact field-for-field reconciliation of
   the other.
3. Alert before `public_indices_remaining` approaches zero. Reaching the reserve
   threshold is an intentional HTTP 503/fail-closed condition, not permission to
   lower it ad hoc.
4. A `reserved` or `allocated` final record after restart is expected crash
   recovery. Retry that exact `request_id`; do not delete or edit the record.
5. Journal rollback/deletion must be treated as an incident. Atomic local files
   do not prove freshness against a privileged rollback; pin backups/sequence
   evidence to the launch WORM/external checkpoint authority.

## Owner-selected working policy and remaining ceremony inputs

- The intended launch policy is the post-freeze owner-signed C1 record:
  current-only 24-bit work with
  a 600-second epoch, 5 allocations per epoch and 200 per UTC day,
  1,000,000,000-sat per-principal and per-destination compatibility ceilings, a 10,000-sat
  minimum, public range `[1000,10999]`, a 100,000-row/64-MiB journal, and a 10%
  lifecycle reserve. Services verify the exact signed bytes and do not accept
  operator-edited substitutes. The current working record is not yet signed
  against a frozen source identity. The owner-confirmed 1,000,000,000-sat shared
  absolute ceiling now matches issuer and SPV consensus; the sustained-work
  ladder remains the lower effective mint-capacity clamp.
- Trusted proxy source/IP is a bounded principal, not botnet-resistant identity.
  For a distributed-availability SLA, select authenticated account/wallet
  identity or another scarce credential at the proxy. The code does not claim
  IP throttling is authentication.
- Install the approved external monotonic/WORM checkpoint implementation and
  retain its signed store/verify and restore-ceremony evidence.
- A future public-range increase requires an owner-signed, hash-linked C1 policy
  successor and a new full operational manifest whose canonical `[0,999]`
  prefix still hashes byte-for-byte to the compiled consensus manifest. It does
  not change the consensus/SPV identity, but it is never an ad-hoc operator knob.

No fee, peg ratio, min/max mint economics, custody quorum, or consensus rule is
changed by these controls.
