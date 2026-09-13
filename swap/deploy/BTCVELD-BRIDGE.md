# btcVELD bridge deployment gates

The live bridge now fails closed unless its two independent policy planes are
configured. Do not point production services at the development escape hatches.

## Mint signer

Install `veld_signerd.py`, `veld_peg_solvency.py`, `rpc_url_policy.py`, the
issuer key material, and `signer-config.json` on the isolated issuer signer. Start from
`signer-config.example.json` and point `veld_rpc` at a Veld node operated by the
signer—not the mint coordinator's node. The signer derives input outpoints from
the transaction, resolves their exact value, script, and confirmations through
that node, and accepts only the exact 100,000-unit mint fee.

`inputs[].value` and `inputs[].prev_script_hex` sent by a coordinator have no
signing authority and are no longer transmitted by `veld_mintd.py`.

Production also requires the exact single-active/shared-witness topology in
`signer-config.example.json`. The independent witness durably allocates fleet-wide
headroom before any signature exists and binds the reservation to the exact signed
transaction before it can be returned. Deploy, fail over, back up, and restore it
only through [MINT-SIGNER-WITNESS-RUNBOOK.md](MINT-SIGNER-WITNESS-RUNBOOK.md).
Before reserving headroom, that witness also requires the exact wrap request in
its own append-only allocation ledger and resolves the MNP1 Bitcoin outpoint
through its independently operated mainnet Core. Confirmation depth, script and
exact satoshi amount must match the registered recipient binding. The minter's
local journal and JSON claims have no signing authority.
Legacy signer state must pass `reconcile_mint_state.py`; a restored witness ledger
must pass `reconcile_witness_restore.py`. Both paths fail closed and require two
operator approvals.

## Redemption authority and 3-of-5 custody

1. Create the Taproot `multi_a(3,...)` custody descriptor using five keys generated
   and held on five independent signer hosts. `scripts/btcveld-taproot-custody-proof.sh`
   exercises the same 3-of-5 PSBT construction on regtest.
2. Import only the public descriptor into the coordinator wallet. It must remain
   watch-only.
3. Start from `redeemd-threshold.example.json`. Put `authority_db` outside the
   disposable runtime/state directory on durable storage.
4. On each signer host, install one private descriptor share, its own Veld node,
   `veld_payout_signerd.py`, `veld_redeemd.py`, `rpc_url_policy.py`,
   `veld_redeem_commitment.py`, `veld_custody_binding.py`, and a private copy of
   `payout-signer-config.example.json`. Pin the exact Taproot custody scriptPubKey.
5. Restrict the coordinator SSH key to the payout signer forced command shown in
   `signer-authorized_keys.example`.
6. Before launch, fund distinct small outputs at descriptor indices 0, 1000,
   and the signed public-range end (10999 for the launch policy). For each index,
   preserve a signed report proving that three distinct signer hosts finalized
   and spent the output, and a separate report proving that two distinct signer
   hosts did not finalize the same policy-valid drill PSBT. Record the funding
   outpoint, exact descriptor index/script, signer IDs, PSBT/transaction hashes,
   3-of-5 spend txid, and detached report hashes. A regtest proof, unfunded PSBT,
   or one successful index is not launch evidence for the other two boundaries.

On first observation—before the 100-block maturity delay—the coordinator fsyncs
the burn into SQLite and sends it to all five signers. A run continues only after
an intersecting threshold quorum has independently found the burn in its own Veld
node and fsynced it. At payout, three signers independently re-check Veld
canonicality/finality, every Bitcoin prevout, the exact destination, amount,
change, fee, and the burn marker before contributing a PSBT signature.

The coordinator and every signer pin the complete operational custody manifest.
Inputs at operator indices 0--999 remain ordinary eligible reserve. An input at
public index 1,000 or above is excluded until `getbtcveldmintstatus` reports the
exact canonical `C1_MINT` credit for that Bitcoin outpoint and the credit is
strictly more than 100 Veld blocks deep. The accepted and credit locators must
be identical and their carrier blocks canonical under one stable tip snapshot.
Signers repeat this check immediately before key use, and the coordinator
repeats it after the threshold quorum before broadcast. Payout change may return
only to indices 0--999. These rules prevent a redemption from spending a funded
public deposit before its corresponding btcVELD mint is irreversibly settled.

Each signer atomically commits to the first raw payout transaction it reviews.
Because any two 3-of-5 quorums intersect, split-brain coordinators cannot obtain
valid signatures for two different payouts. Every broadcast also carries a
41-byte `VLDR\x01 || burn_txid || vout` OP_RETURN. The Bitcoin wallet/chain marker
is the paid-state authority after local-state loss, stale restore, or a crash;
Bitcoin reorg recovery rebroadcasts the exact same transaction rather than using
new reserve inputs.

`single_wallet_dev` is rejected unless `allow_unsafe_single_wallet` is explicitly
true. That mode is for isolated fixtures only and is not a production fallback.

## Custody address allocator separation and migration

Descriptor index 0 is consensus-bound to the launch-live permissionless SPV
deposit path. It must never be returned by the issuer `/wrap` allocator and must
never carry a VELD recipient label. Indices 1-999 are also reserved from public
C1 allocation. `custody-build-descriptor.sh` therefore produces two byte-pinned
manifests from one descriptor: the compiled consensus/SPV prefix `[0,999]` and
the launch operational range `[0,10999]`. It imports the latter as an inactive,
cursorless descriptor. Production `veld_wrapd.py` independently requires that
exact inactive operational range, re-derives every operational script, verifies
that the canonical `[0,999]` prefix has the separately pinned compiled hash,
and selects unused public indices 1,000--10,999 through its durable private
CSPRNG permutation. No active Core `next` cursor may reveal the public C1
allocation sequence, and index 0 may never have a VELD-address label.

This is a mandatory migration gate for every wallet created by an older script
that imported the descriptor with `next_index: 0`:

1. Stop wrap ingress and both issuer/SPV minting before inspecting or changing
   the wallet. Keep the halt in place throughout reconciliation.
2. Record `listdescriptors false`, derive exact index 0 from the pinned
   descriptor, and record `getaddressinfo` plus all wallet transactions and
   UTXOs for that address.
3. If the wallet has no unresolved legacy issuer allocations, import the exact
   full operational range `[0,10999]` with `active:false` and no `next_index`,
   then retain both before/after records and both manifest hashes. Do not call
   `getnewaddress` to advance a cursor; public indices come only from the
   allocator's witnessed private permutation.
4. If index 0 has ever carried a VELD recipient label or issuer request, treat
   the wallet as cross-path contaminated. Do not relabel it, delete history, or
   guess which mint path applied. Reconcile every index-0 deposit against both
   Veld mint paths and replace/reset the public-test custody state through the
   controlled ceremony before resuming. This condition is a mainnet blocker.
5. Treat any historical issuer allocation in indices 1-999 as legacy state.
   Reconcile it against the old journal, deposits, and mints before cutover; do
   not insert it into the C1 public allocation ledger or reuse its index.
6. On the independent watchtower, initialize
   `wrap-allocation-authority.json` before the public allocator journal. Temporarily
   set `wrap_allocation_authority.allow_initial_ledger_creation` to `true`, run
   `veld_wt_allocate.py /opt/veld-wt/watchtowerd.conf --initialize` locally once,
   verify the mode-0600 empty version-1 ledger, then set the flag back to `false`.
   Install the allocator SSH key only for the separate `veld_wt_allocate.py`
   forced command; never reuse the mint signer's `veld_wt_reserve.py` key.
7. During the audited first-start ceremony only, verify the descriptor is
   inactive/cursorless and that no prior allocation journal should exist;
   temporarily set
   `allow_initial_allocation_store_creation` to `true` and start once. The
   service must fsync the empty journal and intentionally exit. Immediately set
   the flag back to `false`, then start `veld_wrapd.py` only after its production
   startup check passes. Verify issued addresses are unique manifest indices in
   1,000--10,999 and match the journal's durable private permutation evidence.
   A missing journal after this point is an incident,
   never permission to repeat initialization.
8. Install `nginx-wrapd.conf` inside the authenticated TLS wallet server and
   require `nginx -t` to pass before reload. The desktop uses the exact
   `/wrapd-api` prefix; port 8097 remains loopback-only and no catch-all proxy is
   permitted. Verify authenticated GET `/wrapd-api/admission` and `/health`,
   then verify an unauthenticated request is rejected before launch.

Reserving indices 0-999 leaves indices 1000-10999 for launch public allocation.
Production now requires the explicit capacity-policy block in
`veld_wrapd.config.json`, stateless admission work, a crash-safe exactly-once
allocation journal, persistent principal/destination quotas, and a configured
reserve threshold. Review `swap/WRAP_ALLOCATOR_CAPACITY.md` before deployment.
Its example resource values are not owner approval; authenticated principal and
external rollback/WORM authority remain launch decisions. No peg economics are
changed by this allocator policy.

## Issuer mint allocation binding

The production mint coordinator must read the **same live journal file** as
`veld_wrapd.py`; a copied, periodically synchronized, reconstructed, or
independently initialized file is not an authority. Add the complete C1 binding
to the `veld_mintd.py` production configuration, using the same values reviewed
for wrapd:

```json
"allocation_store": "/var/lib/veld-wrapd/allocations.json",
"allocation_store_max_bytes": 67108864,
"public_capacity_config_sha256": "REPLACE_WITH_SHA256_OF_EXACT_OWNER_SIGNED_C1_POLICY_BYTES",
"public_descriptor_range_end": 10999,
"custody_manifest_sha256": "REPLACE_WITH_EXACT_EXTENDED_0_10999_MANIFEST_SHA256",
"custody_consensus_manifest_sha256": "REPLACE_WITH_COMPILED_CANONICAL_0_999_PREFIX_SHA256"
```

Production startup fails closed if any field is omitted, the path is not
absolute, or the owner-only journal is absent, linked, oversized, malformed, or
unreadable. The operational manifest must cover exactly `[0,signed_public_end]`;
its canonically reconstructed `[0,999]` prefix must hash to the manifest identity
compiled into `getpeginfo`. This preserves the consensus/SPV identity while C1
uses public allocation indices 1000 and above. Run wrapd and mintd under a
deployment identity that can read this single mode-0600 journal without
weakening its permissions.

For every candidate Bitcoin UTXO, mintd now requires an `issued` journal record
whose request ID, custody address, descriptor script, VELD recipient, and exact
satoshi amount all match. `reserved`, unallocated, wrong-recipient,
wrong-script, and under/overpaid outputs remain in custody but are held
unminted. Mintd re-reads the journal immediately before recording mint intent,
so an allocation change between wallet discovery and mint processing cannot
fall back to a wallet label. Treat any resulting HALT as an allocation-authority
incident and reconcile the live journal, Core descriptor cursor, custody UTXO,
and operator backup before removing it.

The production C1 allocator journal is version 6. Its explicit intermediate
states cover descriptor allocation, independent-witness durability, C1
reservation/exposure, funding, exact mint credit, rollback, and bounded terminal
compaction. If Core advances but the independent witness has not durably bound
the allocation, that address is never returned and mintd never accepts it. An
exact retry resumes the same descriptor index and allocation id; it never
consumes another index or invents a replacement identity. Older production
journals are rejected rather than silently migrated. Narrow legacy-fixture
readers used by tests are not a production migration path.

`wrap-allocation-authority.json` is authorization state. Back it up with the
version-6 wrapd journal, descriptor manifest, bounded active mint-reservation
ledger, chained terminal tombstone log, digest-bound full-receipt WORM objects,
coordinator checkpoints, and signer state as one immutable consistency set. A
missing, truncated, prefix-rolled-back, or rebuilt copy is a mint HALT, never
permission to repeat one-shot initialization.

Every public address/index and C1 allocation id is one-use and is never
reassigned. Exactly one proven Bitcoin outpoint can fund an active allocation;
C1F1 consumes that outpoint and MNP2 later performs the root-neutral credit.
Additional or late payments to the same script are not a second public mint
authorization and require explicit recovery handling. Changing that policy
requires a separate protocol/economic decision.
