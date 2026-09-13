# btcVELD mint signer and shared-witness runbook

This runbook is mandatory for the public-mainnet configuration. A mainnet build
running a public test phase is still treated as production: do not enable the
development markers, bypass the shared witness, or run two active mint signers.

## Safety topology

- Exactly one issuer signer is active. Its root-owned `active-mint-signer` file
  contains the exact `mint_authority.signer_id` and is mode `0600`.
- Every current or future signer reaches one shared `veld_wt_reserve.py` instance
  and one witness state set: bounded active `mint-reservations.json`, chained
  append-only `mint-reservation-tombstones.jsonl`, and the independently archived
  full terminal receipts. Never deploy per-signer witness state.
- The witness is on the independent watchtower host. Its SSH key is authorized
  only through `watchtower-authorized_keys.example`'s forced command.
- The signer verifies reservation receipts with the same pinned ML-DSA public key
  used for watchtower beats. The private beat/receipt key remains on the
  watchtower.
- Production watchtower custody comes only from its local mainnet Bitcoin Core
  watch-only wallet and the exact, descriptor-hash-bound
  `custody-spks-operational.json` manifest through the signed C1 public end. Its
  canonical `[0,999]` prefix must be byte-identical to
  `custody-spks-consensus.json` and match `getpeginfo`. API custody and
  supplementary address lists are forbidden.
- Issuer headroom is `custody - backing_liability - margin`, where backing
  liability is live btcVELD supply plus every canonical REDEEM that lacks one
  exact marker-, destination-, amount-, and confirmation-matched Bitcoin payout.
  The watchtower rebuilds this set from both chains every cycle; payout-daemon
  state and restored caches are never authority.
- The public wrap allocator reaches the same host through a distinct SSH key
  forced only to `veld_wt_allocate.py`. Before an address is returned, it appends
  the next exact descriptor-index/address/script/recipient/amount binding to
  `wrap-allocation-authority.json`. The mint-signer key cannot append that ledger.
- Each issuer mint reservation independently looks up the registered allocation
  and resolves the MNP1 Bitcoin outpoint through the watchtower's local Core. A
  missing registration/output, wrong script/amount, insufficient confirmations,
  or changing Bitcoin tip refuses the reservation.
- Operationally, this means a **different SSH key** is required for allocation
  registration and mint reservation; sharing either private key or forced-command
  identity collapses the independent authorization boundary and is forbidden.

The signer persists a witness receipt before producing a randomized issuer
signature. It then persists the exact signed bytes, commits those bytes to the
witness, persists the commit acknowledgement, and only then returns the
transaction. A crash at any earlier point consumes capacity conservatively.

### Terminal archive hook contract

`reservation_ledger.terminal_archive_command` is argv, never a shell string. It
receives one compact JSON line on stdin with exactly `version`, `action`,
`entry_sha256`, `minimum_retention_until`, and `entry`; `action` is
`archive_terminal`. The digest is SHA-256
of the sorted-key compact JSON encoding of `entry`, whose kind is
`VELD_MINT_RESERVATION_TERMINAL_ARCHIVE`. The hook must use that digest as an
idempotency key, durably commit the exact `entry` object to independently
administered immutable/WORM storage, read the stored object back, verify the
digest, place it under COMPLIANCE object lock through at least
`minimum_retention_until` (ten years from the request), and only then return one
compact JSON object with exactly these fields:

```json
{"archive_id":"<stable object/version id>","durable":true,"entry_sha256":"<same 64 lowercase hex>","object_lock_mode":"COMPLIANCE","readback_sha256":"<same 64 lowercase hex>","retention_until":2147483647,"stored":true,"version":1}
```

Retries of the same digest must verify and acknowledge the already stored exact
object and extend retention when necessary. An existing key with different
bytes, timeout, write uncertainty, bad JSON, extra/missing response fields,
readback mismatch, non-COMPLIANCE mode, short retention, or digest mismatch must
fail. For restore,
export each stored `entry` object (not the transport wrapper) as a separate
`--receipt-archive` input. Selecting the storage provider, retention/legal-hold
policy, credentials, and independent rollback authority is an operator ceremony
decision; the source does not pretend a writable local directory is WORM.

## First deployment

1. Install identical audited copies of `veld_peg_solvency.py`, `veld_chain_identity.py` and
   `rpc_url_policy.py` on the signer and watchtower; install `swap_admission.py`
   on the watchtower for signed C1 policy verification; install `veld_signerd.py`
   only on the signer and
   `veld_wt_reserve.py`, `veld_wt_allocate.py`, `veld_watchtowerd.py`, `veld_custody_binding.py`, and
   `veld_redeem_liability.py` only on the watchtower. Record and compare SHA-256
   hashes before enabling SSH keys.
   Set the same independently reviewed `veld_rpc.expected_chain` pins on both
   services. The witness verifies them before loading mutable ledgers, again
   while holding its state lock, and before returning any reservation, commit,
   allocation or initialization response. Missing pins stop the service; never
   populate them automatically from whichever RPC server answers. Existing
   ledgers and receipts still require the reviewed migration/reconciliation
   procedure; adding pins does not establish historical authority.
2. Build the custody descriptor with `custody-build-descriptor.sh`. Archive its
   descriptor, `custody-spks-operational.json`, and
   `custody-spks-consensus.json`; confirm both manifest hashes and the descriptor
   hash in the actual watchtower config.
3. On the watchtower, create `/var/lib/veld-wt` owned by the service UID and mode
   `0700`. Initialize `mint-reservations.json` as exactly (the hash is 64 zeroes):

   ```json
   {"reservations":[],"terminal_count":0,"terminal_head_sha256":"0000000000000000000000000000000000000000000000000000000000000000","version":3}
   ```

   Initialize `mint-reservation-tombstones.jsonl` as exactly:

   ```json
   {"kind":"VELD_MINT_RESERVATION_TOMBSTONE_LOG","version":1}
   ```

   Terminate both with a newline, set service ownership and mode `0600`, and fsync
   both files and the directory before activation. Ledger version 3 retains full
   ML-DSA receipts only while reorg-relevant; strictly beyond 100 confirmations it
   archives the full receipt first, appends and fsyncs a compact hash-chained
   terminal tombstone, then checkpoints the bounded active snapshot. An older
   ledger format is not accepted or auto-migrated by the live forced command.
4. In the same stopped first-start ceremony, temporarily set
   `wrap_allocation_authority.allow_initial_ledger_creation` to true and run
   `veld_wt_allocate.py /opt/veld-wt/watchtowerd.conf --initialize` locally once.
   Verify the owner-only empty version-1 ledger begins at descriptor index 1000,
   then immediately set the flag false. Never repeat this after an allocation.
5. Configure `watchtowerd.conf` with `production: true`, the compiled issuer ID,
   a unique witness ID, the exact issuer P2PKH script, local Bitcoin Core and Veld
   RPC commands, the custody manifest/hash, and the beat signing key. Set the BTC
   confirmation count to the exact compiled `getpeginfo.spv_k_btc`; any mismatch
   is a hard startup/read failure. Pin the owner-confirmed C5 values exactly:
   `btc.tip_age_alert_secs=3600` and `btc.max_tip_age_secs=7200`; production
   refuses either omitted or changed value. Every mint reservation now refuses
   Bitcoin Core in IBD, with `blocks != headers`, behind Veld's
   in-consensus Bitcoin-header height, or with an older best-block timestamp.
   Ages 3,600 through 7,199 alert while full service continues. At age 7,200,
   the watchtower enters recovery-only and continues lifecycle-only solvency
   beats; the reserve witness refuses first-seen reservations while exact
   durable reservation retries, commits, and reconciliation remain available.
   Configure every `reservation_ledger` row/byte/free-space ceiling explicitly and
   an idempotent external/WORM archive command administered outside the witness
   host. The hook must durably store the exact digest-keyed archive request before
   acknowledging it; hook refusal, malformed acknowledgement, capacity exhaustion,
   or low disk space fail closed before terminal history is removed. These are
   operational capacity values and do not change mint amounts or eligibility.
   The config, beat private key, and passphrase
   are mode `0600`; the state directory is `0700`.
6. Pin the beat public key on the signer as
   `/opt/veld-signer/watchtower-beat-pubkey.hex`. It must be a regular non-symlink
   file and not group/world writable.
7. Create a private signer config from `signer-config.example.json`. The issuer
   ID and witness ID must exactly match the witness config. The witness command
   must use `BatchMode=yes`, a finite connection timeout, the dedicated SSH key,
   and the forced command. Keep
   `authority_state_activation_marker=/opt/veld-signer/signer-authority-state.json`
   exact. Set config/key/passphrase files to `0600`.
   Review and set every `veld_rpc.expected_chain` pin as described in
   [ISSUER-CHAIN-BINDING.md](ISSUER-CHAIN-BINDING.md).
8. With both forced-command SSH keys still absent and every signer process
   stopped, run exactly once on the signer host:

   ```sh
   /usr/bin/python3 /opt/veld-signer/veld_signerd.py --initialize-authority-state
   ```

   This ceremony creates `signer-state.json`,
   `c1-reservation-signer-state.json`, and `issuer-prevout-leases.json` as one
   empty authority set, fsyncs each owner-only file, and commits
   `signer-authority-state.json` last. Normal signing never auto-creates a
   missing member. The version-two marker binds the set to the reviewed chain
   pins. Existing pre-marker files and version-one markers require independent
   offline chain reconciliation; this command never adopts or resets them.
   It also refuses any one- or two-file partial set. If a fresh
   initialization stops before all three files exist, or any member is later
   missing, keep ingress disabled and treat it as a restore/reconciliation
   incident; never fill the missing file by hand. Re-running the command after
   activation performs an idempotent full parse of all three members and the
   same cross-capability signed-input reconciliation (including safe one-way
   migrations); it never treats existence and file mode alone as validation.
9. Write the one active signer ID to `/opt/veld-signer/active-mint-signer` using an
   atomic root operation and mode `0600`. Do not put this marker in a reusable
   image or restore archive.
10. Arm `watchtower-required`. Do not create `caps-only-ok`, `beat-unsigned-ok`, or
   any other development opt-out on a production/mainnet-build host.
11. Install the allocator's dedicated public key with the
    `veld_wt_allocate.py` forced-command line. The signer uses a different key
    forced only to `veld_wt_reserve.py`; neither key may invoke the other command.
12. Start the local verification nodes and production watchtower first. Confirm a
   fresh, signed, tip-bound beat and local Core descriptor inventory. Then enable
   the witness forced-command key, and enable only the designated signer.
13. Run the release verification and a tiny mint. Confirm the allocation request
    and descriptor index match on wrapd and witness, then confirm the same
    reservation ID, amount, recipient, signed-transaction digest, and txid in
    signer state and witness ledger before raising limits.

## Planned signer failover

There is no active/active mode. Stop and disable the old signer/minter ingress,
arm `WITNESS_RECONCILIATION_REQUIRED` on the witness, copy the complete old signer
state to the review set, and follow the restore reconciliation below. Only after
the witness union is applied may two operators change the active signer IDs and
install a new `active-mint-signer` marker. Remove the old signer's forced-command
key before enabling the new one.

## Backup rules

- Back up all witness authorization state (`mint-reservations.json`,
  `mint-reservation-tombstones.jsonl`, and
  `wrap-allocation-authority.json`), every active and retired signer state, the custody
  descriptor/SPK manifest, configs, key pins, and append-only deployment hashes as
  one consistency set. Preserve multiple generations on immutable/off-host media.
- Never restore `active-mint-signer`, SSH `authorized_keys`, service enablement,
  or an absent HALT marker from backup. They are live authorization state.
- Use the `signer` role of `veld-backup-secrets.sh` for the issuer authority
  host. It takes the same `.signerd.lock` used by both forced-command
  capabilities while archiving the three journals and deterministic staging
  directory. The producer excludes `active-mint-signer`, and the safe archive
  inspector rejects any old or custom archive that contains it. A timeout
  waiting for a quiescent signer is a failed backup, never a reason to copy the
  files unlocked.
- A witness-state restore is unsafe by itself: an older active snapshot or truncated
  tombstone chain may omit already issued reservations and recreate headroom. The
  exact tombstone log, every signer state, and external/WORM full-receipt archives
  are mandatory union inputs. A tombstone is replay-prevention state, not a
  substitute for its digest-bound full receipt archive.
- An older allocation ledger may omit an address already returned to a user.
  Restore it only as the immutable consistency generation paired with the
  C1 version-3 wrapd journal, and compare every request, index, address, script,
  recipient and amount before enabling either SSH key. Missing evidence is a
  blocker, not permission to initialize a new ledger.
- Redemption liability has no restorable authority file or manual release flag.
  After every restart the watchtower must complete a fresh, tip-coherent lifetime
  redeem-page walk and complete Bitcoin wallet-history reconciliation before it
  may publish another heartbeat.

## Any witness or signer-state restore

1. Stop the mint ingress, minter, every issuer signer, watchtower daemon, and
   witness SSH account. Confirm no process retains the issuer key.
2. **Before copying or replacing any backup file**, create
   `/var/lib/veld-wt/WITNESS_RECONCILIATION_REQUIRED`, owned by the witness service
   UID and mode `0600`, and fsync it and `/var/lib/veld-wt`. If a restore replaced
   the whole directory, recreate and fsync this marker before starting anything.
   For a one-time version-2 ledger migration, keep this HALT armed, preserve and
   hash the byte-exact v2 file, and create only the empty v1 tombstone-log header
   shown in First deployment. The offline reconciliation tool can normalize v2
   full-receipt rows into v3 under the same artifact/two-approval procedure; the
   live forced command cannot. Never use this path if terminal history already
   exists or the complete v2 receipt inventory is uncertain.
3. Keep all services stopped. Confirm the mint mempool is empty, the minter queue
   is empty, and record a coherent Veld tip hash/height, supply, local Core custody,
   descriptor hash, and margin.
4. Collect the restored active ledger, its exact terminal tombstone log, **every**
   active and retired signer-state file, and every digest-bound terminal object
   from off-host/WORM receipt storage. Missing inventory is a blocker. Each compact
   tombstone must resolve to the exact full receipt object named by its archive
   digest; an aggregate list or signer state alone is not enough to clear a restore.
5. Wait until the same canonical chain is strictly more than 100 blocks beyond the
   quiesced height. Exactly 100 blocks is insufficient. Re-read the exact tip,
   supply, custody, descriptor-bound UTXOs, mempool, and queue.
6. Create a `VELD_WITNESS_RESTORE_RECONCILIATION` version-2 JSON artifact bound to
   both `restored_ledger_sha256` and `restored_terminal_log_sha256`, plus the sorted
   SHA-256 list of every signer
   state, immutable ledger snapshot, and receipt archive (use empty lists only
   when that source class truly has no file). Bind the exact operator-policy and
   beat/receipt public-key file SHA-256 values too. Set
   `source_inventory_complete: true`; include issuer/witness IDs,
   coherent inventory/wait evidence, and exactly one row for every unioned
   reservation. Mark it `outstanding` unless its exact known txid has canonical
   block hash/height evidence strictly deeper than 100 blocks.
7. Serialize the artifact without `approvals` using sorted keys and compact JSON.
   Two distinct operators independently review it and sign those exact bytes with
   `veld-keygen sign-release`. Add both operator IDs, the statement SHA-256, and
   lowercase signature hex to `approvals`. The approval policy maps each ID to its
   pinned public-key file.
8. Validate without mutation, then apply:

   ```bash
   python3 /opt/veld-wt/reconcile_witness_restore.py \
     --state-dir /var/lib/veld-wt \
     --artifact /secure-review/witness-restore.json \
     --approval-policy /secure-review/operator-policy.json \
     --keygen /opt/veld-wt/veld-keygen \
     --beat-pubkey /secure-review/watchtower-beat-pubkey.hex \
     --signer-state /secure-review/mint-primary-state.json \
     --signer-state /secure-review/retired-mint-signer-state.json \
     --ledger-snapshot /secure-review/worm-witness-ledger.json \
     --receipt-archive /secure-review/worm-receipts.json

   # Repeat every signer/snapshot/archive argument and output above, then:
   python3 /opt/veld-wt/reconcile_witness_restore.py ... --apply
   ```

   The tool verifies every ML-DSA receipt, signed transaction, chained tombstone,
   and exact WORM archive digest; unions all reservations; retains every non-final
   reservation as charged; stores byte-exact mode-`0600` backups of both restored
   files; atomically fsyncs the reconciled active ledger; and finally renames the
   HALT marker to an artifact-bound audit marker. Existing tombstones remain
   append-only. Newly proven-final full rows are archived/compacted by the live
   witness before it can admit new work. Never delete or rename the HALT marker
   manually.
9. If a pre-accounting signer state is encountered, reconcile it separately with
   `reconcile_mint_state.py`. It requires exact old-state binding, complete row
   disposition evidence, coherent inventory, a strictly-greater-than-100-block
   wait, an artifact binding to the exact pinned approval-policy SHA-256, and two
   operator approvals. `veld_signerd.py` will not auto-migrate it.
10. Re-run deployment verification. Start the watchtower and wait for a fresh beat;
    then enable only the one active signer and finally the minter. Start with a tiny
    cap and compare both durable journals.

## Ceremony-only launch gates

Code readiness does not complete the launch ceremony. Before public mainnet
activation, operators must independently pin the Bitcoin Core release-key
fingerprint, verify its authenticated `SHA256SUMS`, generate/distribute custody
shares and beat/operator keys, record binary/config/descriptor hashes, approve the
initial witness inventory, prove backups/restores, and sign the final activation
record. A missing person, key, host, hash, backup, or signature is a launch blocker,
not a reason to weaken a check.
