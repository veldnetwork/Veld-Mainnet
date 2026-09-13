# btcVELD mint nullifier and C1 reservation state (MNP1 / MNP2 / MSP2)

Status: launch consensus specification for the fresh v2.7.88 genesis.

Every direct issuer-authorized or Bitcoin-SPV btcVELD mint consumes exactly one
Bitcoin deposit outpoint. In the public C1 path, C1F1 consumes the outpoint and
creates no supply; the exact later MNP2 credits the recipient without consuming
the outpoint a second time. The consensus state stores a fixed-size, exact set
commitment instead of a lifetime in-memory outpoint set. Every insertion
supplies an authenticated nonmembership witness. Its accumulator transition is
atomic with either the direct monetary credit or the C1 funded-lease transition.

This design is exact. It is not a Bloom filter, rolling hash, pruning window,
or arbitrary cap. It does not create false positives and does not forget old
deposits.

## Consensus state and ordering

The authenticated state is:

```
root         : 32-byte sparse-Merkle set root
count        : unsigned 64-bit accepted-insertion count
effect_root  : 32-byte ordered accepted-effect commitment
effect_count : unsigned 64-bit accepted-effect count
```

The tree has 256 levels. A canonical Bitcoin outpoint is
`<64 lowercase hex display-txid>:<canonical uint32 decimal vout>`. The vout has
no leading zero unless it is exactly `0`. The path is the SHA-256 key read most
significant bit first, from depth 0 through depth 255.

Transactions are evaluated in canonical block transaction order. Marker
outputs are evaluated in output order, although the one-marker rule means an
accepted mint transaction contributes at most one transition. Each insertion
must prove nonmembership against the immediately preceding root; a C1_MINT must
instead match the existing funded lease and leave that root unchanged.
All four fields are committed by `D_tokens` encoding v7 and are included in
the composed consensus state digest. Version 7 also commits the canonical C1
sequence authority and reservation/funding map described below; this is a
fresh-genesis consensus encoding, not a version-bump-compatible change to an
existing chain. The
sparse root/count authenticate exact set membership. The independent effect
root/count bind the canonical height, transaction index, marker output,
transaction ID, outpoint, and old/new sparse roots for every accepted
transition. It distinguishes direct `MINT`, supply-neutral `C1_FUND`, and the
later root-neutral `C1_MINT`, so an included paid-no-op carrier or a funding
effect cannot be mistaken for the transaction that credited supply.

The count advances once per successful root transition. `UINT64_MAX` fails
closed. A duplicate, stale proof, malformed proof, key collision, arithmetic
overflow, invalid recipient, or failed mint authorization changes neither the
money state nor the accumulator.

## Hash construction

All hashes are SHA-256 of the ASCII domain tag concatenated directly with the
specified body. Integer lengths are little-endian.

```
key(outpoint) = SHA256(
  "VELD_BTCVELD_MINT_NULLIFIER_KEY_v1|" ||
  uint32_le(byte_length(outpoint)) || utf8(outpoint))

empty_leaf = SHA256(
  "VELD_BTCVELD_MINT_NULLIFIER_EMPTY_LEAF_v1|")

occupied_leaf(key) = SHA256(
  "VELD_BTCVELD_MINT_NULLIFIER_OCCUPIED_LEAF_v1|" || key)

node(left, right) = SHA256(
  "VELD_BTCVELD_MINT_NULLIFIER_NODE_v1|" || left || right)

empty_effect_root = SHA256(
  "VELD/BTCVELD/MINT_ACCEPTED_EFFECT/v2")

next_effect_root = SHA256(
  "VELD/BTCVELD/MINT_ACCEPTED_EFFECT/v2" ||
  previous_effect_root || uint64_le(block_height) ||
  uint32_le(transaction_index) || uint32_le(marker_vout) ||
  uint32_le(byte_length(txid_text)) || utf8(lowercase_txid_text) ||
  uint32_le(byte_length(canonical_outpoint)) || utf8(canonical_outpoint) ||
  uint32_le(byte_length(effect_kind)) || utf8(effect_kind) ||
  uint32_le(byte_length(c1_allocation_id)) || utf8(c1_allocation_id) ||
  old_sparse_root || new_sparse_root)
```

`empty[256]` is `empty_leaf`; for depth 255 down to 0,
`empty[depth] = node(empty[depth+1], empty[depth+1])`. `empty[0]` is the
fresh-genesis empty-set root.

Collision resistance and second-preimage resistance of SHA-256 are the
security assumptions. Two distinct canonical outpoints producing the same key
fail closed rather than aliasing.

## Canonical compressed witness

A proof begins with a 32-byte, 256-bit sibling bitmap. Bitmap bits use the same
MSB-first depth order as tree paths. It is followed by one 32-byte sibling for
each set bit, in ascending depth order.

A zero bit means the sibling is `empty[depth+1]`. A set bit must carry a
non-default sibling. Explicitly encoding a default sibling is rejected. The
encoded byte length must equal `32 + 32 * popcount(bitmap)` exactly.

The minimum proof is 32 bytes and the hard maximum is 8,224 bytes. There is one
wire encoding for each mathematical proof: no trailing bytes, missing
siblings, redundant default siblings, or uppercase text carriers are accepted.

A nonmembership proof starts with `empty_leaf` at the target key and folds the
siblings upward. It is valid only if the result equals the current root. The
insertion replaces that leaf with `occupied_leaf(key)`, folds the same siblings,
and produces the next root. The same witness is a membership witness for that
key at the new root.

## Issuer MNP1 carrier

The issuer TOKEN MINT memo is ASCII:

```
MNP1;<canonical-outpoint>;<lowercase-hex-compressed-proof>
```

The entire memo is canonicalized by parse-and-reencode. The old raw-outpoint
memo is rejected. `preparetokenmint` does not accept an operator-supplied
witness: it queries the node's authenticated current-root proof service and
constructs the MNP1 memo itself.

## C1 reservation, exposure, cancellation, funding, and MNP2 credit

The public C1 address-allocation path first places an issuer-authorized `C1R1`
reservation on chain and, only after that carrier is 101 blocks deep, places an
issuer-authorized `C1E1` exposure marker. Both carry only the allocation id and
a blinded commitment over id, recipient, exact amount, exact P2TR script, and a
nonzero 32-byte blind. The Bitcoin address and script are not released to the
requester until C1E1 is itself 101 blocks deep.

Allocation ids are canonical 128-bit lowercase hex strings whose first 64 bits
are zero and whose final 64 bits encode a strictly increasing, nonzero sequence.
Every accepted C1R1 consumes exactly the next sequence. If descriptor state has
advanced but C1R1 never becomes canonical, C1C1 consumes that exact next
sequence without reserving capacity or revealing the script. This permanently
invalidates stale signed C1R1 bytes without retaining a lifetime id set.

The canonical marker memos are:

```
C1R1;<allocation-id>;<allocation-commitment>
C1E1;<allocation-id>;<allocation-commitment>
C1C1;<allocation-id>;<allocation-commitment>
C1F1;<allocation-id>;<p2tr-script-hex>;<blind-hex>;<outpoint>;<cfp1-hex>
```

C1F1 is accepted only for the exact active exposed allocation, after its
funding window starts and early enough to leave 100 further heights before the
unfunded lease expires. It opens the commitment and proves one unique Bitcoin
output with the exact script and amount, the exact derived display-order
`txid:vout`, membership of the stripped legacy transaction in the referenced
Bitcoin block, the required Bitcoin finality, and current sparse-set
nonmembership. C1F1 atomically inserts that outpoint, records `C1_FUND`, and
turns the lease into a funded lease without changing btcVELD supply.

The decoded CFP1 payload is:

```
"CFP1"                       4 bytes
bitcoin_block_hash           32 bytes, internal byte order
merkle_directions            uint32 little-endian
merkle_branch_length         uint8, 0..32
merkle_siblings              length * 32 bytes
legacy_bitcoin_tx_length     uint32 little-endian, 10..8000
legacy_bitcoin_transaction   exact stated length
compressed_nullifier_proof   remaining 32..8224 bytes
```

Direction bits above the branch length must be zero. The Bitcoin transaction
must exceed the Merkle-ambiguity floor and have exactly one output matching the
committed script and amount. The nullifier proof must consume the exact
remainder and be canonical.

The matching issuer TOKEN MINT memo is ASCII:

```
MNP2;<allocation-id>;<p2tr-script-hex>;<blind-hex>;<canonical-outpoint>
```

MNP2 must open the same commitment and match the funded lease's allocation id,
recipient, amount, script, and outpoint. It is the only mint form allowed to
consume that lease. C1F1 already inserted the nullifier, so MNP2 carries no
sparse witness and must leave the sparse root/count unchanged. Monetary credit,
the `C1_MINT` effect commitment, and lease deletion are one atomic consensus
transition. A failed MNP2 changes none of them.

`D_tokens` v7 commits the last allocation sequence, sequence-history count and
rolling history root. It serializes active reservations sorted by allocation
id. Each entry commits, in order, allocation id, sequence, recipient, blinded
commitment, amount, creation and pre-exposure expiry heights, exposed flag and
height, funding-start and funding-expiry heights, funded flag and height, and
funding outpoint. An unfunded unexposed lease expires after its first finite
term; an exposed but unfunded lease expires after its finite funding term; a
funded lease persists until exact MNP2. The encoding also commits the ordered
trailing-work window and authenticated redeem commitment used by capacity and
payout rules. Consequently, two states that can make different next-block
economic decisions cannot share a token-state digest merely because their
balances and supply are equal.

## Permissionless MSP2 carrier

The outer Veld marker remains `VELD_MSPV|<lowercase hex>`. Its decoded fresh-
genesis binary payload is:

```
"MSP2"                       4 bytes
bitcoin_block_hash           32 bytes, internal byte order
merkle_directions            uint32 little-endian
merkle_branch_length         uint8, 0..32
merkle_siblings              length * 32 bytes
legacy_bitcoin_tx_length     uint32 little-endian, 1..12000
legacy_bitcoin_transaction   exact stated length
compressed_nullifier_proof   remaining 32..8224 bytes
```

Direction bits above the Merkle branch length must be zero. The nullifier proof
must consume the exact remainder and be canonical. Consensus and the fees-only
relay signer both require magic `MSP2`; the old witness-free `MSPV` binary
format is rejected. The legacy transaction must also pass the existing
Merkle-ambiguity floor and all deposit/custody/finality checks.

## Derived proof index

The consensus authority is sparse root/count plus effect root/count. Accepted
transitions are also written atomically to the ordinary on-disk index under
`btcmn:`. Each derived row contains its canonical block height/hash,
transaction/output locator, outpoint, input witness, old root, and new root.

`getbtcveldmintstatus <outpoint>` scans canonical rows in transition order,
filters stale-fork rows by canonical block hash, verifies every insertion and
root-neutral credit, and updates only the requested target witness in memory.
It returns:

- distinct `consumed` and `minted` flags, `proof_version`, and `proof_hex`;
- authenticated `root` and `count`; and
- the matched `tip` and `tip_hash`;
- the accepted effect kind and C1 allocation id, when applicable; and
- separate consumer and credit locators. For a direct MINT they are identical;
  for C1 they identify C1F1 and MNP2 respectively.

The answer is released only if the reconstructed final root/count exactly
match the token ledger and the returned target proof verifies at that root.
Missing, corrupt, reordered, duplicated, or incomplete rows fail closed.
The node samples the accumulator only after briefly quiescing the consensus
transition sequencer, then releases that sequencer before the lifetime scan.
Canonical bodies are checked under brief per-height locks; the proof service
does not retain the chain mutex across the scan. Any start/end tip-height or
tip-hash drift is a normal retryable race, not permanent index degradation.

The index is rebuildable, not trusted consensus state. Startup/replay writes
the same accepted transition feed again in atomic batches. Reorg-orphan rows
may remain on disk, but canonical-hash filtering excludes them. A stable index
error latches proof production closed until restart/replay repairs it.

Current proof construction uses constant RAM but scans the lifetime canonical
mint-transition log, so an uncached query is O(number of accepted mints) and
the derived disk log grows linearly. Operators must monitor proof-RPC latency
and index health. This affects new-mint witness availability, not consensus
verification cost, which is always 256 tree folds per mint.

## Availability and failure behavior

A new mint cannot be created without a witness for the exact current root. No
trust is placed in the witness provider: any node can rebuild a witness from
canonical transitions, and every consumer verifies it against consensus.

If the local proof index is unavailable or degraded:

- `getbtcveldmintstatus` and `preparetokenmint` fail closed;
- the SPV mint operator waits and spends no replacement relay fee;
- existing btcVELD transfers, redeems, AMM operations, Bitcoin-header relay,
  and ordinary chain validation remain live; and
- already-carried valid mint proofs remain consensus-verifiable.

The safe recovery is to stop the affected proof service, preserve diagnostic
evidence, restart/replay the canonical chain to rebuild rows, and verify that a
status response's root/count/tip matches the node before reopening mint intake.
Never bypass the gate with a guessed proof, an empty proof on a nonempty root,
or a manually edited index.

## Same-block throughput and stale proofs

Two independently prepared direct mints normally reference the same parent
root. Only the first in canonical order can succeed; under the historical token
carrier contract the stale direct carrier is a paid no-op and must be rebuilt.
This is deterministic first-valid-writer behavior, not a replay ambiguity.
The C1 carriers are deliberately stricter: an invalid C1R1, C1E1, C1C1, C1F1,
or MNP2 makes the containing block invalid rather than silently landing as a
paid no-op.

Multiple mints can succeed in one block only when they are explicitly
sequenced: mint 2 proves against mint 1's post-root, mint 3 against mint 2's
post-root, and block ordering preserves that sequence. Ordinary independent
clients should assume one uncoordinated accepted mint per root/block. Mempool
revalidation removes entries whose witnesses become stale, and operator WALs
rebuild only after proving an old signed carrier is no longer visible.

## Later-finality-stall completion boundary

Before launch, every C1, MNP1, MNP2, and MSPV transition is closed. During
normal launch operation, all canonical forms are eligible for their ordinary
structural and stateful validation. If finality later stalls after the peg has
unlocked, C1R1, C1E1, direct MNP1, and MSPV are rejected because each creates
new exposure. Only C1C1 for the exact next missing sequence, C1F1 for an exact
already-exposed allocation, and MNP2 for an exact already-funded allocation
reach normal transition validation. The exception is phase-specific, not a
generic `MINT` permission: an MNP2-looking memo with a wrong allocation,
opening, recipient, amount, or outpoint is still invalid, and C1F1 still runs
the complete CFP1/Bitcoin-SPV and sparse-nullifier checks.

## Genesis and compatibility

This is a fresh-genesis consensus format. There is no in-place migration from
the lifetime exact set and no activation path for the old witness-free forms.
A chain that already accepted legacy issuer or MSPV mints must not apply this
change as an ordinary version bump: it needs a separately specified state
migration or a fresh genesis. The launch bundle uses the fresh-genesis path.

## Required qualification

Release qualification must include:

- independent pointer-trie differential roots/proofs;
- canonical proof and text-carrier rejection vectors;
- duplicate, stale, same-block sequential, and same-parent conflict cases;
- issuer-first and SPV-first cross-path replay tests;
- snapshot/restore, reset/replay, startup rebuild, and reorg-stale-row tests;
- missing/corrupt/index-write failure tests;
- proof scans that permit concurrent canonical-chain lock acquisition;
- RPC proof re-verification and operator root/count race barriers; and
- ASan/UBSan focused binaries plus the hermetic and regression suites.

Normative implementation: `include/consensus/btcveld_mint_nullifier.h`,
`include/core/btc_deposit_verify.h`, `include/core/onchain_tokens.h`, and
`include/core/mint_nullifier_index.h`.
