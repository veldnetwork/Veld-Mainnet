# btcVELD launch/liveness gate and anchor consensus rules — owner record entry

**Status:** DRAFT FOR OWNER SIGNATURE — design selected in working session
2026-07-16. Per the MAINNET_GO approval rules, this becomes policy only when
signed with owner, UTC timestamp, and source-tree SHA-256.

**2026-08-05 supersession:** btcVELD mint, redeem, public WRAP, and the
four-band AMM wait for the chain's first completed seven-validator finality
activation. The threshold is a one-time latch: falling below seven later does
not close the peg. Parts 2 and 3 remain the anchor safety design; Bitcoin
anchors are additive security, not another economic activation gate.

**Scope:** four consensus rules that must be frozen into the August 30 fresh
genesis, plus the operational daemon values that follow from them. These
rules supersede parts of A3 as recorded. Anchor effectiveness remains a
function of real finality state rather than an operator-set height. Economic
launch permission is separately derived from the compiled launch profile and
the retained later-liveness rule.

---

## Part 1 — Launch/liveness gate (superseding consensus rule)

### Rule

btcVELD issuer mint, redemption, public WRAP, and the four-band AMM become
available after the chain completes its first qualified seven-validator
finality activation. Every path derives that state from consensus; there is no
operator flag or separate activation ceremony. A promoted Bitcoin anchor is
not required to unlock the peg.

After activation, a later finality stall pauses C1R1/C1E1, direct MNP1, and
MSPV new exposure while
preserving only exact C1C1/C1F1/MNP2 completion for allocations already in the
required canonical lifecycle state. Redeem remains available. On 2026-07-21,
the owner ratified the implemented 60-block liveness window and continued AMM
swaps during such a later stall. The detached post-freeze owner signature must
still bind those choices to the final source and evidence. Finality and anchor
records remain digest-committed additive security and continue to constrain
anchor targets.

### What it replaces

This replaces the earlier fresh-genesis-live draft and the older requirement
for both finality and a promoted anchor. Anchor effectiveness remains
state-derived, but it is not reused as an economic permission.

### Rationale

The single consensus-derived gate keeps consensus, mempool, RPC, services, and
UI in agreement. The one-time threshold establishes initial validator
participation without turning every later validator-count fluctuation into a
peg outage. Bitcoin anchoring adds defense only when the chain can truthfully
produce it.

### Required tests

- Before activation, AMM, mint, and redeem reject atomically; after the first
  qualified activation they become available without an anchor.
- A later finality stall rejects C1R1/C1E1, direct MNP1, and MSPV without
  partial token state mutation; exact canonical C1C1/C1F1/MNP2 remain
  executable, and malformed completion carriers remain invalid.
- Same-carrier and no-anchor MINT + first-seed candidates produce identical
  economic permission; a malformed optional anchor cannot partially mutate
  parent state or close launch economics.
- Reorg and replay reproduce identical token, AMM, header, anchor, and digest
  state on Linux and native Windows UCRT64.

---

## Part 2 — Anchor consensus rules

Four rules, all frozen at genesis.

### R1 — Anchor target must be finalized

An anchor operation is valid only if its `(veld_height, veld_block_hash)`
pair matches a block that the chain's own finality state has **finalized**.
An anchor naming a height that is not yet finalized, or naming a hash other
than the finalized hash at that height, is invalid.

**Replaces:** the operator-side `anchor_lag` config
(`swap/veld_anchord.py:350`, default 2). That parameter is deleted, not
retuned. The audit's finding stands as written: a shallow operator
`anchor_lag` is not a consensus defense because any submitter can bypass the
daemon. Safety cannot live in a config file that the adversary is not obliged
to use.

**Kills the partition attack.** The reviewed attack — two valid Bitcoin proofs
binding competing Veld hashes during a network split, each side then rejecting
the other regardless of work — requires anchoring a block that is not
canonical. Under R1 this is impossible: during a partition neither side reaches
a two-thirds quorum, so neither side finalizes, so neither side can record any
anchor at all. The anchor set cannot cement a split it cannot observe.

**Kills the pre-mined secret fork.** A secret chain cannot be finalized by an
honest validator set, so it cannot be anchored.

### R2 — Accept window widened to 1,000 blocks

At carrying height `C`, an anchor targeting `veld_height H` is accepted only
if `H >= C - 1000`.

**Replaces:** the effective `C - 99` bound. Confirmed 2026-07-16:
`MAX_REORG_DEPTH = 100` (`include/core/constants.h:79`), so the current window
lies entirely inside the reorg horizon — every recordable anchor targets a
still-reorganizable block. That is the defect A3 identified.

**Why widening is correct, not a loosening.** Under R1 the safety property is
*finalized*, not *recent*. A finalized checkpoint 500 blocks back is exactly as
immovable as one 30 blocks back; recency was never the thing protecting the
anchor, and under the old window recency was actively the thing endangering it.

**Why widening is necessary.** The anchor round trip is: finalize (up to one
checkpoint interval) → build and broadcast the BTC transaction → wait
`BTCVELD_ANCHOR_BTC_CONFS` confirmations → a submitter carries the SPV proof
back onto Veld. In good weather this is roughly two hours; the old 99-block
window is only about five hours wide at the 180-second target. A fee-patient
strategy — which is exactly what `veld_anchord.py:185` was built to do
("anchor at cheap dips, bounded by a hard deadline") — routinely produces a
proof that arrives stale, is rejected, and has already cost its Bitcoin fee.
The current window and the current daemon design are mutually incompatible.
1,000 blocks is about 50 hours, which makes patience affordable.

**Why a window at all.** An unbounded window permits anchor spam targeting
ancient heights. A bounded one keeps the accepted set adjacent to the live
chain. Note that spam is already weakly priced: each anchor requires a real
Bitcoin transaction, `AnchorSet::Record` is first-seen-wins per Veld height,
and under R1 a spammer can only ever reinforce what is already finalized and
immovable.

### R3 — Activation is dynamic, not a constant

`BtcVeldAnchorActive(height)` becomes a function of the finality state, not of
`BTCVELD_ANCHOR_ACTIVATION_HEIGHT`. The constant is retired along with the
"ARMED = 1" semantics documented in `btcveld_anchor_params.h`.

This closes the code-readiness blocker recorded in A3 (the gate currently
fails closed while `BTCVELD_ANCHOR_ACTIVATION_HEIGHT` is nonzero and
`BTCVELD_FINALITY_ACTIVATION_HEIGHT` is zero) by removing the mismatched pair
rather than by reconciling two constants that could drift again.

### R4 — Bitcoin confirmations = 6

`BTCVELD_ANCHOR_BTC_CONFS = 6`.

An admitted proof is first staged in its exact Veld carrier A. It becomes a
permanent, irreversible commitment only after a later retained finality record
finalizes a prefix containing A and consensus rechecks that the exact Bitcoin
proof block is still six confirmations deep. The highest promoted floor binds
the target T, proof carrier A, Bitcoin block and txid, and the full authorizing
finality record including its certificate carrier C. Consensus thereafter
rejects a substituted T and any reorganization that would erase C, regardless
of work. Six confirmations keep that irreversible transition from resting on
a shallow Bitcoin fact.

This permanent consensus floor protects nodes that observed or imported it;
it does not let a brand-new node discover an anchor omitted from the candidate
history it is replaying. Fresh-sync long-range protection therefore uses a
separate, explicitly imported weak-subjectivity artifact signed by the
owner-approved dedicated 2-of-3 offline ML-DSA-65 anchor keyset. The artifact
pins exact T/A/C hashes before replay. It is not the URL-fetched rolling
checkpoint feed, does not reuse the automated fleet checkpoint key, and is not
described as trustless Bitcoin discovery. Without a verified artifact, a fresh
node is PoW/finality-protected but not Bitcoin-anchor-pinned.

### Required tests

- R1: anchor naming an unfinalized height → invalid. Anchor naming a finalized
  height with a non-canonical hash → invalid. Anchor naming the finalized
  (height, hash) → valid.
- R1 partition drill: simulated split, neither side finalizes, no anchor
  recordable on either side; on heal, the losing side reorgs by work with no
  anchor conflict.
- R2 boundary: `H = C - 999` / `C - 1000` / `C - 1001` (last invalid).
- R2 round-trip drill: anchor a finalized checkpoint after a simulated 40-hour
  Bitcoin confirmation delay → still accepted.
- R3: replay from genesis produces the identical state-derived anchor-
  effectiveness transition with no activation constant present; no node-local
  flag can advance or delay it.
- R4: anchor SPV proof at 5 confirmations → rejected; at 6 → accepted.
- Reorg of the Bitcoin chain unwinding an anchor transaction below 6
  confirmations before promotion → staged proof dropped, no permanent floor.
- A proof carrier is reorganizable before its covering C; after promotion,
  common ancestor C-1 is rejected before disconnect and C is accepted.
- Advance more than 1,000 Veld blocks: the highest T and C floor remain
  enforced and replay-identical after the active proof window retires.
- Signed bootstrap artifact: wrong domain/key/network/genesis, one signature,
  altered T/A/BTC/finality/C, stale/lower/conflicting sequence, truncation, and
  trailing bytes all fail closed; two distinct valid ceremony signatures pass.
- Fresh IBD branches that omit A, substitute T, or fork before C are rejected
  when the verified artifact is installed before replay.
- Digest equality across all of the above on Linux and Windows UCRT64.

---

## Part 3 — Daemon operational values (not consensus; finalize with the
finality qualification)

These do not gate genesis. They are recorded now so the qualification has a
target.

```
Cadence (target):        anchor the latest finalized checkpoint once per
                         ~24 h, opportunistically at fee dips
Hard deadline:           48 h — anchor regardless of fee, up to ceiling
Fee target:              5 sat/vB   (opportunistic)
Fee fallback:            20 sat/vB  (deadline approaching)
Fee ceiling:             50 sat/vB  (never exceed)
Above ceiling:           skip, alert, retry. Do not pay. Finality still
                         protects the chain; the anchor is a backstop for
                         syncing nodes and long-range defense, not an
                         acute-safety dependency.
Tx-size ceiling:         400 vB (a real anchor is ~200 vB: one input, one
                         52-byte OP_RETURN, one change output). The ceiling
                         is a bug catch, not a tuning knob.
Resubmit / RBF bump:     3,600 s   (replaces resubmit_timeout_secs = 600 in
                         swap/veld_btcrelayd.py:159)
anchor_lag:              DELETED (superseded by R1)
Expected cost:           ~1,000 sats/day at target fee ≈ USD 1/day
```

**On the resubmit interval.** 600 s is one mean Bitcoin inter-block gap.
Because those gaps are exponentially distributed, a healthy unconfirmed
transaction looks "dropped" roughly 37% of the time at that threshold — the
daemon would replace perfectly good transactions on ordinary variance, paying
an RBF premium each time. This is the same false-alarm error corrected in C5
(600 s tip-age), in a different costume. 3,600 s reduces the false-replace rate
to well under 1%.

**Interaction with C5.** Anchor submission is subject to the C5 freshness gate:
no new anchor is broadcast once Bitcoin tip age reaches 7,200 s. In-flight
anchors continue their lifecycle.

---

## Part 4 — Interaction with the rest of the board

- **A3** direction is unchanged (`ACTIVATE_REVIEWED_FINALITY_FIRST`); the
  mechanism is now state-derived. The twelve normative blockers in
  `VALIDATOR_FINALITY_ACTIVATION_EVIDENCE.md` remain mandatory: R1 is only
  as sound as the finality it depends on.
- **A4** (locked seed core) is frozen and live at the first AMM candidate; the
  first valid permissionless ADD may establish the opening ratio at launch.
- **C1** new public and operator allocation/exposure paths are launch-live when
  the authoritative candidate-height gate reports mint permission. Exact
  C1C1/C1F1/MNP2 recovery follows the separate completion permission.
- **D-STATE-01/02** bound launch-live state growth; their benchmark and
  release-evidence requirements remain unchanged.
- **D1** genesis ceremony: the `GENESIS_TIME` comment block must be rewritten
  to describe the gated design. The July 13 testnet timestamp and nonce are
  superseded; `GENESIS_BITS = 0x1e390000` remains empirically calibrated and
  is retained.

## Approval record

```
Item:        btcVELD launch/liveness gate + anchor consensus rules R1–R4
Option:      FRESH_GENESIS_LIVE; anchor security remains state-derived
Exact values: mint/redeem/four-band AMM = one-time seven-validator activation
             Bitcoin anchor = not an activation prerequisite
             later finality stall = new exposure paused; exact C1C1/C1F1/MNP2
                                    completion + redeem remain live; AMM swaps
                                    continue (owner-ratified 2026-07-21;
                                    detached freeze signature pending)
             accept window = 1,000 blocks
             BTCVELD_ANCHOR_BTC_CONFS = 6
             highest promoted T/A/BTC/full-finality-C floor = permanent
             fresh-sync artifact authority = dedicated offline 2-of-3 ML-DSA-65
             BTCVELD_ANCHOR_ACTIVATION_HEIGHT = retired
             anchor_lag = deleted
Owner:       ____________________
UTC time:    ____________________
Tree SHA256: ____________________ (post-implementation freeze)
Rationale:   as recorded above
Evidence:    Part 1 and Part 2 test matrices, PASS on Linux + Windows
             UCRT64, signed and archived to the C4 authority
```
