# btcVELD Peg — 51%-Attack Defense & Cap-Growth Design

> Historical design record from July 2026, before the current mainnet launch.
> Implementation status, pilot-chain observations, and activation proposals below
> describe that review period. They are not current deployment instructions or
> a security clearance. Use the [current whitepaper](WHITEPAPER.md),
> [custody security model](btcVELD-custody-security.md), and
> [release qualification](release-3.2.2-qualification.md) for current scope.

Status: **DESIGN — for sign-off.** Only the staged static cap (§3.1) has code; nothing else here is implemented.
Date: 2026-07-04

---

## 0. Decisions locked in this review

- **Emission:** 0.8M VELD/year (down from 1.0M). Zero premine (genesis supply = 0).
- **Block time:** 3 minutes (up from 60s). Per-block reward auto-derives = `annual ÷ blocks_per_year` = 800,000 ÷ 175,200 ≈ **4.57 VELD/block**. Annual emission and the ~24-year mining runway are invariant to block time (time-based cap, not block-based).
- **Both set at the fresh Aug-30 genesis** — no migration.
- **Peg defense:** the four layers below. **No operator gating anywhere** — every gate is a pure function of `(height, on-chain state, constants)`.
- **Staged now:** custody cap 1 BTC → 0.001 BTC, per-mint → 0.0005 BTC (`constants.h`, not yet deployed).

---

## 1. Threat model

Two attacks, one root cause — **a young chain is cheap to mine and cheap to reorg**:

- **A. Cheap-VELD drain.** Mine cheap VELD → swap for pool btcVELD → redeem for BTC. Victim = the **LP** (the peg stays 1:1; you can't redeem more btcVELD than was minted).
- **B. 51% reorg.** Reverse a redeem (double-spend the custody BTC) or rewrite peg state. Victim = the **custody BTC**.

**Governing principle:** keep **attack cost > prize** at every moment. The peg is never made 51%-*proof*, only 51%-*unprofitable*, with a hard ceiling on worst-case loss.

---

## 2. Locked chain parameters → the security budget

`security budget (USD/yr) = 0.8M VELD × VELD_price`. Everything downstream sizes to this. At today's BTC ($62,860), the safe-cap ladder (see the chart in the review) gives: the staged **0.001 BTC (~$63)** cap is safe once VELD ≥ ~**$0.057**; **1 BTC (~$62,860)** needs VELD ≥ ~**$57**.

---

## 3. Layer 1 — Security-sized custody cap (the backstop)

The cap bounds the maximum BTC the peg can ever hold = the maximum prize. **It is the one guarantee that survives every other layer failing** — anchoring bug, small validator set, mis-tuned confirmations. Everything else lowers the *probability* of loss; the cap fixes its *maximum*.

### 3.1 Static staged values (now)
```
BTCVELD_ISSUER_MAX_CUSTODY_SATS  = 100,000   // 0.001 BTC ≈ $63
BTCVELD_ISSUER_MAX_PER_MINT_SATS =  50,000   // 0.0005 BTC ≈ $31
```
Enforced in `onchain_tokens.h` issuer-MINT branch (`supply + amount > cap → reject`). Live supply is 0.0002 BTC < cap, so lowering to it rejects nothing historical → no fork.

### 3.2 The difficulty-tier growth ladder (trustless auto-growth)
```
effective_mint_ceiling = max( live_supply , min( DECLARED_CAP , tier_cap( sustained_difficulty ) ) )
```
- The cap can **never exceed what measured hashrate supports** — even a reckless or buggy `DECLARED_CAP` is clamped by real on-chain security.
- `tier_cap` is a step function of **sustained** difficulty (§3.3), not price → **no oracle**.
- The `max(live_supply, …)` term is the sticky-up rule (§3.3) made explicit: the clamp never falls below outstanding supply, so a difficulty drop blocks new mints but never forces a burn.

| Tier | Gate (sustained difficulty) | Cap unlocked | Notes |
|------|-----------------------------|--------------|-------|
| Pilot | genesis / any | 0.001 BTC | sole-operator, trivial exposure |
| 1 | ≥ D₁ | 0.01 BTC | calibrated at release |
| 2 | ≥ D₂ | 0.1 BTC | |
| 3 | ≥ D₃ | 1 BTC | |
| … | … | raised in later releases | never above what §3.4 justifies |

**Status: IMPLEMENTED 2026-07-05 (staged, dormant).** `consensus/btcveld_tier_ladder.h` (pure core: `TierCap` step function + `EffectiveMintCeiling` = `max(live_supply, min(declared, tier))`; `btcveld_tier_ladder_test.cpp` **22/22**). The token ledger tracks the trailing window **in-instance** — a `recent_work_` ring of per-block `BlockWork(header.bits)` pushed every `ProcessBlock`, so each ledger (main or alt) measures its OWN chain with no external chain read and no main/alt aliasing, and `Reset()`+replay rebuilds it identically (the same replay-exactness the whole ledger relies on — and the divergence trap the L3 first-cut hit is structurally avoided here). `SustainedWork()` = trailing-**minimum** (full window required; a partial/young window returns 0 ⇒ pilot floor). The issuer-MINT aggregate check uses `EffectiveMintCeiling` when armed, `BTCVELD_ISSUER_MAX_CUSTODY_SATS` when dormant (byte-identical). Constants: `BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT = 0`, `BTCVELD_TIER_WINDOW_BLOCKS = 14 days`. Proven: full node + desktop compile; repro_btcveld ALL-PASS with the ladder staged. **Tier thresholds are PLACEHOLDER** (the caps are firm; the work thresholds are the §3.4 estimate) — lock at the bench before arming.

### 3.2a "What happens if the hashrate explodes?" (the ladder's design test)
- **Honest, sustained explosion.** Difficulty rises, higher rungs unlock — but `min(DECLARED_CAP, …)` means the effective cap can rise only up to the **human-declared cap**, never past it. The ladder is a **clamp, not an amplifier**: an explosion *relaxes* the clamp, it cannot lift the ceiling above what a coordinated release authorized. To actually raise the peg's exposure still takes a human `DECLARED_CAP` bump in a release.
- **Spike (rent-and-attack).** `sustained` is the trailing **minimum** over a 14-day window, so a burst shorter than the window leaves the minimum low and unlocks **nothing** — the hashrate that clears a rung is committed for longer than any plausible rented attack.
- **Explosion then collapse.** When difficulty falls, the clamp tightens for *new* mints, but `max(live_supply, …)` grandfathers everything already minted — the peg never force-burns, and existing btcVELD stays redeemable. New minting simply pauses until difficulty recovers or supply is redeemed down.
- **Metric saturation.** `BlockWork` saturates at `UINT64_MAX`; a saturated `sustained` just selects the top rung, and `min(DECLARED_CAP, top)` still bounds it — saturation is harmless. The metric uses `min` (never a sum), so it never accumulates and cannot itself overflow. (The chain-wide `cumulative_work` fork-choice accumulator is a separate, pre-existing uint64 concern, independent of this ladder.)

### 3.3 Anti-gaming: sustained, trailing, sticky-up
- **Sustained / trailing:** the gate reads the **minimum difficulty over a trailing window** (e.g. 14 days), not the instantaneous value — a momentary hashrate spike can't unlock a tier. The window must exceed the longest plausible attack, so the hashrate that unlocks a tier is *committed honest* hashrate, not attack hashrate briefly rented then turned on the chain.
- **Sticky-up for supply:** a difficulty *drop* never forces burns (you can't un-mint). It only blocks *new* mints above the now-lower tier. Live supply is always grandfathered (`ceiling ≥ live supply`, matching the existing "never lower below supply" rule).

### 3.4 Calibration methodology (open — §9)
Mapping difficulty → safe cap needs an attack-cost estimate. Two independent anchors:
- **Price-based:** `safe_cap_USD ≈ ½ × daily security budget = ½ × 0.8M × VELD_price ÷ 365`. Needs a VELD market price.
- **Energy-based:** `attack_cost ≈ hashrate × window × energy_cost_per_hash`. Price-independent; needs a VeldHash energy model.
At each release, set the tier thresholds to the **conservative min of both**. Until VELD has a real market, stay at the **Pilot** tier.

### 3.4b Calibration — first pass (2026-07-04, live data)

Current network hashrate: **~1,378 H/s** (`getminerstatus.network_hashrate_est`; difficulty 1.9e-5, ~82.7k expected hashes/block at 60s). A handful of CPUs.

**Model choice — hardware acquisition, not electricity.** VeldHash is a *custom* algo with **no rental market**, so an attacker cannot rent hashrate — they must **build a farm**. The realistic attack cost is therefore dominated by the **hardware to acquire >50% of network hashrate**, not the electricity to run it:
```
attack_cost ≈ network_hashrate × $/(H/s)      // $/(H/s) = machine_cost ÷ machine_hashrate
safe_cap    ≈ ½ × attack_cost
```
Electricity is a much smaller lower-bound floor (a short reorg burns little power; the farm is the cost). **This no-rental property is a genuine security advantage of a custom algo over rentable SHA-256/Scrypt** — it is why VeldHash, despite low absolute hashrate, isn't trivially 51%-rentable.

**The one benchmark that locks the numbers:** `$/(H/s)`. **BENCHED 2026-07-05 (LOCKED)** on the home-miner PC — an **Intel i9-11900K** (8 physical / 16 logical) producing **1047.66 H/s** at its tuned 7 threads (= physical−1; the miner deliberately skips hyperthreads, which don't help memory-hard hashing), ≈ **1,197 H/s peak** at all 8 physical cores (149.7 H/s/core). At the i9-11900K's **$540 launch price that is $0.52/(H/s)**; across the realistic rig-cost range (~$300 used CPU → ~$1,000 new full rig) it spans **$0.29–$0.95/(H/s)**, centered squarely on the **$0.50/(H/s)** the ladder was built on — so the placeholder is confirmed, not merely plausible. (This single rig is also **~81% of the entire ~1,296 H/s network** — hashrate as concentrated as stake, another reason finality launches dormant.) Energy cross-check: the i9 draws ~125–200 W all-core → ~0.12–0.19 W/(H/s); at $0.10/kWh electricity is ~1000× below the hardware cost, confirming the hardware-acquisition model dominates. GPUs could still push `$/(H/s)` lower — the **10× conservatism factor** (caveat 1) absorbs that, and the tiers now key on it.

**Hashrate required per cap tier** (at $0.50/(H/s), margin ½ → `safe_cap = H × $0.25`), before any conservatism factor:

| Cap tier | Safe cap | Network hashrate needed | ≈ home miners @1 kH/s |
|----------|----------|-------------------------|-----------------------|
| 0.001 BTC (~$63) | pilot floor | ~250 H/s (already met) | <1 |
| 0.01 BTC (~$629) | tier 1 | ~2.5 kH/s | ~3 |
| 0.1 BTC (~$6,286) | tier 2 | ~25 kH/s | ~25 |
| 1 BTC (~$62,860) | tier 3 | ~250 kH/s | ~250 |

**Two hard caveats:**
1. **Model sensitivity.** The pure-electricity floor is ~1,000× more pessimistic (it would say even $63 needs ~500 kH/s). Truth sits between; for safety, apply a conservatism factor (e.g. 10×) to the hardware-model thresholds above, *and* require the hashrate **sustained** (§3.3). Pinning the factor is a policy call.
2. **Today there is almost no cryptoeconomic security.** At ~1.4 kH/s the economic ceiling is ~$345 (hardware model) / ~$0 (electricity floor). **The pilot's real safety is "solo operator, no adversary present," not economics** — which is exactly why the cap is pinned at 0.001 BTC.

**The deeper finding:** memory-hard home mining keeps `$/(H/s)` low *by design*, which structurally **caps the peg's PoW-only security**. Even a healthy 10k-miner network (~10 MH/s) defends only ~$2.5M ≈ 40 BTC by this model — less on GPUs. **This is the quantitative case for Layer 2:** anchoring lets the peg exceed what out-hashing alone can defend, by borrowing Bitcoin's immutability instead of VELD's hashrate.

---

## 4. Layer 2 — Bitcoin checkpoint anchoring (bounds reorg DEPTH)

### 4.1 Mechanism
- An **anchor** = a Bitcoin tx `OP_RETURN` committing `{VELD height H, VELD block hash}`. **Permissionless** — anyone can post one.
- VELD nodes already run a BTC light client (the SPV relay that gates MINT); they observe anchors with SPV inclusion proofs.
- **Consensus rule:** once VELD block H is anchored and the anchoring BTC tx has ≥ B confirmations, VELD **rejects any fork that changes history at or before H** — a deep reorg would have to contradict a hash already immortalized in Bitcoin.

### 4.2 Canonical selection (the hard part)
- **First-seen-in-Bitcoin wins:** for a given VELD height, the anchor at the *lowest BTC height* is authoritative — Bitcoin's own ordering breaks ties.
- **Anti-front-run (secret-fork anchoring):** only **validator-finalized** VELD blocks (Layer 3) may be anchored/honored. An attacker can't finalize a secret fork (validators won't sign it), so can't anchor one first. → **Layers 2 and 3 compose:** finality makes anchoring un-front-runnable; anchoring makes finality Bitcoin-immutable.

### 4.3 Cadence
Anchor roughly once per Bitcoin block (~3 VELD blocks at 3-min). **Redeems do not finalize until anchored**, so the reorg window a redeem is exposed to is bounded by the anchor interval, not an arbitrary confirmation depth.

### 4.4 Implementation spec
- **Anchor tx (on Bitcoin):** one `OP_RETURN` output = `VELD_ANCHOR` magic + `{version:1, veld_height:u64_le, veld_block_hash:32B}` (~43 bytes). Permissionless; the fleet/maker posts routinely so the honest tip is always promptly anchored (a small BTC fee per anchor).
- **Consensus verification (reuses the dormant Phase-2 SPV relay):** the node's BTC light client already tracks BTC headers to gate MINT. It (1) observes the anchor tx via a Merkle inclusion proof against a BTC header with ≥ `BTCVELD_ANCHOR_BTC_CONFS` (e.g. 3) confirmations, (2) parses `(H, block_hash)`, (3) records `anchored[H] = (block_hash, btc_height)` keeping only the **lowest-btc_height** anchor per H.
- **Fork-choice rule:** reject any chain whose block at an anchored height H ≠ `anchored[H].block_hash`. A reorg that rewrites an anchored height is invalid **regardless of work**.
- **Anti-front-run:** honor an anchor only if its committed VELD block is validator-finalized (§5) — an attacker can't finalize a secret fork, so can't anchor one first.
- **State digest:** `anchored[]` joins `ConsensusStateDigest` (like `D_tokens`) so every node agrees on the anchor set; replay-exact.

---

## 5. Layer 3 — Validator finality on redeems (raises reorg COST)

- Veld already has validators / endorsements / staking / slashing.
- **Rule:** a redeem's btcVELD burn is *final* (BTC payout permitted) only once the burning block carries a **validator supermajority endorsement**.
- Reversing a finalized burn forces validators to endorse a conflicting history → **slashable** → the attacker must burn a supermajority of *stake* on top of out-hashing. Attack cost jumps from "electricity" to "electricity + a supermajority of the bonded stake."
- **Caveat:** the staked value must be meaningful — which loops back to Layer 1: peg cap ≤ `min(hashrate cost, staked value)`.

### 5.1 Implementation spec
- **Finality state:** block H is *final* once its endorsement tally (already maintained) reaches validators holding ≥ `FINALITY_STAKE_THRESHOLD` (e.g. ⅔) of active stake. A `final_height` high-water-mark advances monotonically.
- **Redeem gate:** a redeem burn's BTC payout is permitted only once its burning block is final (`block_height ≤ final_height`). The redeem daemon and the §5b drain-guard accounting key on `final_height`, not raw confirmation depth.
- **Slashing condition:** a validator that endorses two conflicting blocks at the same height, or endorses a chain that reorgs a finalized block, is slashed via the existing SLASH machinery (`SLASH_EVIDENCE_WINDOW`, bond lockup). This is what makes reversing a finalized redeem cost *stake*, not just hashrate.
- **Composition:** finality is the gate that lets a block be anchored (§4.4 anti-front-run); anchoring makes finality Bitcoin-immutable. Together they bound reorg **depth** (anchor) at **stake-cost** (finality) — neither suffices alone.

### 5.2 Slash coverage — verified against the implemented machinery (2026-07-05)

What the existing SLASH branch (validators.h) actually punishes: one validator key, **two
valid ML-DSA endorsement signatures at the SAME height over two DIFFERENT block hashes**
(`VELD_VALIDATOR|SLASH|pk|height|hash_a|sig_a|hash_b|sig_b`), evidence accepted within
`SLASH_EVIDENCE_WINDOW` of the signed height, deduped per (pubkey, height). Penalty (Phase 3,
active): permanent re-registration ban + bond confiscation + 25% slasher bounty. An
endorsement signs `(genesis-domain, height, block_hash)` — no ancestry commitment.

Coverage verdict for finality violations:

- ✅ **Same-height double-finalization — covered.** Two conflicting blocks finalized at the
  same height means the two ⅔ supermajorities overlap in ≥⅓ of active stake, and every
  overlap validator produced exactly the evidence pair the SLASH branch accepts. This is
  the case the §4.2 anti-front-run composition FORCES an attacker into: to anchor a
  competing fork they must first finalize it, and first-seen-in-BTC means already-anchored
  heights can't be re-anchored — the contest happens at a height the honest chain also
  finalizes.
- ⚠️ **Cross-height ("surround") double-finalization — NOT expressible.** If the ≥⅓ overlap
  endorses the honest chain at height h and the attacker fork only at h′ ≠ h, the pair
  cannot be packed into the one-height evidence format, and because endorsements don't
  commit to ancestry, no signature pair alone PROVES the two chains conflict. This is
  Casper-FFG's second slashing condition (surround votes). Closing it needs an endorsement
  or SLASH format change (commit a recent finalized ancestor in the endorsement message, or
  carry header-chain proofs in the evidence) — same forward bucket as the existing
  "carry both block headers inline in SLASH" hardening note in validators.h. Not an arming
  blocker at pilot scale: it requires ⅓+ of stake actively colluding, and worst-case loss
  stays bounded by the cap (§3) + drain guard (§5b).
- ➖ **Pure-PoW reorg of a final-but-unanchored block — out of slashing's scope by
  construction.** Finality is deliberately not a fork-choice veto (the anchor gate is the
  depth veto); a most-work reorg needs no validator signatures, so there is nothing to
  slash. Mitigations: the redeem daemon keeps the K_veld depth gate ON TOP of the finality
  gate; once Layer 2 is armed the §4.3 anchor cadence bounds the unanchored window a paid
  redeem is exposed to; the cap + drain guard bound the worst case.

---

## 5b. Redeem drain guard — consensus outflow rate-limit

Modeled directly on the existing **VAULT-NEVER-DRAINS** rule (`VAULT_INFLOW_PAYOUT_PPM` = 900,000 / `VAULT_DISTRIBUTION_PPM` = 80,000 in `constants.h` — each cycle the vault pays out at most a bounded fraction of inflow/balance, so it can never be emptied and in fact grows). The peg gets the same *rate* protection on BTC outflow, with **one deliberate difference**: btcVELD must stay fully redeemable, so the guard **defers** excess rather than permanently retaining it (the vault keeps 10% forever; the peg must let 100% out eventually).

**Rule (consensus, per window):** a redeem burn is valid only if
```
redeemed_in_window + amount  ≤  effective_custody_cap × BTCVELD_REDEEM_WINDOW_PPM_OF_CAP / 1e6
```
- Window = `BTCVELD_REDEEM_WINDOW_BLOCKS` (≈ 1 day, or the anchor interval).
- The per-window ceiling is a **fraction of the current custody-cap tier** (20% = `BTCVELD_REDEEM_WINDOW_PPM_OF_CAP` 200,000 ppm), so it auto-scales as the difficulty-tier cap (§3.2) grows. All custody is redeemable over 5 windows; any single window — including one an attacker reorgs — can move at most that fraction.
- An over-budget redeem is **rejected WHOLE — nothing is burned** (the unpayable-burn lesson: funds stay with the redeemer, who resubmits next window; never partial, never trapped). Full redeemability preserved; only the *rate* is bounded.
- Consensus tracks `redeemed_in_window` in state (exactly as the vault tracks per-cycle distributions), so it is trustless and replay-exact — no operator, no daemon discretion.

**Status: IMPLEMENTED 2026-07-05 (staged, dormant).** `consensus/btcveld_redeem_guard.h` (pure core: `WindowId` / 128-bit-safe `WindowCeilingSats` / overflow-safe `FitsWindow`; `btcveld_redeem_guard_test.cpp` **24/24**) enforced in the `onchain_tokens.h` REDEEM branch (peg token only) with a lazy-rolled per-window accumulator — windows are pure functions of height and the accumulator moves only on accepted chain ops, so replay is exact and the alt-chain shadow ledgers inherit it free. The accumulator joins the `D_tokens` digest **active-only at compile time** (`if constexpr` on the activation height — dormant builds are digest-byte-identical, the ANCHORS pattern). `preparetokenredeem` mirrors the ceiling as a loud front-door error. Constants: `BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT = 0` (dormant; arm on the fresh genesis), window = `BLOCKS_PER_DAY` (wall-clock day, sweep convention). Proven: full node + desktop compile, and the repaired `repro_btcveld` battery ALL-PASS with the guard staged (behavior-neutral while dormant).

**Why it matters:** it caps what a *successful* reorg-double-spend can extract to one window's worth — turning a catastrophic drain into a bounded, observable trickle that anchoring/finality catch within the window. Composes with §3 (bounds total prize) and §4 (bounds reorg depth): **worst-case single-attack extraction ≤ one window's redeem ceiling.**

---

## 6. Layer 4 — AMM swap gate (LP protection)

Per the earlier AMM-gate spec: a trustless consensus gate on the VELD↔btcVELD **swap** plus a **pool btcVELD cap**, so cheap VELD can't drain LP btcVELD until VELD is valued. **Wrap, redeem, and liquidity-remove are never gated** (never trap funds). Independent surface from the reorg layers.

**Status: IMPLEMENTED 2026-07-05; launch policy updated in v2.9.9.** `consensus/btcveld_amm_gate.h` provides `SwapAllowed` and `PoolReserveAllowed`; decreases remain allowed so liquidity cannot be trapped. For the August 30 fresh genesis, swaps are enabled from block 1 and `BTCVELD_AMM_MAX_POOL_BTCVELD_SATS` equals the aggregate 10 BTC custody ceiling. There is no smaller liquidity-only cap.

---

## 7. How the layers compose

- **Anchoring** bounds reorg **depth** (can't cross an anchor).
- **Finality** bounds reorg **cost** within that depth (must slash stake) *and* makes anchoring un-front-runnable.
- **The cap** bounds the **loss** if all else fails, and auto-grows only as measured hashrate justifies it.
- **The AMM gate** protects LPs on a separate surface.

Net: **51%-unprofitable + bounded worst case, with zero operator trust.**

---

## 8. Rollout (staged, sign-off gated)

1. **Now (staged):** tighter static cap (0.001 BTC / 0.0005 BTC). Ships in the next coordinated **fleet + Windows** consensus release. Operational guard: **do not mint > 0.001 BTC total** until it's live.
2. **Fresh Aug-30 genesis:** bake in 0.8M/yr + 3-min block time + wall-clock-derived intervals (§9) + Layer-1 tier ladder + Layer-4 AMM gate — all active from genesis on the fresh chain (no grandfathering needed).
3. **Post-launch:** Layer 2 (anchoring) + Layer 3 (finality) — larger builds; detailed spec + implement after genesis. **Cap stays at the Pilot tier until these layers *and* a real VELD market exist.**

Monitoring (non-consensus): a solvency dashboard reads `btcusd.json` + `getpeginfo` live to show current cap headroom in USD. The *consensus* cap keys on difficulty, not this feed.

---

## 9. Open items

- **Layer-1 tier ladder — DONE + CALIBRATED (implemented, 22/22, dormant; see §3.2 status + §3.2a + §3.4b).** The `$/(H/s)` bench is LOCKED (2026-07-05, i9-11900K → $0.52/(H/s), validating the $0.50 basis; §3.4b), so the thresholds are calibrated (25k/250k/2.5M H/s @3min with the 10× conservatism factor). Remaining: only (b) arm `BTCVELD_TIER_LADDER_ACTIVATION_HEIGHT` in the release that first raises `DECLARED_CAP` above the pilot floor (the ladder is inert while declared == pilot, since `min(pilot, anything) == pilot`).
- **Layer 2 — DONE (implemented, wired, tested, dormant).** `consensus/btcveld_anchor.h` (VerifyAnchor + AnchorSet) + `btcveld_anchor_params.h`; node.h `FeedAnchors_` + `anchors_` + reorg rebuild; blockchain.h `anchor_gate_` consulted beside `PassesCheckpoint` at both accept sites; `ComposeV4`/`ANCHORS` digest. Full-node compile passes; `mainnet-launch/dryrun/btcveld_anchor_test.cpp` — 19/19 pass (accept + all negatives + merkle-ambiguity + first-seen-wins + reorg-VETO). Inert while `BTCVELD_ANCHOR_ACTIVATION_HEIGHT == 0`. **Remaining:** the §5 finality anti-front-run gate on `Record` (needs Layer 3), then arm the activation height in a coordinated release.
- **Layer 3 — DONE except arming (dormant).** `consensus/btcveld_finality.h` (pure `IsSupermajority` / `ComputeFinalHeight`, now 25/25 tests) + `ValidatorRegistry::GetEndorsedStake`/`GetActiveStake` (stake-weighted) + node.h per-block `UpdateFinality_` advancing the atomic `final_height_` off the endorsement tally; `FeedAnchors_` gates anchor `Record` on it — the anti-front-run composition (only finalized blocks are anchorable). **Replay-exactness root fix (2026-07-05):** the first cut computed finality lazily keyed on `chain_.Height()`, which during a reorg/startup replay is already the final tip while the validator registry is only partially rebuilt — a replaying node would have frozen one stale value for the whole replay while a live node advanced per block, admitting different anchor sets → ANCHORS-digest chain split once both layers armed. Now `UpdateFinality_(b.height)` runs at the identical per-block position on all three paths (incremental accept, reorg replay, startup replay) and the anchor gate keys on `b.height`, never the tip; the scan is bounded to the trailing `BTCVELD_FINALITY_WINDOW` (old heights can no longer be directly finalized — a current-height supermajority still implies ancestry final, so old burns finalize with the live chain) and zero active stake early-outs (fail-closed AND keeps a validator-less replay O(1)/block). **Redeem-daemon gate (2026-07-05, done):** `getpeginfo` exposes `final_height` + `finality_active`, and `getbtcveldredeems` returns `final_height` in the SAME snapshot as the tip; `veld_redeemd.py` holds BTC payout unless `burn_height <= final_height` IN ADDITION to the K_veld depth gate (dormant node reports final == tip ⇒ behaviour byte-identical until armed; missing field = pre-finality node ⇒ depth-only with a warning). **Slash coverage verified — see §5.2** (same-height double-finalization covered; surround-vote gap documented as a forward format change). **Remaining:** arm `BTCVELD_FINALITY_ACTIVATION_HEIGHT` — a coordinated release decision gated on a real staked validator set (with ~zero stake, armed finality fail-closes and would hold every redeem).
- **Wall-clock sweep — EXECUTED 2026-07-05 (staged, value-preserving, compile-proven).** Every consensus duration whose semantic is wall-clock is now *expressed* as `N × BLOCKS_PER_DAY/YEAR`, each with a `static_assert(TARGET_BLOCK_TIME != 60 || X == <old literal>)` pin — compile-time proof the live 60s chain is byte-identical (pins go vacuous on a non-60s build, where the derived values rescale automatically). Re-expressed: `STAKING_RESERVE_BLOCKS` (3y), `SLASH_EVIDENCE_WINDOW` (7d), `SLASH_BOND_LOCKUP_BLOCKS` (30d), `BOND_YIELD_VEST_BLOCKS` (90d), `MIN_EVIDENCE_WINDOW` (12h), `STAKE_LOCKUP_BLOCKS`/`STAKE_COOLDOWN_BLOCKS` (7d/1d), `BTCVELD_FINALITY_WINDOW` (7d), `GOV_SUBMIT_COOLDOWN_BLOCKS` (12h), `GOV_PRUNE_DELAY_BLOCKS` (30d), `GOV_PROTOCOL_TIMELOCK`/`GOV_ACTIVE_WINDOW` (7d, governance.h), `PROMO_MAX_DURATION_BLOCKS`/`PROMO_MAINNET_COOLDOWN` (1d/30d, promos.h), the governance daily prune cadence (node.h `% BLOCKS_PER_DAY`), **plus constants the 07-04 catalog MISSED:** `LOCKUP_TIERS` (staking.h — the REAL consensus lockups, 7/14/30/90d; `STAKE_LOCKUP_BLOCKS` is display-only) now cross-asserted `Long == BOND_YIELD_VEST_BLOCKS`, the tier "active day" `WINDOW_BLOCKS` (tiers.h + blockchain.h `GetActiveWindowCount`, 1d), the validators.h recently-active window (7d), and the staking.h 10-year unlock sanity bound.
  - **CORRECTION to the 07-04 catalog:** `BOND_SETTLEMENT_INTERVAL`/`VAULT_DISTRIBUTION_INTERVAL` = 144 is **2.4 h** at 60s, *not* "1 d". It cannot move on the live chain (all `%144` height asserts key on it; now also explicitly asserted equal to each other). **DECIDED — user sign-off 2026-07-05: `BLOCKS_PER_DAY` (480) at the fresh genesis, i.e. settlement + staker flush become truly DAILY** (vault outflow per day drops ~10× vs today's 2.4 h cadence — accepted). The tripwire `static_assert(TARGET_BLOCK_TIME == 60 || BOND_SETTLEMENT_INTERVAL == BLOCKS_PER_DAY)` now *requires* exactly that on any non-60s build, and the existing `%`-asserts force every aligned activation height to be recomputed with it.
  - **Review bucket — DECIDED (block-native, stay literal):** `CHECKPOINT_INTERVAL_BLOCKS`/`VAULT_BLOCK_INTERVAL` (100, cadences), `EARLY_RETARGET_INTERVAL`/`EARLY_LWMA_WINDOW` (36, retarget sample counts), `NMS_WINDOW_DEDUP_BLOCKS` (200) / `COMINE_WINDOW_BLOCKS` (100, coupled to `MAX_REORG_DEPTH ≤` assert), `BOOTSTRAP_BLOCKS` (30), `MAX_REORG_DEPTH` (100, pairs with the daemon's K_veld=100 block-depth gate), `VALIDATOR_OP_COOLDOWN_BLOCKS` (100) and the short anti-abuse windows (`GOV_VOTE_CHANGE_COOLDOWN_BLOCKS` 6, `GOV_SIG_REPLAY_WINDOW_BLOCKS` 60). Non-consensus local caps (e.g. staking.h `UNSTAKE_HISTORY_CAP`) left alone.
  - **Remaining at the genesis cut (manual, interlocked):** set `TARGET_BLOCK_TIME = 180` + `ANNUAL_EMISSION_CAP = 800'000` (§0) → build fails on the cadence tripwire → set `BOND_SETTLEMENT_INTERVAL = VAULT_DISTRIBUTION_INTERVAL = BLOCKS_PER_DAY` (decided; see above) → recompute the `%`-aligned activation heights (all reset at genesis) → set `PROMO_RETIREMENT_HEIGHT = 1` and physically delete the promo system (engine + governance promo type + RPC/UI stubs; see the retirement bullet below) → update display copy that hardcodes 60s math (ui_desktop.h/explorer.h "1440 blocks ≈ 1 day"-style strings, rpc.h `/1440.0` day conversions) → new genesis block + checkpoint.

- **Promo system RETIRED (decommission executed 2026-07-05; staged, dormant until armed).** Decision: the promo system is being retired outright. Consensus: `PROMO_RETIREMENT_HEIGHT` (promos.h; 0 = staged default — arm ABOVE the fleet-convergence tip at the release cut, exactly the `BTCVELD_AMM_ACTIVATION_HEIGHT` pattern, so a mixed-version fleet cannot diverge on a promo op landing in the deploy window; the fresh genesis sets 1 = retired from birth) gates the only two chain-op ingresses that can mutate promo state: new promo-proposal submissions (`governance.h::ApplyPromoProposalFromChain`) and votes on promo-type proposals (`ApplyVoteFromChain`). Once armed no promo can ever newly pass; the execution/replay paths (`ExecuteIfPromo` / `ReplayPassedPromos`) are deliberately untouched so history replays byte-identically. **Live-chain facts verified before designing (n1 RPC, tip 20952):** zero promos have ever activated (PromoEngine empty ⇒ `D_promos` = empty-state digest, multiplier 1.0 everywhere); one OPEN test proposal exists (id 1, "Promo: test", submitted block 7060, 0-yes/1-no, expires 27220) — it stays visible history, freezes once armed, and expires naturally. **Operational note until armed: don't vote it up** (4 validators are registered; `promo_votes_needed` = 2). RPC: `preparegovpromo` refuses loudly when retired; `submitpromo*`/`activatepromo` stubs now say retired; read-only `getpromos`/`getpromoinfo` stay for history. UI decommissioned now (independent of arming): wallet + explorer promo submission forms, the promo option, the cooldown panel, and both mining-boost banners removed; historical promo proposals still render in the proposal lists; explorer docs §14 marked retired. Full node + desktop compile clean. Physical deletion of the promo code (engine, digest slot, tx-history labels) is a fresh-genesis task — the pilot chain's history (the block-7060 proposal tx) still needs the parse/render paths until then.
- **Redeem drain guard (§5b) — DONE (implemented, tested 24/24, dormant; see §5b status).** Remaining alongside the other arming decisions: set `BTCVELD_REDEEM_GUARD_ACTIVATION_HEIGHT` (fresh genesis = 1); when the difficulty-tier ladder (§3.2) lands, switch `WindowCeilingSats`' cap argument from the static constant to the tier-effective ceiling. **Found while proving it:** `repro_btcveld`'s fixtures were still sized for the 1-BTC-era caps and the battery had been silently RED in-tree since the 07-05 tightening (first mint 100k sats > the new 50k per-mint cap ⇒ 12 cascade failures — including in the published `e45fe40e` bundle). Repaired cap-relative (amounts derive from `BTCVELD_ISSUER_MAX_PER_MINT_SATS`; exact-fill proof loops per-mint-sized mints; divisibility static_assert) so cap moves can never silently re-break it — ALL PASS.

---

## 10. Audit remediation (2026-07-05)

External audit of the pilot returned **AMBER** — the live custodial path is defensible at the 0.001-BTC cap (authorized ML-DSA mint, on-chain aggregate cap ⇒ ~$100 blast radius, reorg-safe, fail-closed independent solvency gate). Two code findings are fixed here; both are staged/dormant and grandfather the live chain.

- **F-MED — unpayable-redeem burn.** On-chain REDEEM validated only that the memo (dest BTC scriptPubKey, hex) was non-empty, so a garbage/non-standard spk would burn btcVELD to a destination no custodian can pay — destroyed with no payout, no restore. **Fix:** `consensus/btcveld_redeem_spk.h::IsStandardBtcRedeemSpk` (P2PKH / P2SH / P2WPKH / P2WSH / P2TR + future witness versions; rejects OP_RETURN / bare data / malformed), enforced in `onchain_tokens.h` REDEEM branch under `BTCVELD_REDEEM_SPK_CHECK_ACTIVATION_HEIGHT` (0 = dormant; set to 1 on fresh genesis or > tip on the live chain). Proven by `mainnet-launch/dryrun/btcveld_redeem_spk_test.cpp` (16/16).

- **F-MED — AMM sigless-spend had no activation height of its own.** The pool's sigless UTXO-spend (ValidateTransaction exempts it, trusting the AMM block guard) piggybacked `BTCVELD_ACTIVATION_HEIGHT`, so a pool seeded on a mixed-version mainnet could split the chain with no height gate to coordinate. **Fix:** `BTCVELD_AMM_ACTIVATION_HEIGHT` gates `amm_pool.h::MaybeCreatePool` (the single choke point for pool creation → seeding → the sigless exemption). 0 = inert (grandfathers the live pilot pool); set > the launch-convergence tip on the fresh mainnet so pools can't be seeded until node versions converge.

Full-node compile passes with both fixes. The **package-integrity finding (F-CRIT, the stale README)** is resolved at the root: the cover-letter source is deleted and the bundle cutter permanently bans any `README_AUDIT.md` — audit bundles now ship code + current design docs only.

Current references: [AMM design](btcVELD-AMM-design.md),
[redemption design](btcVELD-redeem-path-design.md),
[validator lifecycle implementation](../include/consensus/validators.h), and
[protocol economics](WHITEPAPER.md).
