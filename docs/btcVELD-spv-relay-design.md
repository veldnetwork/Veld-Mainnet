# btcVELD Phase-2 — Bitcoin SPV Relay in Veld Consensus

Companion to `btcVELD-redeem-path-design.md` (§8) and `btcVELD-automated-minter-design.md`.
This is the **first and load-bearing Phase-2 component**: an in-consensus Bitcoin light client
that lets **Veld consensus itself verify Bitcoin facts** — so a btcVELD mint is gated by a
*proven* BTC deposit instead of the issuer's word. It is the gate between "custodial" and
"trust-minimized," and it is consensus-critical: a bug that accepts a forged header or a bad
Merkle proof = an unbacked mint = reserve insolvency. Precedents: BTC Relay, tBTC relay, Summa.

---

## 0. The trust upgrade (say it out loud)

**Phase 1:** `ApplyTokenOp` credits a MINT because the tx is signed by the issuer key. The
off-chain minter *promises* it saw the BTC. The chain trusts the operator.

**Phase 2 (this doc):** `ApplyTokenOp` credits a MINT only when the op carries an **SPV proof** —
a Bitcoin deposit tx, a Merkle branch to a block header, and that header buried `K_btc` deep in a
**most-work BTC header chain that Veld consensus has independently validated**. The operator can no
longer mint unbacked btcVELD; *every full node checks the Bitcoin deposit for itself.* This holds
**even with a single operator** — which is why it's the first thing we build.

Symmetrically, the **redeem/slashing** triggers in `redeem-path-design.md §7` ("fraudulent spend",
"wrong payout", "non-payment") become chain-checkable, because the chain can now verify the custody
UTXO's spend on Bitcoin. So this one component unlocks the trust-minimization of *both* legs.

---

## 1. What lives in Veld consensus state

A new consensus object, `BtcHeaderChain` (mirrors the existing ledger pattern —
deterministic, part of the state digest, re-applied on Veld reorg via `Reset()`):

```
struct BtcHeader {            // exactly the 80 wire bytes, parsed
    uint32_t version;
    uint8_t  prev_hash[32];   // internal (LE) byte order
    uint8_t  merkle_root[32];
    uint32_t time;
    uint32_t bits;            // compact target (nBits)
    uint32_t nonce;
};
struct BtcHeaderRecord {
    BtcHeader hdr;
    uint8_t   block_hash[32]; // SHA256d(80 bytes), the natural (internal) order
    uint32_t  height;         // BTC height (derived from the checkpoint)
    uint256   chain_work;     // cumulative work up to & including this header
};
```

State:
- `headers_by_hash : map<hash256, BtcHeaderRecord>` — every valid header we've accepted (bounded;
  prune below finality, keep a rolling window ≥ `K_btc + MAX_BTC_REORG`).
- `best_tip : hash256` — the tip of the **most-work** valid chain.
- `used_deposits : set<hash256>` — `(txid || vout)` of deposits already minted (idempotency).

Only `best_tip`, the header set above finality, and `used_deposits` enter the **state digest**
(so every Veld node agrees on the canonical BTC view). Below-finality/orphan headers are cache.

---

## 2. Bootstrap — a compiled checkpoint, NOT Bitcoin genesis

Syncing 900k+ headers in-consensus is absurd. We pin a **checkpoint**: a recent, deeply-buried BTC
header the whole world agrees on, as compile-time constants (same trust basis as a Veld hardcoded
checkpoint):

```
BTCVELD_SPV_CHECKPOINT_HEIGHT   = <e.g. 900000, a retarget boundary>
BTCVELD_SPV_CHECKPOINT_HASH     = "<block hash>"
BTCVELD_SPV_CHECKPOINT_BITS     = <nBits at that height>
BTCVELD_SPV_CHECKPOINT_TIME     = <header time>          // seeds MTP
BTCVELD_SPV_CHECKPOINT_CHAINWORK= "<cumulative work>"    // seeds most-work compare
BTCVELD_SPV_PREV_11_TIMES[11]   = {...}                  // seeds the median-time-past window
```

Choosing a **retarget boundary** (`height % 2016 == 0`) means we never need pre-checkpoint headers
to compute the first retarget. The relay accepts headers building forward from the checkpoint only.
The checkpoint advances each Veld release (like our other checkpoints).

---

## 3. Header validation (consensus-critical — every rule mainnet-exact)

A submitted header `h` extending parent `p` (already in `headers_by_hash`) is **rejected unless**:

1. **Linkage:** `h.prev_hash == p.block_hash`.
2. **PoW:** `SHA256d(h.rawbytes)` as a 256-bit LE integer `≤ target(h.bits)`, and `h.bits`
   decodes to a positive target `≤ POW_LIMIT` (never easier than Bitcoin's max target).
3. **Correct difficulty:** `h.bits == expected_bits(p)`:
   - **Non-retarget height:** `expected == p.bits` (Bitcoin mainnet has **no** 20-minute testnet
     rule — we target mainnet only, so this is unconditional).
   - **Retarget height** (`(p.height+1) % 2016 == 0`): recompute from the 2016-block timespan:
     `actual = clamp(last.time − first.time, T/4, T*4)` with `T = 1209600`, then
     `new_target = old_target * actual / T`, clamped to `POW_LIMIT`; re-encode to compact and
     require exact match. (`first` = the header 2015 back; keep a 2016-window index.)
4. **Median-time-past:** `h.time > median(time of the last 11 headers)`.
5. **No future beyond a deterministic bound:** `h.time ≤ enclosing_veld_block.time + 2h`. We CANNOT
   use wall-clock in consensus, so the bound is the timestamp of the Veld block that carries the
   relay tx (already consensus-agreed) + 2h. (A miner can't forge this without also forging Veld
   time, which Veld consensus already bounds.)
6. **Version** ≥ 4 (post-BIP65; sanity only).

Accepted → compute `chain_work = p.chain_work + work(h.bits)` where
`work = floor(2^256 / (target+1))`. Store the record.

**Most-work selection:** `best_tip = argmax(chain_work)` over all stored tips. On a tie, keep the
first-seen (deterministic). A reorg simply re-points `best_tip`; deposits proven only against
headers no longer on the best chain (or shallower than `K_btc`) are **not** creditable — the mint
op that referenced them fails to apply (fail-closed).

---

## 4. How headers get in — permissionless relay

A new Veld op, `BTC_HEADER` (OP_RETURN, same envelope family as the token ops), carries one or more
80-byte headers. **Anyone** may submit — it's validated by consensus, so a liar wastes only their
own fee; an honest relayer keeps the chain current. In practice the fleet + the minter relay
continuously (a header every ~10 min is trivial). Batch up to N headers per op.

`node.h::ProcessBlock` feeds `BTC_HEADER` ops to `BtcHeaderChain::SubmitHeaders` exactly where it
already feeds token ops to the ledger — deterministic, reorg-safe (Veld `Reset()` rebuilds it).

---

## 5. The mint gate (the payoff)

The MINT op grows an SPV-proof payload:
`MINT | btcVELD | recipient | amount_sats | { deposit_txid, vout, block_hash, merkle_branch[],
branch_dirs, raw_output_spk } `.

`ApplyTokenOp` (is_mint) now requires, INSTEAD OF (Phase-2 final) or IN ADDITION TO (transition) the
issuer signature:

1. `block_hash` is on the **best** header chain and buried `≥ K_btc` (record.height ≤ best.height − K_btc).
2. **Merkle proof:** folding `deposit_txid` up `merkle_branch` with `branch_dirs` yields
   `record.hdr.merkle_root`.
3. The proven tx's output `vout` has `scriptPubKey == custody_spk` (the FROST/Taproot custody key,
   §6 of the redeem doc — a compiled constant until rotation) and `value ≥ amount_sats`.
4. `(deposit_txid||vout) ∉ used_deposits` → insert it (idempotent; no double-mint).

Then credit `amount_sats` btcVELD to `recipient` and bump supply. **No trust in the operator's
"I saw it."** The `supply ≤ custody` reconciliation the minter does off-chain becomes *provable
on-chain*: `Σ minted == Σ SPV-proven deposits − Σ redeemed`.

**Transition plan:** ship with `require_issuer_sig && require_spv_proof` BOTH true for one release
(belt-and-suspenders while the relay soaks), then drop the issuer-sig requirement — at which point
**the operator can no longer mint at all without a real deposit**, and the issuer key's only power
is gone. That is the graduation.

---

## 6. Reorgs & failure modes

| Event | Handling |
|---|---|
| BTC reorg shallower than `K_btc` | deposit not yet creditable (we require `K_btc` depth); no action |
| BTC reorg deeper than `K_btc` (extremely rare, ≥6+) | a credited deposit's block leaves the best chain → **supply now unbacked**. Mitigation: `K_btc` set high (e.g. 6–12) + a `BTC_REORG_ALERT` op any node can submit with the competing headers → auto-HALT mints. Bounded, monitored, matches every SPV bridge's residual risk. |
| Veld reorg | `BtcHeaderChain` is rebuilt deterministically from `Reset()` + replay — same as the token ledger |
| Header spam / invalid | rejected by §3; costs the submitter a fee, changes no state |
| Fake deposit (no real BTC) | Merkle proof fails against the real header's root → mint op does not apply |
| Withheld headers (censorship) | permissionless relay: any honest party submits; the operator can't stall it alone |

---

## 6b. Integration reality — the FROZEN state digest (learned 2026-07-04)

`include/consensus/state_digest.h` freezes the consensus digest as **v1**:
`SHA256("VELD_STATE_DIGEST_v1|" ‖ u64(H) ‖ best_hash ‖ D_utxo ‖ D_validators ‖ D_staking ‖ D_bondyield ‖ D_nmstally ‖ D_tokens)`.
It must NOT change without bumping the spec version and re-baselining every prior
determinism proof (Phase 1.1/1.2 cross-host, `equiv_c2`, the dry-run). So folding
the SPV header chain in (`D_spv`) is a **v2 bump = a coordinated consensus upgrade**,
not an inert edit. Consequence for the build order:

- Stages 1–3a (btc_pow / btc_header_chain / BTC_HEADER op + reorg-determinism) are
  standalone, tested modules — **no deployed-binary risk, done + green**.
- The `node.h` integration (hold a `BtcHeaderChain` member, feed `BTC_HEADER` ops in
  the rebuild loops, add `D_spv` to a **v2** digest, Reset+replay on reorg, extend
  `equiv_c2`) belongs to ONE coordinated **activation upgrade** shipped with the mint
  gate — after regtest-E2E + audit — NOT piecemeal inert edits now. Ship it once,
  correctly, with the digest re-baseline and a fleet+miners rollout before the
  activation height (same discipline as the peg activation).

**Recipient binding — RESOLVED (2026-07-04), see `btcVELD-spv-recipient-binding-design.md`.**
Front-running (a third party SPV-proving someone's real deposit and minting to
their own VELD address) is closed by reading the recipient FROM the SPV-proven
deposit tx, never from the mint submitter. Chosen: **Option B** — an `OP_RETURN`
`"btcVELD:"‖<VELD addr>` output in the deposit tx (trustless, no in-consensus
secp256k1 — which Veld lacks). Planned fallback **Option D** — an issuer-signed
`spk→recipient` BIND op for exchange/from-anywhere deposits (trust-reduced,
user-verifiable). Custody consolidates to one canonical `CUSTODY_SPK`. That doc is
the buildable spec for the stage-4 mint gate.

## 7. Build order & test plan (regtest-first, audit-gated)

1. **`btc_pow.h`**: compact-target decode/encode, `work()`, `SHA256d` over 80 bytes (reuse the
   vendored SHA256), the retarget math — pure, exhaustively unit-tested against **mainnet vectors**
   (known headers/retargets from real BTC blocks; the retarget at 900k etc.).
2. **`BtcHeaderChain`**: storage + `SubmitHeaders` + validation + most-work + Merkle verify. Unit +
   property tests (feed real mainnet header ranges incl. a retarget; feed forged headers → all
   rejected).
3. **Wire `BTC_HEADER` op** into `node.h::ProcessBlock`; make the chain part of the state digest;
   prove Veld-reorg determinism with the existing `equiv_c2` harness (digest equal reorg vs cold).
4. **Mint gate**: extend the MINT op + `ApplyTokenOp`; `require_spv_proof` behind
   `BTCVELD_SPV_ACTIVATION_HEIGHT` (0 = off until set), issuer-sig kept during transition.
5. **Regtest E2E** against a real **bitcoind regtest**: mine BTC → relay its headers via `BTC_HEADER`
   → build a real Merkle proof of a deposit → MINT with the proof → consensus credits it; plus the
   negative battery (forged header, bad proof, wrong spk, reused deposit, shallow depth) all reject.
6. **Audit** the crypto + consensus surface. **Only then** flip `BTCVELD_SPV_ACTIVATION_HEIGHT` on a
   real network. No real BTC is gated by unaudited SPV code.

---

## 8. Honest limits (for the skeptic)

1. **Checkpoint trust:** the pinned checkpoint is a weak subjectivity point (same as any Veld
   checkpoint). It's a hash the entire world agrees on, advanced each release. Not trustless from
   genesis, but the standard, accepted SPV-bridge posture.
2. **Deep-reorg residual:** a >`K_btc` BTC reorg can un-back a mint. Un-removable in any SPV bridge;
   we bound it with a high `K_btc`, the alert-op auto-HALT, and the caps.
3. **This is the easy half of Phase 2.** The SPV relay makes *minting* trust-minimized. Making
   *redeeming* trust-minimized still needs the FROST/threshold custody key (§6) + the bond/slashing
   covenant (§7) + — the part no code can supply — **≥ N independent, bonded signer operators.**
   Until independent signers exist, redeem custody is still the operator's keys; the SPV relay does
   not change that. It is, however, the prerequisite every later piece is built on.
