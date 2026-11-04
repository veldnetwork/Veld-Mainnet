# btcVELD ⇄ BTC — Native DEX + Two-Way Peg: Engineering Design & Trust Model

Audience: the VELD dev team. Purpose: a buildable, honest spec for pairing VELD↔BTC via a
wrapped asset (`btcVELD`) where users **burn btcVELD to redeem BTC**. It states the one
constraint that governs the whole design, separates what is trustless from what is not, and
specifies how to build the part that cannot be made trustless so the residual trust is
*minimized, bonded, and visible* — not hidden.

---

## 0. Read this first — which "fork" this is

A skeptic on the team framed it correctly: *"you don't have the keys" tells you how the BTC is
locked, not how it gets released, and the release is where the answer lives.* Two designs:

- **Fork A — bilateral atomic swap (HTLC).** BTC is locked in an HTLC; it releases only when a
  *live counterparty* reveals a hash preimage tied to one specific trade. Genuinely trustless.
  But it needs a counterparty per swap — it is a **desk**, not a pool. (This is exactly what
  `swapd` already is.)
- **Fork B — wrapped peg.** A user burns `btcVELD` on Veld with **no live counterparty**, and
  BTC pays out to them from a reserve. **This is what you are building.**

**The theorem that governs Fork B:** *Bitcoin cannot verify Veld state.* Bitcoin Script has no
opcode to check another chain, no general computation, no light client of Veld inside it. So a
BTC release **cannot be conditioned by Bitcoin on a Veld burn**. Therefore something *off
Bitcoin* must (1) observe the burn and (2) hold the BTC keys and (3) choose to sign the release.

That "something" is the trust root. "Mike has zero access" only removes *you* as a key-holder;
it does **not** remove the requirement that *some* party can sign. If btcVELD redeems to
strangers and you truly have zero access, then **someone/something else has the signing power**,
and *that* is the thing to design, bond, and audit. There is no trustless autonomous BTC pool —
anyone who claims one is either secretly doing Fork A (needs counterparties) or has a hidden
signer (the honeypot).

This document does not pretend otherwise. It tells you **exactly what signs the BTC, exactly
what fires it, and exactly how to make stealing it economically irrational and provably
punishable.**

---

## 1. Decompose into three layers — they have three *different* trust levels

| Layer | What it is | Trust |
|------|------------|-------|
| **L1 — DEX** | VELD/btcVELD trading (AMM or order book), 100% on Veld | **Trustless** |
| **L2 — Peg-in / mint** (BTC→btcVELD) | Lock BTC, mint btcVELD 1:1 | **Trust-minimized** (SPV proves backing; custody holds the BTC) |
| **L3 — Peg-out / redeem** (btcVELD→BTC) | Burn btcVELD, release BTC | **Trusted signer set** (irreducible) — minimized by bonds |

**The trap to avoid:** L1 being trustless does *not* make the system trustless. The DEX trades a
token whose entire value is *redeemability*, and redeemability lives in L3. **A trustless DEX
over a trusted peg is a trusted system with a trustless veneer.** All the trust is concentrated
in L3's custody — which is good (one thing to harden) only if you *admit it's there*.

---

## 2. The asymmetry — why mint can be ~trustless but redeem cannot

- **Veld → Bitcoin: verifiable.** Build a **Bitcoin SPV light client inside the Veld node**: it
  ingests BTC block headers, checks PoW + difficulty retargeting, follows the most-work chain,
  and verifies a Merkle inclusion proof for a deposit tx. Then the Veld chain can *trustlessly*
  assert: "BTC tx `T` paying the custody address with `K` confirmations exists." → **mint without
  trusting an operator's word.**
- **Bitcoin → Veld: NOT verifiable.** There is no way to run a Veld light client inside Bitcoin
  Script. Bitcoin cannot be shown "a btcVELD burn happened." → **the release tx must be produced
  by an off-chain signer that chose to act.**

This asymmetry is the whole game: **mint = SPV-trust-minimized, redeem = bonded-trusted.** No
amount of cleverness moves redeem into the trustless column, because that would require Bitcoin
to verify a foreign fact, which it cannot.

> Caveat on "trustless mint": SPV proves *backing accounting* (you can't mint btcVELD without a
> real BTC deposit). It does **not** make custody non-custodial — the instant BTC lands in the
> custody multisig, the L3 trust applies. SPV stops *unbacked inflation*; it does not stop the
> signers from later refusing to release. Both are needed.

---

## 3. Components to build

1. **`btcVELD` asset** — a Veld-native token on the covenant layer. Supply changes *only* via
   (a) a proven peg-in mint and (b) a peg-out burn. No admin mint. Reuse VELD's covenant
   machinery (the same fail-closed, client-re-derived model used for escrow/swap/channel
   covenants).
2. **Bitcoin SPV relay** (in-protocol, the major new piece) — header chain + PoW/retarget rules +
   Merkle-proof verifier, exposed to consensus so mints and payout-proofs can be validated by
   every Veld node. Precedents to study: BTC Relay, Summa/Keep relay, tBTC's relay maintainer.
3. **Custody + signer set** (the trust root) — `M-of-N` BTC multisig holding the reserve.
   Prefer **FROST threshold Schnorr (Taproot)** so the on-chain footprint is a single key and the
   threshold is invisible to Bitcoin; fall back to a Taproot `OP_CHECKSIGADD` `M-of-N` if FROST
   tooling isn't ready. Each signer is **bonded on Veld** (see §5).
4. **Peg-in pipeline** (§4a). **Peg-out pipeline** (§4b — the path your advisor wants to read).
5. **Watchtowers / challengers** — permissionless Veld actors that verify every mint is backed,
   every redemption is honored on BTC within its deadline, and submit fraud/censorship proofs
   that trigger slashing.
6. **DEX** — native VELD/btcVELD market on Veld (constant-product AMM is the simplest honest
   start; order book if you want price-time priority). Pure L1, trustless.
7. **Safety rails** — per-group and global custody caps, an insurance fund funded by peg/DEX fees,
   and a circuit-breaker (governance pause) with its *own* documented trust caveat.

---

## 4. The two pipelines

### 4a. Peg-in (mint) — BTC → btcVELD
1. User requests a deposit; system assigns the current **custody address** (the active signer
   group's Taproot key) and a deposit id.
2. User sends BTC to that address.
3. After `K` confirmations, anyone submits an **SPV proof** (header chain + Merkle proof) to the
   Veld peg module.
4. The module verifies the proof against its in-protocol BTC header chain and **mints btcVELD 1:1**
   to the user's Veld address (minus a peg fee).
5. Custody now holds the BTC; backing is provable on-chain by anyone (sum of custody UTXOs vs.
   btcVELD supply).

*Trust here:* none for *accounting* (SPV). The BTC is custodial from step 2 on — that's L3.

### 4b. Peg-out (redeem) — btcVELD → BTC  ← the release path, line by line

This is the exact thing the skeptic asked to see. Walk it:

1. **Burn.** User calls the peg module's `redeem(btc_address, amount)`. The module **burns** the
   btcVELD (supply drops) and **emits a redemption request** = `{request_id, btc_address, amount,
   deadline_height, fee}` recorded in Veld consensus state. *This is the only thing Bitcoin will
   never see.*
2. **Observe.** Each signer runs a Veld node and **watches for redemption requests**. This is the
   *watcher* — not a live counterparty. (This is the precise word your advisor used: a watcher
   observes the Veld burn and acts.)
3. **Sign.** The active group selects custody UTXOs and produces a BTC transaction paying
   `amount` to `btc_address`. `M` of the `N` signers sign it (FROST → one Schnorr sig). **The
   signing capability that releases the BTC lives here: the M-of-N custody keys.**
4. **Broadcast.** Any signer broadcasts the BTC tx. The user receives native BTC.
5. **Close the loop.** Anyone submits an **SPV proof of the payout** back to the Veld peg module,
   which marks `request_id` fulfilled and releases the group's obligation lock on their bonds.
6. **Failure → slash.** If `deadline_height` passes with no SPV-proven payout, the request is
   **defaulted**: the bonds of the responsible group are **slashed**, the user is **compensated
   from the slashed bond** (and/or re-issued btcVELD), and the group is penalized/ejected.

**Answering the three questions directly:**
- *What holds the signing capability?* → the **M-of-N custody keys**, held by the bonded signer
  group. Not a preimage (that'd be Fork A). Not you.
- *What triggers it?* → a **watcher** (signers watching Veld for the burn event), not a live
  counterparty.
- *What stops it from stealing?* → **not "nothing"** (that's an unbonded honeypot) and **not
  "math"** (impossible across this boundary) → **economics + accountability**: threshold so no
  one signs alone, bonds ≥ exposure so collusion loses money, slashing + user compensation on
  default, rotation so the target moves, caps so the prize is bounded. (§5, §6.)

---

## 5. Trust-minimization toolkit (how to bond the irreducible trust)

You cannot remove the L3 signer. You can squeeze it until stealing is irrational and punishable:

- **Threshold `M-of-N`.** No single party can move custody; theft needs `M` colluders.
- **Bonds ≥ custody share.** Each signer posts collateral (in VELD, or over-collateralized
  btcVELD/stable value) **worth at least the BTC they can touch**. If the honest payout value a
  group controls never exceeds the slashable bond behind it, **collusion is -EV** and a defaulted
  user is *made whole from the bond*. This is the single most important number in the system:
  **bonded value per group ≥ custody value per group.**
- **Random group rotation.** Re-randomize the active signer group on a schedule (random beacon),
  and redistribute custody UTXOs. Turns a static honeypot into a moving, time-boxed target
  (tBTC-v2 pattern).
- **Optimistic redemption + challenge window + fraud proofs.** Process redemptions optimistically;
  let permissionless watchtowers prove non-payment, double-spend, or unbacked mint, and trigger
  slashing. The *threat* of a provable challenge is what keeps signers honest between rotations.
- **SPV in both directions.** Mint: BTC→Veld deposit proof. Peg-out close: BTC→Veld payout proof.
  Both let consensus — not an operator — decide what happened on Bitcoin.
- **Custody caps + sharding.** Cap BTC per group and globally; run **multiple independent groups**
  so no single key set is the whole reserve. Shrinks the maximum loss from any one compromise.
- **Insurance fund.** Skim peg/DEX fees into an on-chain fund that backstops depeg events beyond
  slashing.

---

## 6. Threat model — the honeypot map

| Threat | Mechanism | Residual risk |
|--------|-----------|---------------|
| **Signer collusion / key compromise** (the big one) | threshold + bonds ≥ exposure + caps + rotation + sharding | bounded to one group's cap; -EV if bonds ≥ value |
| **Censorship** (refuse to honor redeem) | deadline + fraud proof → slash → compensate user | user made whole from bond; signer ejected |
| **Unbacked mint** (inflate btcVELD) | SPV-proven deposits only; watchtowers verify supply==custody | none if SPV is sound |
| **SPV relay attack** (fake BTC headers) | require `K` deep confs; most-work header rule; relay incentives | economically secure at depth; not at 1 conf |
| **Bank run / depeg** | over-collateralization + insurance fund + caps | depeg possible if custody < supply |
| **Governance capture** (pause/upgrade keys) | time-locks, minimal scope, documented trust | governance is itself a trust assumption — keep it small and visible |
| **Bridge-hack class** | minimize custody, audit + formally verify SPV/slashing/signer code | bridges are the #1 loss category in crypto — treat the custody code as crown-jewels |

**The central honeypot is the custody UTXO set.** Every design choice above exists to shrink it,
bound it, bond it, and make draining it provably punishable. Name it on the architecture diagram
so no one forgets where the money actually sits.

---

## 7. The decision the team must make — custody spectrum

Pick deliberately; each is *honest* about a different trust level. Don't ship one while
describing another.

- **A. Centralized custodian** (wBTC/BitGo model). One entity holds BTC, mints/burns on attest.
  Simplest, fastest, fully trusted. Honest if labeled "custodial."
- **B. Fixed federation** (Liquid / RSK powpeg). Known `M-of-N` functionaries, often in HSMs.
  Trusted federation; better than one party; still a closed set.
- **C. Bonded threshold + rotation + fraud proofs** (tBTC-v2 direction). Permissionless-ish,
  bonded, rotating signer groups with slashing. **Trust-minimized; most engineering.**
  **← recommended target if you want a credibly decentralized peg.**
**Recommendation.** If the goal is a *decentralized* VELD/BTC market, build **C**, and be willing
to **ship in phases starting from an honest custodial peg (A/B) and decentralize the custody over
time** (§9). If the goal is *trustless* and you can live without a pool, **D** is already done —
extend liquidity there. What you must not do is build A or B and market it as trustless: that is
precisely the "hidden watcher" your advisor is warning about, and it is how bridges become
honeypots that drain.

---

## 8. Precedents — copy the good, study the failures

- **wBTC** — centralized custodian. Works, large, fully trusted. The honest-centralized baseline.
- **Liquid (Blockstream)** — federation of functionaries. Trusted federation, HSM-guarded.
- **RSK powpeg** — federation + HSMs + PoW notarization. Federation trust.
- **tBTC v1 → v2** — bonded ECDSA (v1, heavy collateral, UX issues) → random-beacon threshold +
  optimistic minting (v2). The reference for **C**.
- **RenVM** — marketed "decentralized" darknode threshold ECDSA; in reality the keys were
  controlled by one party (Alameda) and **funds were frozen on its collapse, Nov 2022.** This is
  the exact cautionary tale: a "trustless pool" with a hidden signer is a honeypot with a
  countdown. Read its post-mortem before writing a line of custody code.

**The lesson every one of these teaches:** there is no trustless wrapped-BTC. They are all
*trust-minimized custody*, on a spectrum. Choose your point on the spectrum on purpose.

---

## 9. Build plan (phased, each phase honest about its trust)

- **Phase 0 — DEX + token (trustless L1).** Ship `btcVELD` as a covenant asset and a VELD/btcVELD
  AMM. Back it initially with an **explicitly custodial** peg (Option A). Label it custodial.
  This delivers a working market immediately and de-risks the L1 covenant/AMM code.
- **Phase 1 — SPV relay (trust-minimized mint).** Add the in-protocol Bitcoin SPV light client;
  switch minting to require SPV-proven deposits. Now backing is provable; no unbacked mint.
- **Phase 2 — Bonded threshold custody + redeem + slashing.** Replace the custodian with an
  `M-of-N` bonded signer set; implement the §4b redeem pipeline, deadlines, payout SPV proofs,
  and bond slashing with user compensation. This is the heart of Option C.
- **Phase 3 — Decentralize + harden.** Group rotation (random beacon), permissionless watchtowers
  + fraud proofs, custody caps + sharding, insurance fund, audits + formal verification of the
  SPV verifier and the slashing logic.

> VELD-specific leverage: you already have the **covenant layer** (escrow/swap/channel, fail-closed,
> client-re-derived) to express the btcVELD asset, the bonds, and the slashing covenant; the
> **HTLC/atomic-swap machinery** in `swapd`/`veld_chain.py` as a working BTC-script reference; and
> **ML-DSA** for Veld-side signatures. Note the crypto split: **BTC custody is secp256k1
> Schnorr/Taproot (FROST), Veld-side bonds/assets are ML-DSA** — keep them clearly separated.

---

## 10. The "is it a honeypot?" self-audit (answer truthfully)

If any answer is "an unbonded party can take the BTC," you've found the honeypot — fix it before
launch.

1. Who can sign a custody spend, concretely? (names/keys, threshold `M-of-N`)
2. Is each signer bonded **≥** the BTC value they can touch? If not, collusion is +EV.
3. If all `M` collude, what's the maximum BTC they take? (= your per-group cap) Is it acceptable?
4. Can a user who is **not paid** on a redemption *prove it on-chain* and get compensated
   automatically? If not, redemptions are a promise, not a guarantee.
5. Is every minted btcVELD backed by an **SPV-proven** deposit? Can anyone verify supply==custody?
6. Who can **pause/upgrade** the peg, and on what time-lock? (governance is trust — keep it minimal)
7. When the active group rotates, is custody actually redistributed, or is it the same keys?
8. If the SPV relay is fed a fake header chain, what depth `K` defeats it, and is `K` enforced?

---

### TL;DR for the team
- DEX (VELD/btcVELD): **build it, it's trustless.**
- Mint (BTC→btcVELD): **trust-minimize with a Bitcoin SPV light client.**
- Redeem (btcVELD→BTC): **irreducibly a trusted signer set** — Bitcoin can't see the burn, so a
  bonded `M-of-N` watcher must sign the release. **Build Option C** (bonded threshold + rotation +
  fraud proofs), bond each signer ≥ their custody exposure, cap and shard the reserve, and make
  non-payment provably slashable. That is the most decentralized an honest btcVELD peg can be —
  and it is a real, shippable design, as long as no one calls the redeem path trustless.
