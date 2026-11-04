# btcVELD — Phase-1 Bootstrap Decisions (2026-06-30)

Decisions locked with the operator during design. This is the **policy / "how we actually turn it on"** layer that sits on top of the mechanism spec in `btcVELD-redeem-path-design.md`. Governs the pilot launch only.

---

## 1. Custody cap — $250, operator's own BTC, pilot-labeled
- Maximum custodial BTC exposure in Phase 1 = **$250 USD of BTC, operator's own funds only.** No third-party BTC in the custodial phase — nobody else is at risk on the single box.
- The cap is a **dial that turns up only as custody earns it:** clean run + published proof-of-reserves → low thousands; real tradeable liquidity waits for Phase 2 (bonded / decentralized signers), never the bootstrap box.
- **Small cap, full rigor:** same daemon, same finality gate, same regtest proof, same audit as at any size. A sloppy $250 test teaches bad habits and can leak a key reused later.

## 2. Genesis liquidity / seed — at the desk rate, 50/50 by value
- Seed the VELD/btcVELD AMM at the **swap-desk rate: 1 BTC = 100,000 VELD**, balanced 50/50 by value.
- $250 mints `b` btcVELD where `b = $250 / BTC_usd` (≈ 0.0025 btcVELD at BTC ≈ $100k). Pair it with `b × 100,000` VELD (≈ 250 VELD). Opening spot price = `VELD_reserve / btcVELD_reserve` = exactly 100,000 VELD/btcVELD.
- **Rationale:** keeps desk / AMM / redeem all at the same price (1 BTC = 1 btcVELD = 100,000 VELD) → no launch-day arbitrage bleed. Seeding at any other ratio opens two BTC→VELD prices and gifts the first arbitrageur the gap.

## 3. Operator LP risk (accepted, eyes open)
- The LP position is a **directional bet that VELD holds or rises vs BTC.** btcVELD is the hard (BTC-pinned) side; VELD floats (soft).
- IL **grows** as VELD diverges from the seed (−5.7% at ½, −20% at ¼, −40% at ⅑); it does *not* "weaken" until already deep (asymptotes toward ~−100% vs holding). Bounded in absolute terms by the cap.
- **Rule: do not defend a fixed VELD price with BTC.** Seed at the rate, keep the pool small, let the price float. Defending a number with the reserve = becoming someone's exit liquidity.

## 4. Anti-pump-dump policy (structural)
- **btcVELD** cannot be pumped/dumped when mint/redeem arbitrage is fast + uncapped (mint caps the top, redeem caps the bottom). In the capped pilot the anchor is weak but the pool is tiny → all bounded.
- **VELD** is the pumpable side; the pool is the extraction vehicle — a VELD holder dumps VELD → pulls btcVELD (real BTC) → LP is left holding the VELD. This is *structural* (a bet on VELD's true value vs the offered rate), not a latency bug.
- **Removals:** (a) **cap hard** (bounds the prize); (b) **let VELD float**, don't prop; (c) **grow real VELD demand** so the price is earned, not artificial; (d) **decentralize liquidity** (not the sole underwriter); (e) **protect retail** — label the pilot a pilot, no hype, no hypeable tradeable market until there is real depth *and* real demand.

## 5. Swap-desk latency
- Keep settlement in **hours, not days.** A 2-day swap widens the peg-manipulation surface (arbitrage won't correct across two days of price risk → the peg drifts) and hands a slow fixed-rate desk a **free option** to gamers (lock the rate, complete only if price moved your way). Fast = tight arb = tight peg.
- **Floor:** redeem is inherently finality-bound (K_veld) and can never be instant. "Fast" means *as fast as finality safely allows*.

## 6. Founder commitment — lock, don't dump
- Commitment is signaled by **on-chain VELD time-lock / vesting** (provable "cannot sell for N years") and/or by bringing **fresh external BTC** in to mint btcVELD that is then locked or LP'd — **NOT** by dumping VELD for btcVELD.
- Dumping VELD → btcVELD *sells* VELD, *reduces* VELD exposure, and on-chain reads as an **exit**. If the operator is the sole LP it is economically circular (pocket-to-pocket); if others are in the pool it is the drain attack, self-inflicted.
- Publish the vesting schedule + proof-of-reserves. The **transparency is the signal.**

## 7. Finality prerequisite (hard gate on mainnet)
- Mainnet peg is gated on Veld reorg-stability: a signer must **not** release BTC until the burn is buried past `MAX_REORG_DEPTH` (**K_veld ≥ 100**). Releasing on an unfinalized burn is a reorg double-spend against the reserve.
- The miner reorg fixes (Defect A owned-worker join + B/C/D) are **prerequisite #1**; runtime confirmation is in progress (ASan canary on n3 awaiting a natural reorg). The Windows miner rebuild needs the operator's PC.
- The **regtest prototype may proceed in parallel** (fake BTC, throwaway chain). Only the *mainnet cutover* waits on the fix landing.

---

## Build order (from here)
1. **btcVELD asset + burn/redeem-request covenant** — new covenant type in the existing app-layer (escrow/swap/channel) framework; `redeem(amount_sats, dest_btc_scriptpubkey)` destroys btcVELD and emits the request into consensus state.
2. **Phase-1 daemon** — validate → finality-gate (K_veld) → deterministic BTC tx build → sign → broadcast → SPV-prove back.
3. **End-to-end on the swapd regtest rig** (bitcoind-regtest) — mint → LP → swap → burn → redeem.
4. **Audit → capped mainnet** — behind the finality gate landing.
