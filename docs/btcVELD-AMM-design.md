# VELD/btcVELD AMM — Design (2026-07-01)

On-chain constant-product AMM pairing **native VELD** with the **btcVELD** peg token,
so anyone can swap VELD ⇄ btcVELD (and thus reach BTC via the redeem path) and
provide liquidity for fees — no custodial order book. Companion to
`btcVELD-redeem-path-design.md` + `btcVELD-phase1-bootstrap.md`.

## 1. The core problem — two asset models
- **VELD** — native, **UTXO-based**, fixed/capped supply, int64 sats (8-dec).
- **btcVELD** — **account-ledger** token (`OnChainTokenLedger`), int64 sats, BTC-backed.

A constant-product pool must hold BOTH reserves and enforce `x·y = k`. Neither pure
approach works alone:
- A **P2SH covenant script cannot** enforce the AMM — a script sees only the spending
  tx, not the btcVELD ledger, so it can't check a cross-asset invariant.
- **Minting VELD** out of the pool is impossible — VELD supply is capped; the pool
  can't create it.

So the pool's VELD must be **real UTXOs that swaps spend**, and the invariant must be
enforced by **consensus** (a dedicated AMM validator), not by a script.

## 2. Pool representation — the hybrid
Each pool is one logical object split across the two models:

| Component | Where it lives | Why |
|---|---|---|
| `reserve_veld` | a **chained pool covenant UTXO** (native VELD) | VELD can't be minted; held as spendable UTXOs |
| `reserve_btcveld` | the **AMM ledger** (consensus-tracked) | btcVELD is already ledger-native |
| `lp_supply` + `lp_balances[addr]` | the **AMM ledger** | LP shares are internal accounting |
| `pool_utxo` (txid:vout) | AMM ledger (pointer) | ties the two halves together |

The **pool covenant** is a deterministic script (P2SH of a pool marker keyed by
`pool_id`). Consensus **special-cases** it: the pool UTXO is spendable ONLY by a valid
AMM-op tx that (a) spends it as `input[0]`, (b) recreates the pool UTXO as `output[0]`
with the correct new `reserve_veld`, and (c) satisfies the invariant. Any other spend
is rejected.

## 3. AMM ledger state (mirrors OnChainTokenLedger)
```
struct Pool {
    int64_t  reserve_veld;      // sats; MUST equal the pool UTXO value
    int64_t  reserve_btcveld;   // sats
    int64_t  lp_supply;         // total LP shares
    OutPoint pool_utxo;         // current chained VELD UTXO
    uint32_t fee_bps;           // e.g. 30 = 0.30%
};
pools:        pool_id            -> Pool
lp_balances:  "pool_id:addr"     -> int64_t shares
```
Folded into the state digest under a new `sd::tags::AMM`; `Reset()` + replay on reorg;
**all integer math, no floats** — same determinism discipline as the btcVELD ledger.

## 4. Operations (OP_RETURN op + pool-UTXO spend)
Every op is one tx: `input[0]` = current pool UTXO; user VELD inputs (if any);
`output[0]` = new pool UTXO; user VELD payouts (if any); an `OP_RETURN`
(`VELD_AMM|action|pool|user|params`). The btcVELD + LP deltas are applied in the AMM
ledger by consensus.

### 4.1 ADD_LIQUIDITY — deposit BOTH, proportional (doesn't move price)
```
Δbtcveld = Δveld · reserve_btcveld / reserve_veld      (consensus computes exact)
Δlp      = lp_supply · Δveld / reserve_veld
```
First LP (empty pool): `Δlp = isqrt(Δveld · Δbtcveld)`, and `MIN_LIQUIDITY` shares are
locked forever (Uniswap-style — kills the first-LP share-price inflation attack). The
consensus-pinned seed ratio sets the opening price (§7).

### 4.2 REMOVE_LIQUIDITY — burn shares, take pro-rata
```
Δveld    = reserve_veld    · Δlp / lp_supply
Δbtcveld = reserve_btcveld · Δlp / lp_supply
```

### 4.3 SWAP VELD → btcVELD
```
Δin_net = Δin · (10000 − fee_bps) / 10000
Δout    = reserve_btcveld · Δin_net / (reserve_veld + Δin_net)     // FLOOR
reserve_veld    += Δin ;  reserve_btcveld -= Δout
```
Fee stays in the pool → `k` grows → LPs earn. Pool UTXO **grows** by `Δin`.

### 4.4 SWAP btcVELD → VELD  (symmetric; pool UTXO **shrinks**, pays user VELD)
```
Δin_net = Δin · (10000 − fee_bps) / 10000
Δout    = reserve_veld · Δin_net / (reserve_btcveld + Δin_net)     // FLOOR
reserve_btcveld += Δin ;  reserve_veld -= Δout
```

**Rounding rule:** every user output is **floored** (toward the pool); consensus
asserts `new_reserve_veld · new_reserve_btcveld ≥ k_before` on swaps, so rounding can
never drain the pool.

## 5. Consensus validation (the AMM validator, in ProcessBlock)
For each AMM-op tx:
1. Parse op; look up `pool`.
2. `input[0] == pool.pool_utxo` (spends the live pool).
3. `output[0]` = pool covenant script, value == new `reserve_veld`.
4. btcVELD delta matches (via the token ledger — debit/credit user + pool reserve);
   user's btcVELD balance + signature verified for btcVELD-in ops.
5. Invariant holds (§4).
6. Apply: `pool` (reserves, lp_supply, `pool_utxo = output[0]`), token ledger, `lp_balances`.
Any failure ⇒ tx invalid, pool unchanged.

## 6. Reorg-determinism
AMM module `Reset()` + replays with the block sequence on reorg; integer-only math +
the pool-UTXO chain make replay byte-exact; state digest `sd::tags::AMM`.

## 7. Pool initialization (consensus-pinned desk rate)
The first ADD_LIQUIDITY on the empty pool must use the consensus-pinned launch
price. Per the Phase-1 bootstrap: seed **`b` btcVELD + `b·100000` VELD**
(1 BTC = 100k VELD, 50/50 by value) → opening spot
`reserve_veld/reserve_btcveld` = 100,000 VELD/btcVELD. A first seed at any other
ratio is invalid.
`lp_supply = isqrt(reserve_veld · reserve_btcveld)` minus the locked `MIN_LIQUIDITY`.

## 8. Honest limits / hazards
- **UTXO-AMM serialization** — the pool is a single UTXO, so state transitions
  **serialize**: at most one swap "slot" per tx-chain. Multiple swaps in a block must
  chain (tx₂ spends tx₁'s pool output) and are strictly ordered ⇒ inherent MEV/ordering
  surface + a throughput ceiling (unlike account-based AMMs). Mitigations: relayer/batch
  ordering, or multiple pools. Documented, not hidden.
- **First-LP attack** — mitigated by the consensus-pinned launch ratio and
  permanent minimum-liquidity lock.
- **Rounding** — always floor toward the pool; assert `k` non-decreasing on swaps.
- **Value at risk** — the pool holds real VELD + BTC-backed btcVELD. The invariant +
  the pool-covenant special-casing must be airtight — the piece most needing adversarial
  audit + fuzzing before mainnet.
- **Price is seeded, not oracle'd** — consensus fixes the first seed to the
  documented desk ratio; later reserve prices still move by trading and arbitrage.
- **Not a limit-order book** — constant-product only; large trades slip (the anti-whale
  property from the bootstrap doc).

## 9. Build increments
1. **AMM ledger module** (pool state + LP + ops + invariant, integer math) beside
   `OnChainTokenLedger`; **dry-run** proving add / swap(both) / remove, the invariant,
   rounding-favors-pool, and reorg-replay determinism (mirrors `repro_btcveld.cpp`).
2. **Pool covenant + block-validation wiring** (pool-UTXO chain + consensus special-case).
3. **Full-node regtest**: seed → swap → add/remove, end-to-end with the redeem path
   (VELD → btcVELD → burn → BTC).
4. **Wallet UI** swap/LP surface.
Gated behind `VELD_BTCVELD_REGTEST` (mainnet-inert) exactly like the ledger; MAINNET
behind the finality work + an audit.
