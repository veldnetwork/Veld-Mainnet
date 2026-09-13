# btcVELD Custody Security Posture (audit H-06 remediation)

Audit finding **H-06** ("bridge remains a trusted issuer + single hot-wallet payout system")
is a *design-risk*. The audit accepts either (a) launch the bridge disabled/clearly-labeled,
or (b) move to threshold custody **plus** consensus-enforced one-time deposit/redeem IDs and
independent signing policy — and in **both** cases: "Define emergency pause, proof-of-reserves,
loss limits, and public incident procedures."

This document is that definition. The enforceable technical controls below are now IN THE
CODE (C-04/C-05/C-06 + pre-existing guards); threshold custody is the documented upgrade that
must precede removing the pilot caps.

## Launch posture
- **Pilot, capped, and consensus-gated.** btcVELD launches with the AMM swap gate LOCKED
  (`BTCVELD_AMM_SWAP_UNLOCK_HEIGHT = UINT64_MAX` in the mainnet template) and the peg dormant
  unless an issuer is configured. The effective aggregate custody ceiling is the
  amount-at-risk control; there is no narrower per-address mint ceiling.
- **Not represented as trustless.** Until threshold custody lands, users trust the operator's
  custody + signer policy. This is stated plainly in user-facing btcVELD copy.

## Enforceable controls (in code)
| Control | Mechanism | Source |
|---|---|---|
| One-time deposit id (no double-mint) | Consensus records the funding BTC outpoint; re-mint rejected on-chain | onchain_tokens.h `minted_btc_outpoints_` (C-04) |
| One-time redeem id (no double-pay) | `burn_txid:opreturn_vout` keying + append-only intent WAL + chain reconciliation | onchain_tokens.h vout + veld_redeemd.py (C-05) |
| Independent signer policy | Signer fully deserializes the tx + enforces the canonical mint output template (issuer-change-only outputs, one MINT marker) | btcveld_mint_policy.h, veld_signerd.py (C-06) |
| Aggregate mint loss limit | Effective custody headroom is enforced by consensus, minter, and signer; compatibility single/window bounds equal the absolute custody ceiling and are not independently narrower | constants.h, onchain_tokens.h, veld_mintd.py, veld_signerd.py |
| Redeem outflow rate limit | §5b drain guard: ≤20%/day of custody may leave via REDEEM; over-budget burn rejected whole | btcveld_redeem_guard.h |
| Aggregate solvency invariant | `btcVELD_supply + mint ≤ confirmed_custody` re-checked before EVERY mint | veld_mintd.py `reconcile_ok` |
| Durable ledgers | fsync(file)+fsync(dir) on every mint/redeem ledger write; single-writer flock | veld_mintd.py, veld_redeemd.py |

## Emergency pause (kill-switch)
- **Minter:** create `<state>/HALT` → all minting stops until a human removes it.
- **Signer:** create `<signer>/HALT` → the issuer key signs nothing until removed.
- **Redeemer:** stop the service (systemd) or remove its config; single-writer lock prevents a
  second payer.
- **AMM:** the swap gate is height-locked; the pool covenant can be frozen (disable the sigless
  pool-input exemption) without touching pooled funds.
Tripping ANY halt is fail-closed: the daemons refuse rather than guess.

## Proof-of-reserves
- The **F1 solvency watchtower** (independent box, ML-DSA-signed heartbeat) attests confirmed
  custody headroom. The signer's `watchtower_gate` is **fail-closed**: it refuses to sign a mint
  that would exceed the last independently-attested headroom (plus everything already signed in
  the rolling window). Custody addresses are derived from public xpubs so new deposits auto-track.

## Loss limits
- Issuer minting cannot exceed current effective custody headroom. A single
  allocation may use all of that headroom; signer and minter compatibility bounds
  equal the absolute custody ceiling. Redeem outflow remains bounded by the §5b
  window ceiling.

## Incident procedure
1. **Detect** (watchtower headroom breach, HALT tripped, reconciliation gap, or report).
2. **Freeze**: trip minter + signer HALT; stop redeemd; if AMM is implicated, freeze the pool.
3. **Preserve**: snapshot all ledgers + logs; do NOT restore mint/redeem state without a
   monotonic reconciliation of every historical outpoint/burn against the chain.
4. **Reconcile**: recompute `supply` vs `confirmed_custody`; enumerate consumed deposit outpoints
   (on-chain) and paid burns (append-only intent log) before resuming.
5. **Disclose**: publish a public incident note (scope, impact, remediation) once contained.
6. **Resume** only after root cause is fixed and reconciliation is clean.

## Required before removing pilot caps (threshold-custody upgrade — tracked, not yet built)
- Taproot k-of-n custody (the §6 3-of-5 covenant regtest exists) as the SOLE payout path.
- Threshold / HSM issuer signing with independent policy + payout-history verification.
- Off-host, immutable, signed backups with rehearsed restore.
Until then, the pilot caps above are the blast-radius bound.
