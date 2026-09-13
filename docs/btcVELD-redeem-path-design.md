# btcVELD → BTC Redeem Path — Full Design

Companion to `btcVELD-DEX-design.md`. This is the trust-critical layer (L3): burning btcVELD on
Veld → releasing real BTC. It is the piece that actually moves Bitcoin, and the piece that is
irreducibly trusted (Bitcoin can't verify a Veld burn), so this document specs it to the level a
team can build and audit — including the Phase-1 (custodial) and Phase-2 (bonded threshold)
forms, which share almost all of the same code.

---

## 0. The trust statement (say it out loud)

The redeem path releases BTC on a Veld event Bitcoin cannot see, so **something off-Bitcoin
holds the BTC keys and chooses to sign.** That signer set is the trust root. We do not remove it;
we (Phase 2) reduce it to *M-of-N independent signers whose collusion is economically -EV*, make
every action provable, and compensate users on failure. Phase 1 is honestly custodial (operator
holds the keys), capped, with published proof-of-reserves.

---

## 1. Redemption lifecycle (state machine)

```
REQUESTED ── K_veld confs ──► LOCKED_IN ──► ASSIGNED ──► SIGNED ──► BROADCAST
                                                                        │
                                              ┌── K_btc confs + SPV proof┘
                                              ▼
                                          FULFILLED   (bond-lock released)

  LOCKED_IN ── deadline_height passed, no FULFILLED ──► DEFAULTED
                                                          └─► slash group + compensate user
```

- **REQUESTED** — user burned btcVELD; the request is in Veld state but not yet final.
- **LOCKED_IN** — the burn is buried `K_veld` blocks deep (§3). Only now is it safe to release BTC.
- **ASSIGNED** — the active signer group has picked it up and deterministically built the BTC tx.
- **SIGNED / BROADCAST** — threshold signature produced; BTC tx on the wire.
- **FULFILLED** — an SPV proof of the payout is posted back to Veld; the request closes and the
  signers' per-request bond-lock releases.
- **DEFAULTED** — `deadline_height` passed with no fulfilled payout → the covenant slashes the
  group and compensates the burned user from the slash (re-mint btcVELD or pay out).

---

## 2. The burn transaction (Veld side)

`redeem(amount_sats, dest_btc_scriptpubkey)` is a covenant tx that:
1. **Destroys** `amount` btcVELD (supply drops — provably, on-chain).
2. Emits a redemption record into Veld consensus state:
   `{ request_id, amount_sats, dest_btc_scriptpubkey, request_height, deadline_height, fee_ceiling }`
   - `dest_btc_scriptpubkey` — the exact Bitcoin output script the user wants paid (their address).
     Binding the *scriptPubKey* (not a display address) means the signers pay precisely that and a
     watchtower can check the payout byte-for-byte.
   - `deadline_height` = `request_height + REDEEM_SLA` (the signers' honor window).
   - `fee_ceiling` — max BTC fee the user will absorb (protects them; bounds signer discretion).

The redemption queue is consensus state so *every* Veld node — signers, watchtowers, users — sees
the identical set of obligations. No signer can invent or hide a request.

---

## 3. Finality gate — the direct tie to the reorg work

**A signer must NOT release BTC until the burn is buried beyond Veld's reorg depth.** BTC is
irreversible; a Veld burn is not, until it's deep. If a signer paid out on a 1-confirmation burn
and Veld then reorged that burn away, the btcVELD would be un-burned (back in supply) *and* the BTC
would be gone — a double-spend against the reserve. So:

- `K_veld` ≥ `MAX_REORG_DEPTH` (currently 100) — the LOCKED_IN gate.
- This is why the **miner reorg-stability work is a hard prerequisite for the peg.** A chain that
  reorgs unpredictably (or a node that crashes mid-reorg) is a chain you cannot safely release BTC
  against. The Defect-A/B/C/D fixes and the dark-fork throttle aren't just "stop the miner
  crashing" — they're what make Veld finality trustworthy enough to anchor real BTC. Redeem
  cannot ship on an unstable chain.

---

## 4. The daemon (what each signer box runs)

Per signer: a **Veld full node** (sees burns, posts proofs) + a **Bitcoin node** (sees custody
UTXOs, broadcasts, verifies payouts) + its **key share** + an authenticated channel to the other
signers. Its loop:

1. **Watch** Veld for requests reaching LOCKED_IN (§3).
2. **Independently validate** (never trust another signer's say-so):
   - burn is real, final, `amount ≤ available_custody`, `dest` well-formed, not already FULFILLED,
     within per-request and rolling-window **caps** (§9).
3. **Deterministically construct** the BTC tx (§5) — byte-identical across all signers.
4. **Threshold-sign** (§6): each signer that independently agrees contributes a share; `M` combine.
5. **Broadcast**, monitor for `K_btc` confirmations.
6. **Post the SPV payout proof** back to Veld → FULFILLED.

The honest signer's **independent validation + refusal** is the security core: a fraudulent payout
needs `M` signers to *all* choose to sign it. Each honest signer is a veto.

---

## 5. Deterministic BTC tx construction (subtle, critical)

All signers must build the **exact same transaction** or their signature shares won't combine into
one valid signature. Canonical, consensus-fixed rules (pinned in the covenant so every node agrees):
- **Input selection:** deterministic (e.g. oldest-confirmed-first, tie-broken by `txid:vout`) until
  `≥ amount + fee`. Handles multi-UTXO and consolidation.
- **Outputs:** `[ amount → dest_btc_scriptpubkey ], [ change → custody scriptPubKey ]`; drop change
  if below dust.
- **Fee:** `min(fee_ceiling, feerate_oracle × vsize)`, where `feerate_oracle` is a Veld-consensus
  value (median of recent BTC feerates the chain agrees on), so all signers pick the identical fee.
- **version=2, nLockTime=0, sequence** fixed. Anti-fee-stuck: RBF-enabled + a CPFP/bump policy that
  is itself deterministic (bump to the next oracle tier on a timeout, re-sign).
- Batching multiple due requests into one BTC tx (cheaper) is allowed *if* the batching rule is
  canonical (e.g. all LOCKED_IN requests in `request_id` order, up to a size cap).

---

## 6. Threshold signing

- **Custody key:** a single **Taproot** output key that is a **FROST 3-of-5 threshold Schnorr**
  key. On-chain it looks like one ordinary key (cheap, private).
- **DKG:** the 5 signers generate the key with distributed key-generation — **the full private key
  never exists on any machine, ever**, not even at creation.
- **Signing:** 2-round FROST (nonce commitments → signature shares) over the authenticated signer
  channel; any 3 valid shares combine into one Schnorr signature for the key-path spend.
- **Fallback if FROST tooling isn't ready:** Taproot **script-path `3-of-5` via `OP_CHECKSIGADD`**
  — simpler crypto, but larger on-chain and it reveals the threshold. Ship FROST when ready.
- **Phase 1:** the same daemon signs with a single operator key (or a small M-of-N of the
  operator's own boxes for uptime). Code path is identical; only the key/threshold changes.

---

## 7. The bond + slashing covenant (Veld-side enforcement — Phase 2)

This is where Veld's covenant layer earns the whole design. Each signer locks a **bond** (VELD,
over-collateralized ≥ their pro-rata custody share) in a covenant. Slash triggers, each with an
on-chain proof anyone can submit:

| Trigger | Proof | Consequence |
|---|---|---|
| **Non-payment / censorship** | request LOCKED_IN + `deadline_height` passed + no FULFILLED record | slash group → **compensate the burned user from the slash** (re-mint btcVELD or pay out) |
| **Fraudulent spend** | a custody UTXO spent by a BTC tx (SPV-proven) with **no** matching redemption request | slash the whole group |
| **Wrong payout** | BTC payout's amount/scriptPubKey ≠ the request | slash group + make user whole |
| **Unbacked mint** | btcVELD minted with no SPV-proven deposit | slash |

- **Bond release** is per-request: when a request reaches FULFILLED (SPV-proven correct payout), its
  bond-lock frees.
- **The invariant that makes it work:** *bonded value behind the group ≥ the BTC the group can
  move.* Then even 3 colluders **lose money** stealing.
- **Insurance fund:** peg + DEX fees accrue to a covenant fund that backstops losses beyond slash.

---

## 8. The Bitcoin SPV bridge (the long pole)

Every "prove a BTC fact to Veld" step above (payout FULFILLED, deposit for mint, fraudulent spend)
needs Veld to **verify Bitcoin trustlessly** — i.e. a **Bitcoin SPV light client inside Veld
consensus**: ingest BTC block headers (validate PoW + difficulty retarget + most-work selection),
then verify a Merkle inclusion proof for a specific tx at `K_btc` depth. This is a substantial,
consensus-critical, in-protocol component (precedents: BTC Relay, tBTC's relay, Summa).

- **Phase 1 shortcut:** the operator *attests* to BTC facts (trusted — fine, since the operator is
  already the custodian). No SPV relay needed to launch custodially.
- **Phase 2 requires it:** trust-minimized slashing/compensation is only real if the *chain* (not an
  operator) decides what happened on Bitcoin. **Building this relay is the gate between "custodial"
  and "trust-minimized."**

---

## 9. Custody management, caps, circuit breaker

- **UTXO hygiene:** periodic consolidation (deterministic), a fee-reserve UTXO, dust handling.
- **Rotation:** the active group re-randomizes from a bonded candidate pool on a schedule; custody
  moves to the new group's key via a signed move tx + a fresh DKG. Shrinks the static-honeypot window.
- **Caps (bound the blast radius):** `MAX_CUSTODY` (the honeypot ceiling — mint refuses past it),
  `MAX_PER_REQUEST`, `MAX_PER_WINDOW` (rate-limit outflow). In Phase 1 the cap is what keeps the
  custodial risk to a number the operator can eat.
- **Circuit breaker:** a governance pause on anomalies (has its own trust caveat — keep it minimal,
  time-locked, and documented).

---

## 10. Phase 1 (custodial) → Phase 2 (bonded) — mostly the same code

| Component | Phase 1 (custodial, ship first) | Phase 2 (bonded threshold) |
|---|---|---|
| State machine (§1) | same | same |
| Burn/request (§2) | same | same |
| Finality gate (§3) | same | same |
| Daemon validation + construction (§4,5) | same | same |
| Signing (§6) | single operator key / operator M-of-N | FROST 3-of-5, DKG, **operator holds no share** |
| BTC verification (§8) | operator attests | in-consensus SPV relay |
| Bonds/slashing (§7) | none (self-custody, capped, labeled) | full covenant |
| Transparency | published proof-of-reserves + queue | + published signer set, bonds, SLAs |

Phase 1 is a **real subset** of Phase 2, not a throwaway — the daemon you build now is the daemon
you keep. The graduation adds DKG + the SPV relay + the bond covenant, and the operator **exits the
signing set**.

---

## 11. Failure modes

| Failure | Mitigation |
|---|---|
| ≥M signer collusion | bonds make it -EV; `MAX_CUSTODY`/`MAX_PER_WINDOW` bound it |
| < M signers online | redemptions stall (funds safe); rotation / standby signers |
| Non-deterministic build (shares won't combine) | strict canonical construction (§5) + a re-derive fallback |
| BTC fee spike → tx stuck | fee oracle + RBF/CPFP bump policy (deterministic) |
| **Bitcoin reorg** un-confirms a payout | require `K_btc` depth before FULFILLED; reprocess if orphaned |
| **Veld reorg** un-burns a request after payout | §3 finality gate (`K_veld ≥ reorg depth`) — the reorg-fix dependency |
| Double-processing a request | consensus request state + single-assignment; idempotent by `request_id` |
| Bond value (VELD) < custody value (BTC) | over-collateralize, cap custody, monitor, prefer a stabler bond asset |

---

## 12. Build order (dependencies)

1. **Veld finality hardened** (the reorg fixes) — *prerequisite*; can't release BTC against a
   flaky chain. (In progress now.)
2. **btcVELD asset + burn/request covenant** (§2) + the redemption-queue consensus state.
3. **The daemon** (§4,5) + **Phase-1 signing** (§6) — custodial, operator-attested BTC verification.
4. **Regtest end-to-end**: burn btcVELD → daemon builds+signs → pays regtest BTC → SPV/attest proof
   → FULFILLED; plus the DEFAULTED/compensation path. (Reuse the swapd regtest BTC rig.)
5. **Audit** → **capped mainnet custodial launch** with proof-of-reserves.
6. **Phase 2:** Bitcoin SPV relay (§8) → DKG + FROST (§6) → bond/slashing covenant (§7) → signer
   screening + onboarding → operator exits the signing set.

---

## 13. Honest limits (for the skeptics — including the advisor)

1. Phase 2 is trust-**minimized**, not trustless: 3-of-5 collusion can still steal — it's just -EV
   and bounded. Phase 1 is openly custodial.
2. **Bond-value vs custody-value** is the hard, permanent risk of every bonded bridge (VELD priced
   vs the BTC it guards). Over-collateralize + cap; there's no free version.
3. Liveness needs M-of-N online; below that, redemptions stall (safe but stuck).
4. The **SPV relay and DKG/FROST are real cryptographic/consensus engineering** with their own audit
   surface — the bulk of the Phase-2 work.
5. Real BTC touches nothing until §12.4–5 (regtest-proven + audited). No exceptions.
