# btcVELD Phase-2 — SPV Mint: Recipient Binding (design)

Companion to `btcVELD-spv-relay-design.md` (§5, the mint gate). This resolves the
one open design question the SPV relay hits before it can credit anyone: **when
Veld consensus proves a real BTC deposit, how does it know WHOSE VELD address to
credit — provably, without trusting whoever submitted the mint?**

Blocking for stage 4 (the mint gate). No code here — a buildable spec.

---

## 0. The threat — say it out loud

An SPV proof proves *"X sats landed at the custody address in a buried Bitcoin
block."* It says nothing about the intended VELD recipient. If the recipient is
just a field in the Veld MINT op, chosen by whoever submits it:

> Alice deposits 0.001 BTC to custody, meaning to mint to `V_alice`. Mallory
> watches Bitcoin, sees the deposit confirm, and submits the MINT op first with
> `recipient = V_mallory`. The proof is valid, the deposit real and unused —
> consensus can't tell the difference. **Mallory gets the btcVELD; Alice gets
> nothing.**

This is deposit front-running / theft. The recipient MUST be committed **on
Bitcoin, in a way Veld consensus can read from the proof itself** — never
supplied by the mint submitter.

---

## 1. Hard constraint (measured 2026-07-04)

**Veld consensus has no secp256k1 EC point math.** The node dropped
libsecp256k1 when signing moved to ML-DSA-65 (build_linux.sh). So any scheme that
requires consensus to *derive* a Bitcoin address — e.g. a per-recipient Taproot
tweak `Q = P + H(P‖recipient)·G` — is out until secp256k1 is (re)introduced. The
binding must be verifiable with only what consensus already has: **SHA256d, byte
comparison, and Bitcoin-tx-output parsing.** The ledger credits by VELD address
string (`balances_["btcVELD:" + recipient]`, onchain_tokens.h:444), and
`AddressToScript` validates an address — both available.

---

## 2. Options considered

| # | Scheme | Binds recipient by | In-consensus EC? | Deposit from any BTC wallet? | Operator trust | 
|---|---|---|---|---|---|
| **A/C** | Per-recipient Taproot tweak; the deposit *address* commits to the recipient; consensus re-derives it | address = `f(custody_key, recipient)` | **YES (blocker)** | yes | none |
| **B** | Depositor adds an `OP_RETURN` to the deposit tx naming the recipient; consensus reads it from the SPV-proven tx | an output in the deposit tx | no | **no — needs OP_RETURN-capable wallet** | none |
| **D** | Operator/wrap-service issues a fresh address per user and posts a signed `spk → recipient` BIND op; consensus looks it up | a consensus bind-map | no | yes | small, **user-verifiable** |

A/C is the trustless-from-anywhere endgame but needs secp256k1 in consensus (a
large, consensus-critical crypto surface; defer — Phase-2 FROST is Bitcoin-side,
so it does not by itself pull secp256k1 into Veld consensus).

---

## 3. Chosen design

**Primary — Option B (OP_RETURN commitment).** Trustless, no EC, no operator, no
new consensus state beyond `used_deposits`. Build this for stage 4.

**Planned fallback — Option D (operator-posted BIND).** For "deposit from an
exchange / any wallet" where the depositor can't add an OP_RETURN. Trust-*reduced*
(auditable, user-verifiable at deposit time), no EC. Add after B; specified in §7.

Both close front-running: the recipient is fixed **before/at deposit time**, not
by the mint submitter. B fixes it in the deposit tx; D fixes it in a bind the user
checks before sending. Ship B first (it is the trust story); layer D for UX.

---

## 4. Option B — wire formats

**Canonical deposit transaction** (the wallet builds exactly this on Bitcoin):
- **exactly one** output paying `CUSTODY_SPK` (a compiled constant — the single
  canonical custody scriptPubKey; see §6). Its value = the mint amount.
- **exactly one** `OP_RETURN` output carrying the recipient tag (below).
- any number of other outputs (change, etc.) — ignored.

**Recipient OP_RETURN payload:** `"btcVELD:" ‖ <VELD address, ASCII>`
(≈ 8 + 34 ≈ 42 bytes, well under Bitcoin's 80-byte standard OP_RETURN). The full
address string is carried (not a hash160) so consensus uses it directly as the
ledger key — no reconstruction, no ambiguity.

**Veld `MINT_SPV` op** (an OP_RETURN op in a Veld tx; anyone may submit —
permissionless, like BTC_HEADER). Payload:
`"MSPV" ‖ block_hash(32) ‖ merkle_dirs(u32 le) ‖ merkle_len(u8) ‖ merkle_len×branch(32) ‖ legacy_deposit_tx_bytes`.
- It carries **no recipient and no amount** — both are read from the proven tx.
- `legacy_deposit_tx_bytes` = the deposit tx in its **non-witness (legacy)**
  serialization (version ‖ vin ‖ vout ‖ locktime). The wallet strips any segwit
  marker/flag/witness, so consensus never parses witnesses; `txid =
  SHA256d(legacy_deposit_tx_bytes)` is exactly the Merkle leaf. A BTC tx is a few
  hundred bytes — fits Veld's extended-push OP_RETURN (up to 64 KB;
  BuildOpReturnScript's 0x4d branch).

---

## 5. Option B — consensus mint gate (fail-closed)

On a `MINT_SPV` op at Veld block height H (only when the SPV relay is active):

1. Parse the payload → `{block_hash, dirs, branch[], legacy_tx}`. Malformed → **no-op** (state unchanged).
2. `txid = SHA256d(legacy_tx)`.
3. `BtcHeaderChain::VerifyMerkle(block_hash, txid, branch, dirs)` — txid ∈ that block. Else reject.
4. `BtcHeaderChain::IsFinal(block_hash, K_BTC)` — block on the best BTC chain, buried ≥ `K_BTC`. Else reject.
5. Parse `legacy_tx` outputs (§8):
   - count outputs with `spk == CUSTODY_SPK`. **Require exactly 1**; its value = `amount`. Else reject.
   - count `OP_RETURN` outputs whose data begins `"btcVELD:"`. **Require exactly 1**; the remainder = `recipient` (ASCII). Else reject.
6. `recipient` must be a valid VELD address (`AddressToScript(recipient)` non-empty). Else reject.
7. `deposit_key = txid ‖ custody_vout` (the specific custody outpoint). If `used_deposits` contains it → reject (no double-mint).
8. **Caps** (bound blast radius, §9): `amount ≤ MAX_PER_MINT_SATS`, and `supply + amount ≤ MAX_CUSTODY_SATS`. Else reject.
9. **Apply:** `balances["btcVELD:" + recipient] += amount`; `supply += amount`;
   `used_deposits.insert(deposit_key)`. **No issuer signature required** — the
   proven, buried, unused BTC deposit IS the authorization.

The recipient and amount come solely from the SPV-proven deposit tx, so a hostile
submitter can only relay a mint to the address the depositor themselves named,
for the amount they actually sent. Front-running yields nothing.

---

## 6. Custody consolidation implication

Option B needs a **single canonical `CUSTODY_SPK`** (or a small compiled set) so
consensus can recognize the custody output. So Phase-2 custody consolidates
deposits to one known address (the FROST/Taproot key's scriptPubKey), instead of
Phase-1's bitcoind-issued address-per-user. The wrap service (`veld_wrapd`) changes
from *"issue a unique deposit address"* to *"return the canonical custody address
+ the OP_RETURN tag to attach for your VELD address"*, and the wallet's Wrap flow
builds the two-output BTC tx. (`getpeginfo` should also publish `CUSTODY_SPK` so
the wallet can show it.)

---

## 7. Option D — operator-posted BIND (planned from-anywhere fallback)

For depositors who cannot add an OP_RETURN (exchange withdrawals):

- `BTC_BIND` op: `"BIND" ‖ deposit_spk ‖ recipient`, **signed by the issuer key**
  (already the Phase-1 trust anchor). Consensus stores `bind[deposit_spk] =
  recipient` in a map that enters the state digest (so all nodes agree).
- Deposit flow: user asks the wrap service for an address for `V_alice`; the
  service generates a fresh custody-controlled address `A`, posts `BIND[A]=V_alice`,
  and returns `A` **plus its on-chain bind** so the user can VERIFY `A` is bound to
  their own address before sending. User sends BTC to `A` from any wallet.
- Mint gate (variant of §5): the custody output pays some `spk`; look it up in
  `bind`; the bound `recipient` is credited. No OP_RETURN needed.
- **Trust:** the issuer signs the bind, but (a) it only maps an address to a
  recipient — it can't move the user's BTC (the signer set controls `A`), and (b)
  the user verifies the bind before depositing, so a lying wrap service is caught
  pre-deposit. Trust-reduced + auditable, not trustless. Honest to label it so.

Deferred until after B; it adds a bind-map to consensus state + the digest.

---

## 8. BTC-tx output parser (new, minimal, consensus-critical)

Parse only what the gate needs, over the **legacy** serialization:
`version(4) → varint vin_count → vin×[prevout(36) ‖ varint scriptlen ‖ script ‖ sequence(4)] → varint vout_count → vout×[value(8 le) ‖ varint scriptlen ‖ script] → locktime(4)`.
Extract each output's `(value, script)`. Strict bounds-checking; any overrun →
malformed → reject (fail-closed). **No segwit handling** — the op carries the
stripped legacy form by construction, and if bytes[4..6]==`00 01` (a segwit
marker slipped in) the parser rejects (varint vin_count of 0 → 0 inputs is
non-standard → reject). Unit-tested against real mainnet txs + crafted adversarial
byte streams.

---

## 9. Caps, idempotency, reorgs

- **Caps** stay consensus constants (`MAX_PER_MINT_SATS`, `MAX_CUSTODY_SATS`) —
  the Phase-1 pilot cap (0.0005 BTC) becomes an on-chain rule, bounding the
  honeypot even with a trustless mint.
- **Idempotency:** `used_deposits` keyed by the custody outpoint; a deposit mints
  once. Rebuilt deterministically on Veld reorg (Reset + replay — proven in
  `btc_relay_reorg_test.cpp`).
- **BTC deep-reorg** (> `K_BTC`) can un-back a mint — the residual every SPV
  bridge carries; bound by a high `K_BTC` + the caps + the alert-op HALT (relay
  design §6). Set `K_BTC` conservatively (6–12).

---

## 10. Test plan (stage 4)

Standalone module + test (like stages 1–3a; no deployed-binary):
1. BTC-tx output parser vs real mainnet txs + adversarial/truncated bytes.
2. Mint gate accepts a crafted valid deposit (custody output + `btcVELD:` OP_RETURN,
   SPV-proven against a synthetic `BtcHeaderChain`) → credits the RIGHT recipient
   the RIGHT amount.
3. **Front-run negative:** the same proof re-submitted with any different intent
   still credits the OP_RETURN recipient — theft impossible.
4. Rejects: not final, bad Merkle, wrong/absent custody output, zero/multiple
   custody outputs, absent/multiple `btcVELD:` OP_RETURN, invalid recipient,
   reused deposit, over-cap.
5. Idempotency + reorg determinism of `used_deposits`.

---

## 11. Honest limits

1. **B needs an OP_RETURN-capable BTC wallet** (Sparrow, Electrum, a node — not
   "withdraw from Coinbase"). That's the price of a trustless binding without EC
   in consensus. D covers the rest at a small, auditable trust cost.
2. **Custody consolidates to one address** (§6) — a bigger static honeypot than
   per-user addresses; bounded by the caps and (Phase-2) the bond/rotation.
3. **Not trustless-from-anywhere** until A/C (in-consensus secp256k1) — a
   deliberate, documented deferral, not an oversight.
4. Real BTC is credited by *consensus* here — so this gate ships only inside the
   audited, coordinated activation upgrade (relay design §6b), never piecemeal.
