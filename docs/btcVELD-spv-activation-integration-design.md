# btcVELD Phase-2 — SPV Relay Activation Integration Design

**Status:** design, pre-implementation. This specifies wiring the five proven SPV
modules (`btc_pow.h`, `btc_header_chain.h`, `btc_relay_op.h`, `btc_deposit_verify.h`,
+ the real-`bitcoind` E2E) into **deployed consensus**. It is the auditable plan
for the one coordinated change held back so far. **No live-binary code lands until
this is signed off, the regtest peg-money E2E passes, and it is audited.** Every
consensus rule here is a pure function of chain state + compile-time constants —
never a per-node flag (per the fresh-chain relaunch rule).

---

## 0. What the modules already guarantee (done)

- **`BtcHeaderChain`** — ingest/validate BTC headers (PoW, 2016-retarget, MTP,
  most-work), `IsFinal(k)`, `VerifyMerkle`, `Reset()`+replay determinism,
  `StateDigest()`, `MarkDepositUsed`/`IsDepositUsed`.
- **`ApplyBtcHeaderOp`** — permissionless `BTC_HEADER` op; malformed = pure no-op.
- **`VerifyDepositMint`** — the mint gate: `MSPV` proof → credit decision, recipient
  + amount read **from the proven deposit tx** (front-run-proof), no issuer sig, no
  in-consensus EC math. Fail-closed on every branch.
- **Proven** against synthetic chains (reorg determinism) **and against real Bitcoin
  Core v28.1** (E2E: our txid/Merkle/PoW/parser all agree with bitcoind).

This document is only about **how those plug into the node** — not new crypto.

---

## 1. Key finding — the state digest is a *measuring instrument*, not consensus-enforced

`veld::state_digest::Compose` is referenced in exactly two places:
`include/network/rpc.h:1739` (an RPC that **reports** the digest for
cross-host/monitoring) and `mainnet-launch/dryrun/equiv_c2.cpp:181` (the
determinism **proof** harness). **It is never called in a block-acceptance path.**
Nodes do not reject blocks by digest; the digest exists to *prove* two nodes/replays
reach identical state.

**Consequences for this integration:**

1. The SPV relay's real consensus effect is **entirely through the token ledger**: a
   `MINT_SPV` op credits `onchain_tokens_`, changing `D_tokens` — which is already in
   the digest and already deterministically rebuilt on reorg. Nothing new needs to be
   *enforced*.
2. Adding the BTC view to the digest (`D_spv`) is a **proof-instrument extension**
   (re-baseline `equiv_c2` + update the RPC), **not** an enforced-value hard-fork.
3. This is therefore the **same activation-height pattern** already used by covenants
   / vault-sigless / bond-yield (`node.h:5209/5264/5312`), not a novel consensus
   mechanism.

---

## 2. The determinism argument (this MUST hold, or the chain splits)

A `MINT_SPV` op credits **iff** `VerifyDepositMint` returns `ok`, which depends only on:

- **(a)** the `BtcHeaderChain` state,
- **(b)** the op bytes (in the Veld block),
- **(c)** compile constants (`BTCVELD_CUSTODY_SPK`, `K_BTC`, caps).

(b) and (c) are identical on every node. (a) is the crux:

> `BtcHeaderChain` state = a pure function of the **ordered `BTC_HEADER` ops embedded
> in the Veld chain** up to this point.

Every node that replays the same Veld chain feeds the identical header-op sequence and
builds the identical `BtcHeaderChain` (proven in `btc_relay_reorg_test.cpp`:
Reset+replay == forward apply, grouping-independent). **The relay does not depend on
any node's own Bitcoin connectivity** — only on headers already relayed *into* the Veld
chain. That is the whole point of an in-consensus SPV relay.

**Reorg safety:** a Veld reorg triggers `btc_headers_.Reset()` + replay of the new
chain's header ops (mirroring the token-ledger rebuild). If the reorg drops the Veld
blocks that carried the deposit's confirmations, `used_deposits` and the header view
are re-derived from scratch — an un-buried deposit un-mints, deterministically.

**Intra-block ordering:** within one Veld block, **all `BTC_HEADER` ops are applied
before any `MINT_SPV` op** (headers-first). Combined with the `IsFinal(K_BTC)`
requirement — which forces the proven BTC block to be buried `K_BTC` deep, i.e. its
headers were necessarily relayed in *strictly earlier* Veld blocks — an in-block mint
can never depend on an in-block header. Belt and suspenders.

---

## 3. `node.h` wiring — mirror `onchain_tokens_` exactly

The token ledger is the template; the header chain gets a parallel member fed at the
identical sites. Line anchors are current-tree references (verify at edit time).

| Concern | Token ledger (template) | Add for SPV |
|---|---|---|
| main member | `OnChainTokenLedger onchain_tokens_;` @3902 | `BtcHeaderChain btc_headers_;` |
| fork-aware alt | `onchain_tokens_alt_` @3910 | `btc_headers_alt_` (unique_ptr) |
| ctor init | @818 | construct from the compiled `BTCVELD_BTC_CHECKPOINT` |
| main rebuild | Reset+loop @955-976 | `btc_headers_.Reset()`; feed header ops per block **before** `onchain_tokens_.ProcessBlock` |
| reorg rebuild | @4329-4362 | same Reset+feed, same order |
| bootstrap rebuild | @4867-4880 | same |
| forward-apply | @4580-4581 | feed header ops **before** token ProcessBlock |
| alt overlay | @3974-4016 | mirror for the fork-aware path |
| accessor/RPC | `GetTokens()` @1655, `SetOnChainTokens` @1074 | `GetBtcHeaders()`, RPC getter for peg status |

**Feeding pattern (each block `b`):** iterate `b`'s OP_RETURN outputs; for each
`IsBtcHeaderOp`, call `ApplyBtcHeaderOp(btc_headers_, payload, len, b.time)` — a no-op
if malformed. Do this pass **first**, then the existing token pass.

**Passing the chain into the mint gate:** the token ledger's `ProcessBlock` needs a
`const BtcHeaderChain*` to run `VerifyDepositMint`. Follow the existing `amm_` overlay
convention (`amm_.ProcessBlock("VELD:btcVELD", b, onchain_tokens_)`) — pass
`&btc_headers_` (or the overlay's alt) as an argument. The ledger stays a pure function
of (block, header-chain-snapshot).

---

## 4. `onchain_tokens.h` mint-gate wiring — the `PHASE-2 SPV HOOK` (@404-420)

The current mint branch is Phase-1 custodial:

```cpp
// @420 (Phase-1): only the configured issuer may mint.
if (tok_it->second.issuer != op.from) return;
```

Change (gated, additive):

- **New op** `MINT_SPV` carrying the `MSPV` proof bytes (recipient + amount are NOT in
  the op — read from the proof, per the recipient-binding design).
- At height `>= BTCVELD_SPV_ACTIVATION_HEIGHT`:
  - `MINT_SPV`: `auto r = VerifyDepositMint(*btc_headers, proof, len, BTCVELD_CUSTODY_SPK, K_BTC, MAX_PER_MINT, current_supply, MAX_CUSTODY, [](const std::string& a){ return !AddressToScript(a).empty(); });`
    → on `r.ok`: credit `r.recipient` `r.amount`, then `btc_headers->MarkDepositUsed(r.deposit_key)`.
  - Issuer-signed `MINT`: **still honored** during the transition window
    `[BTCVELD_SPV_ACTIVATION_HEIGHT, BTCVELD_ISSUER_MINT_SUNSET_HEIGHT)`, then rejected.
- Below `BTCVELD_SPV_ACTIVATION_HEIGHT`: `MINT_SPV` is a **no-op**; issuer `MINT`
  unchanged. Fully dormant.

`AddressToScript` (@384) is the real recipient validator — it returns a
`std::vector<uint8_t>` script, **empty ⇒ invalid address** (the codebase's existing
validity convention). `BTCVELD_CUSTODY_SPK` is a new canonical compile constant
(custody consolidates to one scriptPubKey).

---

## 5. Digest measurement extension (proof instrument — §1)

- Add `D_spv` to a **v3** `Compose` (new domain tag `VELD_STATE_DIGEST_v3|`,
  `VELD_D_SPV_v1|`). `D_spv = active ? btc_headers_.StateDigest() : <excluded>`.
- **Dormant excludes it** → `rpc.h` + `equiv_c2` byte-identical to today for all heights
  `< BTCVELD_SPV_ACTIVATION_HEIGHT`. Keep `ComposeV1`/`Compose(v2)` for historical
  baselines; select by height.
- Update `rpc.h:1739` and re-baseline the `equiv_c2` expected digest for post-activation
  scenarios only.

---

## 6. `equiv_c2` extension

Add a node-level `MINT_SPV` reorg scenario to the existing C2 harness: relay headers +
mint on branch A; force a Veld reorg to branch B that re-orders / un-buries the deposit;
assert the Reset+replay rebuild reproduces the token + header state exactly (mint present
iff the deposit is `IsFinal(K_BTC)` on the winning branch). This proves the *node's*
BtcHeaderChain rebuild is reorg-deterministic, extending the module-level proof.

---

## 7. Activation constants (all compile-time)

```
BTCVELD_SPV_ACTIVATION_HEIGHT     // 0 = disabled; set to a future height for rollout
BTCVELD_ISSUER_MINT_SUNSET_HEIGHT // issuer-signed mint removed at/after this height
BTCVELD_CUSTODY_SPK[]             // canonical custody scriptPubKey (hex → bytes)
BTCVELD_BTC_CHECKPOINT            // compiled header checkpoint at a retarget boundary
K_BTC                            // deposit burial depth (e.g. 6)
BTCVELD_MAX_PER_MINT, BTCVELD_MAX_CUSTODY  // sat caps
```

Mainnet-inert while `BTCVELD_SPV_ACTIVATION_HEIGHT == 0` **and** issuer unset — same
dormancy property the token ledger already ships with.

---

## 8. Dormant-inertness — the no-drift gate (must pass before any deploy)

With `BTCVELD_SPV_ACTIVATION_HEIGHT` unset/future on the live chain:

- no `MINT_SPV` is honored, `D_spv` is excluded from the digest, and (even though
  `btc_headers_` may ingest relayed headers) it never touches `onchain_tokens_`.

**Proof obligation (differential):** replay the live chain through both the current
production binary and the SPV-integrated binary; assert the reported
`ConsensusStateDigest` is **byte-identical at every height** `< activation`. This
differential-digest equality is the hard gate before the fleet/Windows rollout — it
demonstrates the integrated binary is a consensus no-op until activation.

---

## 9. Rollout discipline (audit-gated, no-drift)

1. Implement behind the dormant gate (this spec).
2. Prove dormant-inert (§8 differential digest) + full SPV regression stays green.
3. Regtest **peg-money** E2E: real `bitcoind` deposit → `MINT_SPV` credits btcVELD →
   AMM seed → swap → REDEEM → burn, end-to-end.
4. **AUDIT.**
5. Set `BTCVELD_SPV_ACTIVATION_HEIGHT` to a future height.
6. Rebuild + deploy **the full fleet + veld-desktop + the Windows zip** to the same
   version **before** that height (no binary drift; sighash/constant-change rebuild rule).
7. Activate at the height; monitor the peg watchtower.
8. Later: set `BTCVELD_ISSUER_MINT_SUNSET_HEIGHT` to drop the custodial path.

---

## 10a. Integration correctness requirements (audit surfaced — do not miss)

These are non-obvious ways the wiring could be *correct in isolation but wrong in the
node*. Each is a hard requirement on the integration code:

1. **`veld_time` must be the enclosing Veld block time (nonzero).** `SubmitHeader`/
   `ApplyBtcHeaderOp` disable the BTC-header +2h future-time bound when `veld_time == 0`
   (the module tests pass 0 deliberately). The node **must** pass `block.time`, or a
   relayer could inject far-future-timestamped BTC headers.
2. **`current_supply` must be the deterministic total btcVELD supply** at that point in
   `ProcessBlock` (from `onchain_tokens_`), so the custody cap is enforced identically on
   every node. (The gate is now overflow-safe regardless, but the value must be right.)
3. **`K_BTC` convention:** `IsFinal(block, k)` means **k blocks on top** of the deposit
   block (deposit at height H is final once best ≥ H+k) — i.e. k+1 Bitcoin confirmations.
   Pick `K_BTC` with that in mind (e.g. 6 → 7 confirmations).
4. **No orphan-header buffering (by design):** a header whose parent isn't yet known is
   dropped, not queued. Relayers must submit **parent-before-child**; out-of-order headers
   are dropped **deterministically** (every node drops the same ones — no split) and must be
   re-relayed. Liveness only, never safety.
5. **`used_deposits_` grows unbounded in principle** (one 32-byte entry per successful
   mint). Economically bounded (each entry = a real locked BTC deposit), but a
   long-horizon note for state size / snapshot design.

## 10b. Pre-mainnet test requirement (coverage gap)

`CalcNextBits` (retarget arithmetic) is proven against **real mainnet retarget vectors**;
the `BtcHeaderChain` walk-back-2015 logic is proven on a **synthetic** chain; the E2E
runs on **regtest (no retarget)**. The *composition* — ingesting ≥2016 real mainnet headers
through `BtcHeaderChain` and retargeting correctly at the boundary — is **not yet
E2E-tested against real data.** Add a real-mainnet-headers-across-a-retarget-boundary E2E
before mainnet activation. Low risk (both halves are proven), but insolvency-critical, so
prove the join.

## 10. Honest limits

- **Liveness, not safety, needs relayers:** someone must relay BTC headers into the Veld
  chain (permissionless; the operator can run one). If no one relays, mints stall — they
  never become *wrong*.
- **Deposits must supply the stripped legacy serialization** of the deposit tx (txid is
  over legacy bytes, not the segwit wtxid). Wrong bytes simply fail the Merkle proof.
- **Custody consolidation:** deposits must pay the one canonical `BTCVELD_CUSTODY_SPK`.
- **Redeem leg out of scope:** trust-minimizing the *custody key* (FROST 3-of-5 + bond/
  slash + independent signers) is a separate workstream; this doc only removes issuer
  trust from the **mint** leg.

---

*Precursor to: the gated implementation. See `docs/btcVELD-spv-relay-design.md`,
`docs/btcVELD-spv-recipient-binding-design.md`.*
