# btcVELD Automated Minter — Design & Threat Model (Phase-1)

Status: DESIGN (2026-07-02). Companion to `swap/veld_redeemd.py` (the mirror: burn→BTC).
This service is the INBOUND leg of the peg: **confirmed BTC deposit → mint btcVELD**.

## 1. Trust model — why this must be bulletproof

Consensus (`onchain_tokens.h::ApplyTokenOp`) authorizes a MINT **iff** the tx is
signed by `BTCVELD_ISSUER_ADDRESS`. It performs **no** BTC verification — the
Phase-2 SPV hook (deposit txid + merkle branch + K_btc confs proven into consensus)
is not live. The only on-chain supply guard is int64-overflow.

Therefore in Phase-1 the **minter is the sole trust anchor**: everything that ties a
mint to real, final, not-already-used BTC lives here, off-chain. A bug or compromise
that mints without matching BTC silently breaks the peg (unbacked btcVELD). The
design goal is that **no single failure — bad input, replay, reorg, crash, race,
partial compromise — can mint btcVELD that isn't 1:1 backed by confirmed custody BTC.**

## 2. Threat model (attacks the design must defeat)

| # | Attack | Defense |
|---|--------|---------|
| T1 | Fake/forged deposit (no real BTC) | Only act on `gettxout`/`getblock` confirmed on-chain state; never mempool/unconfirmed; never trust user-supplied "I deposited" claims |
| T2 | Double-mint (replay one deposit) | Per-outpoint idempotency ledger (txid:vout), atomic, intent-before-broadcast |
| T3 | Amount inflation (mint > deposit) | Mint amount is a PURE function of the confirmed deposit value in sats; 1:1; int64; no rounding (BTC sats == btcVELD sats) |
| T4 | BTC reorg reverses a deposit after mint | Finality gate: deposit buried ≥ K_BTC confirmations before minting |
| T5 | Wrong recipient / recipient confusion | Deposit address is UNIQUE per request and bound to the recipient VELD address at creation (bitcoind label); the address itself is the binding |
| T6 | Key/passphrase theft from the box | Hot key unavoidable for automation → contain: single-purpose hardened box, key encrypted at rest, passphrase from secret store (not on disk), key in RAM only, seed piped on stdin never argv |
| T7 | Over-mint beyond custody (peg break) | **Supply-reconciliation invariant** checked before EVERY mint: `supply(btcVELD) + amount ≤ confirmed_BTC_in_custody`; violation → HALT + alert |
| T8 | Anomalous mint volume (compromise) | Per-window rate cap + max-single-mint; breach → HALT + alert |
| T9 | Injection via addresses/txids/amounts | Strict format+range validation on every external field before use |
| T10 | Concurrency / double-processing | Single-writer daemon, file lock, per-outpoint state guard |
| T11 | Dependency down (bitcoind/veld-node) | Fail closed: any RPC error/uncertainty → do NOT mint, alert |
| T12 | Silent tampering with the mint ledger | Atomic writes; on restart, reconcile intent-ledger vs on-chain reality before any new mint |
| T13 | Deposit to a change/internal address counted as a deposit | Only externally-issued, request-labeled deposit addresses are eligible; change + custody-internal addresses are excluded |

## 3. Architecture

```
  user ──BTC──▶ [unique deposit addr, labeled = their VELD addr]  (bitcoind custody wallet)
                              │
                    veld_mintd.py  (single-writer daemon, on the custody box)
        ┌──────────────┬───────────────┬───────────────┬──────────────┐
     detect         finality        idempotency     RECONCILE       build+sign+
   confirmed        ≥K_BTC          per-outpoint     supply≤custody  broadcast MINT
   deposits         confs           ledger          (HARD gate)      (issuer key)
        └──────────────┴───────────────┴───────────────┴──────────────┘
                              │                                │
                        bitcoind RPC                     veld-node RPC
                     (deposits, custody)          (preparetokenmint→sign→send)
                                                         + watchtower (independent
                                                          supply==custody monitor,
                                                          can trip the kill-switch)
```

- **Deposit binding (T5):** to wrap, a requester's VELD address `V…` is handed a
  fresh BTC deposit address via `bitcoin-cli getnewaddress "V…"` (label = the VELD
  address). Whatever BTC arrives there mints btcVELD to `V…`. The address *is* the
  binding — no sender memo, no OP_RETURN, no ambiguity.
- **Mint builder:** node RPC `preparetokenmint <issuer> <recipient> <sats>` (sibling
  of `preparerawtransaction`, no 80-B memo cap) → `{unsigned_tx_hex, inputs}`.
- **Signer:** issuer seed piped on stdin to `veld_signer.js signtransfer` (never argv).
- **Broadcaster:** `sendrawtransaction` to the veld-node.

## 4. The mint decision — every gate, in order (fail-closed at each)

For each confirmed deposit UTXO `(txid, vout, addr, value_sats)`:

1. **Eligible address?** `addr` must be a request-issued deposit address (has a VELD
   label, not change/internal). Else skip. (T13)
2. **Recipient resolves?** label parses to a valid VELD address `V…`. Else skip+alert. (T5,T9)
3. **Already minted?** `(txid:vout)` not in the mint ledger with status `minted`. Else skip. (T2)
4. **Crash recovery?** if status `minting` (intent recorded, crashed mid-broadcast):
   query the veld-node for the recorded mint txid — if on-chain, mark `minted` (NO
   re-mint); else safe to re-send. (T2,T12)
5. **Finality?** `tip_btc − deposit_height + 1 ≥ K_BTC`. Else HOLD (not final). (T4)
6. **Amount sane?** `0 < value_sats ≤ remaining effective custody headroom`. Else HALT+alert. (T3,T8)
7. **Aggregate cap?** supply + reservations + value must remain within effective custody capacity. Else HALT+alert. (T8)
8. **RECONCILE (load-bearing):** `btcVELD_supply + value_sats ≤ confirmed_BTC_custody_sats`.
   Else HALT+alert — the peg would be under-backed; refuse to mint. (T7)
9. **Mint:** record intent `{status:minting, outpoint, recipient, sats}` (atomic) →
   `preparetokenmint` → sign (issuer key) → `sendrawtransaction` → record `minted`
   with the VELD txid. (T2,T11)

Any exception anywhere → the deposit is left unminted, logged, alerted; the daemon
never "guesses." A tripped HALT sets a kill-switch file that blocks all further mints
until a human clears it.

## 5. Key & box hardening (T6)

- Runs only on the dedicated custody box; nothing else user-facing on it.
- Issuer key: ChaCha20-Poly1305 encrypted at rest (the cold-key kit format);
  decrypted to RAM at service start only; passphrase supplied out-of-band (secret
  store / systemd credential), never written to disk beside the key.
- Seed reaches the signer only via **stdin** (argv is world-readable in `/proc`).
- No inbound anything except SSH-from-operator-IP; bitcoind + veld-node bound to
  localhost; the minter is a local client of both.
- Kill-switch: `HALT` file (or SIGUSR1) instantly stops minting; the independent
  watchtower can create it if it ever sees `supply > custody`.

## 6. Independent watchtower (defense in depth) — BUILT, see `btcVELD-watchtower.md`

A separate, minimal process (different code path, different box, read-only creds) that
on a timer compares `btcVELD_supply` (veld-node) vs `confirmed_BTC_custody` (bitcoind)
and re-derives the invariant from primary sources the minter can't fake.

As-built (F1), the enforcement point is the **signer**, not the custody box: writing
the kill-switch only on the custody box (as first sketched here) does nothing if that
box is the one compromised. Instead the watchtower pushes a short-lived **SOLVENT
heartbeat** to the signer, which **refuses to sign without a fresh one** — so it is
fail-CLOSED (watchtower down/partitioned ⇒ minting pauses) rather than fail-open, and
survives a fully compromised custody box. Sustained insolvency additionally trips the
sticky `HALT`. Files: `swap/veld_watchtowerd.py`, `swap/veld_wt_recv.py`,
`swap/veld_peg_solvency.py`, and the gate in `swap/veld_signerd.py`; tests in
`swap/test_peg_solvency.py` + `swap/test_watchtower_integration.py`.

## 7. Determinism & Phase-2

The mint tx is built deterministically (sorted issuer-UTXO selection, fixed fee) so a
Phase-2 threshold (FROST) signer set reconstructs the byte-identical tx, and the
issuer-trust gate (§1) is replaced by the on-chain SPV-proof-of-deposit hook already
stubbed in `ApplyTokenOp`. Only the signer set + the deposit proof change; the
deposit-detection, finality, idempotency, reconciliation, and rate logic here are the
shared, phase-independent core.
