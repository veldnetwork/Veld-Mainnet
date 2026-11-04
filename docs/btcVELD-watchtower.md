# btcVELD Peg-Solvency Watchtower — As-Built (F1)

Status: BUILT (2026-07-03). Closes external-review finding **F1** — *"peg solvency
has no independent enforcement."* Companion to `btcVELD-automated-minter-design.md`
§6, which specified this component; this document is what was actually built.

## The problem F1 named

Phase-1 consensus authorizes a MINT solely on the issuer signature — it does **not**
verify BTC. The load-bearing invariant

        btcVELD_supply + mint  ≤  confirmed_BTC_custody

was checked in exactly one place: `veld_mintd.reconcile_ok()` on the **custody box**.
The isolated signer re-derives recipient/amount from the tx bytes and enforces caps,
but **has no view of the BTC chain**, so it cannot tell whether custody actually
backs a mint. Result: a **compromised custody box** could ask the signer to mint up
to the signer's rate caps (5 BTC/mint, 25 BTC/hour) with **no BTC behind it** — the
peg breaks and nothing independent stops it.

## What was built

Three small programs + one shared invariant module. The signer now **refuses to
sign** unless an *independent* observer has, seconds ago, confirmed real BTC backs
the mint.

| File | Box | Role |
|---|---|---|
| `swap/veld_peg_solvency.py` | (shared) | Pure invariant + heartbeat schema/gate. One source of truth, no I/O — unit-tested identically on every box. |
| `swap/veld_watchtowerd.py` | **watchtower box** | Timer loop: reads custody (own `bitcoind`) + supply (`getbtcveldsupply`), pushes a SOLVENT heartbeat or a sticky HALT to the signer. |
| `swap/veld_wt_recv.py` | **signer box** | Locked-down SSH forced-command receiver. Writes the heartbeat / HALT and nothing else. |
| `swap/veld_signerd.py` (edit) | **signer box** | New fail-closed gate: no fresh heartbeat, or a mint beyond attested headroom ⇒ REFUSE. |

```
   watchtower box (independent)                         signer box (holds the key)
  ┌───────────────────────────┐                        ┌────────────────────────────┐
  │ own bitcoind → custody sats│   ssh forced-command   │ veld_wt_recv.py            │
  │ veld-node   → supply  sats │ ───────────────────▶   │  → signer-heartbeat.json   │
  │ headroom = C − S − margin  │   (SOLVENT | HALT)     │  → HALT (sticky)           │
  │ veld_watchtowerd.py        │                        │                            │
  └───────────────────────────┘                        │ veld_signerd.py            │
        every interval:                                 │  gate: fresh beat? headroom│
          solvent  → push SOLVENT(headroom)             │  covers mint+in-flight?    │
          insolvent→ withhold beat, then HALT           │  else REFUSE (fail-closed) │
        can only PAUSE/HALT, never sign  ───────────────┴────────────────────────────┘
```

## Why it is fail-CLOSED (not fail-open)

A naive "watchtower drops a HALT" is fail-**open**: cut the watchtower→signer path
and the HALT never arrives, so signing continues. This design inverts it — the
signer requires a **fresh, short-lived heartbeat** to sign:

- **Watchtower dies / is partitioned / errors reading either source** → it pushes no
  beat → the last heartbeat expires (`ttl_secs`, receiver-clamped ≤ 600s) → the
  signer refuses. Minting **pauses automatically**, no human needed, and resumes on
  its own once solvent beats return.
- **Sustained insolvency** (`supply + margin > custody` for N reads) → the watchtower
  additionally trips a **sticky HALT** that only a human clears (matches T7).
- **In-flight** mints (signed, not yet in confirmed supply) are charged against the
  same headroom via the signer's rolling window, so the confirm lag can't be used to
  mint the same headroom twice.
- The watchtower key on the signer box is pinned to a forced-command that can **only**
  pause/HALT — it can never sign, read the key, or get a shell. Granting "can stop
  minting" grants no "can cause minting."

## Residual trust (honest boundary)

This does **not** make the peg trustless — Phase-1 is inherently custodial. What it
changes is the *number of independent failures* required to break the peg:

- **Before F1:** compromise the custody box → mint unbacked btcVELD up to the caps.
- **After F1:** the watchtower's key can only *pause/HALT*, never sign. A compromised
  watchtower **cannot cause a mint** — it can only fail to stop one. To actually mint
  unbacked btcVELD you must **simultaneously** compromise the custody box (to request
  the mint) **and** the watchtower (to keep falsely attesting SOLVENT). Two
  independent boxes, different code paths, different creds.

The end state that removes custody trust entirely is the Phase-2 on-chain
SPV-proof-of-deposit hook (below), not this backstop.

## Install

**Signer box** (137.131.26.78):
```
sudo cp swap/veld_wt_recv.py swap/veld_peg_solvency.py /opt/veld-signer/
# add the watchtower key's forced-command line (see signer-authorized_keys.example)
# ARM enforcement (go-live): the signer refuses caps-only signing once this exists
sudo -u veldsigner touch /opt/veld-signer/watchtower-required
```

**Watchtower box** (its own host — neither custody nor signer):
```
sudo mkdir -p /opt/veld-wt/state
sudo cp swap/veld_watchtowerd.py swap/veld_peg_solvency.py /opt/veld-wt/
sudo cp swap/deploy/watchtowerd.conf.example /opt/veld-wt/watchtowerd.conf   # edit
# generate the signer SSH key, install its PUBLIC half on the signer (line 2 above)
ssh-keygen -t ed25519 -f /opt/veld-wt/wt_signer_ed25519 -N ""
sudo cp swap/deploy/veld-watchtowerd.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now veld-watchtowerd
journalctl -u veld-watchtowerd -f
```

`custody` source: point the watchtower's `bitcoind` at a **watch-only** custody
wallet, or leave the wallet out and list every custody receive address in
`custody_addresses` (scanned with `scantxoutset`, no wallet, no keys on this box).

## Arming / disarming

- `watchtower-required` **present** on the signer box → fail-closed enforcement ON
  (production / live peg). This is the go-live state.
- **absent** → the signer signs on its own caps only (regtest / dev). The signer logs
  `WT-GATE off` at every sign so an un-armed production signer is loud, not silent.

## Failure playbook

| Symptom | Meaning | Action |
|---|---|---|
| signer log: `heartbeat expired …s ago` | watchtower down or unreachable | restart `veld-watchtowerd`; check its journal for read errors |
| watchtower log: `INSOLVENT read k/N` | supply > custody − margin | investigate BEFORE it becomes a HALT — is a deposit un-credited, or is this a real over-mint? |
| signer `HALT` present, `WATCHTOWER …` | sustained insolvency tripped the sticky halt | audit supply vs custody; only a human removes `HALT` after confirming solvency |
| signer log: `would exceed watchtower headroom` | a mint request beyond attested backing (possible custody-box compromise) | do not clear; investigate the custody box |

## Test coverage

- `swap/test_peg_solvency.py` — the pure invariant (headroom math, beat build/validate,
  fail-closed gate: missing/stale/forged/over-headroom/in-flight).
- `swap/test_watchtower_integration.py` — the **real** `veld_wt_recv.py` receiver
  (SOLVENT/HALT/garbage/liar) and the **real** `veld_signerd.watchtower_gate`
  (marker on/off, missing/fresh/stale/over/in-flight), proving both boxes agree on
  the wire format and every refusal path fires.

## Phase-2 note

When the on-chain SPV-proof-of-deposit hook in `ApplyTokenOp` goes live, consensus
verifies BTC directly and this off-chain backstop becomes defense-in-depth rather
than the sole independent check. The invariant module and the gate stay as-is.
