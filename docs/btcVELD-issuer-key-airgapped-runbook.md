# btcVELD Issuer Key — Air-Gapped Generation & Custody Runbook

The issuer key is the **Phase-1 trust anchor**: whoever holds it can mint btcVELD.
It is a standard ML-DSA-65 keypair; its address becomes the consensus constant
`BTCVELD_ISSUER_ADDRESS`, and it authorizes every MINT (a MINT is an ordinary
transaction whose input is *signed by the issuer address*, carrying a trailing
`OP_RETURN` MINT op — there is no privileged `minttoken` RPC). Custody model
chosen: **dedicated air-gapped** — the private key is generated on, and never
leaves, a machine that never touches a network.

> Handling rule: the private keyfile and its passphrase never touch a networked
> host, are never pasted into a terminal that logs, and are never echoed. Only
> the **address** (and optionally the pubkey) ever crosses back to an online
> machine — both are public.

---

## Part 1 — Prepare the air-gapped machine
1. A machine (or a fresh VM) with **no network** — Wi-Fi/Ethernet physically off
   or absent. A live-USB Linux with persistence works well.
2. Transfer **`veld-keygen`** in via USB only. Build it from the audited source
   (`bash build_linux.sh` on a trusted online box, then copy the binary), and
   verify its SHA-256 on the air-gapped side against the value you recorded
   online before trusting it.
3. Nothing else about this machine needs to be online — ever.

## Part 2 — Generate the key (offline)
```
# Pick a strong passphrase; it protects the keyfile at rest. Store it as
# LF-only (no CRLF) — the keygen pass path is newline-sensitive.
export VELD_VAULT_PASSPHRASE='<strong-passphrase>'
veld-keygen new /media/keys/btcveld-issuer.key      # writes the encrypted keyfile
veld-keygen show /media/keys/btcveld-issuer.key      # prints ADDRESS + pubkey (public)
```
Record the **address** (write it down / to a USB text file). That single string
is all that crosses back online.

## Part 3 — Back up (offline, redundant, tested)
- Copy `btcveld-issuer.key` to **at least two** offline media, stored in
  **separate physical locations**.
- Store the **passphrase separately** from the keyfile (both are required to
  sign; splitting them means neither medium alone is sufficient).
- **Test a restore**: on the air-gapped machine, `veld-keygen show` the backup
  copy and confirm it prints the **same address**. A backup you haven't verified
  is not a backup.
- Never place the keyfile or passphrase on any fleet host or networked machine.

## Part 4 — Wire the address into consensus
1. Bring the **address** online.
2. Set it in `include/core/constants.h`:
   ```
   inline constexpr const char* BTCVELD_ISSUER_ADDRESS = "<issuer-address>";
   ```
   (Production default is `""` = dormant; setting it — together with a future
   `BTCVELD_ACTIVATION_HEIGHT` — is what arms the peg.)
3. This constant is baked into the coordinated-upgrade binary that the whole
   fleet + all miners must run *before* the activation height. It is a compile
   constant, not a runtime flag — so every node gates identically (a per-node
   flag would fork the chain).

## Part 5 — Minting offline (the ceremony)
A MINT is a normal issuer-signed tx: a P2PKH spend from the issuer address with a
trailing `OP_RETURN` op `VELD_TOKEN|MINT|btcVELD|<issuer>|<recipient>|<sats>|`.
So minting air-gapped is a sign-offline ceremony:

0. **Fund the issuer address** once with a little native VELD — every mint tx
   needs a UTXO at the issuer address to spend as its input.
1. **Online:** build the *unsigned* mint tx and save the JSON to USB (fields
   `unsigned_tx_hex` + `inputs[].prev_script_hex`). See the note below on the
   builder.
2. **Air-gapped:** sign it —
   ```
   VELD_VAULT_PASSPHRASE='<passphrase>' \
     veld-keygen sign-tx /media/keys/btcveld-issuer.key mint-prepared.json --out mint-signed.hex
   ```
   `sign-tx` decrypts the key, **refuses** unless every input is a P2PKH owned by
   this key (fail-closed), **prints the decoded outputs for you to review** — the
   credited amount + recipient are shown as the `VELD_TOKEN|MINT|…` line — signs
   each input with ML-DSA-65 via the exact consensus path, and writes the signed
   raw tx hex. The private key never leaves the box; stdout carries only the hex.
3. **Online:** `sendrawtransaction <mint-signed.hex>`.

> **★ Build the air-gapped `veld-keygen` to match the target chain's network-id.**
> The sighash binds a network-id byte (`0x4D` mainnet / `0x54` testnet, set by
> `-DVELD_MAINNET_POW`). Build the air-gapped `veld-keygen` with the SAME flags as
> the live fleet (`-DVELD_MAINNET_POW -DVELD_TEST_CHAIN_BUILD` for the current
> chain) or every mint is rejected. `sign-tx` is
> proven: it produces a consensus-valid signature (3311-B sig push + 1952-B
> pubkey, `SIGHASH_ALL`) and fail-closes on any input it doesn't own.

> **⚠ One remaining online piece — the mint-tx builder.** `preparerawtransaction`
> caps its memo at 80 bytes, but the MINT op is ~104 bytes, so it can't build the
> mint tx. A dedicated node builder is needed — a `preparetokenmint <issuer>
> <recipient> <sats>` RPC that selects the issuer's UTXOs and emits the full
> `OP_RETURN` op in the same `{unsigned_tx_hex, prev_script_hex}` shape `sign-tx`
> already consumes. This ships with the coordinated btcVELD node release (it's a
> node change, batched with setting the issuer address + activation height). Until
> then the signer half is complete and verified; only this online builder is
> pending, and it is not needed for keygen, backup, or setting the constant.

## Notes
- Mints are deliberate, infrequent offline ceremonies in Phase-1 (seed the pool,
  occasional top-ups) — the friction is a feature for a trust anchor.
- Compromise of this key lets an attacker mint unbacked btcVELD; it does **not**
  let them violate the AMM/ledger invariants (see the audit cover letter §5).
- For scale beyond the pilot, consider a threshold/multisig issuer so no single
  medium is sufficient to mint (a Phase-2 consideration).
