# Mining to a payout address

This feature is a pending update, not part of the published 3.2.6 binaries.

## Windows

For solo mining, open **Mining → Payout settings → Set address**, paste an
address from your wallet and confirm it. Turn on CPU mining if it is off, then
start the node. Mining starts after synchronization and the usual work checks.
The address and mode are saved for the next launch. Saving an address does not
start mining or enable Windows startup. To return to the local wallet, stop the
node and turn off **Address-only solo mining**.

For pool mining, use **Pool mining**, enter the pool endpoint and payout address,
choose workers and start. This existing flow does not require a wallet key or
passphrase. Each device retains its own pool account credentials and balance
history even when several devices pay the same wallet address. Pool credits,
maturity and batched payments remain unchanged.

Only change the solo payout while the node and pool worker are stopped. The
confirmation shows the complete address. Veld validates its checksum, network
and supported destination type; it cannot determine whether you hold its key.
Keep the receiving wallet and its backup elsewhere if that is your intended
setup. Mining to an address does not grant this computer permission to spend it.

## What address-only solo mode does

- Produces ordinary proof-of-work blocks paying the chosen destination. It does
  not change rewards, network difficulty, synchronization or work admission.
- Does not create, import or unlock `miner.key`, `pool.key`, or
  `endorsement_pool.key`. It does not load an extra endorser key.
- Disables local validator endorsements, authenticated co-mining participation
  and automatic signed NMS transactions. Existing on-chain funds, registrations
  and stake positions are not changed by selecting this mode.
- Can use an official signed snapshot on a fresh datadir. The imported state
  remains quarantined from RPC, inbound P2P and mining until a separate
  genesis replay matches the exact snapshot tip and consensus-state digest.
  Snapshot failures fall back to ordinary full validation. **Full IBD** stays
  selectable in the Blockchain screen.
- Uses a distinct encrypted, local-only `address-only-validation.key` to sign
  its own full-IBD restart receipt. That key is never used as the payout
  address, for transaction signing, or for validator endorsements. The receipt
  is bound to the chosen payout address, deployment profile, genesis and local
  network identity; changing the payout requires fresh validation. It cannot
  reuse wallet or fleet receipts. This is a node-validation credential, not a
  spending key for the receiving wallet.
- Keeps local RPC authentication. Windows protects an independent random local
  credential with current-user DPAPI in `address-only-rpc-unlock.dat`; the
  encrypted RPC token is `address-only-rpc.token`. These are not wallet keys and
  are separate from wallet mode's `rpc.token`. A damaged or inaccessible
  credential is refused, not replaced. These machine/user-bound files are not
  portable wallet backups.
- Retains the saved startup mode and managed update handoff. The update resume
  identity is bound to the payout address and mode; changing either prevents
  reuse of a previous wallet/address resume identity. The optional remembered
  wallet unlock is not used in address-only mode.

## Command line

On Windows:

```text
veld-node.exe --address-only --mine --miner YOUR_ADDRESS --no-prompt --datadir YOUR_DIRECTORY
```

Use `--nomine` instead of `--mine` to run the address-only node without hashing.
Signing/setup flags cannot be combined with `--address-only`. Fleet binaries
refuse the address-only flag, including when combined with utility flags.
SHA-384 destinations also require their normal consensus activation height.

On Linux, provision `VELD_ADDRESS_RPC_PASSPHRASE` as a private local service
secret of at least 16 characters, then use the same flags. It protects only the
separate address-mode RPC token. Keep the same secret across restarts; do not
put it in command arguments or reuse a wallet passphrase. Linux does not have
the Windows automatic DPAPI credential provisioning.

Qualification uses disposable profiles and a private network namespace. It does
not establish signed-package, real Windows sign-in or live mainnet payout
qualification. Publication and installation are separate release steps.
