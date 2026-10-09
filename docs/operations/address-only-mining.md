# Mining to a payout address

Address-only solo mining is included in Veld Node 3.2.7.

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
- Disables local validator endorsements and automatic signed NMS transactions.
  An eligible payout wallet can separately sign a public near-miss proof using
  the flow below. Existing on-chain funds, registrations
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

## Near-miss lottery entries

The payout address must meet the lottery's **1,000 VELD** staking requirement
and have confirmed spendable funds for the **0.001 VELD** transaction fee.
Finding a block alone does not submit a near-miss entry.

Near-miss entries require a standard Veld payout address. SHA-384 payout
destinations support block mining after their activation height, but the
current near-miss transaction format does not support them. Their proof status
reports this limitation instead of waiting for an entry.

1. Keep the address-only miner running. On Windows, use **Copy near miss** on
   the node's Mining tab when a proof is available.
2. Open the payout wallet and go to **Co-Mining Lottery → Address-only mining**.
   Paste the proof, or select **Choose proof file** and open
   `address-only-nms.json` in the miner's data folder. The file option works on
   Linux and Windows. Use the folder passed to `--datadir`; the direct command
   line defaults to `./veld-data` when that option is omitted.
3. Select **Sign near miss** and confirm the fee. The wallet checks the payout
   address, chain and current proof before signing. The entry counts after
   the transaction confirms.

On Linux, open the graphical wallet with **Start Wallet.sh**. Its normal
connection is to the public service, so use **Choose proof file** for a local
address-only miner. **Read from this node** is for a wallet connected directly
to the miner's RPC endpoint. Hidden data folders can be shown in your desktop's
file picker.

The exported file contains only public proof data. It contains no wallet keys
or RPC credentials. A separate payout-wallet computer can receive this file
without receiving the miner's credentials. Keep the file current: proofs expire
at the next block, and the wallet refuses expired or already credited entries.
This is a manual signing flow; it does not automatically sign future proofs.
