# Launch-live btcVELD SPV deposit and mint runbook

This is the explicit operational path for permissionless, Bitcoin-SPV-proven
btcVELD minting. It is additive: the existing `/wrap` plus `veld_mintd.py`
issuer-authorized path remains live and is not replaced, disabled, or assigned
different economics.

The two SPV steps are intentionally separate:

1. `deposit` spends a configured Bitcoin Core mainnet descriptor wallet into
   exactly one ceremony-bound descriptor-index-0 custody output and exactly one
   `btcVELD:<VELD recipient>` OP_RETURN.
2. `mint` waits until the deposit block is buried by the compiled `spv_k_btc`
   depth, proves inclusion, obtains an authenticated current-root MNP1
   nonmembership witness, and posts the permissionless Veld `VELD_MSPV|` op
   with a strict binary MSP2 payload.

Do not tell a user to make an ordinary payment to the custody address. The
recipient OP_RETURN is consensus-critical. Use the deposit command so the whole
transaction is built and checked as one exact template.

## Prerequisites

- A fully synchronized Bitcoin Core node reporting `chain=main` and a
  private-key-enabled descriptor wallet containing the BTC to deposit and its
  network fee.
- The exact custody SPK manifest produced by the witnessed custody ceremony.
  Its byte SHA-256 and descriptor SHA-256 must match `getpeginfo`; index 0 must
  derive to the compiled P2TR script.
- A synchronized Veld node with the Bitcoin header relay current. Keep
  `veld_btcrelayd.py` running. Its derived btcVELD mint-nullifier proof index
  must also be healthy; `getbtcveldmintstatus` must return a verifiable MNP1
  proof, root, count, tip, and tip hash.
- A dedicated Veld fees-only address and encrypted key. It must not be an
  issuer, pool, custody, validator, or treasury key. Fund it with only the VELD
  needed for relay fees.
- The updated `veld-keygen` containing `sign-op`. `sign-tx` remains
  issuer-mint-only and will correctly refuse relay transactions.

Create the relay-fee key, record the printed V-address in the config, and fund
that address:

```sh
install -d -m 700 /var/lib/veld-spvmint
systemd-run --wait --pipe --property=EnvironmentFile=/etc/veld/spvmint.env \
  /usr/local/bin/veld-keygen new \
  --out /var/lib/veld-spvmint/relay-fee.key
chmod 600 /var/lib/veld-spvmint/relay-fee.key
```

In production, inject `VELD_VAULT_PASSPHRASE` through the protected service
environment/secret manager. Do not put it in the JSON config.

## Install the always-on Bitcoin header relay

The SPV mint CLI is not self-relaying. Install the shipped
`veld-btcrelayd.service` and copy `btcrelayd.example.json` to
`/etc/veld/btcrelayd.json`. The relay uses a separate fees-only hot key so its
UTXO selection cannot race an interactive SPV mint operation:

```sh
useradd --system --home-dir /var/lib/veld-btcrelayd \
  --shell /usr/sbin/nologin veldbtcrelay
install -d -m 700 -o veldbtcrelay -g veldbtcrelay /var/lib/veld-btcrelayd
install -m 600 -o root -g root /dev/null /etc/veld/btcrelayd.env
# Populate the protected env file from the service secret manager before
# generating the encrypted fees-only key.
systemd-run --wait --pipe --uid=veldbtcrelay \
  --property=EnvironmentFile=/etc/veld/btcrelayd.env \
  /usr/local/bin/veld-keygen new \
  --out /var/lib/veld-btcrelayd/header-relay-fee.key
chmod 600 /var/lib/veld-btcrelayd/header-relay-fee.key
install -m 600 -o veldbtcrelay -g veldbtcrelay \
  swap/deploy/btcrelayd.example.json /etc/veld/btcrelayd.json
install -m 644 -o root -g root swap/deploy/veld-btcrelayd.service \
  /etc/systemd/system/veld-btcrelayd.service
```

Populate `/etc/veld/btcrelayd.env` from the service secret manager with only
`VELD_VAULT_PASSPHRASE=...`; never place the passphrase in JSON. Replace the
fees-only Veld address in the JSON and fund it with only relay fees. Grant the
service user read-only access to the local Bitcoin Core RPC cookie (normally by
the deployment's `bitcoin` group); do not grant custody-wallet access.

Production validation is deliberately strict:

- `state_dir` is absolute, service-owned, non-symlink, and mode 0700;
- the JSON config, encrypted fee key, and relay state are bounded,
  single-link, owner-controlled files; config/key/state files are mode 0600;
- Bitcoin Core, `veld-node`, and `veld-keygen` are absolute trusted executable
  paths, RPC is exactly local `http://127.0.0.1:PORT`, and the bearer token is
  obtained only through `veld-node --print-rpc-token`;
- `max_headers_per_op` is 1..100 (and therefore fits the one-byte wire count),
  resubmission and loop intervals are bounded; and
- `checkpoint_height` may never exceed the running Veld consensus
  `best_height`. The authoritative next frontier is always `best_height + 1`;
  a mistyped future checkpoint exits with configuration status 64 instead of
  silently skipping headers. Leaving the example value at `0` is safe.

Then start and verify the relay:

```sh
systemctl daemon-reload
systemctl enable --now veld-btcrelayd
journalctl -u veld-btcrelayd -f
```

Do not begin an SPV deposit until `getbtcheaderinfo` advances with Bitcoin and
the relay reports no in-flight or configuration error.

Copy `spvmint.example.json` to a root-owned mode-600 path and replace all
deployment paths, wallet name, and the fees-only Veld address. The
`custody_manifest` path must be absolute. The config intentionally contains no
operator-authored custody address, SPK, caps, or confirmation threshold: those
are read from the manifest and the running node's compiled `getpeginfo`, then
cross-checked.

Use only the builder's canonical `custody-spks-consensus.json` `[0,999]`
manifest here. The separate `custody-spks-operational.json` extends the same
descriptor through the signed C1 public end for allocator/custody services; it
must not replace the exact consensus manifest compiled into `getpeginfo`.

## Create and broadcast a deposit

Amounts are integer satoshis:

```sh
python3 /opt/veld/swap/veld_spvmint.py \
  /etc/veld/spvmint.json deposit \
  --recipient VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg \
  --amount-sats 50000
```

Before broadcast the command:

- requires a synchronized Bitcoin mainnet node and private descriptor wallet;
- matches descriptor/manifest hashes, range, index-0 SPK, and live SPV status
  to `getpeginfo`;
- re-derives all 1,000 ceremony scripts through Bitcoin Core;
- checks the amount against both the compiled SPV per-mint cap and current
  aggregate custody headroom;
- creates and signs a PSBT with one exact custody output and one exact recipient
  OP_RETURN;
- allows at most one Bitcoin Core-created, wallet-owned change output;
- checks the finalized raw bytes, witness-stripped txid, fee ceiling, and
  `testmempoolaccept`; and
- records the raw transaction and exact `txid:vout` durably before/after
  broadcast.

The JSON result contains `btc_txid`, `outpoint`, `custody_vout`, and
`required_confirmations`. The required Bitcoin RPC confirmation count is
`spv_k_btc + 1`: consensus defines `spv_k_btc` as blocks *on top of* the
deposit block.

## Submit the SPV mint

Run once after the deposit is mined, with an optional bounded wait:

```sh
python3 /opt/veld/swap/veld_spvmint.py \
  /etc/veld/spvmint.json mint \
  --txid REPLACE_WITH_64_HEX_BITCOIN_TXID \
  --expected-recipient VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg \
  --wait-seconds 7200
```

Mint mode:

- requires the deposit block to remain on Bitcoin Core's best chain at
  `block_height + spv_k_btc <= Bitcoin tip`;
- requires Veld's in-consensus BTC header relay to reach the same finality
  height and report the same compiled `k_btc`;
- obtains the block's ordered txids, constructs the Bitcoin Merkle branch, and
  folds it locally back to the block's reported Merkle root;
- parses both legacy and SegWit transactions, removes only witness data, and
  requires double-SHA256 of the exact stripped serialization to equal the
  displayed Bitcoin txid;
- revalidates the unique index-0 custody output, amount, unique recipient tag,
  recipient address, caps, supply headroom, block-height mapping, and compiled
  identity immediately before submission;
- queries `getbtcveldmintstatus txid:vout`, validates its MNP1 version and
  root/count/tip fields, and embeds its exact canonical nonmembership witness,
  so a previously consumed issuer/SPV outpoint never spends another relay fee;
- rechecks the same nullifier root, count, and witness at the final pre-fee
  barrier; a concurrent mint changes the root and returns safely to pending;
- builds through `preparerawop`, signs through the strict fees-only
  `veld-keygen sign-op` policy, and broadcasts through `sendrawtransaction`;
  and
- persists the signed transaction before broadcast, allowing an interrupted
  run to rebroadcast the exact same Veld tx rather than construct a second fee
  spend.

Exit 75 means the deposit/header relay is safely pending and may be retried.
Any identity drift, reorg, ambiguous output, malformed proof, nullifier
root/count race, or cap race exits nonzero without constructing a replacement
proof in place.

## Idempotency and recovery

`/var/lib/veld-spvmint/spvmint-state.json` is mode 600 and keyed by the exact
Bitcoin `txid:vout`. Back it up with the other operator state, but do not treat
it as consensus authority. `getbtcveldmintstatus` reconstructs and verifies an
exact witness against the chain-committed shared issuer/SPV root and count, so
loss of the local file cannot cause a second btcVELD credit. If the process
stops after signing or broadcast, rerun the same mint command; it checks chain
status and rebroadcasts only the persisted identical transaction. If the stored
signed carrier was built for an older root, it is retained while visible; only
after the node proves it absent may the operator discard those carrier fields
and build a new witness/transaction.

## Nullifier-index degradation

The proof index is derived and repairable; it is not a consensus authority. A
missing, corrupt, reordered, incomplete, or write-failed transition stream
causes `getbtcveldmintstatus` and new mint preparation to fail closed. It does
not stop existing btcVELD transfers, redeems, AMM operations, or normal block
validation.

On an index-degraded error, pause new deposits, retain logs and the data
directory, restart the node so canonical replay repairs the transition rows,
then verify a status response's root/count/tip before resuming. Do not bypass
the error with an empty, cached, or hand-authored witness. The complete wire and
recovery specification is `docs/BTCVELD_MINT_NULLIFIER_ACCUMULATOR.md`.

## Verification commands

Network-free focused Python tests:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest -v \
  swap.test_btcrelayd swap.test_spvmint
```

The focused C++ RPC/policy regression is executed by both
`scripts/run-hermetic-tests.sh` and `scripts/run-regression.sh`; it is not an
out-of-band optional check. To reproduce just that binary, use the same clean
PQC archive/link flags and `VELD_TEST_HOOKS` used by those runners:

```sh
g++ -std=c++17 -O1 -DVELD_USE_DILITHIUM -DVELD_TEST_HOOKS \
  -Iinclude -Ivendor/pqc -Ivendor/pqc/mldsa65 \
  mainnet-launch/dryrun/repro_spv_rawop_rpc.cpp \
  -o /tmp/repro_spv_rawop_rpc /path/to/clean/libveldpqc.a \
  -lcrypto -lpthread
/tmp/repro_spv_rawop_rpc
```

## Explicit limitations

- `preparerawop` caps the ASCII op string at 24,000 characters. Because the
  MSP2 inclusion data, legacy transaction, and 32..8,224-byte nullifier proof
  are hex-encoded, a large Bitcoin transaction or late-tree witness can exceed
  this stricter policy even though consensus permits a 32 KiB OP_RETURN.
  Deposit mode normally builds a compact one-input/few-output transaction;
  mint mode fails closed if the final carrier is too large.
- Proof reconstruction uses constant RAM but currently scans the lifetime
  canonical mint-transition log for each uncached target. Monitor proof RPC
  latency and index health as mint volume grows. Degradation pauses new witness
  production; it does not invalidate existing balances or halt other token
  operations.
- This source-level qualification includes mocked end-to-end operator tests and
  a compiled RPC construction/policy regression. It is not evidence of a real
  Bitcoin mainnet deposit or a funded Veld broadcast. Perform a low-value
  witnessed public-test transaction before opening the public front door.
- The CLI is the launch SPV front door. The desktop `/wrap` endpoint remains
  clearly issuer-only; no claim is made that the desktop UI itself constructs
  an SPV deposit.
