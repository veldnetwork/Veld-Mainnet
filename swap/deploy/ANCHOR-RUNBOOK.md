# Bitcoin checkpoint anchoring launch runbook

`veld_anchord.py` commits an exact Veld block hash into a witnessless Bitcoin
transaction, waits for the compiled Bitcoin depth, and posts its Merkle proof to
Veld. It is permissionless, but this deployment is a production availability
service and spends real BTC and Veld fees. A failure or missing check below keeps
the anchoring service closed.

The shipped `anchord.example.json` carries the production launch policy and
`veld_anchord.py` pins those values in production: anchor the latest finalized
checkpoint no sooner than 480 Veld blocks (~24 hours), enforce a 960-block
(~48-hour) deadline, target fee dips at 5 sat/vB, use a 20 sat/vB fallback,
and never pay above 50 sat/vB. Above the ceiling the daemon skips the new
transaction, alerts, and retries on a later pass—even at the deadline. The
Bitcoin depth is `k_btc=6` (seven Bitcoin Core confirmations because the
containing block is confirmation one), and `anchor_lag` is retired.

The 400-vB `anchor_tx_vsize` value is a bug-catching hard ceiling, not an
estimate. The daemon builds and signs, measures the actual signed vsize,
rebuilds change with `ceil(actual_vsize × selected_rate)`, and fails closed if
the exact fee does not converge, exceeds 20,000 sats, or has an effective rate
above 50 sat/vB. The launch fallback is 20 sat/vB, and relay resubmission waits
3,600 seconds. `fee_conf_target=6` is Bitcoin Core's fee-estimator horizon in
blocks; it is distinct from the 5 sat/vB opportunistic fee target.

## 1. Prerequisites and authority separation

- `veld-node` reports `getbtcheaderinfo.spv_active=true` and
  `getanchorinfo.anchor_active=true`.
- `veld-btcrelayd.service` is healthy and its consensus Bitcoin-header height is
  advancing. A local Bitcoin node behind the consensus header view is rejected.
- Create a dedicated Bitcoin Core wallet named in `btc_wallet`. Generate a
  wallet-owned **legacy P2PKH** address (`getnewaddress "" legacy`). Do not use a
  bech32, P2SH-wrapped witness, custody, peg, or signer wallet.
- Create a dedicated Veld fees-only key for `preparerawop`. The strict
  `veld-keygen sign-op` policy must be used. Do not place issuer, custody,
  validator, pool, vault, or treasury keys in this service account.
- Record the pinned fee/cadence values, their owner, date, rationale, and source
  digest. The daemon rejects a production config that differs from the launch
  values or omits any policy field.

## 2. Install the isolated service

Run as root, adjusting only installation prefixes already approved for the
release:

```sh
useradd --system --home-dir /var/lib/veld-anchord \
  --shell /usr/sbin/nologin veldanchor
install -d -m 700 -o veldanchor -g veldanchor /var/lib/veld-anchord
install -d -m 755 -o root -g root /etc/veld /opt/veld/swap
install -m 755 -o root -g root swap/veld_anchord.py \
  swap/rpc_url_policy.py /opt/veld/swap/
install -m 600 -o root -g root swap/deploy/anchord.example.json \
  /etc/veld/anchord.json
install -m 600 -o root -g root /dev/null /etc/veld/anchord.env
install -m 644 -o root -g root swap/deploy/veld-anchord.service \
  /etc/systemd/system/veld-anchord.service
```

Generate the Veld relay-fee key directly at
`/var/lib/veld-anchord/anchor-relay-fee.key`, owned by `veldanchor`, mode `0600`.
Provide `VELD_VAULT_PASSPHRASE` through `/etc/veld/anchord.env` using the launch
secret procedure. Never put a plaintext passphrase or RPC bearer token in JSON.
Grant `veldanchor` only the Bitcoin RPC-cookie access needed for its dedicated
wallet; do not make the Bitcoin datadir or wallet group-writable.

Fund the configured legacy Bitcoin address and Veld fee address with the
configured bounded operating amount. Confirm with `getaddressinfo` that the
Bitcoin `scriptPubKey` is `76a914...88ac`, `ismine=true`, `solvable=true`, and
`iswatchonly=false`.

## 3. Offline and preflight checks

```sh
python3 -m unittest -v swap.test_anchord_state
python3 -m unittest -v swap.test_btcrelayd
python3 scripts/verify-swap-deployment-gate.py --root .
python3 -m py_compile swap/veld_anchord.py
```

Before enabling the unit, run one foreground pass as the service user. It must
fail closed if any placeholder remains, a file is not private, the Veld RPC is
not exact loopback, the RPC token helper is malformed, the Bitcoin address is
not wallet-owned P2PKH, the actual signed vsize exceeds `anchor_tx_vsize`, or
the exact fee/change differs by one satoshi.

The Bitcoin freshness policy is two-tiered. At a tip age of 3,600 seconds the
daemon emits an operator alert but keeps normal service. At 7,200 seconds it
enters recovery-only mode: no new Bitcoin anchor is prepared or broadcast,
while already prepared, committed, or submitted anchors continue broadcast and
relay lifecycle transitions. Freshness restoration resumes admission without a
restart or state loss. Capture boundary evidence at 3,599 / 3,600 / 7,199 /
7,200 / 7,201 seconds.

## 4. Start and prove liveness

```sh
systemctl daemon-reload
systemctl enable --now veld-anchord
journalctl -u veld-anchord -f
```

For the first cycle, capture all of the following in launch evidence:

1. `COMMITTED` log with Veld height/hash prefix, Bitcoin txid, exact fee sats,
   and observed sat/vB.
2. Bitcoin `getrawtransaction <txid> true` showing one legacy input, exactly one
   `VELD_ANCHOR:` OP_RETURN, one change output to the configured P2PKH script,
   and the approved fee cap not exceeded.
3. After the compiled depth, `SUBMITTED` with a canonical Veld txid.
4. `getanchorinfo.high_water` reaches or exceeds the committed Veld height and
   remains stable across a node restart/replay.
5. `getstatedigest` remains identical across independent nodes after the anchor
   block.

## 5. Crash, reorg, and recovery behavior

`anchor_state.json` is the sole local journal and must remain service-owned mode
`0600` inside the mode-`0700` state directory. The daemon writes status
`prepared` with the complete signed witnessless Bitcoin transaction and fsyncs
the directory **before** first broadcast. On restart it rebroadcasts those exact
bytes and therefore the exact same txid; never delete or hand-edit a prepared
record to “unstick” it.

A Bitcoin reorg below the required depth is held and retried. A conflicted or
dropped transaction does not relax fee policy or consensus checks; later cadence
may create a new anchor while the old record remains auditable. A Veld reorg
removing a submitted anchor causes consensus `high_water` to fall and the daemon
returns the record to retryable state. Stop the service and investigate if the
Bitcoin source tip falls behind Veld's consensus header view, the Veld and
compiled `k_btc` differ, state validation fails, or repeated submissions never
advance `getanchorinfo`.
