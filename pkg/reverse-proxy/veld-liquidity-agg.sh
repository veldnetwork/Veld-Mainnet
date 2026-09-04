#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

# Publish a same-origin snapshot for the explorer Liquidity page.
OUT=/var/www/veld-price/liquidity.json
DATADIR=/var/lib/veld-public-mainnet-v2-build02-03388b12/data
TMP=$(mktemp --tmpdir=/var/www/veld-price .liquidity.json.XXXXXX)
trap 'rm -f "$TMP"' EXIT

set -a
. /etc/veld/env
set +a

T=$(VELD_VAULT_PASSPHRASE="${VELD_VAULT_PASSPHRASE:-}" \
  runuser -u veld --preserve-environment -- \
  /usr/local/bin/veld-node --print-rpc-token \
  --datadir "$DATADIR" 2>/dev/null)
unset VELD_VAULT_PASSPHRASE
[ "${#T}" -eq 64 ]

nrpc() {
  printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$T" |
    curl -q --config - --fail --silent --show-error --max-time 8 \
      --proxy '' --noproxy '*' --proto '=http' --max-redirs 0 \
      --request POST --data "$1" http://127.0.0.1:8334/
}

NETWORK=$(nrpc '{"jsonrpc":"2.0","id":1,"method":"getnetworkinfo","params":[]}')
CHAIN=$(nrpc '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}')
AMM=$(nrpc '{"jsonrpc":"2.0","id":1,"method":"getammpool","params":[]}')
PEG=$(nrpc '{"jsonrpc":"2.0","id":1,"method":"getpeginfo","params":[]}')
VAL=$(nrpc '{"jsonrpc":"2.0","id":1,"method":"getvalidators","params":[0,1]}')
unset T
BTCUSD=$(cat /var/www/veld-price/btcusd.json 2>/dev/null || true)
TS=$(date +%s)

python3 - "$NETWORK" "$CHAIN" "$AMM" "$PEG" "$VAL" "$BTCUSD" "$TS" > "$TMP" <<'PY'
import json
import re
import sys

def result(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get("error") not in (None, {}):
        raise SystemExit("required RPC failed")
    return value.get("result")

def optional(raw):
    try:
        return json.loads(raw)
    except Exception:
        return None

network = result(sys.argv[1])
chain = result(sys.argv[2])
amm = result(sys.argv[3])
peg = result(sys.argv[4])
validators = result(sys.argv[5])
if not all(isinstance(value, dict) for value in (network, chain, amm, peg, validators)):
    raise SystemExit("required on-chain liquidity RPC data unavailable")

if (network.get("profile_id") != "veld-public-mainnet-v2" or
        not isinstance(network.get("subversion"), str) or
        re.fullmatch(r"/Veld:3\.[0-9]+\.[0-9]+/", network["subversion"]) is None or
        network.get("genesis_fingerprint") !=
        "880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b" or
        network.get("disposable") is not False or
        network.get("external_value") is not True):
    raise SystemExit("refusing to publish data from a non-production network")

height = chain.get("blocks")
tip = chain.get("best_block_hash")
if (not isinstance(height, int) or isinstance(height, bool) or height < 0 or
        not isinstance(tip, str) or re.fullmatch(r"[0-9a-f]{64}", tip) is None):
    raise SystemExit("canonical chain identity is invalid")
if peg.get("tip") != height:
    raise SystemExit("peg snapshot is not aligned with the canonical chain height")
processed_height = peg.get("reserve_processed_veld_height")
processed_tip = peg.get("reserve_processed_veld_block_hash")
if processed_height is not None and processed_height != height:
    raise SystemExit("peg snapshot height is stale")
if processed_tip is not None and processed_tip != tip:
    raise SystemExit("peg snapshot tip is stale")

btcusd = optional(sys.argv[6])
print(json.dumps({
    "ts": int(sys.argv[7]),
    "chain": {
        "height": height,
        "tip": tip,
        "network": network["profile_id"],
        "version": network["subversion"],
        "genesis_fingerprint": network["genesis_fingerprint"],
    },
    "amm": amm,
    "peg": peg,
    "validators": {
        "registered": validators.get("validator_count", 0),
        "recently_active": validators.get("recently_active_count", 0),
        "required": 7,
    },
    "btcusd": btcusd.get("usd") if isinstance(btcusd, dict) else None,
}))
PY

chmod 0644 "$TMP"
chown root:root "$TMP"
python3 - "$TMP" <<'PY'
import os
import sys
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY
mv -f -- "$TMP" "$OUT"
trap - EXIT
