#!/usr/bin/env bash
# Verifies the btcVELD redemption custody threshold.
# custody (redeem-path-design §6, shippable form): a Taproot script-path 3-of-5
# via multi_a. Five independent signer keys; ANY 3 can move custody, 2 CANNOT.
# On-chain it is one Taproot output; the operator holds no single key. Uses only
# Bitcoin Core descriptor wallets + PSBT (regtest). Run on a box with bitcoind.
set -euo pipefail
B="bitcoin-cli -datadir=${BTC_REGTEST_DATADIR:-/tmp/rt-btc}"
NUMS="50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"   # BIP341 NUMS (unspendable internal key)
JQ(){ python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
log(){ echo "[custody] $*" >&2; }

# ── 0. five independent signer wallets; extract each key's priv + pub expression ──
KPRIV=(); KPUB=()
for i in 0 1 2 3 4; do
  W="cust_s$i"
  $B -rpcwallet=$W getwalletinfo >/dev/null 2>&1 || $B createwallet "$W" >/dev/null
  priv=$($B -rpcwallet=$W listdescriptors true | python3 -c "
import sys,json
for e in json.load(sys.stdin)['descriptors']:
    d=e['desc']
    if d.startswith('tr(') and '/86' in d and not e.get('internal'): print(d[3:d.rindex(')')]); break")
  pub=$($B -rpcwallet=$W listdescriptors | python3 -c "
import sys,json
for e in json.load(sys.stdin)['descriptors']:
    d=e['desc']
    if d.startswith('tr(') and '/86' in d and not e.get('internal'): print(d[3:d.rindex(')')]); break")
  KPRIV+=("$priv"); KPUB+=("$pub")
done
log "extracted 5 signer keys"

# ── 1. the custody descriptor (public) + address ──
PUBLIST="${KPUB[0]},${KPUB[1]},${KPUB[2]},${KPUB[3]},${KPUB[4]}"
CUST_DESC="tr($NUMS,multi_a(3,$PUBLIST))"
CK=$($B getdescriptorinfo "$CUST_DESC" | JQ "d['checksum']")
CUST_ADDR=$($B deriveaddresses "$CUST_DESC#$CK" "[0,0]" | JQ "d[0]")
log "CUSTODY (3-of-5 taproot) address = $CUST_ADDR"

# coordinator watch-only wallet holds the public descriptor
$B -rpcwallet=cust_coord getwalletinfo >/dev/null 2>&1 || $B createwallet cust_coord true true >/dev/null
$B -rpcwallet=cust_coord importdescriptors "[{\"desc\":\"$CUST_DESC#$CK\",\"range\":[0,0],\"timestamp\":\"now\",\"internal\":false}]" >/dev/null
log "coordinator imported the custody descriptor (watch-only)"

# ── 2. fund custody, mine to confirm ──
FUND=$($B -rpcwallet=custody sendtoaddress "$CUST_ADDR" 1.0)
MINE=$($B -rpcwallet=custody getnewaddress)
$B -rpcwallet=custody generatetoaddress 3 "$MINE" >/dev/null
log "funded custody with 1.0 BTC (txid ${FUND:0:16}…)"

# ── 3. build a spend PSBT paying a user 0.9 BTC ──
USER=$($B -rpcwallet=custody getnewaddress user)
PSBT=$($B -rpcwallet=cust_coord walletcreatefundedpsbt "[]" "[{\"$USER\":0.9}]" 0 "{\"subtractFeeFromOutputs\":[0],\"includeWatching\":true,\"changeAddress\":\"$CUST_ADDR\"}" | JQ "d['psbt']")
log "unsigned spend PSBT built"

# helper: sign a PSBT with signer i (imports its private multi_a leaf)
sign_with(){ local i="$1" p="$2"
  local args=""; for j in 0 1 2 3 4; do local k="${KPUB[$j]}"; [ "$j" = "$i" ] && k="${KPRIV[$i]}"; args+="${args:+,}$k"; done
  local d="tr($NUMS,multi_a(3,$args))"; local c=$($B getdescriptorinfo "$d" | JQ "d['checksum']")
  local W="cust_s$i"
  $B -rpcwallet=$W importdescriptors "[{\"desc\":\"$d#$c\",\"range\":[0,0],\"timestamp\":\"now\",\"internal\":false}]" >/dev/null 2>&1 || true
  $B -rpcwallet=$W walletprocesspsbt "$p" | JQ "d['psbt']"
}

# ── 4. NEGATIVE: 2-of-5 cannot finalize ──
P0=$(sign_with 0 "$PSBT"); P1=$(sign_with 1 "$PSBT")
C2=$($B combinepsbt "[\"$P0\",\"$P1\"]")
F2=$($B finalizepsbt "$C2" | JQ "d['complete']")
log "2-of-5 finalize complete = $F2  (expect False)"

# ── 5. POSITIVE: 3-of-5 finalizes + broadcasts ──
P2=$(sign_with 2 "$PSBT")
C3=$($B combinepsbt "[\"$P0\",\"$P1\",\"$P2\"]")
FIN=$($B finalizepsbt "$C3")
F3=$(echo "$FIN" | JQ "d['complete']")
log "3-of-5 finalize complete = $F3  (expect True)"
RAW=$(echo "$FIN" | JQ "d.get('hex','')")
TXID=""
if [ "$F3" = "True" ] && [ -n "$RAW" ]; then
  TXID=$($B sendrawtransaction "$RAW")
  $B -rpcwallet=custody generatetoaddress 1 "$MINE" >/dev/null
  CONF=$($B getrawtransaction "$TXID" true | JQ "d.get('confirmations',0)")
  PAID=$($B getrawtransaction "$TXID" true | python3 -c "import sys,json;d=json.load(sys.stdin);print(sum(o['value'] for o in d['vout'] if any(a=='$USER' for a in [o['scriptPubKey'].get('address','')])))")
  log "3-of-5 spend broadcast txid=${TXID:0:16}… confirmations=$CONF paid_user=$PAID BTC"
fi

echo "=== RESULT ==="
echo "custody_addr=$CUST_ADDR"
echo "two_of_five_finalizes=$F2  (want False)"
echo "three_of_five_finalizes=$F3  (want True)"
echo "three_of_five_confirmed=${TXID:+yes}"
[ "$F2" = "False" ] && [ "$F3" = "True" ] && [ -n "$TXID" ] && echo "CUSTODY PROOF PASS" || echo "CUSTODY PROOF FAIL"
