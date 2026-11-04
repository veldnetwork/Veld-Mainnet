#!/usr/bin/env bash
# btc-spv-regtest-scene.sh — drive a real bitcoind regtest to produce a genuine
# BTC deposit (real 80-byte headers, real legacy tx serialization, real Merkle
# root) and emit a C++ vector header for the SPV-relay E2E test. Run on a box
# with bitcoind v2x + an isolated regtest datadir. Bitcoin Core is the
# independent oracle: the SPV modules must agree with bytes IT produced.
#
#   ./btc-spv-regtest-scene.sh /path/to/btc_e2e_vectors.h
#
# Deterministic-enough for a one-shot capture; the emitted header is committed so
# the E2E is reproducible forever WITHOUT a live bitcoind (like the mainnet
# vectors in btc_pow_test.cpp).
set -euo pipefail

OUT="${1:?usage: btc-spv-regtest-scene.sh <out.h>}"
DATADIR="${BTC_REGTEST_DATADIR:-/tmp/rt-btc}"
BCLI="bitcoin-cli -datadir=$DATADIR"
WCLI="$BCLI -rpcwallet=custody"

log(){ echo "[scene] $*" >&2; }

# reverse a big-endian display hash (64 hex) -> internal little-endian hex
rev(){ echo -n "$1" | fold -w2 | tac | tr -d '\n'; }

# --- 0. wallet + spendable balance ---------------------------------------
$BCLI -rpcwait getblockchaininfo >/dev/null
$BCLI listwallets | grep -q custody || $BCLI createwallet custody >/dev/null
MINE=$($WCLI getnewaddress mine legacy)
log "priming coinbase maturity (mining 110 to $MINE)"
$WCLI generatetoaddress 110 "$MINE" >/dev/null
BAL=$($WCLI getbalance)
log "spendable balance = $BAL"

# --- 1. custody address (the canonical peg deposit target) ----------------
CUSTODY_ADDR=$($WCLI getnewaddress custody bech32)          # P2WPKH — spk parsed as an opaque blob
CUSTODY_SPK=$($BCLI getaddressinfo "$CUSTODY_ADDR" | jq -r .scriptPubKey)
log "custody addr=$CUSTODY_ADDR spk=$CUSTODY_SPK"

# --- 2. recipient binding: OP_RETURN "btcVELD:<veld addr>" ----------------
VELD_RECIPIENT="VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg"          # Veld-format address (34 char base58, 'V' lead)
DATA_ASCII="btcVELD:${VELD_RECIPIENT}"
DATA_HEX=$(printf '%s' "$DATA_ASCII" | xxd -p | tr -d '\n')
log "op_return data = '$DATA_ASCII' (${#DATA_ASCII} bytes) hex=$DATA_HEX"

# --- 3. a LEGACY input so the deposit tx has NO witness -------------------
#     (txid = double-SHA256 of the *legacy* serialization; the mint gate is fed
#      exactly those bytes, so we need a witnessless tx to feed getrawtransaction
#      the legacy form directly.)
LEG=$($WCLI getnewaddress leg legacy)                        # P2PKH
FUND_TXID=$($WCLI sendtoaddress "$LEG" 2.0)
$WCLI generatetoaddress 1 "$MINE" >/dev/null
read -r IN_TXID IN_VOUT < <($WCLI listunspent 1 9999 "[\"$LEG\"]" | jq -r '.[0] | "\(.txid) \(.vout)"')
log "legacy funding utxo = $IN_TXID:$IN_VOUT (2.0 BTC)"

# --- 4. build + broadcast the deposit tx (legacy input only) --------------
CHANGE=$($WCLI getnewaddress change legacy)
RAW=$($BCLI createrawtransaction \
        "[{\"txid\":\"$IN_TXID\",\"vout\":$IN_VOUT}]" \
        "[{\"$CUSTODY_ADDR\":0.5},{\"data\":\"$DATA_HEX\"},{\"$CHANGE\":1.4999}]")
SIGNED=$($WCLI signrawtransactionwithwallet "$RAW" | jq -r .hex)
DTXID=$($BCLI sendrawtransaction "$SIGNED")
log "deposit txid = $DTXID"

# a few dummy txs so the block's Merkle tree is non-trivial (multi-level branch)
for i in 1 2 3 4; do $WCLI sendtoaddress "$($WCLI getnewaddress d$i)" 0.01 >/dev/null; done

# --- 5. mine the deposit block, then bury it K deep -----------------------
K=3
DBLK=$($WCLI generatetoaddress 1 "$MINE" | jq -r '.[0]')
$WCLI generatetoaddress "$K" "$MINE" >/dev/null
DHEIGHT=$($BCLI getblock "$DBLK" 1 | jq -r .height)
TIP=$($BCLI getblockcount)
log "deposit block $DBLK @ height $DHEIGHT ; tip=$TIP ; K=$K"

# --- 6. legacy tx bytes + custody amount + output index -------------------
LEGACY_TX_HEX=$($BCLI getrawtransaction "$DTXID" false)      # witnessless -> legacy serialization
# sanity: no segwit marker (byte 4..5 must not be 0001)
[ "${LEGACY_TX_HEX:8:4}" = "0001" ] && { log "FATAL: deposit tx is segwit-serialized"; exit 1; }

# --- 7. checkpoint anchor a few blocks before the deposit -----------------
CP_HEIGHT=$((DHEIGHT - 5))
CP_HASH_BE=$($BCLI getblockhash $CP_HEIGHT)
CP_HDR=$($BCLI getblockheader "$CP_HASH_BE" false)
CP_BITS=$(printf '%d' "0x${CP_HDR:144:8}")                  # nBits is LE in the header; decode below in C++ instead
CP_TIME=$($BCLI getblockheader "$CP_HASH_BE" true | jq -r .time)
CP_BITS_HEX=$($BCLI getblockheader "$CP_HASH_BE" true | jq -r .bits)

# prev10 times: heights CP-10 .. CP-1 (oldest first)
PREV10=()
for h in $(seq $((CP_HEIGHT-10)) $((CP_HEIGHT-1))); do
  bh=$($BCLI getblockhash "$h"); PREV10+=("$($BCLI getblockheader "$bh" true | jq -r .time)")
done

# --- 8. forward headers CP+1 .. TIP (raw 80-byte hex, in order) -----------
HEADERS=()
for h in $(seq $((CP_HEIGHT+1)) "$TIP"); do
  bh=$($BCLI getblockhash "$h"); HEADERS+=("$($BCLI getblockheader "$bh" false)")
done

# --- 9. ordered txids in the deposit block + deposit index + merkleroot ---
mapfile -t TXIDS < <($BCLI getblock "$DBLK" 1 | jq -r '.tx[]')
MROOT_BE=$($BCLI getblock "$DBLK" 1 | jq -r .merkleroot)
DIDX=-1; for i in "${!TXIDS[@]}"; do [ "${TXIDS[$i]}" = "$DTXID" ] && DIDX=$i; done
[ "$DIDX" -lt 0 ] && { log "FATAL: deposit txid not found in block"; exit 1; }
log "block has ${#TXIDS[@]} txs; deposit at index $DIDX; merkleroot=$MROOT_BE"

# --- 10. emit the C++ vector header ---------------------------------------
{
  echo "#pragma once"
  echo "// AUTO-GENERATED by scripts/btc-spv-regtest-scene.sh — DO NOT EDIT."
  echo "// Real Bitcoin Core regtest serialization captured as an independent oracle"
  echo "// for the SPV-relay E2E (btc_spv_e2e_test.cpp). Hashes below are INTERNAL"
  echo "// (little-endian) byte order unless suffixed _BE (bitcoind display order)."
  echo "#include <cstdint>"
  echo "namespace e2e {"
  echo "static const char* CUSTODY_SPK_HEX   = \"$CUSTODY_SPK\";"
  echo "static const char* VELD_RECIPIENT    = \"$VELD_RECIPIENT\";"
  echo "static const unsigned long long DEPOSIT_SATS = 50000000ULL;"
  echo "static const char* DEPOSIT_LEGACY_TX_HEX = \"$LEGACY_TX_HEX\";"
  echo "static const char* DEPOSIT_TXID_BE   = \"$DTXID\";"
  echo "static const char* DEPOSIT_BLOCK_HASH_BE = \"$DBLK\";"
  echo "static const char* BLOCK_MERKLEROOT_BE = \"$MROOT_BE\";"
  echo "static const int    DEPOSIT_TX_INDEX = $DIDX;"
  echo "static const int    K_CONFIRMATIONS  = $K;"
  echo "// checkpoint anchor (height MUST predate the deposit region)"
  echo "static const char* CP_HASH_BE        = \"$CP_HASH_BE\";"
  echo "static const unsigned CP_HEIGHT      = $CP_HEIGHT;"
  echo "static const char* CP_BITS_HEX       = \"$CP_BITS_HEX\";"
  echo "static const unsigned CP_TIME        = $CP_TIME;"
  echo -n "static const unsigned CP_PREV10_TIMES[10] = {"; (IFS=,; echo -n "${PREV10[*]}"); echo "};"
  echo "// forward headers, height CP_HEIGHT+1 .. TIP, in order"
  echo "static const char* HEADERS_HEX[] = {"
  for x in "${HEADERS[@]}"; do echo "  \"$x\","; done
  echo "};"
  echo "static const int N_HEADERS = ${#HEADERS[@]};"
  echo "// ordered txids of the deposit block (bitcoind display / BE order)"
  echo "static const char* BLOCK_TXIDS_BE[] = {"
  for x in "${TXIDS[@]}"; do echo "  \"$x\","; done
  echo "};"
  echo "static const int N_BLOCK_TXIDS = ${#TXIDS[@]};"
  echo "}  // namespace e2e"
} > "$OUT"
log "wrote $OUT ($(wc -l < "$OUT") lines)"
