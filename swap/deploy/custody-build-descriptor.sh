#!/usr/bin/env bash
# btcVELD 3-of-5 custody — assemble the Taproot custody descriptor from the FIVE
# signers' PUBLIC key expressions (each produced by custody-signer-keygen.sh on its
# own host). This script handles NO private keys. It produces the custody
# descriptor + checksum, derives index 0 of the ranged 3-of-5 Taproot descriptor,
# imports the exact operational range watch-only to the coordinator wallet,
# reserves 0..999 for consensus/operator use, starts C1 public allocation at
# index 1000 when an extended range is selected, and prints the exact values for
# swap/deploy/redeemd-threshold.json.
#
# Run on the COORDINATOR host (a mainnet bitcoind, watch-only — no signer keys).
# Usage: ./custody-build-descriptor.sh "<pub0>" "<pub1>" "<pub2>" "<pub3>" "<pub4>"
set -euo pipefail
[ $# -eq 5 ] || { echo "usage: $0 <pub0> <pub1> <pub2> <pub3> <pub4>  (the 5 public key expressions)" >&2; exit 2; }

DATADIR="${BTC_DATADIR:-/var/lib/bitcoin}"
RANGE_END="${CUSTODY_RANGE_END:-10999}"
[[ "$RANGE_END" == "10999" ]] || {
  echo "FATAL: v2.7.88 launch CUSTODY_RANGE_END must be exactly 10999; a later linked expansion requires a separately reviewed release" >&2; exit 2;
}
NEXT_INDEX=1000
B=(bitcoin-cli -datadir="$DATADIR")
NUMS="50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"   # BIP341 unspendable NUMS internal key (no key-path spend)
J(){ python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

command -v bitcoin-cli >/dev/null || { echo "FATAL: bitcoin-cli not on PATH" >&2; exit 2; }
"${B[@]}" getblockchaininfo >/dev/null 2>&1 || { echo "FATAL: cannot reach bitcoind at $DATADIR" >&2; exit 2; }

# Reject accidental private-key material and duplicate operators before asking
# Bitcoin Core to canonicalize the descriptor.  Comparing the extended public
# keys (rather than the full origin expressions) prevents the same signer key
# from being relabeled with a different fingerprint/path and counted twice.
python3 - "$@" <<'PY'
import re, sys
pubs = sys.argv[1:]
private_prefix = re.compile(r"(?:xprv|tprv|yprv|zprv|uprv|vprv)", re.I)
wif = re.compile(r"(?:^|[^1-9A-HJ-NP-Za-km-z])(?:5[1-9A-HJ-NP-Za-km-z]{50}|[KLc9][1-9A-HJ-NP-Za-km-z]{51})(?:$|[^1-9A-HJ-NP-Za-km-z])")
exact = re.compile(
    r"^\[[0-9a-fA-F]{8}/86h/0h/0h\]"
    r"(xpub[1-9A-HJ-NP-Za-km-z]{100,120})/0/\*$")
keys = []
for n, expression in enumerate(pubs, 1):
    if not expression or any(c.isspace() for c in expression):
        raise SystemExit("FATAL: public expression %d is empty or contains whitespace" % n)
    if private_prefix.search(expression) or wif.search(expression):
        raise SystemExit("FATAL: public expression %d contains private key material" % n)
    match = exact.fullmatch(expression)
    if not match:
        raise SystemExit(
            "FATAL: public expression %d must exactly match "
            "[8hex/86h/0h/0h]xpub.../0/* (descriptor punctuation is forbidden)" % n)
    keys.append(match.group(1))
if len(set(keys)) != len(keys):
    raise SystemExit("FATAL: duplicate custody signer extended public key")
PY

PUBLIST="$1,$2,$3,$4,$5"
DESC="tr($NUMS,multi_a(3,$PUBLIST))"
INFO=$("${B[@]}" getdescriptorinfo "$DESC")
CK=$(printf '%s' "$INFO" | J "['checksum']")
IS_RANGE=$(printf '%s' "$INFO" | J "['isrange']")
HAS_PRIVATE=$(printf '%s' "$INFO" | J "['hasprivatekeys']")
[ "$IS_RANGE" = "True" ] || { echo "FATAL: custody descriptor is unexpectedly not ranged" >&2; exit 3; }
[ "$HAS_PRIVATE" = "False" ] || { echo "FATAL: custody descriptor contains private keys" >&2; exit 3; }
FULL="$DESC#$CK"
ADDR=$("${B[@]}" deriveaddresses "$FULL" '[0,0]' | J "[0]")
DESC_SHA256=$(printf '%s' "$FULL" | sha256sum | awk '{print $1}')

echo "custody_descriptor : $FULL"
echo "custody_address    : $ADDR"
echo "descriptor_sha256 : $DESC_SHA256"
echo "                     (index 0; any 3 sign, no operator holds more than one key)"

# watch-only coordinator wallet holds only the PUBLIC descriptor
WO="btcveld-custody-watchonly"
"${B[@]}" -rpcwallet="$WO" getwalletinfo >/dev/null 2>&1 || \
  "${B[@]}" createwallet "$WO" true true "" false true >/dev/null
IMPORT=$("${B[@]}" -rpcwallet="$WO" importdescriptors \
  "[{\"desc\":\"$FULL\",\"timestamp\":\"now\",\"active\":false,\"internal\":false,\"range\":[0,$RANGE_END]}]")
printf '%s' "$IMPORT" | python3 -c 'import json,sys
r=json.load(sys.stdin)
if not isinstance(r,list) or len(r)!=1 or not r[0].get("success"):
 raise SystemExit("FATAL: watch-only ranged descriptor import failed: %r" % (r,))'
echo "coordinator wallet '$WO' imported descriptor range [0,$RANGE_END] (watch-only, no keys)."
echo "index 0 is SPV-only; C1 privately selects unused indices [$NEXT_INDEX,$RANGE_END]."

# Generate the exact P2TR scriptPubKey allowlist for the imported range. Signer
# boxes consume this hash-bound object, not an operator-authored JSON list.
SPKS_OUT="${CUSTODY_SPKS_OUT:-custody-spks-operational.json}"
CONSENSUS_SPKS_OUT="${CUSTODY_CONSENSUS_SPKS_OUT:-custody-spks-consensus.json}"
BINDING_OUT="${CUSTODY_BINDING_OUT:-custody-release-binding.json}"
python3 - "$SPKS_OUT" "$CONSENSUS_SPKS_OUT" "$BINDING_OUT" <<'PY'
import os, sys
paths = [os.path.realpath(os.path.abspath(path)) for path in sys.argv[1:]]
if len(set(paths)) != len(paths):
    raise SystemExit("FATAL: operational, consensus, and binding outputs must be distinct")
PY
ADDRS_TMP=$(mktemp); trap 'rm -f "$ADDRS_TMP"' EXIT
"${B[@]}" deriveaddresses "$FULL" "[0,$RANGE_END]" > "$ADDRS_TMP"
python3 - "$FULL" "$DESC_SHA256" "$ADDRS_TMP" "$SPKS_OUT" "$CONSENSUS_SPKS_OUT" "$RANGE_END" <<'PY'
import hashlib, json, os, sys, tempfile
descriptor, expected_hash, addresses_path, output, consensus_output, range_end_text = sys.argv[1:]
range_end = int(range_end_text); expected_count = range_end + 1
if hashlib.sha256(descriptor.encode()).hexdigest() != expected_hash:
    raise SystemExit("FATAL: descriptor hash changed during SPK generation")
addresses = json.load(open(addresses_path))
if (not isinstance(addresses, list) or len(addresses) != expected_count or
        len(set(addresses)) != expected_count):
    raise SystemExit("FATAL: deriveaddresses did not return the exact unique operational range")
charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def polymod(values):
    chk = 1
    generators = (0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3)
    for value in values:
        top = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ value
        for i,g in enumerate(generators):
            if (top >> i) & 1: chk ^= g
    return chk
def convertbits(data, frombits, tobits):
    acc=0; bits=0; out=[]; maxv=(1<<tobits)-1
    for value in data:
        acc=(acc<<frombits)|value; bits+=frombits
        while bits>=tobits:
            bits-=tobits; out.append((acc>>bits)&maxv)
    if bits and ((acc << (tobits-bits)) & maxv):
        raise ValueError("non-zero bech32 padding")
    return bytes(out)
def spk(address):
    if address.lower()!=address or not address.startswith("bc1"):
        raise ValueError("not canonical mainnet bech32m")
    pos=address.rfind("1"); hrp=address[:pos]
    values=[charset.find(c) for c in address[pos+1:]]
    if any(v<0 for v in values) or len(values)<7:
        raise ValueError("bad bech32m alphabet")
    expanded=[ord(c)>>5 for c in hrp]+[0]+[ord(c)&31 for c in hrp]
    if polymod(expanded+values) != 0x2bc830a3:
        raise ValueError("bad bech32m checksum")
    payload=values[:-6]
    if payload[0] != 1:
        raise ValueError("custody address is not witness v1")
    program=convertbits(payload[1:],5,8)
    if len(program)!=32:
        raise ValueError("custody output key is not 32 bytes")
    return "5120"+program.hex()
scripts=[spk(a) for a in addresses]
if len(set(scripts)) != expected_count:
    raise SystemExit("FATAL: derived custody scriptPubKeys are not unique")
operational={"version":1,"descriptor":descriptor,"descriptor_sha256":expected_hash,
             "range":[0,range_end],"script_pubkeys":scripts}
consensus=dict(operational); consensus["range"]=[0,999]
consensus["script_pubkeys"]=scripts[:1000]
def write_exact(path, value):
    directory=os.path.dirname(os.path.abspath(path)) or "."
    fd,tmp=tempfile.mkstemp(prefix="custody-spks.",suffix=".tmp",dir=directory)
    with os.fdopen(fd,"w") as f:
        json.dump(value,f,sort_keys=True,separators=(",",":")); f.write("\n")
        f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path); os.chmod(path,0o644)
write_exact(output, operational)
write_exact(consensus_output, consensus)
PY
MANIFEST_SHA256=$(sha256sum "$SPKS_OUT" | awk '{print $1}')
CONSENSUS_MANIFEST_SHA256=$(sha256sum "$CONSENSUS_SPKS_OUT" | awk '{print $1}')
python3 - "$SPKS_OUT" "$MANIFEST_SHA256" "$CONSENSUS_SPKS_OUT" "$CONSENSUS_MANIFEST_SHA256" "$ADDR" "$BINDING_OUT" <<'PY'
import hashlib, json, os, sys, tempfile
manifest_path, manifest_hash, consensus_path, consensus_manifest_hash, address, output = sys.argv[1:]
manifest = json.load(open(manifest_path, encoding="utf-8"))
consensus = json.load(open(consensus_path, encoding="utf-8"))
scripts = manifest.get("script_pubkeys", [])
if len(scripts) != manifest.get("range", [None, None])[1] + 1:
    raise SystemExit("FATAL: cannot bind an incomplete custody manifest")
prefix = dict(manifest); prefix["range"] = [0,999]; prefix["script_pubkeys"] = scripts[:1000]
if consensus != prefix:
    raise SystemExit("FATAL: consensus manifest is not the exact operational prefix")
binding = {
    "schema": 2,
    "statement": "veld-btcveld-custody-binding-v2-dual-manifest",
    "bitcoin_network": "main",
    "descriptor_sha256": manifest["descriptor_sha256"],
    "manifest_sha256": manifest_hash,
    "consensus_manifest_sha256": consensus_manifest_hash,
    "script_range": manifest["range"],
    "consensus_script_range": [0, 999],
    "spv_custody_descriptor_index": 0,
    "spv_custody_address": address,
    "spv_custody_spk_hex": scripts[0],
}
directory = os.path.dirname(os.path.abspath(output)) or "."
fd, tmp = tempfile.mkstemp(prefix="custody-release-binding.", suffix=".tmp",
                           dir=directory)
with os.fdopen(fd, "w", encoding="utf-8") as target:
    json.dump(binding, target, sort_keys=True, separators=(",", ":"))
    target.write("\n"); target.flush(); os.fsync(target.fileno())
os.replace(tmp, output); os.chmod(output, 0o644)
PY
rm -f "$ADDRS_TMP"; trap - EXIT
echo "generated hash-bound signer allowlist: $SPKS_OUT ($((RANGE_END + 1)) unique P2TR scripts)"
echo "manifest_sha256   : $MANIFEST_SHA256"
echo "consensus manifest: $CONSENSUS_SPKS_OUT (1000 unique P2TR scripts)"
echo "consensus prefix  : $CONSENSUS_MANIFEST_SHA256"
echo "release binding   : $BINDING_OUT (descriptor + manifest + SPV index 0)"
echo
echo "Drop these into swap/deploy/redeemd-threshold.json:"
echo "    \"wallet\":      \"$WO\","
echo "    \"change_addr\": \"$ADDR\""
echo
echo "Then: fund the address with a small test amount, run scripts/btcveld-taproot-custody-proof.sh"
echo "(and the funded failure drills) BEFORE btcVELD signs any live payout."
