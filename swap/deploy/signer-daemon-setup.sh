#!/usr/bin/env bash
# Configure a btcVELD signer: encrypt the custody wallet and deploy the payout signer.
# Expects at /tmp: veld_payout_signerd.py, veld_redeemd.py,
# rpc_url_policy.py, veld_redeem_commitment.py, veld_custody_binding.py,
# custody-spks-operational.json. Run as root.
#   SIGNER_ID=custody-signer-1 WALLET=btcveld-custody-signer-1 bash signer-daemon-setup.sh
set -euo pipefail
SIGNER_ID="${SIGNER_ID:?set SIGNER_ID=custody-signer-1 .. custody-signer-5}"
WALLET="${WALLET:?set the existing local custody wallet name}"
SPKS_FILE="${SPKS_FILE:-/tmp/custody-spks-operational.json}"
EXPECTED_DESCRIPTOR_SHA256="${CUSTODY_DESCRIPTOR_SHA256:?set the independently reviewed 64-hex canonical custody descriptor hash}"
EXPECTED_MANIFEST_SHA256="${CUSTODY_MANIFEST_SHA256:?set the independently reviewed 64-hex custody manifest file hash}"
EXPECTED_CONSENSUS_MANIFEST_SHA256="${CUSTODY_CONSENSUS_MANIFEST_SHA256:?set the compiled canonical 0-999 prefix manifest hash}"
BTC_DATADIR="${BTC_DATADIR:-/var/lib/bitcoin}"
[[ "$EXPECTED_DESCRIPTOR_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "FATAL: CUSTODY_DESCRIPTOR_SHA256 must be lowercase 64-hex" >&2; exit 2; }
[[ "$EXPECTED_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "FATAL: CUSTODY_MANIFEST_SHA256 must be lowercase 64-hex" >&2; exit 2; }
[[ "$EXPECTED_CONSENSUS_MANIFEST_SHA256" =~ ^[0-9a-f]{64}$ ]] || { echo "FATAL: CUSTODY_CONSENSUS_MANIFEST_SHA256 must be lowercase 64-hex" >&2; exit 2; }
# Forced commands may start elsewhere; pin the existing environment file now.
ENV_FILE=$(realpath -e -- "${VELD_ROOT_ENV:-/etc/veld/env}")
case "$SIGNER_ID" in custody-signer-[1-5]) ;; *) echo "FATAL: SIGNER_ID must be custody-signer-1 .. custody-signer-5" >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo "FATAL: signer-daemon-setup.sh must run as root" >&2; exit 2; }
umask 077
[ -f "$ENV_FILE" ] || { echo "FATAL: required root environment file missing: $ENV_FILE" >&2; exit 2; }
[ "$(stat -c '%u' "$ENV_FILE")" = 0 ] || { echo "FATAL: $ENV_FILE must be owned by root" >&2; exit 2; }
ENV_MODE=$(stat -c '%a' "$ENV_FILE")
(( (8#$ENV_MODE & 8#022) == 0 )) || { echo "FATAL: $ENV_FILE must not be group/world writable" >&2; exit 2; }
B(){ bitcoin-cli -datadir="$BTC_DATADIR" "$@"; }

echo "== deploy daemon files =="
install -d -m750 /opt/veld-signer /var/lib/veld-signer
install -m640 /tmp/veld_payout_signerd.py /tmp/veld_redeemd.py \
  /tmp/rpc_url_policy.py /tmp/veld_redeem_commitment.py \
  /tmp/veld_custody_binding.py /opt/veld-signer/

echo "== encrypt custody wallet at rest (unique passphrase, root-600) =="
install -d -m700 /root/.veld-signer
ENC=$(B -rpcwallet="$WALLET" getwalletinfo | python3 -c "import sys,json;print('unlocked_until' in json.load(sys.stdin))")
if [ "$ENC" = "True" ]; then
  echo "  wallet already encrypted"
  [ -s /root/.veld-signer/wallet.pass ] || { echo "FATAL: encrypted wallet has no non-empty passphrase file" >&2; exit 3; }
else
  PASS=$(openssl rand -base64 32)
  printf '%s' "$PASS" > /root/.veld-signer/wallet.pass; chmod 600 /root/.veld-signer/wallet.pass
  # bitcoin-cli arguments are process-visible. Feed the passphrase through
  # bitcoin-cli's stdin-argument mode instead of placing it in argv.
  printf '%s\n' "$PASS" | B -stdin -rpcwallet="$WALLET" encryptwallet >/dev/null
  unset PASS
  echo "  wallet ENCRYPTED (passphrase in /root/.veld-signer/wallet.pass, 0600)"
fi
chown root:root /root/.veld-signer/wallet.pass
chmod 600 /root/.veld-signer/wallet.pass

echo "== write config (pinned custody scriptPubKeys) =="
python3 - "$SIGNER_ID" "$WALLET" "$SPKS_FILE" "$EXPECTED_DESCRIPTOR_SHA256" "$EXPECTED_MANIFEST_SHA256" "$EXPECTED_CONSENSUS_MANIFEST_SHA256" "$BTC_DATADIR" <<'PY'
import hashlib,json,os,re,stat,sys
sid,wallet,path,expected,expected_manifest,expected_consensus,bitcoin_datadir=sys.argv[1:]
if (not os.path.isabs(bitcoin_datadir) or
    os.path.normpath(bitcoin_datadir) != bitcoin_datadir or
    len(bitcoin_datadir) > 4096 or
    any(ord(ch) < 32 or ord(ch) == 127 for ch in bitcoin_datadir)):
 raise SystemExit("FATAL: BTC_DATADIR must be a normalized absolute path without control characters")
info=os.lstat(path)
if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
 raise SystemExit("FATAL: custody SPK manifest must be a regular non-symlink file")
raw=open(path,"rb").read()
if hashlib.sha256(raw).hexdigest()!=expected_manifest:
 raise SystemExit("FATAL: custody SPK manifest differs from independently pinned file hash")
doc=json.loads(raw.decode("utf-8"))
if not isinstance(doc,dict) or doc.get("version")!=1:
 raise SystemExit("FATAL: custody SPK manifest schema invalid")
descriptor=doc.get("descriptor")
if not isinstance(descriptor,str) or hashlib.sha256(descriptor.encode()).hexdigest()!=expected:
 raise SystemExit("FATAL: custody descriptor differs from independently pinned hash")
custody_range=doc.get("range")
if (doc.get("descriptor_sha256")!=expected or not isinstance(custody_range,list) or
    len(custody_range)!=2 or custody_range[0]!=0 or
    not isinstance(custody_range[1],int) or
    not (custody_range[1]==999 or 10999<=custody_range[1]<=1000000)):
 raise SystemExit("FATAL: custody descriptor hash/range binding invalid")
spks=doc.get("script_pubkeys")
if (not isinstance(spks,list) or len(spks)!=custody_range[1]+1 or len(set(spks))!=len(spks) or
    any(not isinstance(x,str) or not re.fullmatch(r"5120[0-9a-f]{64}",x) for x in spks)):
 raise SystemExit("FATAL: custody script allowlist must contain the exact unique operational range")
prefix=dict(doc); prefix["range"]=[0,999]; prefix["script_pubkeys"]=spks[:1000]
prefix_raw=(json.dumps(prefix,sort_keys=True,separators=(",",":"))+"\n").encode()
if hashlib.sha256(prefix_raw).hexdigest()!=expected_consensus:
 raise SystemExit("FATAL: operational manifest prefix differs from compiled consensus manifest")
cfg={"signer_id":sid,
 "veld_rpc":{"url":"http://127.0.0.1:8334","token_cmd":["/usr/local/bin/veld-node","--print-rpc-token","--datadir","/var/lib/veld-node"]},
 "bitcoin_datadir":bitcoin_datadir,
 "cli_base":["/usr/local/bin/bitcoin-cli","-datadir="+bitcoin_datadir],
 "wallet":wallet,"authority_db":"/var/lib/veld-signer/obligations.sqlite3",
 "custody_descriptor":descriptor,"custody_descriptor_sha256":expected,
 "custody_manifest_sha256":expected_manifest,
 "custody_consensus_manifest_sha256":expected_consensus,
 "custody_script_range":custody_range,
 "custody_script_pubkeys":spks,"btc_input_confirmations":1,"max_payout_fee_sats":100000}
open("/opt/veld-signer/payout-signer-config.json","w").write(json.dumps(cfg,indent=1))
print("  config: %d operational custody scriptPubKeys pinned to descriptor %s"%(len(spks),expected))
PY
chown root:root /opt/veld-signer/payout-signer-config.json
chmod 600 /opt/veld-signer/payout-signer-config.json

echo "== provision full C1 child-key range and threshold descriptor =="
RANGE_END=$(python3 -c 'import json; print(json.load(open("/opt/veld-signer/payout-signer-config.json"))["custody_script_range"][1])')
PASS=$(< /root/.veld-signer/wallet.pass)
printf '%s\n60\n' "$PASS" | \
  bitcoin-cli -stdin -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" walletpassphrase >/dev/null
unset PASS
bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" keypoolrefill "$((RANGE_END + 1))"
EXACT_PRESENT=$(bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" listdescriptors false | \
  python3 -c 'import json,sys; cfg=json.load(open("/opt/veld-signer/payout-signer-config.json")); rows=json.load(sys.stdin).get("descriptors",[]); print("yes" if len([r for r in rows if r.get("desc")==cfg["custody_descriptor"] and r.get("internal") is False and r.get("range")==cfg["custody_script_range"]])==1 else "no")')
if [ "$EXACT_PRESENT" != "yes" ]; then
  IMPORT_REQUEST=$(python3 -c 'import json; c=json.load(open("/opt/veld-signer/payout-signer-config.json")); print(json.dumps([{"desc":c["custody_descriptor"],"timestamp":"now","active":False,"internal":False,"range":c["custody_script_range"]}],separators=(",",":")))')
  bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" importdescriptors "$IMPORT_REQUEST" | \
    python3 -c 'import json,sys; r=json.load(sys.stdin); (isinstance(r,list) and len(r)==1 and r[0].get("success")) or (_ for _ in ()).throw(SystemExit("FATAL: full-range threshold descriptor import failed"))'
  unset IMPORT_REQUEST
fi
unset EXACT_PRESENT
bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" walletlock
bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" listdescriptors false | \
  python3 -c 'import json,sys; cfg=json.load(open("/opt/veld-signer/payout-signer-config.json")); rows=json.load(sys.stdin).get("descriptors",[]); matches=[r for r in rows if r.get("desc")==cfg["custody_descriptor"] and r.get("internal") is False and r.get("range")==cfg["custody_script_range"]]; len(matches)==1 or (_ for _ in ()).throw(SystemExit("FATAL: signer wallet lacks exact full-range threshold descriptor"))'
echo "  signer keypool and threshold descriptor cover [0,$RANGE_END]"

echo "== signing wrapper (coordinator forced-command target) =="
{
printf '%s\n' '#!/bin/bash'
printf 'ENV_FILE=%q\n' "$ENV_FILE"
cat <<'WRAP'
# Forced-command target for the coordinator's SSH key. Unlocks the custody wallet,
# runs the policy signer (independently re-verifies the burn before touching the key),
# re-locks. The request JSON arrives on stdin from the coordinator.
set -euo pipefail
umask 077
PASS_FILE=/root/.veld-signer/wallet.pass
CONFIG=/opt/veld-signer/payout-signer-config.json

require_root_file() {
  local path="$1" mode
  [ -f "$path" ] && [ "$(stat -c '%u' "$path")" = 0 ] || {
    echo "sign-wrapper: required root-owned file missing: $path" >&2; exit 2;
  }
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 8#022) == 0 )) || {
    echo "sign-wrapper: insecure writable permissions on $path" >&2; exit 2;
  }
}

require_private_root_file() {
  local path="$1" mode
  require_root_file "$path"
  mode=$(stat -c '%a' "$path")
  (( (8#$mode & 8#077) == 0 )) || {
    echo "sign-wrapper: private file must have no group/world permissions: $path" >&2; exit 2;
  }
}

require_root_file "$ENV_FILE"
require_private_root_file "$PASS_FILE"
require_private_root_file "$CONFIG"
# Serialize wallet unlock/sign/lock cycles. Concurrent forced commands must not
# let one request's EXIT trap lock the wallet underneath another request.
exec 9>/var/lib/veld-signer/sign-wrapper.lock
flock -x 9
set -a
# shellcheck disable=SC1091 -- fixed, root-owned deployment environment
. "$ENV_FILE"
set +a
WALLET=$(python3 -c 'import json; print(json.load(open("/opt/veld-signer/payout-signer-config.json"))["wallet"])')
[ -n "$WALLET" ] || { echo "sign-wrapper: wallet is empty" >&2; exit 2; }
BTC_DATADIR=$(python3 -c 'import json; print(json.load(open("/opt/veld-signer/payout-signer-config.json"))["bitcoin_datadir"])')
case "$BTC_DATADIR" in /*) ;; *) echo "sign-wrapper: configured Bitcoin datadir is not absolute" >&2; exit 2;; esac
PASS=$(<"$PASS_FILE")
[ -n "$PASS" ] || { echo "sign-wrapper: wallet passphrase is empty" >&2; exit 2; }
cleanup() {
  bitcoin-cli -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" walletlock >/dev/null 2>&1 || :
  unset PASS
}
trap cleanup EXIT HUP INT TERM
printf '%s\n60\n' "$PASS" | \
  bitcoin-cli -stdin -datadir="$BTC_DATADIR" -rpcwallet="$WALLET" walletpassphrase >/dev/null
unset PASS
export VELD_PAYOUT_SIGNER_CONFIG="$CONFIG"
python3 /opt/veld-signer/veld_payout_signerd.py
WRAP
} >/opt/veld-signer/sign-wrapper.sh
chown root:root /opt/veld-signer/sign-wrapper.sh
chmod 750 /opt/veld-signer/sign-wrapper.sh

echo "== SIGNER $SIGNER_ID INSTALLED; CUSTODY QUALIFICATION STILL REQUIRED =="
echo "encrypted=$(B -rpcwallet="$WALLET" getwalletinfo | python3 -c "import sys,json;print('unlocked_until' in json.load(sys.stdin))") wrapper=/opt/veld-signer/sign-wrapper.sh"
