#!/usr/bin/env bash
# btcVELD 3-of-5 custody — PER-HOST signer keygen.
#
# Run this ONCE on each of the 5 INDEPENDENT signer hosts (your 4 nodes + the new
# 5th box). It generates THIS signer's key LOCALLY in a Bitcoin Core descriptor
# wallet and prints ONLY the PUBLIC key expression. The private key is born on this
# host and MUST NEVER leave it — do not copy, transmit, screenshot, or paste it.
# Only the single public line at the end is shared with the coordinator.
#
# Requires: a local MAINNET bitcoind + bitcoin-cli reachable at $BTC_DATADIR.
# Usage:  BTC_DATADIR=/var/lib/bitcoin ./custody-signer-keygen.sh custody-signer-1
set -euo pipefail

ID="${1:?usage: $0 <signer-id, e.g. custody-signer-1 .. custody-signer-5>}"
case "$ID" in custody-signer-[1-5]) ;; *) echo "FATAL: signer id must be custody-signer-1 .. custody-signer-5" >&2; exit 2;; esac
DATADIR="${BTC_DATADIR:-/var/lib/bitcoin}"
B=(bitcoin-cli -datadir="$DATADIR")
WALLET="btcveld-$ID"

command -v bitcoin-cli >/dev/null || { echo "FATAL: bitcoin-cli not on PATH" >&2; exit 2; }
"${B[@]}" getblockchaininfo >/dev/null 2>&1 || { echo "FATAL: cannot reach bitcoind at $DATADIR" >&2; exit 2; }
# Refuse to generate a real-funds custody key against anything but mainnet.
CHAIN=$("${B[@]}" getblockchaininfo | python3 -c "import sys,json;print(json.load(sys.stdin)['chain'])")
if [ "$CHAIN" != "main" ] && [ "${ALLOW_NON_MAINNET:-0}" != "1" ]; then
  echo "FATAL: bitcoind chain='$CHAIN', expected 'main'. Set ALLOW_NON_MAINNET=1 only for a testnet." >&2
  exit 2
fi

# 1. create a descriptor wallet (private keys enabled) if it doesn't exist.
#    createwallet <name> disable_private_keys=false blank=false passphrase="" avoid_reuse=false descriptors=true
if ! "${B[@]}" -rpcwallet="$WALLET" getwalletinfo >/dev/null 2>&1; then
  "${B[@]}" createwallet "$WALLET" false false "" false true >/dev/null
  echo "[keygen] created descriptor wallet '$WALLET' on this host" >&2
else
  echo "[keygen] reusing existing wallet '$WALLET' on this host" >&2
fi

# 2. extract THIS signer's PUBLIC taproot key expression (BIP86 external branch).
PUBEXPR=$("${B[@]}" -rpcwallet="$WALLET" listdescriptors | python3 -c "
import sys,json
for e in json.load(sys.stdin)['descriptors']:
    d=e['desc']
    if d.startswith('tr(') and '/86' in d and not e.get('internal'):
        print(d[3:d.rindex(')')]); break")
[ -n "$PUBEXPR" ] || { echo 'FATAL: could not extract the taproot public key expression' >&2; exit 3; }

echo
echo '============ SEND ONLY THE LINE BELOW TO THE COORDINATOR (public) ============'
echo "$ID $PUBEXPR"
echo '=============================================================================='
echo
echo 'NOW protect the PRIVATE key on THIS host (do not skip either step):'
echo '  1) Generate the root-only passphrase file required by signer-daemon-setup.sh'
echo '     and encrypt without exposing the passphrase in process arguments:'
echo '       install -d -m700 /root/.veld-signer'
echo '       umask 077; openssl rand -base64 32 > /root/.veld-signer/wallet.pass'
echo "       bitcoin-cli -stdin -datadir=$DATADIR -rpcwallet=$WALLET encryptwallet < /root/.veld-signer/wallet.pass"
echo "  2) Back it up OFFLINE (encrypted USB, and the descriptor+passphrase on paper):"
echo "       bitcoin-cli -datadir=$DATADIR -rpcwallet=$WALLET backupwallet \"\$HOME/$WALLET.backup.dat\""
echo
echo 'The private key must never leave this host. Losing it = you can no longer be one'
echo 'of the 3 signers; leaking it weakens the 3-of-5. Share ONLY the public line above.'
