#!/usr/bin/env bash
# btcVELD 3-of-5 custody — ONE-SHOT operator box setup.
#
# Each of the 5 signer operators runs this ONCE, on their OWN box, themselves.
# It installs a pruned Bitcoin Core, starts it syncing, generates THIS signer's
# key LOCALLY, and prints only the PUBLIC key line to send to the coordinator.
#
# The private key is created on this box and never leaves it. Nobody else — not
# the coordinator, not another operator, not any shared session — ever touches
# it. That is the entire point: a key you generate yourself is a key only you
# hold, which is what makes the 3-of-5 real.
#
# Usage (as root on a fresh Ubuntu/Debian box):
#   SIGNER_ID=custody-signer-2 bash custody-operator-setup.sh
set -euo pipefail

SIGNER_ID="${SIGNER_ID:?set SIGNER_ID=custody-signer-2 (…-3, -4, -5) — unique per operator}"
case "$SIGNER_ID" in custody-signer-[1-5]) ;; *) echo "FATAL: SIGNER_ID must be custody-signer-1 .. custody-signer-5" >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo "FATAL: custody-operator-setup.sh must run as root" >&2; exit 2; }
BTC_VER="${BTC_VER:-28.1}"                       # bump if you prefer a newer Core; the script self-verifies the hash
ARCH="$(uname -m)"; case "$ARCH" in x86_64) BTAR="x86_64-linux-gnu";; aarch64|arm64) BTAR="aarch64-linux-gnu";; *) echo "unsupported arch $ARCH" >&2; exit 2;; esac
BTC_DATADIR="${BTC_DATADIR:-/var/lib/bitcoin}"
WALLET="btcveld-$SIGNER_ID"
BTC_RELEASE_KEY_FILE="${BTC_RELEASE_KEY_FILE:-/etc/veld/bitcoin-core-release-key.asc}"
BTC_RELEASE_SIGNING_FINGERPRINT="${BTC_RELEASE_SIGNING_FINGERPRINT:-}"
[[ "$BTC_RELEASE_SIGNING_FINGERPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo "FATAL: set BTC_RELEASE_SIGNING_FINGERPRINT to the independently pinned 40-hex Bitcoin Core release-key fingerprint" >&2; exit 3; }
[ -f "$BTC_RELEASE_KEY_FILE" ] && [ ! -L "$BTC_RELEASE_KEY_FILE" ] || {
  echo "FATAL: pinned Bitcoin Core release public key must be a regular non-symlink file: $BTC_RELEASE_KEY_FILE" >&2; exit 3; }
case "$BTC_RELEASE_KEY_FILE" in /*) ;; *) echo "FATAL: BTC_RELEASE_KEY_FILE must be absolute" >&2; exit 3;; esac
[ "$(stat -c '%u' "$BTC_RELEASE_KEY_FILE")" = 0 ] || {
  echo "FATAL: pinned Bitcoin Core release key must be root-owned" >&2; exit 3; }
BTC_RELEASE_KEY_MODE=$(stat -c '%a' "$BTC_RELEASE_KEY_FILE")
(( (8#$BTC_RELEASE_KEY_MODE & 8#022) == 0 )) || {
  echo "FATAL: pinned Bitcoin Core release key must not be group/world writable" >&2; exit 3; }

echo "[setup] ensuring base dependencies (curl, python3, tar, openssl)"
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null || \
   ! command -v tar >/dev/null || ! command -v openssl >/dev/null || \
   ! command -v gpg >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq curl python3 tar openssl ca-certificates gnupg
fi

echo "[setup] installing Bitcoin Core $BTC_VER ($BTAR) with hash verification"
cd /tmp
TARBALL="bitcoin-$BTC_VER-$BTAR.tar.gz"
curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/$TARBALL"
curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/SHA256SUMS"
curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/SHA256SUMS.asc"
# Authenticate SHA256SUMS with one independently pinned release key. Downloading
# sums and tar from the same TLS origin is not a supply-chain signature.
GNUPGHOME=$(mktemp -d); export GNUPGHOME; chmod 700 "$GNUPGHOME"
trap 'rm -rf "$GNUPGHOME"' EXIT
GPG_ARGS=(gpg --no-options --batch --no-tty --homedir "$GNUPGHOME" --no-auto-key-retrieve)
"${GPG_ARGS[@]}" --quiet --import "$BTC_RELEASE_KEY_FILE" || {
  echo "FATAL: pinned Bitcoin Core release key could not be imported" >&2; exit 3; }
GPG_OPTIONS=$("${GPG_ARGS[@]}" --dump-options 2>/dev/null || :)
printf '%s\n' "$GPG_OPTIONS" | tr -d '\r' | grep -Fxq -- '--assert-signer' || {
  echo "FATAL: GnuPG 2.4 with --assert-signer support is required" >&2; exit 3; }
"${GPG_ARGS[@]}" --assert-signer "${BTC_RELEASE_SIGNING_FINGERPRINT^^}" \
  --verify SHA256SUMS.asc SHA256SUMS </dev/null 2>/dev/null || {
  echo "FATAL: SHA256SUMS is invalid or lacks the pinned Bitcoin Core primary signer" >&2; exit 3; }
grep " $TARBALL\$" SHA256SUMS | sha256sum -c - || { echo "FATAL: Bitcoin Core hash mismatch — do NOT proceed" >&2; exit 3; }
tar -xzf "$TARBALL"
install -m755 "bitcoin-$BTC_VER/bin/bitcoind" "bitcoin-$BTC_VER/bin/bitcoin-cli" /usr/local/bin/
rm -rf "$GNUPGHOME"; trap - EXIT; unset GNUPGHOME GPG_ARGS GPG_OPTIONS BTC_RELEASE_KEY_MODE

echo "[setup] pruned mainnet config at $BTC_DATADIR"
install -d -m750 "$BTC_DATADIR"
cat > "$BTC_DATADIR/bitcoin.conf" <<CONF
chain=main
prune=2000
dbcache=300
blocksonly=1
daemon=1
datadir=$BTC_DATADIR
CONF

echo "[setup] starting bitcoind (initial sync begins now; ~a day, runs in background)"
bitcoind -datadir="$BTC_DATADIR" -conf="$BTC_DATADIR/bitcoin.conf"
sleep 5
B=(bitcoin-cli -datadir="$BTC_DATADIR")
for i in $(seq 1 30); do "${B[@]}" getblockchaininfo >/dev/null 2>&1 && break; sleep 2; done
CHAIN=$("${B[@]}" getblockchaininfo | python3 -c "import sys,json;print(json.load(sys.stdin)['chain'])")
[ "$CHAIN" = "main" ] || { echo "FATAL: not on mainnet ($CHAIN)" >&2; exit 2; }

echo "[setup] generating THIS signer's key locally (does not require a finished sync)"
"${B[@]}" -rpcwallet="$WALLET" getwalletinfo >/dev/null 2>&1 || "${B[@]}" createwallet "$WALLET" false false "" false true >/dev/null
PUBEXPR=$("${B[@]}" -rpcwallet="$WALLET" listdescriptors | python3 -c "
import sys,json
for e in json.load(sys.stdin)['descriptors']:
    d=e['desc']
    if d.startswith('tr(') and '/86' in d and not e.get('internal'):
        print(d[3:d.rindex(')')]); break")
[ -n "$PUBEXPR" ] || { echo 'FATAL: could not extract taproot public key' >&2; exit 3; }

echo
echo '============ SEND ONLY THE LINE BELOW TO THE COORDINATOR (public) ============'
echo "$SIGNER_ID $PUBEXPR"
echo '=============================================================================='
echo
echo 'NOW, on THIS box, protect your private key (do not skip):'
echo '  install -d -m700 /root/.veld-signer'
echo '  umask 077; openssl rand -base64 32 > /root/.veld-signer/wallet.pass'
echo "  bitcoin-cli -stdin -datadir=$BTC_DATADIR -rpcwallet=$WALLET encryptwallet < /root/.veld-signer/wallet.pass"
echo "  bitcoin-cli -datadir=$BTC_DATADIR -rpcwallet=$WALLET backupwallet \"\$HOME/$WALLET.backup.dat\"   # store OFFLINE"
echo '  # signer-daemon-setup.sh requires that root-owned 0600 wallet.pass file.'
echo
echo 'Your private key never leaves this box. Sync continues in the background; you'
echo 'can start veld_payout_signerd once it is caught up. Share ONLY the line above.'
