#!/usr/bin/env bash
# btcVELD 3-of-5 signer box — HARDENED phase-1 setup (Ubuntu 24.04 x86_64, run as root).
# Hardening + pruned bitcoind + signer keygen + veld verification node. The signer daemon
# Coordinator forced-command access is applied after the descriptor is rebuilt.
# veld-node binary must be staged at /tmp/veld-node before running.
#   SIGNER_ID=custody-signer-1 bash signer-box-setup.sh
set -euo pipefail
SIGNER_ID="${SIGNER_ID:?set SIGNER_ID=custody-signer-1 .. custody-signer-5}"
case "$SIGNER_ID" in custody-signer-[1-5]) ;; *) echo "FATAL: SIGNER_ID must be custody-signer-1 .. custody-signer-5" >&2; exit 2;; esac
[ "$(id -u)" -eq 0 ] || { echo "FATAL: signer-box-setup.sh must run as root" >&2; exit 2; }
FLEET_CONNECT="--connect 108.61.119.29:8333 --connect 5.78.107.166:8333 --connect 5.78.97.56:8333 --connect 5.78.127.51:8333"
BTC_VER="${BTC_VER:-28.1}"
BTC_RELEASE_KEY_FILE="${BTC_RELEASE_KEY_FILE:-/etc/veld/bitcoin-core-release-key.asc}"
BTC_RELEASE_SIGNING_FINGERPRINT="${BTC_RELEASE_SIGNING_FINGERPRINT:-}"
[[ "$BTC_RELEASE_SIGNING_FINGERPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || {
  echo "FATAL: set the independently pinned 40-hex BTC_RELEASE_SIGNING_FINGERPRINT" >&2; exit 3; }
[ -f "$BTC_RELEASE_KEY_FILE" ] && [ ! -L "$BTC_RELEASE_KEY_FILE" ] || {
  echo "FATAL: missing regular non-symlink pinned release key: $BTC_RELEASE_KEY_FILE" >&2; exit 3; }
case "$BTC_RELEASE_KEY_FILE" in /*) ;; *) echo "FATAL: BTC_RELEASE_KEY_FILE must be absolute" >&2; exit 3;; esac
[ "$(stat -c '%u' "$BTC_RELEASE_KEY_FILE")" = 0 ] || {
  echo "FATAL: pinned Bitcoin Core release key must be root-owned" >&2; exit 3; }
BTC_RELEASE_KEY_MODE=$(stat -c '%a' "$BTC_RELEASE_KEY_FILE")
(( (8#$BTC_RELEASE_KEY_MODE & 8#022) == 0 )) || {
  echo "FATAL: pinned Bitcoin Core release key must not be group/world writable" >&2; exit 3; }
export DEBIAN_FRONTEND=noninteractive

echo "== [1/5] base packages + unattended SECURITY upgrades =="
apt-get update -qq
apt-get install -y -qq curl python3 tar openssl gnupg ufw fail2ban unattended-upgrades ca-certificates libleveldb1d >/dev/null  # libleveldb1d: veld-node runtime dep
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'A'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
A
systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true

echo "== [2/5] SSH hardening (key-only, no root password, low MaxAuthTries) =="
install -d /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-veld-harden.conf <<'S'
PasswordAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
KbdInteractiveAuthentication no
X11Forwarding no
MaxAuthTries 3
AllowAgentForwarding no
S
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true

echo "== [3/5] firewall (DEFAULT-DENY inbound; only SSH in; node is outbound-only) + fail2ban =="
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw allow 22/tcp >/dev/null
ufw --force enable >/dev/null
systemctl enable --now fail2ban >/dev/null 2>&1 || true

echo "== [4/5] Bitcoin Core $BTC_VER (pruned, blocksonly, RPC localhost-only) =="
cd /tmp
if [ ! -x /usr/local/bin/bitcoind ]; then
  A=x86_64-linux-gnu
  curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/bitcoin-$BTC_VER-$A.tar.gz"
  curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/SHA256SUMS"
  curl -fsSLO "https://bitcoincore.org/bin/bitcoin-core-$BTC_VER/SHA256SUMS.asc"
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
  grep " bitcoin-$BTC_VER-$A.tar.gz\$" SHA256SUMS | sha256sum -c -
  rm -rf "$GNUPGHOME"; trap - EXIT; unset GNUPGHOME GPG_ARGS GPG_OPTIONS BTC_RELEASE_KEY_MODE
  tar xzf "bitcoin-$BTC_VER-$A.tar.gz"
  install -m755 "bitcoin-$BTC_VER/bin/bitcoind" "bitcoin-$BTC_VER/bin/bitcoin-cli" /usr/local/bin/
fi
install -d -m750 /var/lib/bitcoin
cat >/var/lib/bitcoin/bitcoin.conf <<C
chain=main
prune=2000
dbcache=300
blocksonly=1
daemon=1
datadir=/var/lib/bitcoin
rpcport=8432
port=8433
C
# ^ bitcoind on 8432/8433 so veld-node can take its default 8333 (P2P) / 8334 (RPC)
pgrep -x bitcoind >/dev/null || bitcoind -datadir=/var/lib/bitcoin -conf=/var/lib/bitcoin/bitcoin.conf
B(){ bitcoin-cli -datadir=/var/lib/bitcoin "$@"; }
for i in $(seq 1 30); do B getblockchaininfo >/dev/null 2>&1 && break; sleep 2; done

echo "== [4b] signer key (LOCAL; private key never leaves this box) =="
# custody-signer-1 (new box): keygen a fresh key. Operator boxes reuse the EXISTING wallet from
# the earlier keygen (set EXISTING_WALLET=btcveld-custody-signer-N) — NEVER regenerate their key.
W="${EXISTING_WALLET:-btcveld-$SIGNER_ID}"
B -rpcwallet="$W" getwalletinfo >/dev/null 2>&1 || B createwallet "$W" false false "" false true >/dev/null
PUB=$(B -rpcwallet="$W" listdescriptors | python3 -c "import sys,json
for e in json.load(sys.stdin)['descriptors']:
 d=e['desc']
 if d.startswith('tr(') and '/86' in d and not e.get('internal'): print(d[3:d.rindex(')')]); break")
[ -n "$PUB" ] || { echo FATAL: no taproot pub; exit 3; }

echo "== [5/5] veld verification node (current signed release; outbound-only sync) =="
[ -f /tmp/veld-node ] && install -m755 /tmp/veld-node /usr/local/bin/veld-node  # -f not -x: scp drops the exec bit
mkdir -p /var/lib/veld-node
[ -f /etc/veld/env ] || { echo "FATAL: required /etc/veld/env is missing" >&2; exit 3; }
[ "$(stat -c '%u' /etc/veld/env)" = 0 ] || { echo "FATAL: /etc/veld/env must be root-owned" >&2; exit 3; }
ENV_MODE=$(stat -c '%a' /etc/veld/env)
(( (8#$ENV_MODE & 8#022) == 0 )) || { echo "FATAL: /etc/veld/env must not be group/world writable" >&2; exit 3; }
cat >/etc/systemd/system/veld-node.service <<U
[Unit]
Description=Veld signer verification node (current signed release)
After=network-online.target
[Service]
EnvironmentFile=/etc/veld/env
ExecStart=/usr/local/bin/veld-node --datadir /var/lib/veld-node --no-prompt --no-snapshot $FLEET_CONNECT
Restart=always
RestartSec=5
StandardInput=null
LimitNOFILE=8192
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/veld-node
[Install]
WantedBy=multi-user.target
U
systemctl daemon-reload && systemctl enable --now veld-node >/dev/null 2>&1
sleep 8

echo
echo "======== SIGNER $SIGNER_ID PHASE-1 READY ========"
echo "PUBKEY_LINE: $SIGNER_ID $PUB"
echo "veld-node=$(systemctl is-active veld-node) bitcoind=$(pgrep -x bitcoind >/dev/null && echo up || echo down) fail2ban=$(systemctl is-active fail2ban)"
echo "firewall: $(ufw status verbose | grep -E '^(Status|Default):' | tr '\n' ' ')"
