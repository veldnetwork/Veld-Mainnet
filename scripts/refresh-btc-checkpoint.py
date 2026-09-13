#!/usr/bin/env python3
"""Emit a fresh BtcVeldCheckpoint for include/consensus/btcveld_spv_params.h.

WHY: the btcVELD header relay bootstraps the in-consensus Bitcoin header view
from a compiled checkpoint (the #else / production branch of BtcVeldCheckpoint()).
The relay then replays every mainnet header from that checkpoint to the current
BTC tip, one ~100-header op per Veld block. If the compiled checkpoint is stale
by N blocks, that is N headers of one-time catch-up after every fresh-genesis
wipe (and once at mainnet launch). Refreshing it each release keeps the gap
bounded to at most one retarget period instead of growing unboundedly.

The checkpoint MUST sit on a Bitcoin retarget boundary (height % 2016 == 0):
only then can the relay validate the first difficulty retarget it observes
(2016 blocks later) purely from relayed headers — a mid-period checkpoint lacks
the prior period's opening timestamp and would reject that retarget.

USAGE (run on a host with a synced mainnet bitcoind):
    BITCOIN_CLI="sudo -u bitcoin bitcoin-cli -datadir=/home/bitcoin/.bitcoin" \
        python3 scripts/refresh-btc-checkpoint.py [min_depth]

    # validate the tool against the currently-compiled checkpoint:
    CHECKPOINT_HEIGHT=957600 BITCOIN_CLI="..." python3 scripts/refresh-btc-checkpoint.py

Paste the printed block over the `cp.height = ...` region of the #else branch in
include/consensus/btcveld_spv_params.h, then rebuild ALL binaries for the release.
"""
import os, sys, json, subprocess, hashlib

CLI       = os.environ.get("BITCOIN_CLI", "bitcoin-cli").split()
MIN_DEPTH = int(sys.argv[1]) if len(sys.argv) > 1 else 512   # burial safety margin
FORCE_H   = os.environ.get("CHECKPOINT_HEIGHT")             # pin a height (validation)

def cli(*a):
    r = subprocess.run(CLI + list(a), capture_output=True, text=True)
    if r.returncode:
        sys.exit("bitcoin-cli %s failed: %s" % (a[0], r.stderr.strip()[:200]))
    s = r.stdout.strip()
    try:    return json.loads(s)
    except Exception: return s

chain = cli("getblockchaininfo")
if isinstance(chain, dict) and chain.get("chain") != "main":
    sys.exit("refusing: bitcoind is on '%s', not mainnet" % chain.get("chain"))

tip = int(cli("getblockcount"))
if FORCE_H:
    boundary = int(FORCE_H)
else:
    boundary = ((tip - MIN_DEPTH) // 2016) * 2016          # latest buried retarget boundary
if boundary <= 0 or boundary % 2016 != 0:
    sys.exit("bad boundary %d (must be a positive multiple of 2016)" % boundary)
depth = tip - boundary

h    = cli("getblockhash", str(boundary))
hdr  = cli("getblockheader", h)                            # {hash,time,bits,...} (display hash, BE)
raw  = cli("getblockheader", h, "false")                   # raw 80-byte header hex
disp = hdr["hash"]
internal_le = bytes.fromhex(disp)[::-1].hex()              # cp.hash = INTERNAL (LE) block hash
bits = int(hdr["bits"], 16)
time_ = int(hdr["time"])

# prev-10 block times, heights boundary-10 .. boundary-1, oldest first (MTP seed)
p10 = []
for hh in range(boundary - 10, boundary):
    p10.append(int(cli("getblockheader", cli("getblockhash", str(hh)))["time"]))

# self-check: dSHA256(raw 80-byte header) == cp.hash (internal LE)
calc = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw)).digest()).digest().hex()
if calc != internal_le:
    sys.exit("FATAL: dSHA256(header) %s != reversed display hash %s" % (calc, internal_le))

print("    // Refreshed for release: mainnet-BTC checkpoint at retarget boundary %d" % boundary)
print("    //   display hash %s" % disp)
print("    //   (buried %d blocks deep at refresh; all fields from bitcoind, self-checked)" % depth)
print("    cp.height = %d; cp.bits = 0x%08xu; cp.time = %d;" % (boundary, bits, time_))
print('    { auto hb = BtcVeldHex_("%s");' % internal_le)
print("      for (size_t i = 0; i < 32 && i < hb.size(); ++i) cp.hash[i] = hb[i]; }")
print("    static const uint32_t p10[10] = { %s," % ", ".join("%du" % t for t in p10[:4]))
print("                                      %s," % ", ".join("%du" % t for t in p10[4:8]))
print("                                      %s };" % ", ".join("%du" % t for t in p10[8:]))
print("    for (int i = 0; i < 10; ++i) cp.prev10_times[i] = p10[i];")
