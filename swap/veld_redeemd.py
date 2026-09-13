#!/usr/bin/env python3
"""Durable btcVELD redemption coordinator.

Security authorities are deliberately separated:

* Veld consensus supplies accepted burns.  They are transactionally inserted into
  an external, full-synchronous SQLite obligation index on first observation, long
  before the K_VELD payout depth.  They therefore cannot age out with the node's
  bounded activity/history view (N-02).
* Bitcoin itself supplies paid/not-paid idempotency.  Every payout contains one
  canonical OP_RETURN marker binding the Veld burn outpoint.  Before every signing
  and broadcast boundary, the coordinator searches its Bitcoin wallet history for
  that marker and verifies the exact destination/amount. This reconciles visible
  payments; unpublished signatures and stale restores need independent intent
  authority before a replacement payout can be authorized.
* Production payout signing is threshold PSBT approval.  The coordinator is
  watch-only and cannot spend by itself.  Single-wallet signing exists only behind
  an explicit development-only flag (H-06).

The daemon fails closed on dependency ambiguity, a canonical-chain mismatch,
state corruption, marker/payment mismatch, incomplete threshold approval, or fee
and transaction-template disagreement.
"""
import base64
import binascii
import hashlib
import itertools
import json
import os
import re
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.request
from decimal import Decimal, InvalidOperation

try:
    from .rpc_url_policy import (load_bounded_json_file,
                                 load_bounded_json_response, open_rpc_request,
                                 read_bounded_secret_file,
                                 run_bounded_subprocess,
                                strict_json_loads,
                                validate_backend_rpc_url)
    from .veld_redeem_commitment import (RedeemCommitment,
                                         authority_for_rows,
                                         parse_page_authority)
except ImportError:  # direct-script execution
    from rpc_url_policy import (load_bounded_json_file,
                                load_bounded_json_response, open_rpc_request,
                                read_bounded_secret_file,
                                run_bounded_subprocess,
                                strict_json_loads,
                                validate_backend_rpc_url)
    from veld_redeem_commitment import (RedeemCommitment,
                                        authority_for_rows,
                                        parse_page_authority)

try:
    import fcntl
except ImportError:  # pragma: no cover - production is POSIX
    fcntl = None


# This value is checked against getblockchaininfo.max_reorg_depth on every live
# coordinator/signer pass.  Payout requires a depth STRICTLY GREATER than this
# horizon; equality remains reorg-watch state throughout the launch stack.
MAX_REORG_DEPTH = 100
K_VELD = MAX_REORG_DEPTH
FEERATE_SAT_VB = 5
SATS = 100_000_000
DUST_SATS = 546
PAYOUT_MARKER_MAGIC = b"VLDR\x01"
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^(?:[0-9a-f]{2})+$")
STATUS_OPEN = ("observed", "broadcasting", "held")
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_OFFLINE_REDEEMS_BYTES = 32 * 1024 * 1024
MAX_CLI_OUTPUT_BYTES = 64 * 1024 * 1024
MAX_SIGNER_OUTPUT_BYTES = 4 * 1024 * 1024
MAX_REDEEM_PAGES = 1_000_000
OPERATOR_CUSTODY_RANGE_END = 999
C1_ALLOCATION_ID_RE = re.compile(r"^0{16}[0-9a-f]{16}$")
P2TR_SPK_RE = re.compile(r"^5120[0-9a-f]{64}$")
MINT_STATUS_KEYS = frozenset({
    "outpoint", "consumed", "minted", "proof_version", "proof_hex",
    "root", "count", "tip", "tip_hash", "accepted_txid",
    "accepted_block_height", "accepted_block_hash", "accepted_tx_index",
    "accepted_marker_vout", "accepted_effect_kind", "c1_allocation_id",
    "consumer_txid", "consumer_block_height", "consumer_block_hash",
    "consumer_tx_index", "consumer_marker_vout", "credit_txid",
    "credit_block_height", "credit_block_hash", "credit_tx_index",
    "credit_marker_vout",
})


class PublicC1MintNotAccepted(RuntimeError):
    """A public custody deposit is canonical, but is not yet an exact C1 mint."""


def partition_custody_policy(binding):
    """Add immutable operator/public script partitions to a custody binding."""
    if not isinstance(binding, dict):
        raise RuntimeError("custody policy is not an object")
    custody_range = binding.get("range")
    scripts = binding.get("script_pubkeys")
    range_valid = (
        isinstance(custody_range, list) and len(custody_range) == 2 and
        custody_range[0] == 0 and type(custody_range[1]) is int and
        (custody_range[1] == OPERATOR_CUSTODY_RANGE_END or
         10999 <= custody_range[1] <= 1_000_000))
    expected_count = custody_range[1] + 1 if range_valid else -1
    if (not range_valid or not isinstance(scripts, (list, tuple)) or
            len(scripts) != expected_count or len(set(scripts)) != expected_count or
            any(not isinstance(script, str) or not P2TR_SPK_RE.fullmatch(script)
                for script in scripts)):
        raise RuntimeError("custody policy has no exact unique ranged P2TR script domain")
    scripts = tuple(scripts)
    answer = dict(binding)
    answer.update({
        "range": list(custody_range),
        "script_pubkeys": scripts,
        "script_pubkey_set": frozenset(scripts),
        "operator_script_pubkeys": frozenset(
            scripts[:OPERATOR_CUSTODY_RANGE_END + 1]),
        "public_script_pubkeys": frozenset(
            scripts[OPERATOR_CUSTODY_RANGE_END + 1:]),
    })
    return answer


def load_payout_custody_policy(cfg):
    """Load redeemd's exact hash-bound operational custody manifest."""
    if not isinstance(cfg, dict):
        raise RuntimeError("redemption configuration is not an object")
    configured_range = cfg.get("custody_script_range")
    if (not isinstance(configured_range, list) or len(configured_range) != 2 or
            configured_range[0] != 0 or type(configured_range[1]) is not int):
        raise RuntimeError("custody_script_range must be [0, exact-range-end]")
    try:
        try:
            from . import veld_custody_binding as custody_binding
        except ImportError:
            import veld_custody_binding as custody_binding
        binding = custody_binding.load_manifest(
            cfg.get("custody_spk_manifest_file"),
            cfg.get("custody_descriptor_sha256"),
            cfg.get("custody_manifest_sha256"),
            expected_range_end=configured_range[1],
            expected_consensus_manifest_sha256=cfg.get(
                "custody_consensus_manifest_sha256"))
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("cannot load payout custody policy: %s" % exc)
    return partition_custody_policy(binding)


def _coherent_supply_snapshot(veld):
    snapshot = veld.call("getbtcveldsupply", [])
    if (not isinstance(snapshot, dict) or
            set(snapshot) != {"supply_sats", "tip", "tip_hash"} or
            type(snapshot.get("supply_sats")) is not int or
            not (0 <= snapshot["supply_sats"] <= (1 << 63) - 1) or
            type(snapshot.get("tip")) is not int or
            not (0 <= snapshot["tip"] <= (1 << 63) - 1) or
            not isinstance(snapshot.get("tip_hash"), str) or
            not TXID_RE.fullmatch(snapshot["tip_hash"])):
        raise RuntimeError("coherent Veld supply snapshot is malformed")
    return snapshot


def _mint_locator(status, prefix, tip):
    txid = status.get(prefix + "_txid")
    height = status.get(prefix + "_block_height")
    block_hash = status.get(prefix + "_block_hash")
    tx_index = status.get(prefix + "_tx_index")
    marker_vout = status.get(prefix + "_marker_vout")
    if (not isinstance(txid, str) or not TXID_RE.fullmatch(txid) or
            type(height) is not int or not (0 <= height <= tip) or
            not isinstance(block_hash, str) or not TXID_RE.fullmatch(block_hash) or
            type(tx_index) is not int or not (0 <= tx_index <= 0xffffffff) or
            type(marker_vout) is not int or not (0 <= marker_vout <= 0xffffffff)):
        raise RuntimeError("canonical public C1 %s locator is malformed" % prefix)
    return txid, height, block_hash, tx_index, marker_vout


def validate_payout_custody_inputs(veld, inputs, custody_policy):
    """Require every public-range input to be an exact canonical C1_MINT.

    Operator indices 0--999 deliberately require no C1 status.  Public indices
    are bracketed by one coherent Veld supply/tip identity, and every carrier
    locator is checked against the canonical chain before the snapshot is
    sampled again.  No result is cached across requests or process restarts.
    """
    policy = partition_custody_policy(custody_policy)
    if not isinstance(inputs, (list, tuple)) or not inputs:
        raise RuntimeError("payout custody input set is empty or malformed")
    public = []
    seen = set()
    for item in inputs:
        if not isinstance(item, dict):
            raise RuntimeError("payout custody input is malformed")
        txid = item.get("txid")
        vout = item.get("vout")
        script = item.get("script_pubkey_hex")
        if (not isinstance(txid, str) or not TXID_RE.fullmatch(txid) or
                type(vout) is not int or not (0 <= vout <= 0xffffffff) or
                not isinstance(script, str) or not P2TR_SPK_RE.fullmatch(script) or
                (txid, vout) in seen):
            raise RuntimeError("payout custody input identity is malformed/duplicate")
        seen.add((txid, vout))
        if script in policy["operator_script_pubkeys"]:
            continue
        if script not in policy["public_script_pubkeys"]:
            raise RuntimeError("payout input is outside the pinned custody range")
        public.append((txid + ":" + str(vout), item))
    if not public:
        return True
    if veld is None:
        raise RuntimeError("public C1 payout inputs require a live Veld authority")

    before = _coherent_supply_snapshot(veld)
    canonical_blocks = {before["tip"]: before["tip_hash"]}
    for outpoint, _item in public:
        status = veld.call("getbtcveldmintstatus", [outpoint])
        if (not isinstance(status, dict) or set(status) != MINT_STATUS_KEYS or
                status.get("outpoint") != outpoint or
                type(status.get("consumed")) is not bool or
                type(status.get("minted")) is not bool or
                status.get("proof_version") != "MNP1" or
                not isinstance(status.get("proof_hex"), str) or
                not (64 <= len(status["proof_hex"]) <=
                     2 * (32 + 256 * 32)) or
                not re.fullmatch(r"(?:[0-9a-f]{2})+", status["proof_hex"]) or
                not isinstance(status.get("root"), str) or
                not TXID_RE.fullmatch(status["root"]) or
                type(status.get("count")) is not int or
                not (0 <= status["count"] <= (1 << 63) - 1) or
                type(status.get("tip")) is not int or
                status["tip"] != before["tip"] or
                status.get("tip_hash") != before["tip_hash"]):
            raise RuntimeError("public C1 mint status is malformed or tip-incoherent")
        proof = bytes.fromhex(status["proof_hex"])
        if (not 32 <= len(proof) <= 32 + 256 * 32 or
                len(proof) != 32 + sum(byte.bit_count()
                                       for byte in proof[:32]) * 32):
            raise RuntimeError("public C1 mint status proof shape is non-canonical")
        if (status["consumed"] is not True or status["minted"] is not True or
                status.get("accepted_effect_kind") != "C1_MINT"):
            raise PublicC1MintNotAccepted(
                "public custody input has no accepted C1_MINT effect: " + outpoint)
        allocation_id = status.get("c1_allocation_id")
        if (not isinstance(allocation_id, str) or
                not C1_ALLOCATION_ID_RE.fullmatch(allocation_id) or
                int(allocation_id, 16) == 0):
            raise RuntimeError("accepted public C1 mint has a malformed allocation id")
        accepted = _mint_locator(status, "accepted", before["tip"])
        consumer = _mint_locator(status, "consumer", before["tip"])
        credit = _mint_locator(status, "credit", before["tip"])
        if accepted != credit:
            raise RuntimeError("accepted public C1 effect is not its exact credit locator")
        if before["tip"] - credit[1] <= MAX_REORG_DEPTH:
            raise PublicC1MintNotAccepted(
                "public C1_MINT credit has not cleared MAX_REORG_DEPTH: " +
                outpoint)
        for locator in (consumer, credit):
            height, block_hash = locator[1], locator[2]
            previous = canonical_blocks.setdefault(height, block_hash)
            if previous != block_hash:
                raise RuntimeError("public C1 locators disagree at one block height")

    for height, expected_hash in sorted(canonical_blocks.items()):
        current_hash = veld.call("getblockhash", [height])
        if current_hash != expected_hash:
            raise RuntimeError("public C1 mint carrier is no longer canonical")
    after = _coherent_supply_snapshot(veld)
    if after != before:
        raise RuntimeError("Veld tip/supply changed during public C1 payout checks")
    return True


def die(msg, code=64):
    sys.stderr.write("veld_redeemd: " + msg + "\n")
    raise SystemExit(code)


def require_consensus_reorg_depth(client):
    """Bind payout policy to the exact consensus limit of the connected node."""
    info = client.call("getblockchaininfo", [])
    if not isinstance(info, dict):
        raise RuntimeError("getblockchaininfo returned no object")
    value = info.get("max_reorg_depth")
    if isinstance(value, bool) or not isinstance(value, int):
        raise RuntimeError("getblockchaininfo omitted integer max_reorg_depth")
    if value != MAX_REORG_DEPTH:
        raise RuntimeError(
            "payout MAX_REORG_DEPTH=%d differs from connected consensus=%d" %
            (MAX_REORG_DEPTH, value))
    return value


def clears_veld_reorg_horizon(tip, burn_height):
    """True only after the burn is strictly deeper than consensus can reorg."""
    if (isinstance(tip, bool) or not isinstance(tip, int) or
            isinstance(burn_height, bool) or not isinstance(burn_height, int)):
        raise ValueError("tip and burn_height must be integers")
    return tip >= burn_height and tip - burn_height > MAX_REORG_DEPTH


def btc_to_sats(value):
    """Exact Bitcoin decimal -> integer sats (never binary float math)."""
    try:
        d = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid BTC amount")
    if not d.is_finite():
        raise ValueError("BTC amount is non-finite")
    scaled = d * SATS
    if scaled != scaled.to_integral_value():
        raise ValueError("BTC amount has sub-satoshi precision")
    sats = int(scaled)
    if sats < 0 or sats > (1 << 63) - 1:
        raise ValueError("BTC amount is outside the bounded sats range")
    return sats


def btc_str(sats):
    if (isinstance(sats, bool) or not isinstance(sats, int) or sats < 0 or
            sats > (1 << 63) - 1):
        raise ValueError("sats must be a bounded non-negative integer")
    return "%d.%08d" % (sats // SATS, sats % SATS)


def _bounded_config_int(value, field, minimum, maximum):
    if type(value) is not int or value < minimum or value > maximum:
        raise RuntimeError(
            "%s must be a JSON integer in [%d,%d]" %
            (field, minimum, maximum))
    return value


def _signer_timeout(signing_cfg):
    return _bounded_config_int(
        signing_cfg.get("signer_timeout_secs", 90),
        "payout_signing.signer_timeout_secs", 1, 300)


def _ensure_secure_directory(path, description, *, create, private):
    path = os.path.abspath(path)
    if os.path.realpath(path) != path:
        raise RuntimeError("%s must not traverse symlinks" % description)
    if create:
        os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    mode = stat.S_IMODE(info.st_mode)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            info.st_uid not in (0, os.geteuid()) or mode & 0o022 or
            (private and mode & 0o077)):
        qualifier = "owner-only " if private else "non-writable "
        raise RuntimeError(
            "%s must be a root/service-owned non-symlink %sdirectory" %
            (description, qualifier))
    return path


def _validate_private_regular(path, description):
    """Validate integrity of a SQLite/lock path without following its last link."""
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("platform lacks O_NOFOLLOW required for %s" % description)
    fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid not in (0, os.geteuid()) or
                stat.S_IMODE(info.st_mode) & 0o022):
            raise RuntimeError(
                "%s must be a root/service-owned, non-linked, non-writable regular file" %
                description)
        return info
    finally:
        os.close(fd)


def _token_from_cfg(rpc):
    token = ""
    if rpc.get("token_cmd"):
        cmd = rpc["token_cmd"]
        if not isinstance(cmd, list) or not cmd:
            raise RuntimeError("token_cmd must be a non-empty argv list")
        out = run_bounded_subprocess(
            cmd, timeout=30, stdout_max=4096, stderr_max=64 * 1024,
            description="rpc token_cmd")
        if out.returncode != 0:
            raise RuntimeError("rpc token_cmd failed: " + out.stderr.strip()[:200])
        token = out.stdout.strip()
    elif rpc.get("token_file"):
        token = read_bounded_secret_file(
            rpc["token_file"], 4096,
            "Veld RPC token").decode("ascii").strip()
    if not token:
        raise RuntimeError("Veld RPC bearer token is missing")
    return token


class VeldRpc:
    def __init__(self, cfg):
        if not isinstance(cfg, dict) or not cfg.get("url"):
            raise RuntimeError("veld_rpc.url is required")
        if not isinstance(cfg["url"], str):
            raise RuntimeError("veld_rpc.url must be a string")
        self.url = validate_backend_rpc_url(cfg["url"], "veld_rpc.url")
        self.token = _token_from_cfg(cfg)

    def call(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params or []}, separators=(",", ":")).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + self.token})
        with open_rpc_request(req, timeout=15) as resp:
            env = load_bounded_json_response(
                resp, 32 * 1024 * 1024, "Veld RPC response")
        if not isinstance(env, dict):
            raise RuntimeError("Veld RPC %s returned a non-object" % method)
        if env.get("error"):
            raise RuntimeError("Veld RPC %s: %s" % (method, env["error"]))
        result = env.get("result", env)
        if isinstance(result, str):
            try:
                result = strict_json_loads(result, "nested Veld RPC result")
            except ValueError:
                pass
        return result


class Btc:
    def __init__(self, cli_base, wallet):
        if (not isinstance(cli_base, list) or not cli_base or
                any(not isinstance(item, str) or not item or "\x00" in item
                    for item in cli_base)):
            raise RuntimeError("cli_base must be a non-empty argv string list")
        if wallet is not None and not isinstance(wallet, str):
            raise RuntimeError("wallet must be a string")
        self.base = list(cli_base) + (["-rpcwallet=%s" % wallet] if wallet else [])

    def call(self, method, *args, deadline=None):
        timeout = 120 if deadline is None else min(120, deadline - time.monotonic())
        if timeout <= 0:
            raise RuntimeError("Bitcoin command deadline reached")
        out = run_bounded_subprocess(
            self.base + [method] + [str(a) for a in args], timeout=timeout,
            stdout_max=MAX_CLI_OUTPUT_BYTES, stderr_max=1024 * 1024,
            description="bitcoin-cli %s" % method)
        if out.returncode != 0:
            raise RuntimeError("bitcoin-cli %s: %s" %
                               (method, out.stderr.strip()[:1000]))
        s = out.stdout.strip()
        try:
            return strict_json_loads(s, "bitcoin-cli %s response" % method)
        except (json.JSONDecodeError, ValueError):
            return s


def normalize_redeem(r):
    """Strict canonical representation of one accepted Veld obligation."""
    if not isinstance(r, dict):
        raise ValueError("malformed redemption record")
    try:
        for field in ("opreturn_vout", "amount_sats", "burn_height"):
            value = r.get(field, 0) if field == "opreturn_vout" else r[field]
            if type(value) is not int:
                raise ValueError("redemption integer fields must be exact JSON integers")
        for field in ("burn_txid", "redeemer", "dest_btc_addr"):
            if not isinstance(r[field], str):
                raise ValueError("redemption text fields must be strings")
        if "burn_block_hash" in r and not isinstance(r["burn_block_hash"], str):
            raise ValueError("redemption block hash must be a string")
        out = {
            "burn_txid": r["burn_txid"].lower(),
            "opreturn_vout": r.get("opreturn_vout", 0),
            "redeemer": r["redeemer"],
            "amount_sats": r["amount_sats"],
            "burn_height": r["burn_height"],
            "burn_block_hash": r.get("burn_block_hash", "").lower(),
            "dest_btc_addr": r["dest_btc_addr"].lower(),
        }
    except (KeyError, TypeError, ValueError):
        raise ValueError("malformed redemption record")
    if not TXID_RE.fullmatch(out["burn_txid"]):
        raise ValueError("redemption burn_txid is not canonical lowercase hex")
    if not (0 <= out["opreturn_vout"] <= 0xffffffff):
        raise ValueError("redemption vout is out of range")
    if (out["amount_sats"] <= 0 or out["amount_sats"] > (1 << 63) - 1 or
            out["burn_height"] < 0 or out["burn_height"] > (1 << 63) - 1):
        raise ValueError("redemption amount/height is invalid")
    if not (1 <= len(out["redeemer"]) <= 128):
        raise ValueError("redemption source identity is invalid")
    if (not HEX_RE.fullmatch(out["dest_btc_addr"]) or
            len(out["dest_btc_addr"]) > 100):
        raise ValueError("redemption destination script is not canonical hex")
    if out["burn_block_hash"] and not TXID_RE.fullmatch(out["burn_block_hash"]):
        raise ValueError("redemption block hash is not canonical hex")
    return out


def redeem_id(r):
    r = normalize_redeem(r)
    # Full 256-bit id.  The old 16-hex truncation provided only 64 collision bits.
    canonical = "%s:%d:%s:%s:%d" % (
        r["burn_txid"], r["opreturn_vout"], r["redeemer"],
        r["dest_btc_addr"], r["amount_sats"])
    return hashlib.sha256(canonical.encode()).hexdigest()


def payout_marker(r):
    r = normalize_redeem(r)
    # 5-byte domain/version + 32-byte txid + uint32 vout = 41 bytes, comfortably
    # within Bitcoin Core's standard 80-byte data-carrier policy.
    return (PAYOUT_MARKER_MAGIC + bytes.fromhex(r["burn_txid"]) +
            r["opreturn_vout"].to_bytes(4, "big"))


def payout_marker_script(r):
    data = payout_marker(r)
    return (bytes([0x6a, len(data)]) + data).hex()


def fetch_from_node(client):
    """Walk one stable, bounded-page canonical-chain snapshot.

    The node never returns a lifetime obligation array in one response.  If the
    canonical tip/finality pair changes between pages, discard the partial walk
    and restart so the caller never persists a mixed-chain snapshot.
    """
    if isinstance(client, dict):
        client = VeldRpc(client)
    page_limit = 512
    for _attempt in range(3):
        cursor = ""
        seen_cursors = {cursor}
        snapshot_tip = None
        snapshot_tip_hash = None
        snapshot_final = None
        snapshot_authority = None
        commitment = RedeemCommitment()
        pending = []
        by_outpoint = set()
        previous_order_key = None
        changed = False
        for _page_number in range(MAX_REDEEM_PAGES):
            result = client.call("getbtcveldredeems", [cursor, str(page_limit)])
            if not isinstance(result, dict):
                raise RuntimeError("getbtcveldredeems returned no object")
            tip = result.get("tip")
            if type(tip) is not int or tip < 0:
                raise RuntimeError("getbtcveldredeems tip is not an exact integer")
            tip_hash = result.get("tip_hash")
            if not isinstance(tip_hash, str) or not TXID_RE.fullmatch(tip_hash):
                raise RuntimeError(
                    "getbtcveldredeems omitted a canonical lowercase tip_hash")
            fin = result.get("final_height")
            if type(fin) is not int or fin < 0 or fin > tip:
                raise RuntimeError("getbtcveldredeems final_height is invalid")
            final_height = fin
            authority = parse_page_authority(result)
            if snapshot_tip is None:
                snapshot_tip, snapshot_tip_hash, snapshot_final = (
                    tip, tip_hash, final_height)
                snapshot_authority = authority
            elif (tip != snapshot_tip or tip_hash != snapshot_tip_hash or
                  final_height != snapshot_final or
                  authority != snapshot_authority):
                changed = True
                break
            if result.get("cursor") != cursor:
                raise RuntimeError(
                    "getbtcveldredeems did not echo the requested cursor")
            if result.get("page_limit") != page_limit:
                raise RuntimeError(
                    "getbtcveldredeems did not honor the requested page limit")
            page = result.get("redeems")
            if not isinstance(page, list) or len(page) > page_limit:
                raise RuntimeError("getbtcveldredeems returned an oversized/malformed page")
            for x in page:
                if not isinstance(x, dict):
                    raise RuntimeError("getbtcveldredeems returned a non-object row")
                if (x.get("is_redeem") is not True or
                        x.get("is_burn") is not False or
                        x.get("is_mint") is not False or
                        x.get("token") != "btcVELD"):
                    raise RuntimeError(
                        "getbtcveldredeems returned a non-canonical redeem row")
                commitment.add_rpc_row(x)
                record = normalize_redeem({
                    "burn_txid": x["txid"],
                    "opreturn_vout": x.get("vout", 0),
                    "redeemer": x["from"],
                    "amount_sats": x["amount_sats"],
                    "burn_height": x["block"],
                    "burn_block_hash": x.get("block_hash", ""),
                    "dest_btc_addr": x["memo"],
                })
                if not record["burn_block_hash"]:
                    raise RuntimeError("getbtcveldredeems item omitted canonical block_hash")
                if record["burn_height"] > tip:
                    raise RuntimeError(
                        "getbtcveldredeems returned a row above its snapshot tip")
                outpoint = (record["burn_txid"], record["opreturn_vout"])
                if outpoint in by_outpoint:
                    raise RuntimeError("getbtcveldredeems repeated a burn outpoint")
                order_key = (record["burn_height"], record["burn_txid"],
                             record["opreturn_vout"],
                             record["burn_block_hash"])
                if (previous_order_key is not None and
                        order_key <= previous_order_key):
                    raise RuntimeError(
                        "getbtcveldredeems rows are not in canonical index order")
                previous_order_key = order_key
                by_outpoint.add(outpoint)
                pending.append(record)
            has_more = result.get("has_more")
            if type(has_more) is not bool:
                raise RuntimeError("getbtcveldredeems has_more is not boolean")
            if has_more and len(page) != page_limit:
                raise RuntimeError(
                    "getbtcveldredeems advertised a short interior page")
            next_cursor = result.get("next_cursor")
            if not isinstance(next_cursor, str) or len(next_cursor) > 256:
                raise RuntimeError("getbtcveldredeems next_cursor is malformed")
            if not has_more:
                commitment.verify(*snapshot_authority)
                return snapshot_tip, snapshot_final, pending
            if (not next_cursor or
                    next_cursor == cursor or next_cursor in seen_cursors):
                raise RuntimeError("getbtcveldredeems cursor did not advance")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            raise RuntimeError("getbtcveldredeems exceeded its page safety bound")
        if not changed:
            break
    raise RuntimeError("getbtcveldredeems chain snapshot changed repeatedly")


class ObligationStore:
    """Durable, monotonic unpaid-redemption index.

    SQLite WAL + synchronous=FULL makes observation/transition commits crash safe.
    Paid truth is still independently reconstructed from Bitcoin markers, so a
    stale database restore cannot resurrect a payment.
    """
    def __init__(self, path):
        self.path = os.path.abspath(path)
        directory = os.path.dirname(self.path) or "."
        _ensure_secure_directory(directory, "redemption authority directory",
                                 create=True, private=False)
        existed = os.path.lexists(self.path)
        if existed:
            _validate_private_regular(self.path, "redemption authority database")
        self.was_created = not existed or os.path.getsize(self.path) == 0
        old_umask = os.umask(0o077)
        try:
            self.db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        finally:
            os.umask(old_umask)
        _validate_private_regular(self.path, "redemption authority database")
        os.chmod(self.path, 0o600)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("PRAGMA foreign_keys=ON")
        ok = self.db.execute("PRAGMA quick_check").fetchone()
        if not ok or ok[0] != "ok":
            raise RuntimeError("redemption authority database failed quick_check")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS obligations (
            rid TEXT PRIMARY KEY,
            burn_txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            redeemer TEXT NOT NULL,
            amount_sats INTEGER NOT NULL CHECK(amount_sats > 0),
            dest_spk TEXT NOT NULL,
            burn_height INTEGER NOT NULL,
            burn_block_hash TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN
              ('observed','broadcasting','paid','orphaned','held')),
            payout_txid TEXT,
            raw_tx_hex TEXT,
            note TEXT,
            first_seen INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            UNIQUE(burn_txid, vout)
          );
          CREATE INDEX IF NOT EXISTS obligations_unpaid
            ON obligations(status, burn_height);
          CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          );
          CREATE TABLE IF NOT EXISTS signing_proposals (
            rid TEXT PRIMARY KEY REFERENCES obligations(rid),
            raw_tx_hex TEXT NOT NULL,
            committed_at INTEGER NOT NULL
          );
          CREATE TABLE IF NOT EXISTS signing_input_commitments (
            txid TEXT NOT NULL,
            vout INTEGER NOT NULL,
            rid TEXT NOT NULL REFERENCES signing_proposals(rid),
            committed_at INTEGER NOT NULL,
            PRIMARY KEY(txid, vout)
          );
          CREATE INDEX IF NOT EXISTS signing_inputs_by_rid
            ON signing_input_commitments(rid);
        """)
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def close(self):
        self.db.close()

    def ingest(self, records, tip, final_height):
        """Commit new burns before any maturity/payout work in one FULL txn."""
        now = int(time.time())
        changed = []
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for source in records:
                r = normalize_redeem(source); rid = redeem_id(r)
                old = self.db.execute(
                    "SELECT rid,redeemer,amount_sats,dest_spk,burn_height,"
                    "burn_block_hash,status FROM obligations WHERE burn_txid=? AND vout=?",
                    (r["burn_txid"], r["opreturn_vout"])).fetchone()
                if old:
                    if old[0] != rid or old[1] != r["redeemer"] or old[2] != r["amount_sats"] or old[3] != r["dest_btc_addr"]:
                        raise RuntimeError("same burn outpoint changed redemption identity")
                    if (old[4] != r["burn_height"] or old[5] != r["burn_block_hash"]):
                        if old[6] == "paid":
                            raise RuntimeError("paid burn moved across a Veld reorg")
                        self.db.execute(
                            "UPDATE obligations SET burn_height=?,burn_block_hash=?,"
                            "status='observed',payout_txid=NULL,raw_tx_hex=NULL,"
                            "note='re-observed after reorg',updated_at=? WHERE rid=?",
                            (r["burn_height"], r["burn_block_hash"], now, rid))
                        changed.append(r)
                else:
                    self.db.execute(
                        "INSERT INTO obligations VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (rid, r["burn_txid"], r["opreturn_vout"], r["redeemer"],
                         r["amount_sats"], r["dest_btc_addr"], r["burn_height"],
                         r["burn_block_hash"], "observed", None, None, None, now, now))
                    changed.append(r)
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('last_tip',?)", (str(tip),))
            self.db.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('last_final_height',?)",
                            ("" if final_height is None else str(final_height),))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise
        return changed

    @staticmethod
    def _row(row):
        keys = ("rid", "burn_txid", "opreturn_vout", "redeemer", "amount_sats",
                "dest_btc_addr", "burn_height", "burn_block_hash", "status",
                "payout_txid", "raw_tx_hex", "note")
        return dict(zip(keys, row))

    def open_records(self):
        rows = self.db.execute(
            "SELECT rid,burn_txid,vout,redeemer,amount_sats,dest_spk,burn_height,"
            "burn_block_hash,status,payout_txid,raw_tx_hex,note FROM obligations "
            "WHERE status != 'paid' ORDER BY burn_height,burn_txid,vout").fetchall()
        return [self._row(x) for x in rows]

    def all_records(self):
        rows = self.db.execute(
            "SELECT rid,burn_txid,vout,redeemer,amount_sats,dest_spk,burn_height,"
            "burn_block_hash,status,payout_txid,raw_tx_hex,note FROM obligations "
            "ORDER BY burn_height,burn_txid,vout").fetchall()
        return [self._row(x) for x in rows]

    def get_record(self, rid):
        row = self.db.execute(
            "SELECT rid,burn_txid,vout,redeemer,amount_sats,dest_spk,burn_height,"
            "burn_block_hash,status,payout_txid,raw_tx_hex,note FROM obligations WHERE rid=?",
            (rid,)).fetchone()
        return self._row(row) if row else None

    def transition(self, rid, status, payout_txid=None, raw_tx_hex=None, note=None):
        if status not in ("observed", "broadcasting", "paid", "orphaned", "held"):
            raise ValueError("invalid obligation status")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            cur = self.db.execute("SELECT status,payout_txid,raw_tx_hex FROM obligations WHERE rid=?", (rid,)).fetchone()
            if not cur:
                raise RuntimeError("unknown redemption id")
            if cur[0] == "paid" and status != "paid":
                raise RuntimeError("paid redemption state is monotonic")
            self.db.execute(
                "UPDATE obligations SET status=?,payout_txid=COALESCE(?,payout_txid),"
                "raw_tx_hex=COALESCE(?,raw_tx_hex),note=?,updated_at=? WHERE rid=?",
                (status, payout_txid, raw_tx_hex, note, int(time.time()), rid))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise

    def signing_proposals_pending_backfill(self):
        """Return legacy raw commitments that predate global input locking."""
        return self.db.execute(
            "SELECT o.rid,o.raw_tx_hex FROM obligations o "
            "LEFT JOIN signing_proposals p ON p.rid=o.rid "
            "WHERE o.raw_tx_hex IS NOT NULL AND p.rid IS NULL "
            "ORDER BY o.rid").fetchall()

    def commit_signing_proposal(self, rid, raw_tx_hex, inputs):
        """Atomically commit a proposal and every custody input it consumes.

        This serializes one signer's local decisions. A fixed 3-of-5 overlap
        may contain only an equivocating member, so local commitments do not
        by themselves establish unique intent across independent signers.

        Commitments are intentionally never released automatically.  A partial
        signature can outlive a coordinator crash or chain reorganization, so
        recycling either its burn id or its inputs would make double payment or a
        cross-redemption conflict possible.  Exceptional recovery is manual.
        """
        if not isinstance(raw_tx_hex, str) or not re.fullmatch(r"[0-9a-fA-F]+", raw_tx_hex):
            raise ValueError("signing proposal raw transaction is malformed")
        raw_tx_hex = raw_tx_hex.lower()
        if not isinstance(inputs, (list, tuple)) or not inputs:
            raise ValueError("signing proposal inputs are missing")
        normalized_inputs = []
        for item in inputs:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError("signing proposal input is malformed")
            txid = str(item[0]).lower()
            vout = item[1]
            if type(vout) is not int:
                raise ValueError("signing proposal input is malformed")
            if not TXID_RE.fullmatch(txid) or not (0 <= vout <= 0xffffffff):
                raise ValueError("signing proposal input is malformed")
            normalized_inputs.append((txid, vout))
        if len(set(normalized_inputs)) != len(normalized_inputs):
            raise ValueError("signing proposal repeats a custody input")
        normalized_inputs = tuple(normalized_inputs)

        self.db.execute("BEGIN IMMEDIATE")
        try:
            cur = self.db.execute(
                "SELECT status,raw_tx_hex FROM obligations WHERE rid=?", (rid,)).fetchone()
            if not cur:
                raise RuntimeError("unknown redemption id")
            proposal = self.db.execute(
                "SELECT raw_tx_hex FROM signing_proposals WHERE rid=?", (rid,)).fetchone()
            if proposal and proposal[0].lower() != raw_tx_hex:
                raise RuntimeError("signer already committed to a different payout transaction")
            if cur[1] and cur[1].lower() != raw_tx_hex:
                raise RuntimeError("signer already committed to a different payout transaction")
            bound = set(self.db.execute(
                "SELECT txid,vout FROM signing_input_commitments WHERE rid=?", (rid,)).fetchall())
            if bound and bound != set(normalized_inputs):
                raise RuntimeError("signer proposal input commitment is inconsistent")
            for txid, vout in normalized_inputs:
                owner = self.db.execute(
                    "SELECT rid FROM signing_input_commitments WHERE txid=? AND vout=?",
                    (txid, vout)).fetchone()
                if owner and owner[0] != rid:
                    raise RuntimeError("custody input is committed to another redemption")
            now = int(time.time())
            self.db.execute(
                "INSERT OR IGNORE INTO signing_proposals(rid,raw_tx_hex,committed_at) "
                "VALUES(?,?,?)", (rid, raw_tx_hex, now))
            for txid, vout in normalized_inputs:
                self.db.execute(
                    "INSERT OR IGNORE INTO signing_input_commitments"
                    "(txid,vout,rid,committed_at) VALUES(?,?,?,?)",
                    (txid, vout, rid, now))
            self.db.execute(
                "UPDATE obligations SET "
                "status=CASE WHEN status='paid' THEN status ELSE 'broadcasting' END,"
                "raw_tx_hex=?,note=CASE WHEN status='paid' THEN note "
                "ELSE 'first threshold signing proposal and custody inputs committed' END,"
                "updated_at=? WHERE rid=?", (raw_tx_hex, now, rid))
            self.db.execute("COMMIT")
        except Exception:
            self.db.execute("ROLLBACK")
            raise


def verify_burn_canonical(veld, r):
    """Re-check the accepted burn's recorded height/hash before any signature."""
    if not veld:
        return True, "offline fixture"
    if not r.get("burn_block_hash"):
        return False, "accepted feed omitted burn block hash"
    try:
        current_hash = veld.call("getblockhash", [int(r["burn_height"])])
        if current_hash != r["burn_block_hash"]:
            return False, "burn block is no longer canonical"
        tx = veld.call("gettransaction", [r["burn_txid"], int(r["burn_height"])])
        if not isinstance(tx, dict) or tx.get("txid") != r["burn_txid"]:
            return False, "burn transaction is absent from its canonical block"
        if tx.get("block_hash") != r["burn_block_hash"]:
            return False, "burn transaction block hash mismatch"
        return True, "canonical"
    except Exception as e:
        return False, "canonical burn check unavailable: " + str(e)[:160]


def spk_to_address(btc, spk_hex):
    d = btc.call("decodescript", spk_hex)
    addr = None
    if isinstance(d, dict):
        seg = d.get("segwit") or {}
        addr = (d.get("address") or (d.get("addresses") or [None])[0]
                or seg.get("address") or (seg.get("addresses") or [None])[0])
    if not addr:
        raise RuntimeError("REDEEM destination script resolves to no standard address")
    return addr


def address_spk(btc, address):
    try:
        d = btc.call("getaddressinfo", address)
        spk = d.get("scriptPubKey") if isinstance(d, dict) else None
        if spk and HEX_RE.fullmatch(spk):
            return spk.lower()
    except Exception:
        pass
    # deriveaddresses isn't universally available for non-descriptor fixtures;
    # decodescript on a script is not an address->script operation, so fail closed.
    raise RuntimeError("cannot independently resolve change address scriptPubKey")


def _decoded_vout_spk(vout):
    spk = vout.get("scriptPubKey") or {}
    return str(spk.get("hex", "")).lower()


def validate_payout_tx(btc, raw_hex, r, selected, fee_sats, change_sats,
                       change_spk_hex, require_unsigned=False):
    """Exact input/output/value/fee template verification before approval."""
    d = btc.call("decoderawtransaction", raw_hex)
    if not isinstance(d, dict):
        raise RuntimeError("decoderawtransaction returned no object")
    if (type(d.get("version")) is not int or d["version"] != 2 or
            type(d.get("locktime")) is not int or d["locktime"] != 0):
        raise RuntimeError("payout transaction version/locktime policy mismatch")
    vin = d.get("vin")
    vout = d.get("vout")
    if (not isinstance(vin, list) or not vin or
            any(not isinstance(item, dict) for item in vin) or
            not isinstance(vout, list) or
            any(not isinstance(item, dict) for item in vout)):
        raise RuntimeError("payout transaction inputs/outputs are malformed")
    for txin in vin:
        if type(txin.get("sequence")) is not int or txin["sequence"] != 0xffffffff:
            raise RuntimeError("payout transaction input sequence is not final")
        if require_unsigned:
            script_sig = txin.get("scriptSig") or {}
            if (not isinstance(script_sig, dict) or
                    script_sig.get("hex", "") != "" or txin.get("txinwitness")):
                raise RuntimeError("unsigned payout contains signature/witness material")
    if any(not isinstance(x.get("txid"), str) or
           not TXID_RE.fullmatch(x["txid"]) or
           type(x.get("vout")) is not int or
           not (0 <= x["vout"] <= 0xffffffff) for x in vin):
        raise RuntimeError("payout transaction input identity is malformed")
    if (not isinstance(selected, (list, tuple)) or not selected or
            any(not isinstance(x, dict) or
                not isinstance(x.get("txid"), str) or
                not TXID_RE.fullmatch(x["txid"]) or
                type(x.get("vout")) is not int or
                not (0 <= x["vout"] <= 0xffffffff) or
                type(x.get("value_sats")) is not int or
                not (0 <= x["value_sats"] <= (1 << 63) - 1)
                for x in selected)):
        raise RuntimeError("selected payout inputs are malformed")
    got_inputs = [(x["txid"], x["vout"]) for x in vin]
    want_inputs = [(x["txid"], x["vout"]) for x in selected]
    if got_inputs != want_inputs or len(set(got_inputs)) != len(got_inputs):
        raise RuntimeError("payout transaction input set/order mismatch")
    dest_paid = 0; change_paid = 0; marker_count = 0; unknown = []
    marker_spk = payout_marker_script(r)
    for o in vout:
        spk = _decoded_vout_spk(o)
        value = btc_to_sats(o.get("value", 0))
        if spk == r["dest_btc_addr"]:
            dest_paid += value
        elif spk == marker_spk and value == 0:
            marker_count += 1
        elif change_sats >= DUST_SATS and spk == change_spk_hex:
            change_paid += value
        else:
            unknown.append((spk, value))
    if unknown or marker_count != 1:
        raise RuntimeError("payout has unknown outputs or wrong idempotency marker count")
    if dest_paid != r["amount_sats"]:
        raise RuntimeError("payout destination amount is not exact")
    want_change = change_sats if change_sats >= DUST_SATS else 0
    if change_paid != want_change:
        raise RuntimeError("payout change amount is not exact")
    total_in = sum(x["value_sats"] for x in selected)
    total_out = sum(btc_to_sats(x.get("value", 0)) for x in vout)
    if total_in - total_out != fee_sats:
        raise RuntimeError("payout fee does not match exact policy")
    return d


def build_payout(btc, r, change_addr, cfg, veld=None, custody_policy=None):
    """Build a deterministic marker-bearing payout from sorted custody UTXOs."""
    r = normalize_redeem(r)
    policy = (partition_custody_policy(custody_policy)
              if custody_policy is not None else
              load_payout_custody_policy(cfg))
    dest_addr = spk_to_address(btc, r["dest_btc_addr"])
    change_spk = address_spk(btc, change_addr)
    if change_spk == r["dest_btc_addr"]:
        raise RuntimeError("change script must differ from redemption destination")
    if change_spk not in policy["operator_script_pubkeys"]:
        raise RuntimeError("payout change must use custody descriptor index 0-999")
    minconf = cfg.get("btc_input_confirmations", 1)
    input_vbytes = cfg.get("custody_input_vbytes", 68)
    feerate = cfg.get("feerate_sat_vb", FEERATE_SAT_VB)
    if (any(type(value) is not int for value in
            (minconf, input_vbytes, feerate)) or
            not (1 <= minconf <= 1_000_000) or
            not (1 <= input_vbytes <= 1_000_000) or
            not (1 <= feerate <= 1_000_000)):
        raise RuntimeError("invalid payout confirmation/vbytes/feerate policy")
    source_utxos = btc.call("listunspent", minconf, 9999999)
    if (not isinstance(source_utxos, list) or len(source_utxos) > 10_000_000 or
            any(not isinstance(u, dict) for u in source_utxos)):
        raise RuntimeError("custody listunspent returned malformed/oversized data")
    utxos = []
    for u in source_utxos:
        if type(u.get("spendable")) is not bool or type(u.get("solvable")) is not bool:
            raise RuntimeError("custody UTXO spendability fields are malformed")
        if not u["spendable"] or not u["solvable"]:
            continue
        txid_value = u.get("txid")
        vout = u.get("vout")
        if (not isinstance(txid_value, str) or type(vout) is not int):
            raise RuntimeError("custody listunspent returned malformed outpoint")
        txid = txid_value.lower()
        if not TXID_RE.fullmatch(txid) or not (0 <= vout <= 0xffffffff):
            raise RuntimeError("custody listunspent returned malformed outpoint")
        confs = u.get("confirmations")
        if type(confs) is not int or confs < minconf or confs > (1 << 63) - 1:
            raise RuntimeError("custody node returned under-confirmed UTXO")
        script = u.get("scriptPubKey")
        if (not isinstance(script, str) or
                not P2TR_SPK_RE.fullmatch(script.lower())):
            raise RuntimeError("custody listunspent omitted a canonical P2TR script")
        script = script.lower()
        if script not in policy["script_pubkey_set"]:
            raise RuntimeError("custody wallet contains an unpinned spendable UTXO")
        utxos.append({**u, "txid": txid, "vout": vout,
                      "value_sats": btc_to_sats(u["amount"]),
                      "script_pubkey_hex": script})
    # Operator reserve is eligible without a C1 effect and is selected first.
    # Public UTXOs retain deterministic outpoint order within their partition.
    utxos.sort(key=lambda u: (
        u["script_pubkey_hex"] not in policy["operator_script_pubkeys"],
        u["txid"], u["vout"]))

    # Serialized output vbytes are exact: 8 value + compact-size + script bytes.
    dest_out_vbytes = 8 + 1 + len(bytes.fromhex(r["dest_btc_addr"]))
    change_out_vbytes = 8 + 1 + len(bytes.fromhex(change_spk))
    marker_out_vbytes = 8 + 1 + len(bytes.fromhex(payout_marker_script(r)))

    def fee_for(n_in, with_change):
        vb = 11 + n_in * input_vbytes + dest_out_vbytes + marker_out_vbytes
        if with_change:
            vb += change_out_vbytes
        return vb * feerate

    selected, total = [], 0
    for u in utxos:
        if u["script_pubkey_hex"] in policy["public_script_pubkeys"]:
            try:
                validate_payout_custody_inputs(veld, [u], policy)
            except PublicC1MintNotAccepted:
                continue
        selected.append(u); total += u["value_sats"]
        fee = fee_for(len(selected), True)
        if total >= r["amount_sats"] + fee:
            break
    if not selected:
        raise RuntimeError("insufficient custodial reserve")
    fee = fee_for(len(selected), True)
    change = total - r["amount_sats"] - fee
    if change < DUST_SATS:
        fee = fee_for(len(selected), False)
        change = total - r["amount_sats"] - fee
    if change < 0:
        raise RuntimeError("insufficient custodial reserve")
    if 0 < change < DUST_SATS:
        fee += change; change = 0             # dust is deliberately added to fee

    # Close a mint/reorg race after selection and before any proposal leaves
    # this coordinator. Independent signers repeat this check from their nodes.
    validate_payout_custody_inputs(veld, selected, policy)

    ins = [{"txid": u["txid"], "vout": u["vout"]} for u in selected]
    outs = {dest_addr: btc_str(r["amount_sats"]), "data": payout_marker(r).hex()}
    if change >= DUST_SATS:
        outs[change_addr] = btc_str(change)
    raw = btc.call("createrawtransaction", json.dumps(ins, separators=(",", ":")),
                   json.dumps(outs, separators=(",", ":")))
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]+", raw):
        raise RuntimeError("createrawtransaction returned no raw transaction")
    validate_payout_tx(btc, raw, r, selected, fee, change, change_spk,
                       require_unsigned=True)
    return raw, selected, fee, change, change_spk


def _wallet_transactions(btc):
    """Return the wallet's complete known transaction set (genesis onward)."""
    result = btc.call("listsinceblock")
    if not isinstance(result, dict):
        raise RuntimeError("listsinceblock returned no object")
    transactions = result.get("transactions")
    removed = result.get("removed")
    if (not isinstance(transactions, list) or not isinstance(removed, list) or
            len(transactions) + len(removed) > 10_000_000):
        raise RuntimeError("listsinceblock returned malformed/oversized history")
    txids = set()
    for item in transactions + removed:
        if not isinstance(item, dict) or not isinstance(item.get("txid"), str):
            raise RuntimeError("wallet history contains a malformed transaction row")
        txid = item["txid"].lower()
        if not TXID_RE.fullmatch(txid):
            raise RuntimeError("wallet history contains a malformed txid")
        txids.add(txid)
    return sorted(txids)


def find_existing_payout(btc, r):
    """Find an exact marker-bearing payout in wallet history, independent of DB."""
    marker_spk = payout_marker_script(r)
    found = []
    for txid in _wallet_transactions(btc):
        info = btc.call("gettransaction", txid)
        if (not isinstance(info, dict) or info.get("txid", txid) != txid or
                not isinstance(info.get("hex"), str) or
                not re.fullmatch(r"[0-9a-fA-F]+", info["hex"]) or
                len(info["hex"]) % 2):
            raise RuntimeError("gettransaction returned malformed wallet transaction data")
        dec = btc.call("decoderawtransaction", info["hex"])
        if not isinstance(dec, dict):
            raise RuntimeError("decoderawtransaction returned no object")
        if dec.get("txid", txid) != txid:
            raise RuntimeError("decoderawtransaction returned the wrong wallet txid")
        vouts = dec.get("vout")
        if not isinstance(vouts, list) or any(not isinstance(o, dict) for o in vouts):
            raise RuntimeError("decoded wallet transaction outputs are malformed")
        if not any(_decoded_vout_spk(o) == marker_spk for o in vouts):
            continue
        # Anyone can publish OP_RETURN bytes.  A third party could pair our marker
        # with a dust payment into the watch-only wallet to censor a redemption if
        # marker bytes alone were authoritative.  Require Bitcoin Core's wallet
        # accounting to classify this as an outgoing (custody-input) transaction.
        details = info.get("details")
        if not isinstance(details, list) or any(not isinstance(x, dict) for x in details):
            raise RuntimeError("marker-bearing wallet transaction details are malformed")
        outgoing = any(x.get("category") == "send" for x in details)
        try:
            outgoing = outgoing or ("fee" in info and Decimal(str(info["fee"])) < 0)
        except (InvalidOperation, ValueError):
            raise RuntimeError("marker-bearing wallet transaction fee is malformed")
        if not outgoing:
            continue
        marker_count = sum(1 for o in vouts
                           if _decoded_vout_spk(o) == marker_spk and btc_to_sats(o.get("value", 0)) == 0)
        paid = sum(btc_to_sats(o.get("value", 0)) for o in vouts
                   if _decoded_vout_spk(o) == r["dest_btc_addr"])
        if marker_count != 1 or paid != r["amount_sats"]:
            raise RuntimeError("Bitcoin payout marker exists with wrong amount/destination")
        confirmations = info.get("confirmations", 0)
        abandoned = info.get("abandoned", False)
        conflicts = info.get("walletconflicts", [])
        if (type(confirmations) is not int or type(abandoned) is not bool or
                not isinstance(conflicts, list) or
                any(not isinstance(value, str) or not TXID_RE.fullmatch(value)
                    for value in conflicts)):
            raise RuntimeError("marker-bearing wallet transaction status is malformed")
        found.append({"txid": txid, "hex": info["hex"],
                      "confirmations": confirmations,
                      "abandoned": abandoned,
                      "walletconflicts": conflicts})
    active = [x for x in found if x["confirmations"] >= 0 and not x["abandoned"]]
    if len({x["txid"] for x in active}) > 1:
        raise RuntimeError("multiple Bitcoin payouts carry the same burn marker")
    if found and not active:
        # A conflicted/abandoned marker transaction is an ambiguous crash/reorg
        # boundary.  Never switch to fresh inputs: the old payout could resurrect
        # on a competing chain.  An operator must resolve the conflict explicitly.
        raise RuntimeError("marker-bearing payout is conflicted/abandoned; manual hold required")
    return active[0] if active else None


def guard_fresh_authority(store, btc, tip):
    """Prevent an unsafe upgrade/bootstrap over legacy markerless payouts.

    A freshly-created authority may safely learn immature burns, and may recover
    mature *paid* burns carrying the new Bitcoin marker.  A mature burn with no
    marker is ambiguous (legacy payout vs unpaid outage), so automatic payment is
    forbidden until an operator performs an explicit migration/reconciliation.
    """
    if not store.was_created:
        return
    for r in store.open_records():
        if (clears_veld_reorg_horizon(int(tip), int(r["burn_height"])) and
                not find_existing_payout(btc, r)):
            raise RuntimeError("fresh redemption authority found a mature unmarked burn; "
                               "legacy/manual reconciliation required before payout")


def _checked_partial_psbt(value):
    if not isinstance(value, str) or not 0 < len(value) <= MAX_SIGNER_OUTPUT_BYTES:
        raise ValueError("PSBT must be a bounded string")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("PSBT encoding is invalid") from exc
    if not decoded.startswith(b"psbt\xff"):
        raise ValueError("PSBT magic is invalid")
    return value


def _has_exact_custody_witness(transaction):
    inputs = transaction.get("vin")
    if not isinstance(inputs, list) or not inputs:
        return False
    for item in inputs:
        witness = item.get("txinwitness") if isinstance(item, dict) else None
        if (not isinstance(witness, list) or len(witness) != 7 or
                any(not isinstance(value, str) for value in witness)):
            return False
        try:
            script = bytes.fromhex(witness[-2])
        except ValueError:
            return False
        if len(script) != 172 or script[-2:] != b"\x53\x9c":
            return False
        keys = []
        for slot in range(5):
            offset = slot * 34
            if (script[offset] != 32 or
                    script[offset + 33] != (0xac if slot == 0 else 0xba)):
                return False
            keys.append(script[offset + 1:offset + 33])
        if len(set(keys)) != 5 or sum(bool(value) for value in witness[:5]) != 3:
            return False
        for value in witness[:5]:
            if value and (not HEX_RE.fullmatch(value) or
                          not (len(value) == 128 or
                               (len(value) == 130 and value.endswith("01")))):
                return False
    return True


def sign_payout(btc, raw, proposal, signing_cfg):
    """Collect and validate the fixed 3-of-5 custody approval."""
    mode = signing_cfg.get("mode", "threshold_psbt")
    if mode != "threshold_psbt":
        raise RuntimeError("payout signing requires the fixed 3-of-5 threshold mode")
    threshold = signing_cfg.get("threshold", 0)
    if type(threshold) is not int:
        raise RuntimeError("threshold must be an exact JSON integer")
    signers = signing_cfg.get("signers") or []
    if threshold != 3 or not isinstance(signers, list) or len(signers) != 5:
        raise RuntimeError("threshold_psbt requires exactly 3-of-5 custody members")
    ids = [x.get("id", "") for x in signers if isinstance(x, dict)]
    if (len(ids) != len(signers) or
            any(not isinstance(x, str) or not 0 < len(x) <= 128 for x in ids) or
            len(set(ids)) != len(ids)):
        raise RuntimeError("threshold signer ids must be non-empty and unique")
    commands = [x.get("command") for x in signers]
    if any(not isinstance(x, list) or not x or
           any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in x)
           for x in commands):
        raise RuntimeError("each threshold signer command must be a non-empty argv list")
    if len({json.dumps(x) for x in commands}) != len(commands):
        raise RuntimeError("threshold signer commands must be independently configured")

    timeout = _signer_timeout(signing_cfg)
    total_timeout = _bounded_config_int(
        signing_cfg.get("collection_timeout_secs", 5 * timeout + 120),
        "payout_signing.collection_timeout_secs", 1, 1800)
    deadline = time.monotonic() + total_timeout

    def call(method, *args):
        return btc.call(method, *args, deadline=deadline)

    expected = call("decoderawtransaction", raw)
    if (not isinstance(expected, dict) or
            not isinstance(expected.get("txid"), str) or
            not TXID_RE.fullmatch(expected["txid"])):
        raise RuntimeError("Cannot bind payout to its exact unsigned transaction")
    psbt = _checked_partial_psbt(call("converttopsbt", raw, "true"))
    # Coordinator wallet is watch-only; this enriches UTXO data but cannot sign.
    enriched = call("walletprocesspsbt", psbt, "false", "ALL", "true")
    if not isinstance(enriched, dict):
        raise RuntimeError("PSBT enrichment returned no object")
    psbt = _checked_partial_psbt(enriched.get("psbt"))
    unsigned = call("decodepsbt", psbt)
    if (not isinstance(unsigned, dict) or not isinstance(unsigned.get("tx"), dict) or
            unsigned["tx"].get("txid") != expected["txid"] or
            not isinstance(unsigned.get("inputs"), list) or not unsigned["inputs"]):
        raise RuntimeError("Enriched PSBT differs from the authorized transaction")
    partials, seen = [], set()
    attempted = set()
    payload = dict(proposal); payload["action"] = "sign"
    payload["psbt"] = psbt; payload["raw_tx_hex"] = raw
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    for signer_cfg in signers:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            out = run_bounded_subprocess(
                signer_cfg["command"], input_text=encoded, timeout=min(timeout, remaining),
                stdout_max=MAX_SIGNER_OUTPUT_BYTES, stderr_max=1024 * 1024,
                description="threshold payout signer")
        except (RuntimeError, OSError, subprocess.SubprocessError):
            continue
        if out.returncode != 0:
            continue
        try:
            answer = strict_json_loads(out.stdout, "threshold signer response")
        except (ValueError, RecursionError):
            continue
        if (not isinstance(answer, dict) or set(answer) != {"signer_id", "psbt"} or
                answer.get("signer_id") != signer_cfg["id"]):
            continue
        try:
            partial = _checked_partial_psbt(answer["psbt"])
            if partial in seen:
                continue
            decoded = call("decodepsbt", partial)
            if (not isinstance(decoded, dict) or
                    not isinstance(decoded.get("tx"), dict) or
                    decoded["tx"].get("txid") != expected["txid"] or
                    not isinstance(decoded.get("inputs"), list) or
                    len(decoded["inputs"]) != len(unsigned["inputs"]) or
                    any(not isinstance(item, dict) for item in decoded["inputs"])):
                continue
        except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
            continue
        seen.add(partial)
        partials.append((answer["signer_id"], partial))
        # Test bounded subsets so an unusable earlier response cannot poison
        # every subsequent combination. Response labels never establish quorum.
        for size in range(threshold, len(partials) + 1):
            for indices in itertools.combinations(range(len(partials)), size):
                if indices in attempted or time.monotonic() >= deadline:
                    continue
                attempted.add(indices)
                try:
                    combined = _checked_partial_psbt(call("combinepsbt", json.dumps(
                        [partials[i][1] for i in indices], separators=(",", ":"))))
                    final = call("finalizepsbt", combined)
                    if (not isinstance(final, dict) or final.get("complete") is not True or
                            not isinstance(final.get("hex"), str) or
                            len(final["hex"]) > 2 * MAX_SIGNER_OUTPUT_BYTES or
                            not HEX_RE.fullmatch(final["hex"])):
                        continue
                    transaction = call("decoderawtransaction", final["hex"])
                    if (not isinstance(transaction, dict) or
                            transaction.get("txid") != expected["txid"] or
                            not _has_exact_custody_witness(transaction)):
                        continue
                    acceptance = call("testmempoolaccept", json.dumps([final["hex"]]))
                    if (not isinstance(acceptance, list) or len(acceptance) != 1 or
                            not isinstance(acceptance[0], dict) or
                            acceptance[0].get("txid") != expected["txid"] or
                            acceptance[0].get("allowed") is not True):
                        continue
                    return final["hex"], [partials[i][0] for i in indices]
                except (ValueError, RuntimeError, OSError, subprocess.SubprocessError):
                    continue
    raise RuntimeError("No usable 3-of-5 payout quorum before collection completed")


def replicate_observations(signing_cfg, records):
    """Durably fan each immature burn to independent threshold signer boxes.

    Signers acknowledge only after verifying the accepted Veld feed through their
    own node and fsyncing their own obligation DB.  Thus N-02 is not merely one
    coordinator SQLite file: a signing quorum retains the burn until payout.
    """
    if not records or signing_cfg.get("mode", "threshold_psbt") != "threshold_psbt":
        return []
    threshold = signing_cfg.get("threshold", 0)
    if type(threshold) is not int:
        raise RuntimeError("threshold must be an exact JSON integer")
    signers = signing_cfg.get("signers") or []
    if threshold < 2 or threshold > len(signers) or 2 * threshold <= len(signers):
        raise RuntimeError("invalid threshold observation replication policy")
    timeout = _signer_timeout(signing_cfg)
    # Stay comfortably below the signer's 2 MiB request cap and its 10,000-row
    # defensive list bound.  A quorum is required independently for EVERY
    # chunk; one oversized backlog can no longer make all signers refuse before
    # the coordinator gets a chance to pay and shrink it.
    batches, current, current_bytes = [], [], 0
    for source in records:
        approx = len(json.dumps(source, sort_keys=True, separators=(",", ":"))) + 2
        if approx > 1024 * 1024:
            raise RuntimeError("one redemption observation exceeds the signer request budget")
        if current and (len(current) >= 500 or current_bytes + approx > 1024 * 1024):
            batches.append(current); current = []; current_bytes = 0
        current.append(source); current_bytes += approx
    if current:
        batches.append(current)

    acked_any = set()
    for batch_no, batch in enumerate(batches, 1):
        payload = json.dumps({"action": "observe", "records": batch}, sort_keys=True,
                             separators=(",", ":"))
        ack = []
        want = sorted(redeem_id(r) for r in batch)
        for s in signers:
            cmd = s.get("command") if isinstance(s, dict) else None
            if not isinstance(cmd, list) or not cmd:
                continue
            try:
                out = run_bounded_subprocess(
                    cmd, input_text=payload, timeout=timeout,
                    stdout_max=MAX_SIGNER_OUTPUT_BYTES,
                    stderr_max=1024 * 1024,
                    description="threshold observation signer")
            except (RuntimeError, OSError, subprocess.SubprocessError):
                continue
            if out.returncode != 0:
                continue
            try:
                answer = strict_json_loads(
                    out.stdout, "threshold observation response")
            except (ValueError, RecursionError):
                continue
            if (not isinstance(answer, dict) or
                    set(answer) != {"signer_id", "observed"} or
                    answer.get("signer_id") != s.get("id") or
                    not isinstance(answer.get("observed"), list) or
                    len(answer["observed"]) != len(want) or
                    any(not isinstance(item, str) for item in answer["observed"])):
                continue
            if sorted(answer.get("observed", [])) != want:
                continue
            if answer["signer_id"] not in ack:
                ack.append(answer["signer_id"])
        if len(ack) < threshold:
            raise RuntimeError(
                "durable signer observation quorum incomplete for chunk %d/%d (%d/%d)" %
                (batch_no, len(batches), len(ack), threshold))
        acked_any.update(ack)
    return sorted(acked_any)


def require_compatible_payout_authority(peg):
    if not isinstance(peg, dict):
        raise RuntimeError("payout authority returned no object")
    if "reserve_semantics" in peg:
        raise RuntimeError(
            "reserve payout signing is unavailable: native finalized reserve "
            "authorization and safe refund retirement must be qualified first")


class RedeemCoordinator:
    def __init__(self, cfg, store, btc, veld=None):
        self.cfg = cfg; self.store = store; self.btc = btc; self.veld = veld
        self.change_addr = cfg["change_addr"]
        self.signing_cfg = cfg.get("payout_signing") or {}

    def reconcile_bitcoin_authority(self):
        """Materialize Bitcoin marker truth after loss/stale restore."""
        for r in self.store.all_records():
            existing = find_existing_payout(self.btc, r)
            if existing:
                # A previously-confirmed payout can become unconfirmed in a Bitcoin
                # reorg.  Re-broadcast the SAME raw transaction (same inputs/marker),
                # never construct a replacement payment from new reserve UTXOs.
                if existing["confirmations"] == 0:
                    try:
                        self.btc.call("sendrawtransaction", existing["hex"])
                    except Exception:
                        pass  # already-in-mempool is normal; marker remains authority
                status = "paid" if (existing["confirmations"] > 0 or r["status"] == "paid") else "broadcasting"
                self.store.transition(r["rid"], status, payout_txid=existing["txid"],
                                      raw_tx_hex=existing["hex"],
                                      note="reconciled from Bitcoin payout marker")
            elif r["status"] == "paid":
                raise RuntimeError("paid redemption marker disappeared from Bitcoin wallet history")
            if r["status"] == "paid" and self.veld:
                canonical, why = verify_burn_canonical(self.veld, r)
                if not canonical:
                    raise RuntimeError("paid Veld burn lost canonical finality: " + why)

    def process(self, tip, final_height):
        if self.veld is not None:
            require_compatible_payout_authority(self.veld.call("getpeginfo", []))
        custody_policy = load_payout_custody_policy(self.cfg)
        self.reconcile_bitcoin_authority()
        for r in self.store.open_records():
            rid = r["rid"]
            existing = find_existing_payout(self.btc, r)
            if existing:
                status = "paid" if existing["confirmations"] > 0 else "broadcasting"
                self.store.transition(rid, status, payout_txid=existing["txid"],
                                      raw_tx_hex=existing["hex"], note="Bitcoin marker found")
                print("  %s: existing Bitcoin payout %s - no re-pay" % (rid[:16], existing["txid"][:16]))
                continue
            depth = int(tip) - int(r["burn_height"])
            if depth <= K_VELD:
                print("  %s: depth %d <= MAX_REORG_DEPTH %d - HOLD" %
                      (rid[:16], depth, K_VELD))
                continue
            if final_height is None:
                self.store.transition(rid, "held", note="node omitted final_height")
                print("  %s: no final_height - HOLD" % rid[:16]); continue
            if int(r["burn_height"]) > int(final_height):
                print("  %s: burn above final_height - HOLD" % rid[:16]); continue
            canonical, why = verify_burn_canonical(self.veld, r)
            if not canonical:
                self.store.transition(rid, "orphaned", note=why)
                print("  %s: %s - NO PAY" % (rid[:16], why)); continue

            # This legacy marker recheck does not establish globally unique intent.
            # Native rolling-reserve authority is refused before this path.
            raw, selected, fee, change, change_spk = build_payout(
                self.btc, r, self.change_addr, self.cfg, veld=self.veld,
                custody_policy=custody_policy)
            if find_existing_payout(self.btc, r):
                print("  %s: payout appeared during build - NO PAY" % rid[:16]); continue
            proposal = {
                "version": 1, "redeem_id": rid,
                "burn_txid": r["burn_txid"], "opreturn_vout": r["opreturn_vout"],
                "burn_height": r["burn_height"], "burn_block_hash": r["burn_block_hash"],
                "dest_spk": r["dest_btc_addr"], "amount_sats": r["amount_sats"],
                "inputs": [{"txid": x["txid"], "vout": x["vout"],
                            "value_sats": x["value_sats"]} for x in selected],
                "fee_sats": fee, "change_sats": change, "change_spk": change_spk,
                "marker_hex": payout_marker(r).hex(),
            }
            signed_hex, approvals = sign_payout(self.btc, raw, proposal, self.signing_cfg)
            # Signatures must not alter transaction semantics.
            validate_payout_tx(self.btc, signed_hex, r, selected, fee, change, change_spk)
            # A public C1 mint can reorg while remote threshold signers are
            # running. Re-sample after quorum and immediately before the local
            # durable broadcasting transition / Bitcoin broadcast boundary.
            validate_payout_custody_inputs(
                self.veld, selected, custody_policy)
            self.store.transition(rid, "broadcasting", raw_tx_hex=signed_hex,
                                  note="threshold approvals: " + ",".join(approvals))
            if find_existing_payout(self.btc, r):
                print("  %s: payout appeared before broadcast - NO PAY" % rid[:16]); continue
            try:
                txid = self.btc.call("sendrawtransaction", signed_hex)
            except Exception:
                # A competing identical broadcast commonly returns already-known.
                existing = find_existing_payout(self.btc, r)
                if not existing:
                    raise
                txid = existing["txid"]
            self.store.transition(rid, "broadcasting", payout_txid=txid,
                                  raw_tx_hex=signed_hex, note="broadcast")
            print("  %s: BROADCAST %d sats btc_txid=%s approvals=%d fee=%d change=%d" %
                  (rid[:16], r["amount_sats"], str(txid)[:16], len(approvals), fee, change))


def _authority_path(cfg, state, live):
    path = cfg.get("authority_db")
    if not path:
        if live:
            raise RuntimeError("live redemption requires authority_db on independent durable storage")
        path = os.path.join(state, "redemption_authority.sqlite3")
    path = os.path.abspath(path)
    state = os.path.abspath(state)
    if ("allow_local_authority_dev" in cfg and
            type(cfg["allow_local_authority_dev"]) is not bool):
        raise RuntimeError("allow_local_authority_dev must be a JSON boolean")
    if (live and os.path.commonpath([path, state]) == state and
            cfg.get("allow_local_authority_dev") is not True):
        raise RuntimeError("authority_db must not reside inside state_dir in live mode")
    return path


def main():
    if len(sys.argv) < 2:
        die("usage: veld_redeemd.py <config.json>")
    cfg = load_bounded_json_file(
        os.path.abspath(sys.argv[1]), MAX_CONFIG_BYTES,
        "redemption coordinator configuration")
    if not isinstance(cfg, dict):
        die("configuration root must be an object")
    state = os.path.abspath(cfg["state_dir"])
    _ensure_secure_directory(state, "redemption state directory",
                             create=True, private=True)
    if "veld_rpc" in cfg and cfg["veld_rpc"] is not None and not isinstance(
            cfg["veld_rpc"], dict):
        raise RuntimeError("veld_rpc must be an object")
    live = isinstance(cfg.get("veld_rpc"), dict) and bool(cfg["veld_rpc"])
    authority = _authority_path(cfg, state, live)

    # Lock the independent authority, not the disposable local state directory.
    lock_path = authority + ".lock"
    _ensure_secure_directory(os.path.dirname(lock_path) or ".",
                             "redemption authority directory",
                             create=True, private=False)
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
                  getattr(os, "O_CLOEXEC", 0))
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
            lock_info.st_uid not in (0, os.geteuid()) or
            stat.S_IMODE(lock_info.st_mode) & 0o022):
        os.close(lock_fd)
        die("redemption authority lock is not a trusted regular file")
    os.fchmod(lock_fd, 0o600)
    lock_fh = os.fdopen(lock_fd, "a+")
    if fcntl:
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            die("another redemption coordinator holds the authority lock", 69)

    store = ObligationStore(authority)
    btc = Btc(cfg["cli_base"], cfg.get("wallet", "custody-coordinator"))
    veld = VeldRpc(cfg["veld_rpc"]) if live else None
    if live:
        require_consensus_reorg_depth(veld)
        tip, final_height, pending = fetch_from_node(veld)
    else:
        tip = cfg["veld_height"]
        final_height = cfg.get("veld_final_height", tip)
        if (type(tip) is not int or type(final_height) is not int or
                tip < 0 or final_height < 0 or final_height > tip):
            raise RuntimeError("offline Veld heights must be exact bounded integers")
        path = os.path.join(state, "pending_redeems.json")
        if os.path.lexists(path):
            offline = load_bounded_json_file(
                os.path.abspath(path), MAX_OFFLINE_REDEEMS_BYTES,
                "offline pending redemptions", private=True)
            if not isinstance(offline, list) or len(offline) > 100_000:
                raise RuntimeError("offline pending redemptions are malformed/oversized")
        else:
            offline = []
        pending = [normalize_redeem(x) for x in offline]
    # N-02 load-bearing ordering: commit every observed burn before printing,
    # checking depth, building a tx, or contacting any signer.
    store.ingest(pending, tip, final_height)
    guard_fresh_authority(store, btc, tip)
    # Then replicate it to a signing quorum while it is still fresh in every
    # signer's independently queried accepted-redeem feed.  Failure leaves the
    # local obligation durable and the pass fails closed before any payout.
    observation_acks = replicate_observations(cfg.get("payout_signing") or {}, store.open_records())
    print("[redeemd] tip=%d final_height=%s observed=%d durable_open=%d" %
          (tip, final_height, len(pending), len(store.open_records())))
    if observation_acks:
        print("[redeemd] signer observation quorum: " + ",".join(observation_acks))
    RedeemCoordinator(cfg, store, btc, veld).process(tip, final_height)
    print("[redeemd] done")


if __name__ == "__main__":
    main()
