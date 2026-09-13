#!/usr/bin/env python3
"""
veld_watchtowerd.py - INDEPENDENT btcVELD peg-solvency watchtower (F1).

Runs on its OWN box - co-located with neither the custody box (veld_mintd.py) nor
the signer box (veld_signerd.py). On a timer it re-derives the peg invariant from
PRIMARY sources the minter cannot fake:

    custody = confirmed BTC in the custody wallet   (this box's OWN bitcoind)
    supply  = confirmed btcVELD supply              (a veld-node: getbtcveldsupply)
    unpaid  = canonical REDEEM burns without an exact K-confirmed BTC payout
    liability = supply + unpaid
    headroom = custody - liability - margin

and then, over its OWN authenticated channel to the signer box (an SSH
forced-command that can only run veld_wt_recv.py), does one of:

  * SOLVENT  -> push a fresh, short-lived heartbeat carrying `headroom`. The
               signer requires this to sign and will not sign past headroom.
  * INSOLVENT -> push NOTHING (the last heartbeat expires -> signer pauses), and
               after N consecutive insolvent reads push a sticky HALT.

Fail-closed everywhere: if custody OR supply cannot be read this cycle, we push
NO heartbeat (so it expires and the signer pauses) and alert. The signer only
ever mints while an independent observer has, seconds ago, confirmed real BTC
backs it - so a fully compromised custody box still cannot mint unbacked btcVELD.

The liability walk is intentionally authority-free and rebuilt each cycle from
the canonical Veld redeem index plus this watchtower's complete Bitcoin-mainnet
wallet history. A REDEEM burn therefore cannot temporarily manufacture issuer
mint headroom before its exact payout leaves custody; either-chain reorgs restore
the liability automatically.

  usage: veld_watchtowerd.py <config.json> [--loop <secs>] [--once]
"""
import json
import os
import re
import shlex
import subprocess
import stat
import sys
import time
import urllib.request
from decimal import Decimal, InvalidOperation
import fcntl

import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_peg_solvency as sol  # noqa: E402
import veld_custody_binding as custody_binding  # noqa: E402
import veld_redeem_liability as redeem_liability  # noqa: E402
import veld_wt_reserve as witness_reserve  # noqa: E402
from rpc_url_policy import (load_bounded_json_file, load_bounded_json_response,
                            open_direct_https_request, open_rpc_request,
                            read_bounded_regular_file,
                            read_bounded_secret_file,
                            run_bounded_subprocess,
                            strict_json_loads,
                            validate_backend_rpc_url)  # noqa: E402

# Optional: derive custody addresses from the wallet's PUBLIC xpub descriptors so new
# deposit addresses are tracked automatically (no hand-maintained address list). Only
# public keys + a public explorer are used, so the custody box is never trusted.
try:
    from bip_utils import Bip32Slip10Secp256k1, P2PKHAddr, P2WPKHAddr
    _HAVE_BIP_UTILS = True
except Exception:
    _HAVE_BIP_UTILS = False

SATS = sol.SATS
MAX_CONFIG_BYTES = 1024 * 1024
MAX_DESCRIPTOR_BYTES = 4 * 1024 * 1024
MAX_CLI_OUTPUT_BYTES = 32 * 1024 * 1024
C5_TIP_ALERT_SECONDS = 3_600
C5_TIP_HARD_SECONDS = 7_200


_REMOTE_COMMAND_RE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]*|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+)\Z")


def _validated_alert_argv(value):
    """Return a shell-free alert command.

    An argv array is the production form.  A legacy simple string is accepted
    through shlex solely as a migration convenience; shell operators are then
    ordinary arguments and are never interpreted by a shell.
    """
    if value is None:
        return None
    if isinstance(value, str):
        try:
            argv = shlex.split(value, posix=True)
        except ValueError as exc:
            raise RuntimeError("alert_cmd has invalid quoting: %s" % exc)
    elif isinstance(value, list):
        argv = list(value)
    else:
        raise RuntimeError("alert_cmd must be null, an argv string list, or a simple string")
    if not argv or len(argv) > 64:
        raise RuntimeError("alert_cmd must contain 1..64 argv elements")
    if any(not isinstance(arg, str) or not arg or len(arg) > 4096 or
           "\x00" in arg or any(ord(ch) < 0x20 for ch in arg)
           for arg in argv):
        raise RuntimeError("alert_cmd contains an invalid argv element")
    if argv[0].startswith("-"):
        raise RuntimeError("alert_cmd executable must not begin with '-'")
    return tuple(argv)


def _validated_remote_command(value):
    """Constrain the command handed to ssh's remote shell to one literal name."""
    if not isinstance(value, str) or not _REMOTE_COMMAND_RE.fullmatch(value):
        raise RuntimeError(
            "signer.remote_cmd must be one command name or absolute path without arguments")
    return value


def _atomic_write(path, text):
    """Durable atomic publication shared by sequence and witness beat state."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                               suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            fd = -1
            out.write(text)
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
        tmp = None
        dfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def log(m):
    sys.stdout.write("%d  %s\n" % (int(time.time()), m)); sys.stdout.flush()


def warn(m):
    sys.stderr.write("%d  [WARN] %s\n" % (int(time.time()), m)); sys.stderr.flush()


def _config_int(value, field, minimum, maximum):
    if (type(value) is not int or value < minimum or value > maximum):
        raise RuntimeError(
            "%s must be a JSON integer in [%d,%d]" %
            (field, minimum, maximum))
    return value


def btc_to_sats(amount):
    """Exact BTC-decimal string -> int sats (no float; bitcoin-cli emits decimals)."""
    try:
        value = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError):
        raise ValueError("invalid BTC amount")
    if not value.is_finite():
        raise ValueError("BTC amount is non-finite")
    scaled = value * SATS
    if scaled != scaled.to_integral_value():
        raise ValueError("BTC amount has sub-satoshi precision")
    sats = int(scaled)
    if abs(sats) > (1 << 63) - 1:
        raise ValueError("BTC amount is outside the bounded sats range")
    return sats


# ------------------------------------------------------------------ RPC clients
class Btc:
    """bitcoin-cli wrapper. The watchtower's bitcoind holds the custody wallet
    WATCH-ONLY (address/descriptor import) OR we scan a fixed address set - either
    way this box never holds a spend key; it only observes confirmed custody."""
    def __init__(self, cli_base, wallet):
        if (not isinstance(cli_base, list) or not cli_base or
                any(not isinstance(item, str) or not item or "\x00" in item
                    for item in cli_base)):
            raise RuntimeError("btc.cli_base must be a non-empty argv string list")
        if wallet is not None and not isinstance(wallet, str):
            raise RuntimeError("btc.wallet must be a string")
        self.base = list(cli_base) + (["-rpcwallet=%s" % wallet] if wallet else [])

    def call(self, method, *args):
        out = run_bounded_subprocess(
            self.base + [method] + [str(a) for a in args], timeout=60,
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


class Veld:
    """veld-node JSON-RPC with a bearer token (read-only use: getbtcveldsupply)."""
    def __init__(self, url, token_file):
        self.url = validate_backend_rpc_url(url, "veld_rpc.url")
        if not isinstance(token_file, str) or not os.path.isabs(token_file):
            raise RuntimeError("veld_rpc.token_file must be an absolute path")
        try:
            self.token = read_bounded_secret_file(
                token_file, 4096, "Veld RPC token").decode("ascii").strip()
        except (OSError, UnicodeError, ValueError) as exc:
            raise RuntimeError("Veld RPC token is unavailable") from exc
        if not re.fullmatch(r"[0-9A-Fa-f]{64}", self.token):
            raise RuntimeError("Veld RPC token is malformed")

    def rpc(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1,
                           "method": method, "params": params or []}).encode()
        req = urllib.request.Request(self.url, data=body, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json"})
        with open_rpc_request(req, timeout=20) as response:
            r = load_bounded_json_response(
                response, 32 * 1024 * 1024, "Veld RPC response")
        if not isinstance(r, dict):
            raise RuntimeError("%s: malformed JSON-RPC envelope" % method)
        if r.get("error"):
            raise RuntimeError("%s: %s" % (method, r["error"]))
        result = r.get("result")
        if isinstance(result, str):
            try:
                result = strict_json_loads(
                    result, "nested Veld RPC result")
            except ValueError:
                pass
        return result


# ------------------------------------------------------------------ watchtower
class Watchtower:
    def __init__(self, cfg):
        if not isinstance(cfg, dict):
            raise RuntimeError("watchtower configuration root must be an object")
        self.cfg = cfg
        self.veld = Veld(cfg["veld_rpc"]["url"], cfg["veld_rpc"].get("token_file"))
        bc = cfg["btc"]
        # Independent BTC custody view: either a local bitcoin-cli (cli_base) OR a public
        # block-explorer API (api="mempool"|"blockstream"|<base-url>). The API mode is
        # independent of the CUSTODY box (it reads the real BTC chain), which is all the
        # threat model needs, and avoids standing up a bitcoind for the pilot.
        self.btc_api = bc.get("api", "")
        self.btc = (Btc(bc["cli_base"], bc.get("wallet", ""))
                    if (not self.btc_api and bc.get("cli_base")) else None)
        if "production" in cfg and type(cfg["production"]) is not bool:
            raise RuntimeError("production must be the JSON boolean true or false")
        self.production = cfg.get("production", False)
        self.k_confs = _config_int(
            bc.get("confirmations", 6), "btc.confirmations", 1, 1_000_000)
        self.tip_age_alert_secs = _config_int(
            bc.get("tip_age_alert_secs") if self.production else
            bc.get("tip_age_alert_secs", 10_800),
            "btc.tip_age_alert_secs", 600, 86_400)
        self.max_tip_age_secs = _config_int(
            bc.get("max_tip_age_secs") if self.production else
            bc.get("max_tip_age_secs", 21_600),
            "btc.max_tip_age_secs", 600, 86_400)
        if self.tip_age_alert_secs >= self.max_tip_age_secs:
            raise RuntimeError(
                "btc.tip_age_alert_secs must be below btc.max_tip_age_secs")
        if self.production and (
                self.tip_age_alert_secs != C5_TIP_ALERT_SECONDS or
                self.max_tip_age_secs != C5_TIP_HARD_SECONDS):
            raise RuntimeError(
                "production Bitcoin freshness must use the configured "
                "3600-second alert and 7200-second recovery-only limit")
        self.custody_addresses = cfg.get("custody_addresses") or []
        if (not isinstance(self.custody_addresses, list) or
                any(not isinstance(x, str) or not x for x in self.custody_addresses) or
                len(set(self.custody_addresses)) != len(self.custody_addresses)):
            raise RuntimeError("custody_addresses must be a unique string list")
        # Durable custody tracking: derive EVERY custody address from the wallet's
        # PUBLIC xpub descriptors (Bitcoin Core `listdescriptors` JSON) and gap-scan
        # them via the explorer, so freshly-issued deposit addresses are covered with
        # no config edits. custody_addresses stays as a dedup'd static supplement. To
        # keep API load sane, the derived address set is cached and only re-scanned
        # every custody_rescan_secs; confirmed balances are re-summed every beat.
        self.custody_desc_file = cfg.get("custody_descriptors_file", "")
        self.gap_limit = _config_int(
            cfg.get("custody_gap_limit", 20), "custody_gap_limit", 1, 100_000)
        self.rescan_secs = _config_int(
            cfg.get("custody_rescan_secs", 180),
            "custody_rescan_secs", 1, 31_536_000)
        self._branches = self._load_branches() if self.custody_desc_file else []
        self._used_cache = None
        self._scan_at = 0.0
        # Non-zero default cushion (fees / dust / timing) so a config that omits
        # margin_sats runs with a real buffer instead of exact break-even solvency.
        # 0.001 BTC; raise per expected BTC fee environment in the config.
        self.margin = _config_int(
            cfg.get("margin_sats", 100_000), "margin_sats", 0, sol.MAX_WIRE_INT)
        self.ttl = _config_int(
            cfg.get("ttl_secs", 120), "ttl_secs", 1, sol.MAX_TTL_SECS)
        self.reads_before_halt = _config_int(
            cfg.get("insolvent_reads_before_halt", 2),
            "insolvent_reads_before_halt", 1, 1_000_000)
        sc = cfg["signer"]
        self.ssh_target = sc["ssh_target"]
        self.ssh_key = sc.get("ssh_key", "")
        if self.ssh_key:
            read_bounded_secret_file(
                os.path.abspath(self.ssh_key), 1024 * 1024,
                "watchtower SSH private key")
        self.remote_cmd = _validated_remote_command(
            sc.get("remote_cmd", "veld_wt_recv"))
        # ML-DSA-sign every beat with a dedicated watchtower
        # key so the signer trusts the beat's CONTENTS, not just the file path. The
        # signer pins the matching pubkey and refuses unsigned beats in production.
        # Unsigned only if beat_keyfile is unset (dev/regtest).
        self.keygen = cfg.get("keygen") or os.path.join(HERE, "veld-keygen")
        self.beat_keyfile = sc.get("beat_keyfile", "")
        self.beat_passfile = sc.get("beat_passfile", "")
        if self.beat_keyfile:
            # The beat key is an independent solvency authority.  Do not hand a
            # linked, shared, or group-readable pathname to the signing helper;
            # validating the opened descriptor also closes a final-component
            # substitution race before each process invocation.
            self.beat_keyfile = os.path.abspath(self.beat_keyfile)
            read_bounded_secret_file(
                self.beat_keyfile, 1024 * 1024,
                "watchtower beat signing key")
        self.alert_cmd = _validated_alert_argv(cfg.get("alert_cmd"))
        self.state_dir = cfg.get("state_dir", ".")
        if not os.path.isabs(self.state_dir):
            raise RuntimeError("state_dir must be an explicit absolute path")
        if os.path.realpath(self.state_dir) != os.path.abspath(self.state_dir):
            raise RuntimeError("state_dir must not traverse symlinks")
        try:
            os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
            state_info = os.lstat(self.state_dir)
        except OSError as e:
            raise RuntimeError("state_dir unavailable: %s" % e)
        if (stat.S_ISLNK(state_info.st_mode) or
                not stat.S_ISDIR(state_info.st_mode) or
                state_info.st_uid != os.geteuid() or
                stat.S_IMODE(state_info.st_mode) != 0o700):
            raise RuntimeError(
                "state_dir must be a service-owned non-symlink mode-0700 directory")
        self.seq = self._load_seq()
        self.insolvent_streak = 0
        self.halted = False
        self.production_descriptor = None
        self.production_spks = None
        self.production_binding = None
        self.production_capacity_policy_sha256 = None
        self.compiled_spv_k_btc = None
        self.production_token_id = None
        self.last_liability_stats = None
        self.last_c5_phase = "FRESH"
        if self.production:
            self._configure_production_custody(bc, cfg)

    @staticmethod
    def _regular_json(path):
        return load_bounded_json_file(
            path, 4 * 1024 * 1024, "custody SPK manifest")

    def _configure_production_custody(self, btc_cfg, cfg):
        """Pin production custody to one local-Core watch-only descriptor wallet."""
        if self.btc_api or self.btc is None:
            raise RuntimeError("production custody observation requires local Bitcoin Core")
        if not btc_cfg.get("wallet"):
            raise RuntimeError("production requires the pinned watch-only custody wallet")
        if self.custody_addresses:
            raise RuntimeError("production forbids supplemental custody addresses")
        try:
            c1_policy, c1_policy_sha256 = (
                witness_reserve._load_signed_c1_policy(cfg))
        except SystemExit as exc:
            raise RuntimeError(
                "production signed C1 capacity policy is invalid") from exc
        range_end = cfg.get("public_descriptor_range_end")
        if (type(range_end) is not int or
                range_end != c1_policy["public_descriptor_range"][1]):
            raise RuntimeError(
                "production public_descriptor_range_end differs from signed C1 policy")
        binding = custody_binding.load_manifest(
            cfg.get("custody_spk_manifest_file"),
            cfg.get("custody_descriptor_sha256"),
            cfg.get("custody_manifest_sha256"),
            expected_range_end=range_end,
            expected_consensus_manifest_sha256=cfg.get(
                "custody_consensus_manifest_sha256"),
        )
        descriptor = binding["descriptor"]
        scripts = binding["script_pubkeys"]
        self._production_bitcoin_chain_identity()
        descriptor_info = self.btc.call("getdescriptorinfo", descriptor)
        if (not isinstance(descriptor_info, dict) or
                descriptor_info.get("hasprivatekeys") is not False or
                descriptor_info.get("isrange") is not True):
            raise RuntimeError("production custody descriptor is private or non-ranged")
        wallet_descriptors = self.btc.call("listdescriptors", "true")
        entries = (wallet_descriptors.get("descriptors")
                   if isinstance(wallet_descriptors, dict) else None)
        if (not isinstance(entries, list) or len(entries) != 1 or
                entries[0].get("desc") != descriptor or
                entries[0].get("internal") is not False or
                entries[0].get("active") is not False or
                entries[0].get("range") != binding["range"]):
            raise RuntimeError(
                "watch-only wallet must contain exactly the pinned custody descriptor")
        custody_binding.verify_core_derivation(self.btc.call, binding)
        self.production_descriptor = descriptor
        self.production_spks = set(scripts)
        self.production_binding = binding
        self.production_capacity_policy_sha256 = c1_policy_sha256

    def _production_bitcoin_chain_identity(self):
        """Return a coherent local-Core tip under the exact two-tier C5 rule."""
        if not self.production or self.btc is None:
            raise RuntimeError("production Bitcoin readiness requires local Bitcoin Core")
        info = self.btc.call("getblockchaininfo")
        if not isinstance(info, dict) or info.get("chain") != "main":
            raise RuntimeError("production custody observer Bitcoin Core is not mainnet")
        blocks = info.get("blocks")
        headers = info.get("headers")
        best = info.get("bestblockhash")
        if (info.get("initialblockdownload") is not False or
                type(blocks) is not int or type(headers) is not int or
                blocks < 1 or headers != blocks or
                not isinstance(best, str) or not sol.HASH256_RE.fullmatch(best)):
            raise RuntimeError("production custody Bitcoin Core is in IBD/header lag")
        header = self.btc.call("getblockheader", best, "true")
        header_time = header.get("time") if isinstance(header, dict) else None
        now = int(time.time())
        if (not isinstance(header, dict) or header.get("hash") != best or
                type(header_time) is not int or
                header_time > now + C5_TIP_HARD_SECONDS):
            raise RuntimeError("production custody Bitcoin Core tip is stale/incoherent")
        age = max(0, now - header_time)
        if age >= C5_TIP_HARD_SECONDS:
            if self.last_c5_phase != "RECOVERY_ONLY":
                self._alert(
                    "C5 RECOVERY_ONLY: Bitcoin tip age %ds >= %ds; "
                    "new admissions are closed while lifecycle-only solvency "
                    "heartbeats continue" %
                    (age, C5_TIP_HARD_SECONDS))
            self.last_c5_phase = "RECOVERY_ONLY"
        elif age >= C5_TIP_ALERT_SECONDS:
            if self.last_c5_phase != "ALERT":
                self._alert(
                    "C5 ALERT: Bitcoin tip age %ds >= %ds; full service "
                    "remains enabled until %ds" %
                    (age, C5_TIP_ALERT_SECONDS, C5_TIP_HARD_SECONDS))
            self.last_c5_phase = "ALERT"
        else:
            if self.last_c5_phase != "FRESH":
                log("C5 freshness restored; mint admission resumed without restart")
            self.last_c5_phase = "FRESH"
        return blocks, best

    def _verify_production_veld_identity(self):
        if getattr(self, "production", False):
            peg = self.veld.rpc("getpeginfo")
            custody_binding.verify_peg_identity(peg, self.production_binding)
            try:
                compiled_k = sol._wire_uint(
                    peg.get("spv_k_btc"), "compiled spv_k_btc", positive=True)
            except ValueError as exc:
                raise RuntimeError("getpeginfo has invalid spv_k_btc: %s" % exc)
            if compiled_k != self.k_confs:
                raise RuntimeError(
                    "watchtower Bitcoin confirmations differ from compiled spv_k_btc")
            if peg.get("token_id") != "btcVELD":
                raise RuntimeError("getpeginfo returned the wrong peg token identity")
            self.compiled_spv_k_btc = compiled_k
            self.production_token_id = peg["token_id"]
            return peg
        return None

    # --- persist the beat sequence so a restart keeps monotonic seqs -----------
    def _seq_path(self):
        return os.path.join(self.state_dir, "watchtower-seq")

    def _load_seq(self):
        path = self._seq_path()
        if not os.path.lexists(path):
            return 0
        raw = read_bounded_regular_file(
            os.path.abspath(path), 128, "watchtower sequence", private=True)
        try:
            text = raw.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise RuntimeError("watchtower sequence is not ASCII") from exc
        if not text.isdigit():
            raise RuntimeError("watchtower sequence is corrupt")
        value = int(text)
        if value < 0 or value > (1 << 63) - 1:
            raise RuntimeError("watchtower sequence is outside the bounded range")
        return value

    def _save_seq(self):
        _atomic_write(self._seq_path(), str(self.seq) + "\n")

    def _current_beat_path(self):
        return os.path.join(self.state_dir, "watchtower-current-beat.json")

    # --- primary-source reads --------------------------------------------------
    def read_supply(self):
        self._verify_production_veld_identity()
        s = self.veld.rpc("getbtcveldsupply")
        if not isinstance(s, dict):
            raise RuntimeError("getbtcveldsupply did not return a tip-bound object")
        try:
            supply = sol._wire_uint(s.get("supply_sats"), "supply_sats")
            tip = sol._wire_uint(s.get("tip"), "tip")
        except ValueError as e:
            raise RuntimeError("getbtcveldsupply returned invalid integers: %s" % e)
        tip_hash = s.get("tip_hash")
        if not isinstance(tip_hash, str) or not sol.HASH256_RE.fullmatch(tip_hash):
            raise RuntimeError("getbtcveldsupply omitted canonical lowercase tip_hash")
        return supply, tip, tip_hash

    def read_production_backing_snapshot(self, supply, tip, tip_hash):
        """Derive custody and complete backing liability from both primary chains.

        The Bitcoin tip is sampled around the wallet-history and UTXO reads.  A
        block/reorg race invalidates the pass instead of combining payout status
        and custody from different Bitcoin snapshots.  Veld pagination is bound
        to the exact coherent supply tip supplied by ``read_supply``.
        """
        if not self.production or self.btc is None:
            raise RuntimeError("production backing snapshot requires local Bitcoin Core")
        if self.compiled_spv_k_btc is None or self.production_token_id is None:
            raise RuntimeError("compiled peg confirmation policy is unavailable")
        before = self._production_bitcoin_chain_identity()
        redeems = redeem_liability.read_canonical_redeems(
            self.veld.rpc, tip, tip_hash, self.production_token_id)
        payouts = redeem_liability.scan_outgoing_payouts(self.btc.call)
        custody = self.read_custody()
        after = self._production_bitcoin_chain_identity()
        if after != before:
            raise RuntimeError(
                "Bitcoin tip changed while deriving custody/redemption liability")
        liability, outstanding_sats, outstanding_count, released_count = (
            redeem_liability.backing_liability(
                supply, redeems, payouts, self.compiled_spv_k_btc))
        self.last_liability_stats = {
            "canonical_redeems": len(redeems),
            "released_redeems": released_count,
            "outstanding_redeems": outstanding_count,
            "outstanding_redeem_sats": outstanding_sats,
            "backing_liability_sats": liability,
            "bitcoin_tip": before[0],
            "bitcoin_tip_hash": before[1],
        }
        return custody, liability

    def _api_base(self):
        a = self.btc_api
        if a in ("mempool", "mempool.space"):
            return "https://mempool.space/api"
        if a in ("blockstream", "blockstream.info"):
            return "https://blockstream.info/api"
        return a.rstrip("/")

    def _api_get(self, path):
        req = urllib.request.Request(self._api_base() + path,
                                     headers={"User-Agent": "veld-watchtowerd"})
        with open_direct_https_request(req, timeout=25) as r:
            raw = r.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("public Bitcoin explorer response exceeds 4 MiB")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuntimeError("public Bitcoin explorer response is not UTF-8") from exc

    def _read_custody_api(self):
        """Confirmed custody sats via a public BTC explorer API (mempool.space /
        blockstream). Independent of the custody box (reads the real BTC chain). Sums
        UTXOs on the custody addresses that have >= k_confs confirmations."""
        if not self.custody_addresses:
            return 0   # no custody address configured yet (pre-pilot) -> 0 sats locked
        tip = int(self._api_get("/blocks/tip/height").strip())
        total = 0
        for a in self.custody_addresses:
            for u in strict_json_loads(
                    self._api_get("/address/%s/utxo" % a),
                    "public Bitcoin explorer UTXO response"):
                st = u.get("status", {})
                if not st.get("confirmed"):
                    continue
                confs = tip - int(st.get("block_height", tip)) + 1
                if confs >= self.k_confs:
                    total += int(u["value"])
        return total

    # --- xpub-derived custody set (auto-tracks new deposit addresses) -----------
    def _load_branches(self):
        """Parse a Bitcoin Core `listdescriptors` JSON into (type, account_xpub,
        change) branches derivable from PUBLIC xpubs. Only wpkh (every deposit target)
        and pkh (legacy holdings) are summed; sh/tr hold no custody and are never a
        deposit target, so any stray funds there fall to the static supplement list."""
        if not _HAVE_BIP_UTILS:
            raise RuntimeError("custody_descriptors_file set but bip_utils is not installed")
        data = load_bounded_json_file(
            os.path.abspath(self.custody_desc_file), MAX_DESCRIPTOR_BYTES,
            "custody descriptors")
        if not isinstance(data, dict):
            raise RuntimeError("custody descriptors root must be an object")
        descriptors = data.get("descriptors", [])
        if not isinstance(descriptors, list) or len(descriptors) > 10_000:
            raise RuntimeError("custody descriptors list is malformed or oversized")
        out = []
        for e in descriptors:
            if not isinstance(e, dict):
                raise RuntimeError("custody descriptor entry is not an object")
            d = str(e.get("desc", "")).split("#")[0]
            typ = d.split("(")[0]
            if typ not in ("wpkh", "pkh") or "]" not in d:
                continue
            xpub = d.split("]")[1].split("/")[0]
            out.append((typ, xpub, 1 if e.get("internal") else 0))
        if not out:
            raise RuntimeError("no wpkh/pkh descriptors in %s" % self.custody_desc_file)
        return out

    def _encode_addr(self, typ, pub):
        if typ == "wpkh":
            return P2WPKHAddr.EncodeKey(pub.KeyObject(), hrp="bc")
        return P2PKHAddr.EncodeKey(pub.KeyObject(), net_ver=b"\x00")

    def _addr_used(self, a):
        """Has this address ever received a tx? (so an emptied address doesn't stop the
        gap scan). Reads the real BTC chain via the explorer."""
        st = strict_json_loads(
            self._api_get("/address/%s" % a),
            "public Bitcoin explorer address response")
        return int(st.get("chain_stats", {}).get("tx_count", 0)) > 0

    def _addr_confirmed_sats(self, a, tip):
        """Confirmed UTXO value (sats) at >= k_confs for one address."""
        total = 0
        for u in strict_json_loads(
                self._api_get("/address/%s/utxo" % a),
                "public Bitcoin explorer UTXO response"):
            st = u.get("status", {})
            if st.get("confirmed") and (tip - int(st.get("block_height", tip)) + 1) >= self.k_confs:
                total += int(u["value"])
        return total

    def _gap_scan_used(self):
        """Gap-limit scan of every derived branch; returns the set of USED custody
        addresses. Independent of the custody box (public xpubs + explorer only)."""
        used = set()
        for (typ, xpub, change) in self._branches:
            node = Bip32Slip10Secp256k1.FromExtendedKey(xpub)
            gap = 0
            idx = 0
            while gap < self.gap_limit:
                a = self._encode_addr(typ, node.ChildKey(change).ChildKey(idx).PublicKey())
                if self._addr_used(a):
                    used.add(a)
                    gap = 0
                else:
                    gap += 1
                idx += 1
        return used

    def _read_custody_api_derived(self):
        """Custody = confirmed BTC across ALL addresses derived from the custody xpubs,
        plus any static supplement not already derived. The (expensive) gap scan that
        discovers used addresses is cached for custody_rescan_secs; balances are summed
        fresh every call so a newly-confirmed deposit is reflected promptly."""
        now = time.monotonic()
        if self._used_cache is None or (now - self._scan_at) >= self.rescan_secs:
            self._used_cache = self._gap_scan_used()
            self._scan_at = now
        tip = int(self._api_get("/blocks/tip/height").strip())
        seen = set()
        total = 0
        for a in self._used_cache:
            seen.add(a)
            total += self._addr_confirmed_sats(a, tip)
        for a in self.custody_addresses:          # dedup'd static supplement / fallback
            if a in seen:
                continue
            total += self._addr_confirmed_sats(a, tip)
        return total

    def read_custody(self):
        """Confirmed custody BTC in sats, at >= k_confs. Independent modes:
          - api mode    : sum custody-address UTXOs via a public explorer (no bitcoind)
          - address mode: scantxoutset over a fixed custody address set (local bitcoind)
          - wallet mode : getbalance over a watch-only custody wallet"""
        if self.production:
            rows = self.btc.call("listunspent", self.k_confs, 9999999, "[]", "true")
            if not isinstance(rows, list):
                raise RuntimeError("production custody listunspent returned invalid data")
            total = 0
            for row in rows:
                if not isinstance(row, dict):
                    raise RuntimeError("production custody UTXO row is invalid")
                script = str(row.get("scriptPubKey", "")).lower()
                if script not in self.production_spks:
                    raise RuntimeError("watch-only wallet returned an unrelated custody script")
                confs = row.get("confirmations", 0)
                if type(confs) is not int or confs < 0:
                    raise RuntimeError("watch-only wallet returned malformed confirmations")
                if confs >= self.k_confs:
                    total += btc_to_sats(row.get("amount"))
            return total
        if self.btc_api:
            if self._branches:
                return self._read_custody_api_derived()
            return self._read_custody_api()
        if self.custody_addresses:
            descs = ["addr(%s)" % a for a in self.custody_addresses]
            res = self.btc.call("scantxoutset", "start", json.dumps(descs))
            if not isinstance(res, dict) or not res.get("success", False):
                raise RuntimeError("scantxoutset did not succeed")
            # scantxoutset reports total_amount for CURRENT UTXOs; enforce k_confs
            # by comparing each unspent's height to the tip.
            tip = int(self.btc.call("getblockcount"))
            total = 0
            for u in res.get("unspents", []):
                confs = tip - int(u.get("height", tip)) + 1
                if confs >= self.k_confs:
                    total += btc_to_sats(u["amount"])
            return total
        bal = self.btc.call("getbalance", "*", self.k_confs)
        return btc_to_sats(bal)

    # --- delivery to the signer box (our own authenticated channel) ------------
    def _sign_payload(self, payload):
        """Attach an ML-DSA signature (over canonical_beat_bytes) so the signer can
        verify the beat came from THIS watchtower key, not merely from something that
        reached the heartbeat path. Fail-closed: if a beat_keyfile is configured but
        signing fails, RAISE (caller then pushes nothing -> last beat expires -> signer
        pauses) rather than send an unsigned beat the signer would reject anyway."""
        if not self.beat_keyfile:
            return payload
        read_bounded_secret_file(
            self.beat_keyfile, 1024 * 1024,
            "watchtower beat signing key")
        core = sol.canonical_beat_bytes(payload)
        env = dict(os.environ)
        if self.beat_passfile:
            try:
                env["VELD_VAULT_PASSPHRASE"] = read_bounded_secret_file(
                    os.path.abspath(self.beat_passfile), 4096,
                    "watchtower beat passphrase").decode("utf-8").strip()
            except Exception as e:
                raise RuntimeError("beat passphrase read failed: %s" % e)
        with tempfile.TemporaryDirectory() as td:
            bf = os.path.join(td, "beat.bin")
            sf = os.path.join(td, "beat.sig")
            with open(bf, "wb") as f:
                f.write(core)
            r = run_bounded_subprocess(
                [self.keygen, "sign-release", self.beat_keyfile, bf, sf],
                timeout=30, stdout_max=64 * 1024, stderr_max=64 * 1024,
                description="watchtower beat signer", env=env)
            if r.returncode != 0:
                raise RuntimeError("beat signing failed: "
                                   + (r.stderr.strip()[:200] or "sign-release rc=%d" % r.returncode))
            with open(sf, "rb") as f:
                sig = f.read(1024 * 1024 + 1)
            if len(sig) > 1024 * 1024:
                raise RuntimeError("beat signature exceeds safety limit")
        out = dict(payload)
        out["sig"] = sig.hex()
        out["sig_alg"] = "mldsa65"
        return out

    def _push(self, payload):
        cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15"]
        if self.ssh_key:
            cmd += ["-i", self.ssh_key]
        cmd += [self.ssh_target, self.remote_cmd]
        out = run_bounded_subprocess(
            cmd, input_text=json.dumps(payload), timeout=45,
            stdout_max=64 * 1024, stderr_max=64 * 1024,
            description="watchtower signer push")
        if out.returncode != 0:
            raise RuntimeError("signer push failed: " + out.stderr.strip()[:200])
        return out.stdout.strip()

    def _alert(self, msg):
        warn(msg)
        if self.alert_cmd:
            try:
                # Alert hooks are intentionally operator-configurable programs,
                # but they are not entitled to consume unbounded daemon memory.
                out = run_bounded_subprocess(
                    list(self.alert_cmd), input_text=msg, timeout=20,
                    stdout_max=64 * 1024, stderr_max=64 * 1024,
                    description="watchtower alert hook")
                if out.returncode != 0:
                    warn("alert_cmd exited %d: %s" %
                         (out.returncode, (out.stderr or "").strip()[:200]))
            except Exception as e:
                warn("alert_cmd failed: %s" % e)

    def push_halt(self, reason):
        try:
            self._push(self._sign_payload(sol.build_halt_payload(reason)))
            self.halted = True
            self._alert("HALT pushed to signer: " + reason)
        except Exception as e:
            self._alert("could NOT push HALT (%s): %s" % (e, reason))

    def push_beat(self, custody, supply, backing_liability, tip, tip_hash):
        self.seq += 1
        self._save_seq()
        payload = sol.build_beat_payload(custody, supply, self.margin, tip, tip_hash,
                                         self.seq, self.ttl,
                                         backing_liability_sats=backing_liability)
        signed = self._sign_payload(payload)
        self._push(signed)
        # Publish only a beat that the signer receiver accepted. The reservation
        # witness uses this same signed core and its own local expiry, so a signer
        # cannot reserve against a beat the independent watchtower did not send.
        local = sol.stamp_heartbeat(signed, time.time())
        _atomic_write(self._current_beat_path(), json.dumps(
            local, sort_keys=True, separators=(",", ":")) + "\n")
        return payload

    # --- one monitoring cycle --------------------------------------------------
    def tick(self):
        # Fail-closed: read BOTH primary sources first; if either fails, push
        # nothing (the last heartbeat expires -> signer pauses) and alert.
        try:
            supply, tip, tip_hash = self.read_supply()
            if self.production:
                custody, backing_liability = self.read_production_backing_snapshot(
                    supply, tip, tip_hash)
            else:
                custody = self.read_custody()
                backing_liability = supply
        except Exception as e:
            self._alert("read failed (no beat this cycle, signer will pause): %s" % e)
            return "READ_FAIL"

        # Empty peg (nothing minted, nothing locked): withhold the beat so the signer
        # correctly refuses to sign (no backing to mint against), but do NOT treat it as
        # insolvency — this is the normal pre-pilot state. A real insolvency is supply>0
        # with custody < supply+margin. (Avoids a spurious sticky HALT before go-live.)
        if backing_liability == 0 and custody == 0:
            self.insolvent_streak = 0
            log("EMPTY peg (supply=0 custody=0) — no beat; signer stays paused")
            return "EMPTY"

        headroom = sol.solvency_headroom(
            custody, backing_liability, self.margin)
        if headroom < 0:
            self.insolvent_streak += 1
            self._alert("INSOLVENT read %d/%d: liability=%d (supply=%d) + margin=%d > custody=%d (no beat)"
                        % (self.insolvent_streak, self.reads_before_halt,
                           backing_liability, supply, self.margin, custody))
            if self.insolvent_streak >= self.reads_before_halt and not self.halted:
                self.push_halt("backing liability %d (supply %d) + margin %d > custody %d"
                               % (backing_liability, supply, self.margin, custody))
            return "INSOLVENT"

        self.insolvent_streak = 0
        try:
            self.push_beat(custody, supply, backing_liability, tip, tip_hash)
        except Exception as e:
            self._alert("solvent but beat push failed (signer will pause): %s" % e)
            return "PUSH_FAIL"
        log("SOLVENT beat seq=%d custody=%d supply=%d liability=%d headroom=%d tip=%d/%s"
            % (self.seq, custody, supply, backing_liability, headroom,
               tip, tip_hash[:16]))
        return "SOLVENT"


def die(msg, code=64):
    sys.stderr.write("veld_watchtowerd: " + msg + "\n")
    raise SystemExit(code)


def main():
    args = sys.argv[1:]
    if not args:
        die("usage: veld_watchtowerd.py <config.json> [--loop <secs>] [--once]")
    cfg = load_bounded_json_file(
        os.path.abspath(args[0]), MAX_CONFIG_BYTES,
        "watchtower configuration")
    if not isinstance(cfg, dict):
        die("configuration root must be an object")
    wt = Watchtower(cfg)

    lock_path = os.path.join(wt.state_dir, "watchtowerd.lock")
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
                  getattr(os, "O_CLOEXEC", 0))
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
            lock_info.st_uid != os.geteuid() or
            stat.S_IMODE(lock_info.st_mode) & 0o022):
        os.close(lock_fd)
        die("watchtower lock is not a trusted service-owned regular file", 69)
    os.fchmod(lock_fd, 0o600)
    lock_file = os.fdopen(lock_fd, "a+")
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        die("another veld_watchtowerd holds the state lock", 69)

    loop_secs = _config_int(
        cfg.get("interval_secs", 30), "interval_secs", 1, 31_536_000)
    if "--loop" in args:
        try:
            loop_secs = int(args[args.index("--loop") + 1])
        except (IndexError, ValueError):
            die("--loop requires a positive integer interval")
        if not (1 <= loop_secs <= 31_536_000):
            die("--loop interval is outside [1,31536000]")
    once = "--once" in args

    log("watchtower start: margin=%d ttl=%d interval=%d halt_after=%d signer=%s"
        % (wt.margin, wt.ttl, loop_secs, wt.reads_before_halt, wt.ssh_target))
    while True:
        try:
            wt.tick()
        except Exception as e:
            wt._alert("tick error (fail-closed, no beat): %s: %s" % (type(e).__name__, e))
        if once:
            break
        time.sleep(loop_secs)


if __name__ == "__main__":
    main()
