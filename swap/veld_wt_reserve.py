#!/usr/bin/env python3
"""Durable, shared mint-headroom reservation witness.

Run this on the independent watchtower host as an SSH forced command.  Every
active issuer signer must use this same witness.  A reservation is fsynced before
its ML-DSA receipt is returned, so signer-state rollback or two signer replicas
cannot independently reuse one heartbeat's headroom.
"""
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_peg_solvency as sol  # noqa: E402
import veld_custody_binding as custody_binding  # noqa: E402
from btcveld_c1 import allocation_commitment  # noqa: E402
from rpc_url_policy import (load_bounded_json_response, open_rpc_request,
                            read_bounded_regular_file,
                            read_bounded_secret_file,
                            run_bounded_subprocess, strict_json_loads,
                            validate_backend_rpc_url)  # noqa: E402
from swap_admission import verify_mldsa65_with_keygen  # noqa: E402

MAX_STDIN = 2 * 1024 * 1024
LEDGER_VERSION = 3
ALLOCATION_LEDGER_VERSION = 5
LEGACY_FIXTURE_ALLOCATION_LEDGER_VERSION = 1
MAX_REORG_DEPTH = 100
C5_TIP_ALERT_SECONDS = 3_600
C5_TIP_HARD_SECONDS = 7_200
C1_UINT64_MAX = (1 << 64) - 1
# The witness independently enforces the allocator's F4 launch boundary.  A
# complete-ledger checkpoint cannot authenticate keyed archive lookups after a
# row is deleted, so range expansion is not activated until that protocol is
# versioned and implemented on both hosts.
C1_ALLOCATION_ROTATION_PROTOCOL_VERSION = 0
TOMBSTONE_VERSION = 1
C1_TOMBSTONE_VERSION = 2
TOMBSTONE_KIND = "VELD_MINT_RESERVATION_TOMBSTONE"
TERMINAL_ARCHIVE_VERSION = 1
TERMINAL_ARCHIVE_KIND = "VELD_MINT_RESERVATION_TERMINAL_ARCHIVE"
TERMINAL_ARCHIVE_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
PRODUCTION_ACTIVE_RESERVATION_ROWS = 10_000
PRODUCTION_ACTIVE_RESERVATION_BYTES = 256 * 1024 * 1024
TERMINAL_LOG_HEADER = {
    "version": TOMBSTONE_VERSION,
    "kind": "VELD_MINT_RESERVATION_TOMBSTONE_LOG",
}
ZERO_HASH = "0" * 64
TOMBSTONE_IDENTITY_FIELDS = (
    "issuer_id", "witness_id", "request_id", "unsigned_tx_sha256",
    "reservation_id", "sats", "recipient", "allocation_verified",
    "allocation_request_id", "allocation_descriptor_index",
    "allocation_btc_address", "allocation_script_pubkey",
    "deposit_outpoint",
)
C1_TOMBSTONE_IDENTITY_FIELDS = TOMBSTONE_IDENTITY_FIELDS + (
    "allocation_capacity_policy_sha256",
    "allocation_public_descriptor_range_start",
    "allocation_public_descriptor_range_end",
)
_CONFIG_ARGS = [arg for arg in sys.argv[1:] if os.path.isabs(arg)]
CONFIG = os.environ.get(
    "VELD_WITNESS_CONFIG",
    _CONFIG_ARGS[0] if len(_CONFIG_ARGS) == 1
    else os.path.join(HERE, "watchtowerd.conf.json"))
ALLOCATION_REQUEST_RE = re.compile(r"[0-9a-f]{32}")
PRINCIPAL_HASH_RE = re.compile(r"[0-9a-f]{64}")
VELD_ADDR_RE = re.compile(r"V[1-9A-HJ-NP-Za-km-z]{25,49}")
BTC_OUTPOINT_RE = re.compile(r"[0-9a-f]{64}:(0|[1-9][0-9]{0,9})")
MNP1_MEMO_RE = re.compile(
    r"MNP1;([0-9a-f]{64}:(?:0|[1-9][0-9]{0,9}));([0-9a-f]+)")
MNP2_MEMO_RE = re.compile(
    r"MNP2;(0{16}[0-9a-f]{16});(5120[0-9a-f]{64});"
    r"([0-9a-f]{64});([0-9a-f]{64}:(?:0|[1-9][0-9]{0,9}))")
ALLOCATION_FIELDS = {
    "request_id", "principal_hash", "veld_address", "amount_sats",
    "descriptor_index", "btc_address", "script_pubkey", "admitted_at",
    "expires_at", "commitment_blind", "consensus_allocation_id",
}
LEGACY_ALLOCATION_FIELDS = ALLOCATION_FIELDS - {
    "admitted_at", "expires_at", "commitment_blind",
    "consensus_allocation_id",
}
REGISTERED_ALLOCATION_FIELDS = ALLOCATION_FIELDS | {
    "registered_at", "deposit_observed_at", "funded_reserved_at",
    "funding_outpoint", "minted_at",
}
LEGACY_REGISTERED_ALLOCATION_FIELDS = LEGACY_ALLOCATION_FIELDS | {"registered_at"}
C1_POLICY_KEYS = {
    "version", "record_sequence", "previous_policy_sha256",
    "pow_bits", "epoch_seconds", "global_allocations_per_epoch",
    "global_allocations_per_day", "principal_lifetime_sats",
    "destination_lifetime_sats", "consensus_custody_ceiling_sats",
    "minimum_allocation_sats",
    "unfunded_expiry_seconds", "operator_descriptor_range",
    "public_descriptor_range", "journal_max_rows", "journal_max_bytes",
    "lifecycle_reserve_percent", "bitcoin_freshness_alert_seconds",
    "bitcoin_recovery_only_seconds", "peg_unlock_required",
    "archive_ack_required", "archive_authority_id",
}
C1_POLICY_EXACT = {
    "version": 1, "pow_bits": 24, "epoch_seconds": 600,
    "global_allocations_per_epoch": 5, "global_allocations_per_day": 200,
    # These compatibility ceilings equal the absolute custody ceiling. They
    # are not independently narrower per-principal or per-destination caps.
    "principal_lifetime_sats": 1_000_000_000,
    "destination_lifetime_sats": 1_000_000_000,
    "consensus_custody_ceiling_sats": 1_000_000_000,
    "minimum_allocation_sats": 10_000,
    "unfunded_expiry_seconds": 7 * 24 * 60 * 60,
    "operator_descriptor_range": [0, 999],
    "journal_max_rows": 100_000, "journal_max_bytes": 64 * 1024 * 1024,
    "lifecycle_reserve_percent": 10,
    "bitcoin_freshness_alert_seconds": 3_600,
    "bitcoin_recovery_only_seconds": 7_200,
    "peg_unlock_required": True, "archive_ack_required": True,
}


def refuse(message):
    sys.stderr.write("veld_wt_reserve REFUSE: %s\n" % str(message)[:300])
    raise SystemExit(2)


def _c5_phase(age):
    """Classify one exact Bitcoin-tip age under the production C5 rule."""
    if type(age) is not int or age < 0:
        raise ValueError("Bitcoin tip age is malformed")
    if age >= C5_TIP_HARD_SECONDS:
        return "RECOVERY_ONLY"
    if age >= C5_TIP_ALERT_SECONDS:
        return "ALERT"
    return "FRESH"


def _require_exact_c5_btc_policy(btc):
    """Refuse production witnesses whose local config drifts from C5."""
    if (getattr(btc, "tip_age_alert_secs", None) !=
            C5_TIP_ALERT_SECONDS or
            getattr(btc, "max_tip_age_secs", None) !=
            C5_TIP_HARD_SECONDS):
        refuse("production Bitcoin freshness policy must be exactly "
               "3600-second alert / 7200-second recovery-only")


def _report_c5_phase(phase, age):
    if phase == "ALERT":
        sys.stderr.write(
            "veld_wt_reserve ALERT: Bitcoin Core tip age %ds >= %ds; "
            "full service remains enabled until %ds\n" %
            (age, C5_TIP_ALERT_SECONDS, C5_TIP_HARD_SECONDS))


def atomic_write(path, text):
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


def _secure_file(path, exact_mode=None, private=False):
    if not os.path.isabs(path):
        refuse("security-sensitive path is not absolute: %s" % path)
    try:
        info = os.lstat(path)
    except OSError as e:
        refuse("required file unavailable: %s" % e)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        refuse("security-sensitive path is not a regular non-symlink file: %s" % path)
    if info.st_uid != os.geteuid():
        refuse("security-sensitive file is not owned by service uid: %s" % path)
    mode = stat.S_IMODE(info.st_mode)
    if exact_mode is not None and mode != exact_mode:
        refuse("%s mode is %04o, expected %04o" % (path, mode, exact_mode))
    if private and mode & 0o077:
        refuse("private file has group/world permissions: %s" % path)
    return info


def _read_text_nofollow(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            refuse("opened path is not a regular file: %s" % path)
        with os.fdopen(fd, "r", encoding="utf-8") as source:
            fd = -1
            return source.read()
    finally:
        if fd >= 0:
            os.close(fd)


def _read_text_nofollow_bounded(path, max_bytes, description, exact_mode=None):
    """Read one security-state file without following links or allocating freely."""
    if type(max_bytes) is not int or max_bytes <= 0:
        refuse("%s byte limit is invalid" % description)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or
                (exact_mode is not None and
                 stat.S_IMODE(info.st_mode) != exact_mode)):
            refuse("%s ownership/type/mode is unsafe" % description)
        if info.st_size > max_bytes:
            refuse("%s exceeds configured byte limit" % description)
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            refuse("%s exceeds configured byte limit" % description)
        try:
            return raw.decode("utf-8"), info.st_size
        except UnicodeDecodeError:
            refuse("%s is not UTF-8" % description)
    finally:
        os.close(fd)


def _canonical_json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _empty_ledger():
    return {
        "version": LEDGER_VERSION,
        "terminal_count": 0,
        "terminal_head_sha256": ZERO_HASH,
        "reservations": [],
    }


def _empty_terminal_log_text():
    return json.dumps(
        TERMINAL_LOG_HEADER, sort_keys=True, separators=(",", ":")) + "\n"


class VeldRpc:
    def __init__(self, cfg):
        if not isinstance(cfg, dict) or not cfg.get("url"):
            raise ValueError("veld_rpc.url is required")
        self.url = validate_backend_rpc_url(str(cfg["url"]), "veld_rpc.url")
        token = ""
        if cfg.get("token_cmd"):
            command = cfg["token_cmd"]
            if not isinstance(command, list) or not command:
                raise ValueError("veld_rpc.token_cmd must be argv")
            run = subprocess.run(command, capture_output=True, text=True, timeout=30)
            if run.returncode != 0:
                raise RuntimeError("veld_rpc token command failed")
            token = run.stdout.strip()
        elif cfg.get("token_file"):
            token = read_bounded_secret_file(
                cfg["token_file"], 4096,
                "Veld RPC token").decode("ascii").strip()
        if not token:
            raise ValueError("veld_rpc bearer token is missing")
        self.token = token

    def call(self, method, params=None):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params or []}, separators=(",", ":")).encode()
        request = urllib.request.Request(self.url, data=body, headers={
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json",
        })
        with open_rpc_request(request, timeout=15) as response:
            envelope = load_bounded_json_response(
                response, 32 * 1024 * 1024, "Veld RPC response")
        if not isinstance(envelope, dict):
            raise RuntimeError("%s: malformed JSON-RPC envelope" % method)
        if envelope.get("error"):
            raise RuntimeError("%s: %s" % (method, envelope["error"]))
        result = envelope.get("result")
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                pass
        return result


class BitcoinCli:
    """Independent watchtower Bitcoin Core used to authorize a wrap mint."""
    def __init__(self, cfg):
        if not isinstance(cfg, dict):
            raise ValueError("production btc policy is required")
        cli = cfg.get("cli_base")
        wallet = cfg.get("wallet")
        confirmations = cfg.get("confirmations")
        tip_age_alert_secs = cfg.get("tip_age_alert_secs")
        max_tip_age_secs = cfg.get("max_tip_age_secs")
        if (not isinstance(cli, list) or not cli or len(cli) > 64 or
                any(not isinstance(item, str) or not item or "\x00" in item
                    for item in cli) or
                not isinstance(wallet, str) or not wallet or len(wallet) > 128 or
                type(confirmations) is not int or
                not 1 <= confirmations <= 1_000_000 or
                tip_age_alert_secs != C5_TIP_ALERT_SECONDS or
                max_tip_age_secs != C5_TIP_HARD_SECONDS):
            raise ValueError("production btc policy is malformed")
        self.base = list(cli) + ["-rpcwallet=%s" % wallet]
        self.confirmations = confirmations
        self.tip_age_alert_secs = tip_age_alert_secs
        self.max_tip_age_secs = max_tip_age_secs

    def call(self, method, *args):
        if (not isinstance(method, str) or
                not re.fullmatch(r"[a-z][a-z0-9]{0,63}", method)):
            raise ValueError("Bitcoin RPC method is malformed")
        run = run_bounded_subprocess(
            self.base + [method] + [str(value) for value in args],
            timeout=60, stdout_max=32 * 1024 * 1024,
            stderr_max=1024 * 1024,
            description="bitcoin-cli %s" % method)
        if run.returncode != 0:
            raise RuntimeError(
                "bitcoin-cli %s: %s" %
                (method, run.stderr.strip()[:500]))

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Bitcoin RPC repeats field %s" % key)
                result[key] = value
            return result

        try:
            return json.loads(
                run.stdout, parse_float=Decimal,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError("non-finite Bitcoin RPC number %s" % value)),
                object_pairs_hook=unique_object)
        except (ValueError, json.JSONDecodeError):
            return run.stdout.strip()


def _btc_to_sats(value):
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("Bitcoin output amount is invalid")
    scaled = amount * 100_000_000
    if (not amount.is_finite() or scaled != scaled.to_integral_value() or
            scaled < 0 or scaled > sol.MAX_WIRE_INT):
        raise ValueError("Bitcoin output amount is not exact bounded satoshis")
    return int(scaled)


def _paths(cfg):
    state_dir = cfg.get("state_dir")
    if not isinstance(state_dir, str) or not os.path.isabs(state_dir):
        refuse("witness state_dir must be an explicit absolute path")
    try:
        info = os.lstat(state_dir)
    except OSError as e:
        refuse("witness state_dir unavailable: %s" % e)
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        refuse("witness state_dir must be a service-owned non-symlink mode-0700 directory")
    return {
        "beat": os.path.join(state_dir, "watchtower-current-beat.json"),
        "ledger": os.path.join(state_dir, "mint-reservations.json"),
        "terminal": os.path.join(
            state_dir, "mint-reservation-tombstones.jsonl"),
        "allocations": os.path.join(
            state_dir, "wrap-allocation-authority.json"),
        "lock": os.path.join(state_dir, ".mint-reservations.lock"),
        "restore_halt": os.path.join(state_dir, "WITNESS_RECONCILIATION_REQUIRED"),
    }


@contextmanager
def exclusive_witness_state_lock(paths):
    """Serialize every live mutation and offline reconciliation of witness state."""
    lock_path = paths.get("lock") if isinstance(paths, dict) else None
    if not isinstance(lock_path, str) or not os.path.isabs(lock_path):
        refuse("witness lock path is invalid")
    flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_CLOEXEC", 0))
    lockfd = os.open(lock_path, flags, 0o600)
    os.fchmod(lockfd, 0o600)
    with os.fdopen(lockfd, "a+") as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            refuse("witness lock is not a service-owned owner-only regular file")
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def _require_restore_clear(paths):
    if os.path.lexists(paths["restore_halt"]):
        refuse("witness restore/reconciliation HALT is present")


def _require_production_reservation_service(cfg):
    """Fail closed unless this forced command is the launch production service.

    The module's pure helpers deliberately support non-production fixtures, but
    the externally reachable reservation/commit entry point must never inherit
    that test behavior.  Otherwise a validly signed reservation receipt could
    be issued without the independent allocation-ledger and Bitcoin-outpoint
    checks below.
    """
    if not isinstance(cfg, dict) or cfg.get("production") is not True:
        refuse("mint reservation witness requires production=true")


def _load_beat(path, now):
    _secure_file(path, exact_mode=0o600)
    try:
        beat = json.loads(_read_text_nofollow(path))
    except Exception as e:
        refuse("fresh local solvency beat unavailable: %s" % e)
    ok, why = sol.validate_heartbeat(beat)
    if not ok:
        refuse("local solvency beat invalid: " + why)
    if now > float(beat["expires_at"]):
        refuse("local solvency beat expired")
    return beat


def _reservation_ledger_policy(cfg=None, production=False):
    """Validate explicit operational storage limits for authorization state.

    These are storage/concurrency ceilings, not mint amount, fee, or eligibility
    policy.  Production has no implicit defaults: an operator must size the
    witness volume and external archive deliberately.
    """
    if (not production and
            (not isinstance(cfg, dict) or "reservation_ledger" not in cfg)):
        return {
            "max_active_rows": 999,
            "max_active_bytes": 16 * 1024 * 1024,
            "max_terminal_rows": 999,
            "max_terminal_bytes": 4 * 1024 * 1024,
            "min_free_bytes": 64 * 1024 * 1024,
            "terminal_archive_command": None,
        }
    policy = cfg.get("reservation_ledger") if isinstance(cfg, dict) else None
    fields = {
        "max_active_rows", "max_active_bytes", "max_terminal_rows",
        "max_terminal_bytes", "min_free_bytes", "terminal_archive_command",
    }
    if not isinstance(policy, dict) or set(policy) != fields:
        refuse("reservation_ledger storage policy is missing or malformed")
    bounded = (
        ("max_active_rows", 1, 1_000_000),
        ("max_active_bytes", 64 * 1024, 512 * 1024 * 1024),
        ("max_terminal_rows", 1, 1_000_000),
        ("max_terminal_bytes", 64 * 1024, 256 * 1024 * 1024),
        ("min_free_bytes", 16 * 1024 * 1024, 1024 * 1024 * 1024 * 1024),
    )
    for name, minimum, maximum in bounded:
        value = policy.get(name)
        if type(value) is not int or not minimum <= value <= maximum:
            refuse("reservation_ledger.%s is outside its safe bound" % name)
    command = policy.get("terminal_archive_command")
    if command is not None:
        if (not isinstance(command, list) or not 1 <= len(command) <= 64 or
                any(not isinstance(arg, str) or not arg or len(arg) > 4096 or
                    "\x00" in arg
                    for arg in command)):
            refuse("reservation terminal archive command must be bounded argv")
    if production and command is None:
        refuse("production requires an external/WORM terminal archive command")
    # The production witness must retain a substantial active-allocation buffer
    # beyond the public admission rate and expiry horizon. The amount on any one
    # allocation is still bounded only by live aggregate custody headroom.
    if production and (
            policy["max_active_rows"] < PRODUCTION_ACTIVE_RESERVATION_ROWS or
            policy["max_active_bytes"] <
                PRODUCTION_ACTIVE_RESERVATION_BYTES):
        refuse(
            "production reservation ledger cannot represent all 10,000 "
            "minimum-size active leases")
    if production and not os.path.isabs(command[0]):
        refuse("production terminal archive executable must be an absolute path")
    if production:
        try:
            info = os.lstat(command[0])
        except OSError as error:
            refuse("terminal archive executable is unavailable: %s" % error)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or
                info.st_uid not in (0, os.geteuid()) or
                stat.S_IMODE(info.st_mode) & 0o022 or
                not info.st_mode & stat.S_IXUSR):
            refuse("terminal archive executable ownership/mode is unsafe")
    return dict(policy)


def _validate_active_entry(entry, index):
    if not isinstance(entry, dict):
        refuse("reservation ledger entry %d is invalid" % index)
    receipt = entry.get("receipt")
    allowed_entry = {"receipt", "status", "txid", "block_height", "block_hash",
                     "signed_tx_sha256"}
    if set(entry) - allowed_entry:
        refuse("reservation ledger entry %d has unexpected fields" % index)
    ok, why = sol.validate_reservation_receipt(receipt)
    if not ok:
        refuse("reservation ledger entry %d: %s" % (index, why))
    txid = entry.get("txid")
    if txid is not None and (not isinstance(txid, str) or
                             not sol.HASH256_RE.fullmatch(txid)):
        refuse("reservation ledger txid is malformed")
    status = entry.get("status")
    # ``final`` is accepted only as bounded, offline-reconciled staging state.
    # The first live reserve archives and compacts it before admitting new work.
    if status not in ("reserved", "confirmed", "final"):
        refuse("reservation ledger status is invalid")
    if status in ("confirmed", "final"):
        if (txid is None or type(entry.get("block_height")) is not int or
                entry["block_height"] < 0 or
                not isinstance(entry.get("block_hash"), str) or
                not sol.HASH256_RE.fullmatch(entry["block_hash"])):
            refuse("confirmed/final reservation lacks canonical block evidence")
    elif "block_height" in entry or "block_hash" in entry:
        refuse("reserved entry unexpectedly carries block evidence")
    if txid is not None:
        digest = entry.get("signed_tx_sha256")
        if not isinstance(digest, str) or not sol.HASH256_RE.fullmatch(digest):
            refuse("committed reservation lacks signed transaction digest")
    elif "signed_tx_sha256" in entry:
        refuse("uncommitted reservation carries signed transaction digest")
    return entry


def _receipt_full_sha256(receipt):
    return hashlib.sha256(_canonical_json_bytes(receipt)).hexdigest()


def _tombstone_payload(record):
    payload = dict(record)
    payload.pop("record_sha256", None)
    return _canonical_json_bytes(payload)


def _validate_tombstone(record, expected_sequence, expected_previous):
    tombstone_version = record.get("version") if isinstance(record, dict) else None
    identity_fields = (C1_TOMBSTONE_IDENTITY_FIELDS
                       if tombstone_version == C1_TOMBSTONE_VERSION
                       else TOMBSTONE_IDENTITY_FIELDS)
    required = {
        "version", "kind", "sequence", "prev_record_sha256", "record_sha256",
        "txid", "signed_tx_sha256", "block_height", "block_hash",
        "finalized_at_tip", "finalized_at_tip_hash", "receipt_sha256",
        "archive_entry_sha256",
    } | set(identity_fields)
    if (not isinstance(record, dict) or set(record) != required or
            tombstone_version not in (TOMBSTONE_VERSION,
                                      C1_TOMBSTONE_VERSION) or
            record.get("kind") != TOMBSTONE_KIND or
            record.get("sequence") != expected_sequence or
            record.get("prev_record_sha256") != expected_previous):
        refuse("terminal reservation tombstone schema/chain is invalid")
    for field in ("request_id", "unsigned_tx_sha256", "reservation_id", "txid",
                  "signed_tx_sha256", "block_hash", "finalized_at_tip_hash",
                  "receipt_sha256", "archive_entry_sha256", "record_sha256"):
        if not isinstance(record.get(field), str) or not sol.HASH256_RE.fullmatch(
                record[field]):
            refuse("terminal reservation tombstone %s is malformed" % field)
    if hashlib.sha256(_tombstone_payload(record)).hexdigest() != record["record_sha256"]:
        refuse("terminal reservation tombstone digest is invalid")
    if (not isinstance(record.get("issuer_id"), str) or
            not sol.IDENTIFIER_RE.fullmatch(record["issuer_id"]) or
            not isinstance(record.get("witness_id"), str) or
            not sol.IDENTIFIER_RE.fullmatch(record["witness_id"]) or
            type(record.get("sats")) is not int or
            not 1 <= record["sats"] <= sol.MAX_WIRE_INT or
            not isinstance(record.get("recipient"), str) or
            not 1 <= len(record["recipient"]) <= 128 or
            type(record.get("allocation_verified")) is not bool):
        refuse("terminal reservation tombstone identity is invalid")
    allocation_values = (
        record.get("allocation_request_id"),
        record.get("allocation_descriptor_index"),
        record.get("allocation_btc_address"),
        record.get("allocation_script_pubkey"),
        record.get("deposit_outpoint"),
    )
    if record["allocation_verified"]:
        if tombstone_version == TOMBSTONE_VERSION:
            descriptor_allowed = (type(allocation_values[1]) is int and
                                  1 <= allocation_values[1] <= 999)
        else:
            policy_sha256 = record.get("allocation_capacity_policy_sha256")
            range_start = record.get(
                "allocation_public_descriptor_range_start")
            range_end = record.get("allocation_public_descriptor_range_end")
            descriptor_allowed = (
                isinstance(policy_sha256, str) and
                sol.HASH256_RE.fullmatch(policy_sha256) is not None and
                type(range_start) is int and range_start == 1000 and
                type(range_end) is int and 10999 <= range_end <= 1_000_000 and
                type(allocation_values[1]) is int and
                range_start <= allocation_values[1] <= range_end)
        if (not isinstance(allocation_values[0], str) or
                not ALLOCATION_REQUEST_RE.fullmatch(allocation_values[0]) or
                not descriptor_allowed or
                not isinstance(allocation_values[2], str) or
                not re.fullmatch(r"bc1p[023456789ac-hj-np-z]{58}",
                                 allocation_values[2]) or
                not isinstance(allocation_values[3], str) or
                not re.fullmatch(r"5120[0-9a-f]{64}", allocation_values[3]) or
                not isinstance(allocation_values[4], str) or
                not BTC_OUTPOINT_RE.fullmatch(allocation_values[4])):
            refuse("terminal reservation allocation identity is invalid")
    elif any(value is not None for value in allocation_values):
        refuse("non-allocation terminal reservation carries allocation identity")
    elif tombstone_version == C1_TOMBSTONE_VERSION:
        refuse("C1 terminal reservation must carry allocation identity")
    expected_rid = sol.reservation_id(
        record["issuer_id"], record["request_id"],
        record["unsigned_tx_sha256"], record["sats"], record["recipient"],
        record["deposit_outpoint"], record["allocation_request_id"])
    if record["reservation_id"] != expected_rid:
        refuse("terminal reservation identity hash is inconsistent")
    height = record.get("block_height")
    tip = record.get("finalized_at_tip")
    if (type(height) is not int or type(tip) is not int or height < 0 or
            tip < height or tip - height + 1 <= MAX_REORG_DEPTH):
        refuse("terminal reservation lacks strictly-deeper-than-reorg evidence")
    return record


def _same_tombstone_identity(receipt, tombstone):
    fields = (C1_TOMBSTONE_IDENTITY_FIELDS
              if tombstone.get("version") == C1_TOMBSTONE_VERSION
              else TOMBSTONE_IDENTITY_FIELDS)
    return (all(receipt.get(field) == tombstone.get(field)
                for field in fields) and
            _receipt_full_sha256(receipt) == tombstone["receipt_sha256"])


def _load_terminal_log(path, policy):
    if not os.path.lexists(path):
        refuse("terminal reservation tombstone log is absent; reconciliation is required")
    _secure_file(path, exact_mode=0o600)
    text, byte_count = _read_text_nofollow_bounded(
        path, policy["max_terminal_bytes"], "terminal reservation tombstone log",
        exact_mode=0o600)
    if not text.endswith("\n"):
        refuse("terminal reservation tombstone log has a partial tail")
    lines = text.splitlines()
    if not lines:
        refuse("terminal reservation tombstone log is empty")
    try:
        header = strict_json_loads(
            lines[0].encode("utf-8"), "terminal tombstone log header")
    except Exception as error:
        refuse("terminal tombstone log header is invalid: %s" % error)
    if header != TERMINAL_LOG_HEADER:
        refuse("terminal reservation tombstone log header is invalid")
    if len(lines) - 1 > policy["max_terminal_rows"]:
        refuse("terminal reservation tombstone row limit exceeded")
    records = []
    previous = ZERO_HASH
    for offset, line in enumerate(lines[1:], 1):
        if len(line.encode("utf-8")) > 16 * 1024:
            refuse("terminal reservation tombstone row exceeds size limit")
        try:
            record = strict_json_loads(
                line.encode("utf-8"), "terminal reservation tombstone")
        except Exception as error:
            refuse("terminal reservation tombstone is invalid: %s" % error)
        _validate_tombstone(record, offset, previous)
        records.append(record)
        previous = record["record_sha256"]
    return records, byte_count


def _validate_identity_uniqueness(active, terminals):
    reservation_ids = set()
    request_ids = {}
    outpoints = {}
    allocations = {}
    for kind, rows in (("active", active), ("terminal", terminals)):
        for row in rows:
            identity = row["receipt"] if kind == "active" else row
            rid = identity["reservation_id"]
            if rid in reservation_ids:
                refuse("reservation identity appears more than once")
            reservation_ids.add(rid)
            for table, field, label in (
                    (request_ids, "request_id", "request_id"),
                    (outpoints, "deposit_outpoint", "Bitcoin deposit outpoint"),
                    (allocations, "allocation_request_id", "wrap allocation")):
                value = identity.get(field)
                if value is None:
                    continue
                if value in table and table[value] != rid:
                    refuse("%s maps to multiple reservation identities" % label)
                table[value] = rid


def _load_ledger(path, cfg=None):
    # This is authorization state, not a cache.  Production initialization is
    # an explicit stopped-service ceremony documented in the runbook.  Treat a
    # deletion, partial restore, or broken symlink as a HALT condition; silently
    # recreating an empty ledger would recreate already-consumed mint headroom.
    if not os.path.lexists(path):
        refuse("mint reservation ledger is absent; reconciliation is required")
    policy = _reservation_ledger_policy(
        cfg, production=isinstance(cfg, dict) and cfg.get("production") is True)
    try:
        _secure_file(path, exact_mode=0o600)
        text, ignored_size = _read_text_nofollow_bounded(
            path, policy["max_active_bytes"], "active reservation ledger",
            exact_mode=0o600)
        ledger = strict_json_loads(text.encode("utf-8"), "active reservation ledger")
    except SystemExit:
        raise
    except Exception as e:
        refuse("reservation ledger unreadable: %s" % e)
    if (not isinstance(ledger, dict) or ledger.get("version") != LEDGER_VERSION or
            not isinstance(ledger.get("reservations"), list) or
            type(ledger.get("terminal_count")) is not int or
            not isinstance(ledger.get("terminal_head_sha256"), str) or
            not sol.HASH256_RE.fullmatch(ledger["terminal_head_sha256"]) or
            set(ledger) != {"version", "terminal_count",
                            "terminal_head_sha256", "reservations"}):
        refuse("reservation ledger schema is invalid")
    if (ledger["terminal_count"] < 0 or
            ledger["terminal_count"] > policy["max_terminal_rows"] or
            len(ledger["reservations"]) > policy["max_active_rows"]):
        refuse("reservation ledger row limit exceeded")
    seen = set()
    for n, entry in enumerate(ledger["reservations"]):
        _validate_active_entry(entry, n)
        receipt = entry["receipt"]
        rid = receipt["reservation_id"]
        if rid in seen:
            refuse("reservation ledger contains duplicate reservation_id")
        seen.add(rid)
    terminal_path = os.path.join(
        os.path.dirname(os.path.abspath(path)),
        "mint-reservation-tombstones.jsonl")
    terminals, terminal_size = _load_terminal_log(terminal_path, policy)
    count = ledger["terminal_count"]
    if len(terminals) < count:
        refuse("terminal reservation log was truncated behind its checkpoint")
    checkpoint_head = ZERO_HASH if count == 0 else terminals[count - 1]["record_sha256"]
    if ledger["terminal_head_sha256"] != checkpoint_head:
        refuse("terminal reservation checkpoint does not match its hash chain")
    # Append is fsynced before the active snapshot is atomically checkpointed.
    # A crash may therefore leave a valid suffix whose exact full receipts still
    # exist in the old active snapshot.  Accept only that one-way safe state.
    tail = terminals[count:]
    active_by_id = {entry["receipt"]["reservation_id"]: entry
                    for entry in ledger["reservations"]}
    for record in tail:
        entry = active_by_id.get(record["reservation_id"])
        if entry is None or not _same_tombstone_identity(entry["receipt"], record):
            refuse("unchckpointed terminal log tail lacks its exact active receipt")
    terminal_ids = {record["reservation_id"] for record in terminals}
    acknowledged_overlap = terminal_ids.intersection(active_by_id)
    allowed_overlap = {record["reservation_id"] for record in tail}
    if acknowledged_overlap != allowed_overlap:
        refuse("active/terminal reservation histories overlap inconsistently")
    ledger["reservations"] = [entry for entry in ledger["reservations"]
                              if entry["receipt"]["reservation_id"] not in allowed_overlap]
    ledger["terminal_count"] = len(terminals)
    ledger["terminal_head_sha256"] = (
        terminals[-1]["record_sha256"] if terminals else ZERO_HASH)
    ledger["_terminals"] = terminals
    ledger["_terminal_size"] = terminal_size
    ledger["_needs_checkpoint"] = bool(tail)
    _validate_identity_uniqueness(ledger["reservations"], terminals)
    return ledger


def _validate_c1_policy(policy):
    if not isinstance(policy, dict) or set(policy) != C1_POLICY_KEYS:
        refuse("signed C1 capacity policy schema is not exact")
    for name, expected in C1_POLICY_EXACT.items():
        if policy.get(name) != expected or type(policy.get(name)) is not type(expected):
            refuse("signed C1 policy field %s differs from owner record" % name)
    sequence = policy.get("record_sequence")
    previous = policy.get("previous_policy_sha256")
    public_range = policy.get("public_descriptor_range")
    authority = policy.get("archive_authority_id")
    if (type(sequence) is not int or not 1 <= sequence <= 0xffffffff or
            not isinstance(previous, str) or not re.fullmatch(r"[0-9a-f]{64}", previous) or
            not isinstance(public_range, list) or len(public_range) != 2 or
            public_range[0] != 1000 or type(public_range[1]) is not int or
            not 10999 <= public_range[1] <= 1_000_000 or
            not isinstance(authority, str) or not 8 <= len(authority) <= 256 or
            authority.startswith("REPLACE_")):
        refuse("signed C1 policy record/range/archive authority is malformed")
    if sequence == 1 and (previous != ZERO_HASH or public_range[1] != 10999):
        refuse("initial signed C1 record must pin range 1000-10999")
    if sequence > 1 and previous == ZERO_HASH:
        refuse("raised C1 policy record must link its predecessor")
    return dict(policy)


def _c1_public_index_allowed(index, policy):
    return (type(index) is int and isinstance(policy, dict) and
            isinstance(policy.get("public_descriptor_range"), list) and
            policy["public_descriptor_range"][0] <= index <=
            policy["public_descriptor_range"][1])


def _c1_receipt_policy_refresh_allowed(old, c1_policy, policy_sha256):
    """Allow only the signed, range-only successor to refresh an active receipt.

    The reservation id/outpoint/allocation remain unchanged and already consume
    headroom. Refreshing the witness signature to the immediately linked policy
    avoids retry liveness failure without permitting rollback, range shrinkage,
    or a second reservation.
    """
    if (not isinstance(old, dict) or
            old.get("v") != sol.C1_RESERVATION_VERSION or
            not isinstance(c1_policy, dict) or
            not isinstance(policy_sha256, str) or
            not sol.HASH256_RE.fullmatch(policy_sha256)):
        return False
    current_range = c1_policy.get("public_descriptor_range")
    old_start = old.get("allocation_public_descriptor_range_start")
    old_end = old.get("allocation_public_descriptor_range_end")
    index = old.get("allocation_descriptor_index")
    old_hash = old.get("allocation_capacity_policy_sha256")
    if (not isinstance(current_range, list) or len(current_range) != 2 or
            old_start != current_range[0] or type(old_end) is not int or
            type(index) is not int or not old_start <= index <= old_end or
            old_end > current_range[1]):
        return False
    if old_hash == policy_sha256:
        return old_end == current_range[1]
    return (old_hash == c1_policy.get("previous_policy_sha256") and
            old_end < current_range[1])


def _load_signed_c1_policy(cfg):
    if not isinstance(cfg, dict):
        refuse("witness configuration is malformed")
    names = (
        "public_capacity_config_file",
        "public_capacity_config_signature_file",
        "public_capacity_config_public_key_file",
    )
    paths = [cfg.get(name) for name in names]
    if any(not isinstance(path, str) or not os.path.isabs(path) for path in paths):
        refuse("witness signed C1 policy paths must be absolute")
    verifier = cfg.get("keygen")
    if not isinstance(verifier, str) or not os.path.isabs(verifier):
        refuse("witness C1 policy verifier path must be absolute")
    try:
        raw = read_bounded_regular_file(paths[0], 1024 * 1024,
                                        "signed C1 capacity policy")
        signature = read_bounded_regular_file(
            paths[1], 16 * 1024, "signed C1 capacity policy signature").decode(
                "ascii", "strict").strip()
        public_key = read_bounded_regular_file(
            paths[2], 16 * 1024, "signed C1 capacity policy public key").decode(
                "ascii", "strict").strip()
        if (not re.fullmatch(r"[0-9a-f]{3904}", public_key) or
                not re.fullmatch(r"[0-9a-f]{6618}", signature) or
                not verify_mldsa65_with_keygen(
                    public_key, raw, signature, verifier)):
            refuse("signed C1 capacity policy signature is invalid")
        policy = strict_json_loads(raw, "signed C1 capacity policy")
    except SystemExit:
        raise
    except Exception as exc:
        refuse("signed C1 capacity policy cannot be loaded: %s" % exc)
    return _validate_c1_policy(policy), hashlib.sha256(raw).hexdigest()


def _allocation_policy(cfg, *, require_c1=False):
    policy = cfg.get("wrap_allocation_authority") if isinstance(cfg, dict) else None
    if (not require_c1 and isinstance(policy, dict) and set(policy) == {
            "version", "initial_descriptor_index",
            "allow_initial_ledger_creation"} and
            policy.get("version") == 1 and
            policy.get("initial_descriptor_index") == 1 and
            type(policy.get("allow_initial_ledger_creation")) is bool):
        return dict(policy)
    if (not isinstance(policy, dict) or set(policy) != {
            "version", "initial_descriptor_index",
            "allow_initial_ledger_creation", "checkpoint_command"} or
            policy.get("version") != 2 or
            policy.get("initial_descriptor_index") != 1000 or
            type(policy.get("allow_initial_ledger_creation")) is not bool or
            not isinstance(policy.get("checkpoint_command"), list) or
            not policy["checkpoint_command"] or
            any(not isinstance(value, str) or not value or "\x00" in value
                for value in policy["checkpoint_command"]) or
            not os.path.isabs(policy["checkpoint_command"][0])):
        refuse("wrap_allocation_authority policy is missing or malformed")
    return dict(policy)


def _require_supported_allocation_range(c1_policy):
    """Fail closed on a successor range until authenticated F4 rotation exists."""
    validated = _validate_c1_policy(c1_policy)
    if (C1_ALLOCATION_ROTATION_PROTOCOL_VERSION != 1 and
            validated["public_descriptor_range"][1] != 10999):
        refuse(
            "C1_RANGE_ROTATION_REQUIRED: signed descriptor range expansion "
            "cannot activate until the audited F4 WORM archive/index "
            "protocol is implemented")
    return validated


def _empty_allocation_ledger(cfg, c1_policy=None, policy_sha256=None):
    policy = _allocation_policy(cfg, require_c1=c1_policy is not None)
    if c1_policy is None:
        return {
            "version": LEGACY_FIXTURE_ALLOCATION_LEDGER_VERSION,
            "initial_descriptor_index": policy["initial_descriptor_index"],
            "allocations": [],
        }
    return {
        "version": ALLOCATION_LEDGER_VERSION,
        "initial_descriptor_index": policy["initial_descriptor_index"],
        "capacity_policy_sha256": policy_sha256,
        "capacity_policy_sequence": c1_policy["record_sequence"],
        "public_descriptor_range_end": c1_policy["public_descriptor_range"][1],
        "last_consensus_sequence": 0,
        "allocations": [],
        "events": [],
    }


def _require_allocation_service_mode(policy, initialize):
    """Keep one-shot creation authority disjoint from normal forced-command use."""
    if not isinstance(policy, dict):
        refuse("wrap allocation authority policy is unavailable")
    armed = policy.get("allow_initial_ledger_creation")
    if initialize:
        if armed is not True:
            refuse("one-shot allocation-ledger initialization is not approved")
    elif armed is not False:
        refuse("allocation service refuses while initialization authority is armed")


def _validate_registered_allocation(record, binding, c1_policy=None):
    fields = (LEGACY_REGISTERED_ALLOCATION_FIELDS if c1_policy is None
              else REGISTERED_ALLOCATION_FIELDS)
    if not isinstance(record, dict) or set(record) != fields:
        refuse("registered wrap allocation schema is invalid")
    request_id = record.get("request_id")
    principal = record.get("principal_hash")
    recipient = record.get("veld_address")
    sats = record.get("amount_sats")
    index = record.get("descriptor_index")
    address = record.get("btc_address")
    script = record.get("script_pubkey")
    commitment_blind = record.get("commitment_blind")
    consensus_allocation_id = record.get("consensus_allocation_id")
    funding_outpoint = record.get("funding_outpoint")
    registered_at = record.get("registered_at")
    index_start = 1 if c1_policy is None else c1_policy["public_descriptor_range"][0]
    index_end = 999 if c1_policy is None else c1_policy["public_descriptor_range"][1]
    expected_range = [0, index_end]
    if (not isinstance(request_id, str) or
            not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
            not isinstance(principal, str) or
            not PRINCIPAL_HASH_RE.fullmatch(principal) or
            not isinstance(recipient, str) or
            not VELD_ADDR_RE.fullmatch(recipient) or
            type(sats) is not int or not 1 <= sats <= sol.MAX_WIRE_INT or
            type(index) is not int or not index_start <= index <= index_end or
            (c1_policy is not None and
             not _c1_public_index_allowed(index, c1_policy)) or
            not isinstance(address, str) or
            not re.fullmatch(r"bc1p[023456789ac-hj-np-z]{58}", address) or
            not isinstance(script, str) or
            not re.fullmatch(r"5120[0-9a-f]{64}", script) or
            type(registered_at) is not int or
            not 0 <= registered_at <= sol.MAX_WIRE_INT or
            not isinstance(binding, dict) or binding.get("range") != expected_range or
            not isinstance(binding.get("script_pubkeys"), tuple) or
            script != binding["script_pubkeys"][index]):
        refuse("registered wrap allocation fields are invalid")
    if c1_policy is not None and (
            sats < c1_policy["minimum_allocation_sats"] or
            not isinstance(commitment_blind, str) or
            not re.fullmatch(r"[0-9a-f]{64}", commitment_blind) or
            int(commitment_blind, 16) == 0 or
            not isinstance(consensus_allocation_id, str) or
            not ALLOCATION_REQUEST_RE.fullmatch(consensus_allocation_id) or
            int(consensus_allocation_id, 16) == 0 or
            type(record.get("admitted_at")) is not int or
            type(record.get("expires_at")) is not int or
            record["expires_at"] - record["admitted_at"] !=
            c1_policy["unfunded_expiry_seconds"] or
            (record.get("deposit_observed_at") is not None and
             (type(record["deposit_observed_at"]) is not int or
              record["deposit_observed_at"] < record["admitted_at"])) or
            (record.get("funded_reserved_at") is not None and
             (type(record["funded_reserved_at"]) is not int or
              record["deposit_observed_at"] is None or
              record["funded_reserved_at"] <
                record["deposit_observed_at"] or
              not isinstance(funding_outpoint, str) or
              not BTC_OUTPOINT_RE.fullmatch(funding_outpoint) or
              int(funding_outpoint.rsplit(":", 1)[1]) > 0xffffffff)) or
            (record.get("funded_reserved_at") is None and
             funding_outpoint is not None) or
            (record.get("minted_at") is not None and
             (type(record["minted_at"]) is not int or
              record["funded_reserved_at"] is None or
              record["minted_at"] < record["funded_reserved_at"]))):
        refuse("registered wrap allocation C1 lifecycle is invalid")
    try:
        derived_script = custody_binding._bech32m_spk(address)
    except Exception:
        refuse("registered wrap allocation address is not canonical P2TR")
    if derived_script != script:
        refuse("registered wrap allocation address/script mismatch")
    return record


def _load_allocation_ledger(path, cfg, binding, c1_policy=None,
                            policy_sha256=None):
    if not os.path.lexists(path):
        refuse("wrap allocation authority ledger is absent")
    try:
        info = _secure_file(path, exact_mode=0o600)
        if info.st_size > 64 * 1024 * 1024:
            refuse("wrap allocation authority ledger exceeds 64 MiB")
        ledger = strict_json_loads(
            _read_text_nofollow(path), "wrap allocation authority ledger")
    except Exception as e:
        refuse("wrap allocation authority ledger unreadable: %s" % e)
    authority = _allocation_policy(cfg, require_c1=c1_policy is not None)
    legacy = authority.get("version") == 1
    if not legacy and c1_policy is None:
        c1_policy, policy_sha256 = _load_signed_c1_policy(cfg)
    if not legacy:
        _require_supported_allocation_range(c1_policy)
    keys = {"version", "initial_descriptor_index", "allocations"}
    version = LEGACY_FIXTURE_ALLOCATION_LEDGER_VERSION
    policy_advanced = False
    if not legacy:
        keys |= {"capacity_policy_sha256", "capacity_policy_sequence",
                 "public_descriptor_range_end", "last_consensus_sequence",
                 "events"}
        version = ALLOCATION_LEDGER_VERSION
    if (not isinstance(ledger, dict) or set(ledger) != keys or
            ledger.get("version") != version or
            ledger.get("initial_descriptor_index") !=
            authority["initial_descriptor_index"] or
            not isinstance(ledger.get("allocations"), list) or
            len(ledger["allocations"]) > (999 if legacy else 100_000)):
        refuse("wrap allocation authority ledger schema is invalid")
    if not legacy:
        stored_sequence = ledger.get("capacity_policy_sequence")
        stored_hash = ledger.get("capacity_policy_sha256")
        stored_end = ledger.get("public_descriptor_range_end")
        last_consensus_sequence = ledger.get("last_consensus_sequence")
        events = ledger.get("events")
        if (type(stored_sequence) is not int or stored_sequence < 1 or
                not isinstance(stored_hash, str) or
                not re.fullmatch(r"[0-9a-f]{64}", stored_hash) or
                type(stored_end) is not int or stored_end < 10999 or
                type(last_consensus_sequence) is not int or
                not 0 <= last_consensus_sequence <= C1_UINT64_MAX or
                not isinstance(events, list) or
                len(ledger["allocations"]) + len(events) >
                c1_policy["journal_max_rows"]):
            refuse("wrap allocation authority C1 ledger is malformed")
        if stored_sequence == c1_policy["record_sequence"]:
            if stored_hash != policy_sha256 or stored_end != c1_policy[
                    "public_descriptor_range"][1]:
                refuse("allocation witness signed-config hash mismatch")
        elif (c1_policy["record_sequence"] != stored_sequence + 1 or
              c1_policy["previous_policy_sha256"] != stored_hash or
              c1_policy["public_descriptor_range"][1] < stored_end):
            refuse("allocation witness detected config rollback/unlinked range update")
        else:
            policy_advanced = True
    seen_requests, seen_addresses, seen_indices = set(), set(), set()
    seen_blinds, seen_allocation_ids = set(), set()
    for offset, record in enumerate(ledger["allocations"]):
        _validate_registered_allocation(record, binding, None if legacy else c1_policy)
        expected = ledger["initial_descriptor_index"] + offset
        consensus_sequence = (int(record["consensus_allocation_id"], 16)
                              if not legacy else 0)
        if ((legacy and record["descriptor_index"] != expected) or
                (not legacy and
                 (consensus_sequence == 0 or
                  consensus_sequence > ledger["last_consensus_sequence"])) or
                record["request_id"] in seen_requests or
                record["btc_address"] in seen_addresses or
                record["descriptor_index"] in seen_indices or
                (not legacy and
                 (record["commitment_blind"] in seen_blinds or
                  record["consensus_allocation_id"] in
                    seen_allocation_ids))):
            refuse("wrap allocation sequence/private mapping is invalid or duplicated")
        seen_requests.add(record["request_id"])
        seen_addresses.add(record["btc_address"])
        seen_indices.add(record["descriptor_index"])
        if not legacy:
            seen_blinds.add(record["commitment_blind"])
            seen_allocation_ids.add(record["consensus_allocation_id"])
    if not legacy:
        by_request = {record["request_id"]: record
                      for record in ledger["allocations"]}
        registered, deposits, funded_reserved, minted = set(), set(), set(), set()
        for event in ledger["events"]:
            if (not isinstance(event, dict) or set(event) != {
                    "action", "at", "request_id"}
                    or event.get("action") not in (
                        "registered", "deposit_observed",
                        "funded_reservation_observed",
                        "funded_reservation_reverted",
                        "mint_effect_observed", "mint_effect_reverted")
                    or type(event.get("at")) is not int or event["at"] < 0
                    or not isinstance(event.get("request_id"), str)
                    or event["request_id"] not in by_request):
                refuse("wrap allocation authority event history is malformed")
            record = by_request[event["request_id"]]
            if event["action"] == "registered":
                if (event["request_id"] in registered
                        or event["at"] != record["registered_at"]):
                    refuse("wrap allocation registration event is inconsistent")
                registered.add(event["request_id"])
            elif event["action"] == "deposit_observed":
                if (event["request_id"] in deposits
                        or record["deposit_observed_at"] is None
                        or event["at"] != record["deposit_observed_at"]):
                    refuse("wrap allocation deposit event is inconsistent")
                deposits.add(event["request_id"])
            elif event["action"] == "funded_reservation_observed":
                if (event["request_id"] in funded_reserved or
                        record["deposit_observed_at"] is None):
                    refuse("wrap allocation funded-reservation event is inconsistent")
                funded_reserved.add(event["request_id"])
            elif event["action"] == "funded_reservation_reverted":
                if event["request_id"] not in funded_reserved:
                    refuse("wrap allocation funded-reservation rollback is inconsistent")
                funded_reserved.remove(event["request_id"])
            elif event["action"] == "mint_effect_observed":
                if (event["request_id"] in minted or
                        record["funded_reserved_at"] is None):
                    refuse("wrap allocation mint-effect event is inconsistent")
                minted.add(event["request_id"])
            else:
                if event["request_id"] not in minted:
                    refuse("wrap allocation mint-effect rollback is inconsistent")
                minted.remove(event["request_id"])
        expected_deposits = {
            record["request_id"] for record in ledger["allocations"]
            if record["deposit_observed_at"] is not None}
        expected_funded_reserved = {
            record["request_id"] for record in ledger["allocations"]
            if record["funded_reserved_at"] is not None}
        expected_minted = {
            record["request_id"] for record in ledger["allocations"]
            if record["minted_at"] is not None}
        if (registered != set(by_request) or deposits != expected_deposits or
                funded_reserved != expected_funded_reserved or
                minted != expected_minted):
            refuse("wrap allocation lifecycle events are incomplete")
    if policy_advanced:
        # Activate the one linked range-only policy update in the ledger bytes;
        # otherwise the witness can keep reporting the new outer config hash
        # while permanently persisting the predecessor inside its own state.
        ledger["capacity_policy_sha256"] = policy_sha256
        ledger["capacity_policy_sequence"] = c1_policy["record_sequence"]
        ledger["public_descriptor_range_end"] = (
            c1_policy["public_descriptor_range"][1])
        ledger["_policy_advanced"] = True
    return ledger


def _activate_allocation_policy_update(cfg, paths, ledger, policy_sha256):
    """Durably publish a linked C1 range raise before serving any action."""
    if ledger.pop("_policy_advanced", False) is not True:
        return False
    raw = (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n")
    _require_restore_clear(paths)
    atomic_write(paths["allocations"], raw)
    _checkpoint_allocation_ledger(
        cfg, ledger, policy_sha256, "store")
    return True


def _c1_capacity_reason(ledger, candidate, policy, now,
                        issuer_headroom_sats=None,
                        issuer_reserved_sats=None):
    if candidate["amount_sats"] < policy["minimum_allocation_sats"]:
        return "allocation is below the C1 minimum"
    epoch = candidate["admitted_at"] // policy["epoch_seconds"]
    day = candidate["admitted_at"] // 86_400
    if sum(row["admitted_at"] // policy["epoch_seconds"] == epoch
           for row in ledger["allocations"]) >= policy[
               "global_allocations_per_epoch"]:
        return "C1 epoch allocation cap reached"
    if sum(row["admitted_at"] // 86_400 == day
           for row in ledger["allocations"]) >= policy[
               "global_allocations_per_day"]:
        return "C1 daily allocation cap reached"
    live = [row for row in ledger["allocations"]
            if row.get("deposit_observed_at") is not None or
            now < row["expires_at"]]
    if issuer_headroom_sats is not None:
        if (type(issuer_headroom_sats) is not int or
                issuer_headroom_sats < 0 or
                type(issuer_reserved_sats) is not int or
                issuer_reserved_sats < 0):
            return "fresh issuer mint headroom is unavailable"
        # RPC headroom is already net of canonical issuer_reserved_sats. Charge
        # only the local active liability not yet represented in that consensus
        # aggregate; subtracting all local rows again would double-count C1R1.
        local_reserved = sum(row["amount_sats"] for row in live
                             if row.get("minted_at") is None)
        offchain_pending = max(0, local_reserved - issuer_reserved_sats)
        if (offchain_pending > issuer_headroom_sats or
                candidate["amount_sats"] >
                issuer_headroom_sats - offchain_pending):
            return "active C1 allocations exceed fresh issuer mint headroom"
    principal = sum(row["amount_sats"] for row in live
                    if row["principal_hash"] == candidate["principal_hash"])
    # A pending allocation reserves destination capacity. Once funding has
    # been observed it remains lifetime cumulative and can never be released.
    destination = sum(row["amount_sats"] for row in live
                      if row["veld_address"] == candidate["veld_address"])
    if principal + candidate["amount_sats"] > policy["principal_lifetime_sats"]:
        return "principal lifetime sat ceiling reached"
    if destination + candidate["amount_sats"] > policy[
            "destination_lifetime_sats"]:
        return "destination lifetime sat ceiling reached"
    return None


def _c1_storage_allows(row_count, byte_count, policy, *, new_admission):
    if type(row_count) is not int or type(byte_count) is not int:
        return False
    if new_admission:
        percent = 100 - policy["lifecycle_reserve_percent"]
        return (row_count < policy["journal_max_rows"] * percent // 100 and
                byte_count < policy["journal_max_bytes"] * percent // 100)
    return (row_count < policy["journal_max_rows"] and
            byte_count < policy["journal_max_bytes"])


def _checkpoint_allocation_ledger(cfg, ledger, policy_sha256, action):
    authority = _allocation_policy(cfg, require_c1=True)
    raw = (json.dumps(ledger, sort_keys=True, separators=(",", ":")) + "\n").encode()
    digest = hashlib.sha256(raw).hexdigest()
    request = json.dumps({
        "version": 2, "action": action,
        "capacity_policy_sha256": policy_sha256,
        "ledger_sha256": digest,
        "last_consensus_sequence": ledger["last_consensus_sequence"],
        "allocation_rows": len(ledger["allocations"]),
        "event_rows": len(ledger["events"]),
        "last_descriptor_index": (max(
            row["descriptor_index"] for row in ledger["allocations"])
                                  if ledger["allocations"] else 999),
    }, sort_keys=True, separators=(",", ":"))
    completed = run_bounded_subprocess(
        authority["checkpoint_command"], input_text=request, timeout=45,
        stdout_max=64 * 1024, stderr_max=64 * 1024,
        description="allocation monotonic/WORM checkpoint")
    try:
        answer = strict_json_loads(
            completed.stdout.encode("utf-8"), "allocation checkpoint acknowledgement")
    except Exception as exc:
        refuse("allocation checkpoint acknowledgement is invalid: %s" % exc)
    if (completed.returncode != 0 or not isinstance(answer, dict) or
            set(answer) != {"version", "stored", "action",
                            "capacity_policy_sha256", "ledger_sha256",
                            "last_consensus_sequence",
                            "monotonic_sequence"} or
            answer.get("version") != 2 or answer.get("stored") is not True or
            answer.get("action") != action or
            answer.get("capacity_policy_sha256") != policy_sha256 or
            answer.get("ledger_sha256") != digest or
            answer.get("last_consensus_sequence") !=
                ledger["last_consensus_sequence"] or
            type(answer.get("monotonic_sequence")) is not int or
            answer["monotonic_sequence"] < 1):
        refuse("allocation checkpoint authority refused or returned an inexact ack")
    return answer


def handle_register_allocation(req, cfg, paths, ledger, binding,
                               c1_policy=None, policy_sha256=None,
                               now=None, issuer_headroom_sats=None,
                               issuer_reserved_sats=None):
    legacy = ledger.get("version") == LEGACY_FIXTURE_ALLOCATION_LEDGER_VERSION
    wrapper_keys = {"version", "action", "allocation"}
    request_fields = LEGACY_ALLOCATION_FIELDS
    actions = ("register_allocation", "verify_allocation")
    version = 1
    if not legacy:
        wrapper_keys.add("capacity_policy_sha256")
        request_fields = ALLOCATION_FIELDS
        actions += ("preflight_allocation",)
        version = 4
    if (not isinstance(req, dict) or set(req) != wrapper_keys or
            req.get("version") != version or req.get("action") not in actions or
            not isinstance(req.get("allocation"), dict) or
            set(req["allocation"]) != request_fields or
            (not legacy and req.get("capacity_policy_sha256") != policy_sha256)):
        refuse("wrap allocation registration/config hash is not canonical")
    verify_only = req["action"] == "verify_allocation"
    preflight = req["action"] == "preflight_allocation"
    observed = int(time.time()) if now is None else now
    candidate = dict(req["allocation"])
    candidate["registered_at"] = observed
    if not legacy:
        candidate.update({"deposit_observed_at": None,
                          "funded_reserved_at": None,
                          "funding_outpoint": None,
                          "minted_at": None})
    _validate_registered_allocation(candidate, binding, None if legacy else c1_policy)
    existing = next((record for record in ledger["allocations"]
                     if record["request_id"] == candidate["request_id"]), None)
    if existing is not None:
        if any(existing[field] != candidate[field]
               for field in request_fields):
            refuse("wrap allocation request_id is already bound differently")
        record = existing
        if not legacy and not verify_only:
            if (type(issuer_headroom_sats) is not int or
                    issuer_headroom_sats < 0 or
                    type(issuer_reserved_sats) is not int or
                    issuer_reserved_sats < 0):
                refuse("AT_CAPACITY: fresh issuer mint headroom is unavailable")
            active_unminted = sum(
                row["amount_sats"] for row in ledger["allocations"]
                if (row.get("deposit_observed_at") is not None or
                    observed < row["expires_at"]) and
                row.get("minted_at") is None)
            # An idempotent register may follow a response-losing tip race.
            # Re-authorize the complete already-recorded liability against the
            # fresh headroom instead of blindly acknowledging it.
            offchain_pending = max(
                0, active_unminted - issuer_reserved_sats)
            if offchain_pending > issuer_headroom_sats:
                refuse("AT_CAPACITY: active C1 allocations exceed fresh issuer mint headroom")
    else:
        if verify_only:
            refuse("wrap allocation is absent from independent authority")
        if not legacy:
            if (candidate["admitted_at"] > observed + 120 or
                    observed - candidate["admitted_at"] > 900):
                refuse("wrap allocation admission epoch is stale/future")
            reason = _c1_capacity_reason(
                ledger, candidate, c1_policy, observed,
                issuer_headroom_sats=issuer_headroom_sats,
                issuer_reserved_sats=issuer_reserved_sats)
            if reason is not None:
                refuse("AT_CAPACITY: " + reason)
        if any(record["descriptor_index"] == candidate["descriptor_index"] or
               record["btc_address"] == candidate["btc_address"] or
               (not legacy and
                (record["commitment_blind"] == candidate["commitment_blind"] or
                 record["consensus_allocation_id"] ==
                    candidate["consensus_allocation_id"]))
               for record in ledger["allocations"]):
            refuse("wrap allocation index/address/blind/id is already bound")
        if legacy:
            expected = (ledger["initial_descriptor_index"] +
                        len(ledger["allocations"]))
            if candidate["descriptor_index"] != expected:
                refuse("wrap allocation registration is not the next contiguous index")
        elif (ledger["last_consensus_sequence"] == C1_UINT64_MAX or
              candidate["consensus_allocation_id"] != "%032x" %
              (ledger["last_consensus_sequence"] + 1)):
            refuse("wrap consensus allocation sequence is not exactly next")
        if preflight:
            record = candidate
        else:
            ledger["allocations"].append(candidate)
            if not legacy:
                prior_sequence = ledger["last_consensus_sequence"]
                ledger["last_consensus_sequence"] = int(
                    candidate["consensus_allocation_id"], 16)
                ledger["events"].append({
                    "action": "registered", "at": observed,
                    "request_id": candidate["request_id"],
                })
                raw = (json.dumps(ledger, sort_keys=True,
                                  separators=(",", ":")) + "\n").encode()
                if not _c1_storage_allows(
                        len(ledger["allocations"]) + len(ledger["events"]),
                        len(raw), c1_policy, new_admission=True):
                    ledger["allocations"].pop()
                    ledger["events"].pop()
                    ledger["last_consensus_sequence"] = prior_sequence
                    refuse("AT_CAPACITY: C1 witness lifecycle reserve reached")
            _require_restore_clear(paths)
            atomic_write(paths["allocations"], json.dumps(
                ledger, sort_keys=True, separators=(",", ":")) + "\n")
            if not legacy:
                _checkpoint_allocation_ledger(
                    cfg, ledger, policy_sha256, "store")
            record = candidate
    return {
        "version": version,
        "action": req["action"],
        "request_id": record["request_id"],
        "descriptor_index": record["descriptor_index"],
        **({"registered": True} if legacy else {
            "authorized": True,
            "capacity_policy_sha256": policy_sha256,
            "commitment_blind": record["commitment_blind"],
            "consensus_allocation_id":
                record["consensus_allocation_id"],
            **({} if preflight else {
                "expires_at": record["expires_at"],
                "deposit_observed_at": record.get("deposit_observed_at"),
                "funded_reserved_at": record.get("funded_reserved_at"),
                "minted_at": record.get("minted_at"),
            }),
        }),
        "idempotent": existing is not None,
    }


def _verify_allocation_deposit(claim, recipient, sats, outpoint,
                               allocations, btc, binding, spv_height,
                               now=None, c1_policy=None,
                               allocation_policy_sha256=None,
                               allow_recovery_only_lifecycle=False):
    observed_now = int(time.time() if now is None else now)
    _require_exact_c5_btc_policy(btc)
    claim_fields = {
        "request_id", "btc_address", "script_pubkey", "deposit_outpoint"}
    if c1_policy is not None:
        claim_fields |= {
            "descriptor_index", "capacity_policy_sha256",
            "public_descriptor_range_start", "public_descriptor_range_end",
            "consensus_allocation_id", "commitment_blind"}
    if not isinstance(claim, dict) or set(claim) != claim_fields:
        refuse("mint allocation claim schema is invalid")
    request_id = claim.get("request_id")
    address = claim.get("btc_address")
    script = claim.get("script_pubkey")
    if (not isinstance(request_id, str) or
            not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
            not isinstance(address, str) or
            not isinstance(script, str) or
            claim.get("deposit_outpoint") != outpoint or
            not isinstance(outpoint, str) or
            not BTC_OUTPOINT_RE.fullmatch(outpoint)):
        refuse("mint allocation claim is malformed or outpoint-mismatched")
    if c1_policy is not None:
        if (claim.get("descriptor_index") is None or
                claim.get("capacity_policy_sha256") !=
                    allocation_policy_sha256 or
                claim.get("public_descriptor_range_start") !=
                    c1_policy["public_descriptor_range"][0] or
                claim.get("public_descriptor_range_end") !=
                    c1_policy["public_descriptor_range"][1] or
                not isinstance(claim.get("consensus_allocation_id"), str) or
                not ALLOCATION_REQUEST_RE.fullmatch(
                    claim["consensus_allocation_id"]) or
                int(claim["consensus_allocation_id"], 16) == 0 or
                not isinstance(claim.get("commitment_blind"), str) or
                not re.fullmatch(r"[0-9a-f]{64}",
                                 claim["commitment_blind"]) or
                int(claim["commitment_blind"], 16) == 0 or
                not _c1_public_index_allowed(
                    claim.get("descriptor_index"), c1_policy)):
            refuse("mint allocation claim differs from signed C1 policy")
    record = next((entry for entry in allocations["allocations"]
                   if entry["request_id"] == request_id), None)
    if (record is None or record["btc_address"] != address or
            record["script_pubkey"] != script or
            record["veld_address"] != recipient or
            record["amount_sats"] != sats or
            (c1_policy is not None and
             (record["descriptor_index"] != claim["descriptor_index"] or
              record["consensus_allocation_id"] !=
                claim["consensus_allocation_id"] or
              record["commitment_blind"] != claim["commitment_blind"]))):
        refuse("mint is not authorized by the independent wrap allocation ledger")
    if ("expires_at" in record and
            record.get("deposit_observed_at") is None and
            observed_now >= record["expires_at"]):
        refuse("LATE_DEPOSIT_MANUAL_RECOVERY: unfunded allocation expired")
    txid, vout_text = outpoint.split(":", 1)
    vout = int(vout_text)
    if vout > 0xffffffff:
        refuse("mint Bitcoin outpoint vout is out of range")
    if type(spv_height) is not int or spv_height < 1:
        refuse("compiled Veld Bitcoin-header height is unavailable")
    before = btc.call("getbestblockhash")
    chain = btc.call("getblockchaininfo")
    best_header = btc.call("getblockheader", before, "true")
    output = btc.call("gettxout", txid, vout, "true")
    after = btc.call("getbestblockhash")
    blocks = chain.get("blocks") if isinstance(chain, dict) else None
    headers = chain.get("headers") if isinstance(chain, dict) else None
    header_time = best_header.get("time") if isinstance(best_header, dict) else None
    if (not isinstance(before, str) or not sol.HASH256_RE.fullmatch(before) or
            after != before or not isinstance(chain, dict) or
            chain.get("chain") != "main" or
            chain.get("initialblockdownload") is not False or
            type(blocks) is not int or type(headers) is not int or
            blocks < spv_height or headers != blocks or
            chain.get("bestblockhash") != before or
            not isinstance(best_header, dict) or
            best_header.get("hash") != before or
            type(header_time) is not int or
            header_time > observed_now + C5_TIP_HARD_SECONDS or
            not isinstance(output, dict)):
        refuse("independent Bitcoin allocation snapshot is unavailable/incoherent")
    tip_age = max(0, observed_now - header_time)
    phase = _c5_phase(tip_age)
    btc.last_c5_phase = phase
    if phase == "RECOVERY_ONLY" and not allow_recovery_only_lifecycle:
        refuse("RECOVERY_ONLY: Bitcoin Core tip is too stale for a new mint reservation")
    if phase == "RECOVERY_ONLY":
        sys.stderr.write(
            "veld_wt_reserve RECOVERY_ONLY: exact durable reservation retry "
            "continues at Bitcoin tip age %ds\n" % tip_age)
    else:
        _report_c5_phase(phase, tip_age)
    confirmations = output.get("confirmations")
    script_info = output.get("scriptPubKey")
    if (type(confirmations) is not int or
            confirmations < btc.confirmations or
            not isinstance(script_info, dict) or
            script_info.get("hex") != record["script_pubkey"] or
            _btc_to_sats(output.get("value")) != record["amount_sats"]):
        refuse("Bitcoin outpoint does not exactly satisfy the registered allocation")
    # Production public allocations use the C1 schema and begin at descriptor
    # index 1000.  Revalidating them with the legacy 0--999 contract makes every
    # otherwise valid issuer mint fail at this final boundary.  Preserve the
    # independently loaded signed policy all the way through deposit validation.
    _validate_registered_allocation(record, binding, c1_policy)
    return record


def _verify_c1_funded_reservation(record, outpoint, beat, rpc):
    """Require the canonical C1F1 consumer before authorizing MNP2.

    A Bitcoin UTXO is only a deposit observation.  It becomes the funded C1
    reservation only when consensus has verified CFP1+MNP1 and inserted the
    exact outpoint.  The later MNP2 is root-neutral and therefore must see that
    insertion rather than asking for a second nonmembership proof.
    """
    allocation_id_value = record.get("consensus_allocation_id")
    if (record.get("funded_reserved_at") is not None and
            record.get("funding_outpoint") != outpoint):
        refuse("persisted C1 funding outpoint differs from the mint request")
    try:
        supply_before = rpc.call("getbtcveldsupply")
        status = rpc.call("getbtcveldc1reservation", [allocation_id_value])
        mint_status = rpc.call("getbtcveldmintstatus", [outpoint])
        supply_after = rpc.call("getbtcveldsupply")
    except Exception as exc:
        refuse("canonical C1F1 status is unavailable: %s" % exc)
    expected_commitment = allocation_commitment(
        allocation_id_value, record["veld_address"], record["amount_sats"],
        record["script_pubkey"], record["commitment_blind"])
    if (not isinstance(supply_before, dict) or
            supply_before != supply_after or
            set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
            supply_before.get("supply_sats") != beat.get("supply_sats") or
            supply_before.get("tip") != beat.get("tip") or
            supply_before.get("tip_hash") != beat.get("tip_hash") or
            not isinstance(status, dict) or
            status.get("allocation_id") != allocation_id_value or
            status.get("found") is not True or
            status.get("active") is not True or
            status.get("exposed") is not True or
            status.get("exposure_canonical_depth_reached") is not True or
            status.get("funded") is not True or
            status.get("funding_outpoint") != outpoint or
            status.get("recipient") != record["veld_address"] or
            status.get("amount_sats") != record["amount_sats"] or
            status.get("allocation_commitment") != expected_commitment or
            status.get("tip") != beat.get("tip") or
            not isinstance(mint_status, dict) or
            mint_status.get("outpoint") != outpoint or
            mint_status.get("consumed") is not True or
            mint_status.get("minted") is not False or
            mint_status.get("proof_version") != "MNP1" or
            mint_status.get("accepted_effect_kind") != "C1_FUND" or
            mint_status.get("c1_allocation_id") != allocation_id_value or
            mint_status.get("tip") != beat.get("tip") or
            mint_status.get("tip_hash") != beat.get("tip_hash")):
        refuse("canonical C1F1 funded reservation is absent or incoherent")
    height = mint_status.get("consumer_block_height")
    block_hash = mint_status.get("consumer_block_hash")
    if (type(height) is not int or not 0 <= height <= beat["tip"] or
            not isinstance(block_hash, str) or
            not sol.HASH256_RE.fullmatch(block_hash) or
            not isinstance(mint_status.get("consumer_txid"), str) or
            not sol.HASH256_RE.fullmatch(mint_status["consumer_txid"]) or
            type(mint_status.get("consumer_tx_index")) is not int or
            mint_status["consumer_tx_index"] < 0 or
            type(mint_status.get("consumer_marker_vout")) is not int or
            mint_status["consumer_marker_vout"] < 0):
        refuse("canonical C1F1 consumer locator is malformed")
    try:
        if rpc.call("getblockhash", [height]) != block_hash:
            refuse("canonical C1F1 consumer is not on the signed-tip chain")
    except SystemExit:
        raise
    except Exception:
        refuse("canonical C1F1 consumer block is unavailable")
    return mint_status


def _tip_matches(beat, rpc):
    try:
        return rpc.call("getblockhash", [beat["tip"]]) == beat["tip_hash"]
    except Exception:
        return False


def _verify_forced_command_peg_policy(rpc, cfg, binding):
    """Bind each public C1 MNP2 reservation to completion + SPV identity.

    Production decoding below accepts only exact MNP2 bytes backed by a
    canonical C1F1-funded allocation. This witness must therefore remain
    available during the configured later-stall completion exception; it
    must never use that exception for direct MNP1 or MSPV.
    """
    try:
        peg = rpc.call("getpeginfo")
        custody_binding.verify_peg_identity(peg, binding)
        if not isinstance(peg, dict) or peg.get("token_id") != "btcVELD":
            raise ValueError("getpeginfo returned the wrong token identity")
        if (peg.get("peg_unlocked") is not True or
                peg.get("completion_live") is not True):
            raise ValueError(
                "canonical launch/liveness gate does not permit exact C1 mint completion")
        compiled_k = sol._wire_uint(
            peg.get("spv_k_btc"), "compiled spv_k_btc", positive=True)
        btc_cfg = cfg.get("btc")
        configured_k = (btc_cfg.get("confirmations")
                        if isinstance(btc_cfg, dict) else None)
        if type(configured_k) is not int or configured_k != compiled_k:
            raise ValueError(
                "witness Bitcoin confirmations differ from compiled spv_k_btc")
        relay = rpc.call("getbtcheaderinfo")
        if (not isinstance(relay, dict) or relay.get("spv_active") is not True or
                type(relay.get("best_height")) is not int or
                relay["best_height"] < 1 or relay.get("k_btc") != compiled_k):
            raise ValueError("compiled Bitcoin SPV header view is inactive/malformed")
        return relay["best_height"]
    except SystemExit:
        raise
    except Exception as exc:
        refuse("compiled peg/SPV policy verification failed: %s" % exc)


def _verify_public_allocation_backend(cfg, c1_policy, now=None, rpc=None):
    """Independently enforce the launch/liveness and C5 admission gates."""
    observed = int(time.time()) if now is None else now
    rpc = VeldRpc(cfg.get("veld_rpc")) if rpc is None else rpc
    peg = rpc.call("getpeginfo")
    if (not isinstance(peg, dict) or peg.get("peg_unlocked") is not True or
            peg.get("mint_live") is not True):
        refuse("PEG_LOCKED: canonical launch/liveness gate does not permit mint")
    if (type(peg.get("issuer_max_per_mint_sats")) is not int or
            peg["issuer_max_per_mint_sats"] <
            c1_policy["minimum_allocation_sats"] or
            type(peg.get("issuer_static_custody_cap_sats")) is not int or
            peg["issuer_static_custody_cap_sats"] !=
            c1_policy["consensus_custody_ceiling_sats"] or
            type(peg.get("issuer_effective_custody_cap_sats")) is not int or
            peg["issuer_effective_custody_cap_sats"] < 0 or
            type(peg.get("issuer_mint_headroom_sats")) is not int or
            peg["issuer_mint_headroom_sats"] < 0 or
            type(peg.get("issuer_reserved_sats")) is not int or
            peg["issuer_reserved_sats"] < 0 or
            type(peg.get("supply_sats")) is not int or
            peg["supply_sats"] < 0 or
            type(peg.get("tip")) is not int or peg["tip"] < 0):
        refuse("compiled issuer limits differ from signed C1 policy")
    try:
        supply_before = rpc.call("getbtcveldsupply")
        before_veld_tip = rpc.call("getblockhash", [peg["tip"]])
        peg_after = rpc.call("getpeginfo")
        supply_after = rpc.call("getbtcveldsupply")
        after_veld_tip = rpc.call("getblockhash", [peg["tip"]])
    except Exception:
        refuse("Veld allocation headroom tip is unavailable")
    capacity_fields = (
        "tip", "supply_sats", "issuer_effective_custody_cap_sats",
        "issuer_mint_headroom_sats", "issuer_reserved_sats",
        "issuer_max_per_mint_sats",
        "issuer_static_custody_cap_sats")
    if (peg["supply_sats"] > peg["issuer_effective_custody_cap_sats"] or
            peg["issuer_reserved_sats"] >
            peg["issuer_effective_custody_cap_sats"] - peg["supply_sats"]):
        refuse("Veld allocation capacity tuple overflows its effective ceiling")
    expected_headroom = (
        peg["issuer_effective_custody_cap_sats"] - peg["supply_sats"] -
        peg["issuer_reserved_sats"])
    if (not isinstance(supply_before, dict) or
            supply_before != supply_after or
            set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
            supply_before.get("supply_sats") != peg["supply_sats"] or
            supply_before.get("tip") != peg["tip"] or
            not isinstance(supply_before.get("tip_hash"), str) or
            not sol.HASH256_RE.fullmatch(supply_before["tip_hash"]) or
            any(peg.get(name) != peg_after.get(name)
                for name in capacity_fields) or
            peg["issuer_mint_headroom_sats"] != expected_headroom or
            not isinstance(before_veld_tip, str) or
            not sol.HASH256_RE.fullmatch(before_veld_tip) or
            before_veld_tip != supply_before["tip_hash"] or
            after_veld_tip != before_veld_tip):
        refuse("Veld allocation capacity tuple changed/is incoherent")
    btc = BitcoinCli(cfg.get("btc"))
    _require_exact_c5_btc_policy(btc)
    before = btc.call("getbestblockhash")
    chain = btc.call("getblockchaininfo")
    header = btc.call("getblockheader", before, "true")
    after = btc.call("getbestblockhash")
    if (not isinstance(before, str) or not sol.HASH256_RE.fullmatch(before) or
            after != before or not isinstance(chain, dict) or
            chain.get("chain") != "main" or
            chain.get("initialblockdownload") is not False or
            type(chain.get("blocks")) is not int or
            chain.get("headers") != chain.get("blocks") or
            chain.get("bestblockhash") != before or
            not isinstance(header, dict) or header.get("hash") != before or
            type(header.get("time")) is not int):
        refuse("Bitcoin Core allocation freshness snapshot is incoherent")
    age = max(0, observed - header["time"])
    phase = _c5_phase(age)
    if phase == "RECOVERY_ONLY":
        refuse("RECOVERY_ONLY: Bitcoin Core tip is too stale for new allocation")
    _report_c5_phase(phase, age)
    return {"phase": phase, "tip_age_seconds": age,
            "issuer_headroom_sats": peg["issuer_mint_headroom_sats"],
            "issuer_reserved_sats": peg["issuer_reserved_sats"],
            "supply_sats": peg["supply_sats"],
            "veld_tip": peg["tip"], "veld_tip_hash": before_veld_tip}


def _canonical_confirmation(entry, beat, rpc):
    txid = entry.get("txid")
    if not txid:
        return None
    receipt = entry.get("receipt")
    c1 = (isinstance(receipt, dict) and
          receipt.get("v") == sol.C1_RESERVATION_VERSION)
    if c1:
        outpoint = receipt.get("deposit_outpoint")
        try:
            supply_before = rpc.call("getbtcveldsupply")
            status = rpc.call("getbtcveldmintstatus", [outpoint])
            supply_after = rpc.call("getbtcveldsupply")
        except Exception as exc:
            # An unavailable canonical index is not evidence that a previously
            # checkpointed monetary effect reorged.  HOLD the full charge and
            # its lifecycle marker until an exact coherent absence is sampled.
            refuse("C1 canonical mint-effect status is unavailable: %s" % exc)
        if (not isinstance(supply_before, dict) or
                supply_before != supply_after or
                set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
                supply_before.get("supply_sats") != beat.get("supply_sats") or
                supply_before.get("tip") != beat.get("tip") or
                supply_before.get("tip_hash") != beat.get("tip_hash") or
                not isinstance(status, dict) or status.get("outpoint") != outpoint or
                type(status.get("consumed")) is not bool or
                type(status.get("minted")) is not bool or
                status.get("proof_version") != "MNP1" or
                not isinstance(status.get("proof_hex"), str) or
                not re.fullmatch(r"[0-9a-f]+", status["proof_hex"]) or
                len(status["proof_hex"]) % 2 != 0 or
                not isinstance(status.get("root"), str) or
                not sol.HASH256_RE.fullmatch(status["root"]) or
                type(status.get("count")) is not int or
                not 0 <= status["count"] <= C1_UINT64_MAX or
                type(status.get("tip")) is not int or
                status.get("tip") != beat["tip"] or
                status.get("tip_hash") != supply_before["tip_hash"]):
            refuse("C1 canonical mint-effect status is malformed/incoherent")
        if status["consumed"] is False:
            if (status["minted"] is not False or
                    any(status.get(name) is not None for name in (
                        "accepted_txid", "accepted_block_height",
                        "accepted_block_hash", "accepted_tx_index",
                        "accepted_marker_vout", "accepted_effect_kind",
                        "c1_allocation_id", "consumer_txid",
                        "consumer_block_height", "consumer_block_hash",
                        "consumer_tx_index", "consumer_marker_vout",
                        "credit_txid", "credit_block_height",
                        "credit_block_hash", "credit_tx_index",
                        "credit_marker_vout"))):
                refuse("C1 unconsumed status carries a stale effect locator")
            return None
        if (status.get("c1_allocation_id") !=
                receipt.get("allocation_request_id") or
                not isinstance(status.get("accepted_txid"), str) or
                not sol.HASH256_RE.fullmatch(status["accepted_txid"]) or
                type(status.get("accepted_block_height")) is not int or
                not 0 <= status["accepted_block_height"] <= beat["tip"] or
                not isinstance(status.get("accepted_block_hash"), str) or
                not sol.HASH256_RE.fullmatch(status["accepted_block_hash"]) or
                type(status.get("accepted_tx_index")) is not int or
                status["accepted_tx_index"] < 0 or
                type(status.get("accepted_marker_vout")) is not int or
                status["accepted_marker_vout"] < 0 or
                status.get("consumer_txid") is None or
                type(status.get("consumer_block_height")) is not int or
                not 0 <= status["consumer_block_height"] <= beat["tip"] or
                not isinstance(status.get("consumer_block_hash"), str) or
                not sol.HASH256_RE.fullmatch(status["consumer_block_hash"]) or
                type(status.get("consumer_tx_index")) is not int or
                status["consumer_tx_index"] < 0 or
                type(status.get("consumer_marker_vout")) is not int or
                status["consumer_marker_vout"] < 0):
            refuse(
                "C1 deposit was consumed by a different/invalid C1F1; HOLD")
        # C1F1 consumption is the funded-reserved phase, not monetary credit.
        # Keep the signer reservation fully charged until the exact C1_MINT
        # effect for these signed MNP2 bytes is canonical.
        if status["minted"] is False:
            if (status.get("accepted_effect_kind") != "C1_FUND" or
                    status.get("accepted_txid") !=
                        status.get("consumer_txid") or
                    status.get("accepted_block_height") !=
                        status.get("consumer_block_height") or
                    status.get("accepted_block_hash") !=
                        status.get("consumer_block_hash") or
                    status.get("accepted_tx_index") !=
                        status.get("consumer_tx_index") or
                    status.get("accepted_marker_vout") !=
                        status.get("consumer_marker_vout") or
                    any(status.get(name) is not None for name in (
                        "credit_txid", "credit_block_height",
                        "credit_block_hash", "credit_tx_index",
                        "credit_marker_vout"))):
                refuse("C1 funded reservation lacks the C1_FUND effect; HOLD")
            return None
        if (status.get("accepted_effect_kind") != "C1_MINT" or
                status.get("credit_txid") != txid or
                status.get("accepted_txid") != status.get("credit_txid") or
                status.get("accepted_block_height") !=
                    status.get("credit_block_height") or
                status.get("accepted_block_hash") !=
                    status.get("credit_block_hash") or
                status.get("accepted_tx_index") !=
                    status.get("credit_tx_index") or
                status.get("accepted_marker_vout") !=
                    status.get("credit_marker_vout") or
                type(status.get("credit_block_height")) is not int or
                status["credit_block_height"] < 0 or
                not isinstance(status.get("credit_block_hash"), str) or
                not sol.HASH256_RE.fullmatch(status["credit_block_hash"]) or
                type(status.get("credit_tx_index")) is not int or
                status["credit_tx_index"] < 0 or
                type(status.get("credit_marker_vout")) is not int or
                status["credit_marker_vout"] < 0):
            refuse("C1 monetary credit differs from the exact MNP2 effect; HOLD")
        height = status["credit_block_height"]
        block_hash = status["credit_block_hash"]
        if height > beat["tip"]:
            refuse("C1 accepted mint-effect locator is above the signed tip")
        try:
            if rpc.call("getblockhash", [
                    status["consumer_block_height"]]) != status[
                    "consumer_block_hash"]:
                refuse("C1 funding consumer locator is not canonical at the signed tip")
            if rpc.call("getblockhash", [height]) != block_hash:
                refuse("C1 monetary credit locator is not canonical at the signed tip")
        except SystemExit:
            raise
        except Exception as exc:
            refuse("C1 monetary credit block is unavailable: %s" % exc)
        return beat["tip"] - height + 1, height, block_hash
    try:
        info = rpc.call("getrawtransaction", [txid])
        if not isinstance(info, dict) or info.get("txid") != txid:
            return None
        reported_confirmations = sol._wire_uint(
            info.get("confirmations"), "confirmations", positive=True)
        height = sol._wire_uint(info.get("block_height"), "block_height")
        block_hash = info.get("block_hash")
        if (height > beat["tip"] or not isinstance(block_hash, str) or
                not sol.HASH256_RE.fullmatch(block_hash)):
            return None
        if rpc.call("getblockhash", [height]) != block_hash:
            return None
        # RPC confirmations are relative to the node's *current* tip, which can
        # advance beyond this signed heartbeat while it remains fresh.  Finality
        # and reservation retirement must instead use the exact heartbeat
        # snapshot or a fast chain can retire reorg protection early.
        snapshot_confirmations = beat["tip"] - height + 1
        if reported_confirmations < snapshot_confirmations:
            return None
        return snapshot_confirmations, height, block_hash
    except Exception:
        return None


def _checkpoint_allocation_effect(cfg, paths, allocation_ledger,
                                  policy_sha256, receipt, present, now,
                                  c1_policy=None):
    """Durably mirror one exact C1 consensus effect into admission state."""
    consensus_allocation_id = receipt.get("allocation_request_id")
    record = next((row for row in allocation_ledger["allocations"]
                   if row.get("consensus_allocation_id") ==
                   consensus_allocation_id), None)
    if (record is None or record.get("funded_reserved_at") is None or
            record.get("amount_sats") != receipt.get("sats") or
            record.get("veld_address") != receipt.get("recipient") or
            record.get("btc_address") != receipt.get("allocation_btc_address") or
            record.get("script_pubkey") != receipt.get("allocation_script_pubkey")):
        refuse("C1 accepted mint effect has no exact allocation authority row")
    currently_present = record.get("minted_at") is not None
    if currently_present == present:
        return False
    if type(now) is not int or now < 0:
        refuse("C1 mint-effect checkpoint clock is invalid")
    record["minted_at"] = now if present else None
    allocation_ledger["events"].append({
        "action": ("mint_effect_observed" if present
                   else "mint_effect_reverted"),
        # Lifecycle events are keyed by the allocator's private retry id; the
        # consensus id above is only the monotonic on-chain lookup key.
        "at": now, "request_id": record["request_id"],
    })
    raw = (json.dumps(allocation_ledger, sort_keys=True,
                      separators=(",", ":")) + "\n").encode("utf-8")
    policy = c1_policy
    if policy is None:
        policy, ignored_hash = _load_signed_c1_policy(cfg)
        if ignored_hash != policy_sha256:
            refuse("C1 mint-effect checkpoint policy changed")
    if not _c1_storage_allows(
            len(allocation_ledger["allocations"]) +
            len(allocation_ledger["events"]), len(raw), policy,
            new_admission=False):
        refuse("allocation lifecycle journal hard capacity reached")
    _require_restore_clear(paths)
    atomic_write(paths["allocations"], raw.decode("utf-8"))
    _checkpoint_allocation_ledger(
        cfg, allocation_ledger, policy_sha256, "store")
    return True


def _checkpoint_funded_reservation(cfg, paths, allocation_ledger,
                                   policy_sha256, record, outpoint, present,
                                   now, c1_policy=None):
    """Durably mirror one exact canonical C1F1 lifecycle transition.

    The outpoint is part of the persistent current state.  Without it, a crash
    after recording C1F1 but before issuing MNP2 loses the only identity with
    which the witness can prove that a later unconsumed nullifier is the exact
    effect that reorged away.
    """
    if (not isinstance(record, dict) or
            not any(row is record for row in
                    allocation_ledger.get("allocations", [])) or
            not isinstance(outpoint, str) or
            not BTC_OUTPOINT_RE.fullmatch(outpoint) or
            int(outpoint.rsplit(":", 1)[1]) > 0xffffffff or
            type(now) is not int or now < 0):
        refuse("C1 funded-reservation checkpoint identity is malformed")
    currently_present = record.get("funded_reserved_at") is not None
    stored_outpoint = record.get("funding_outpoint")
    if currently_present:
        if stored_outpoint != outpoint:
            refuse("C1 funded-reservation outpoint changed without rollback")
        if present:
            return False
    elif stored_outpoint is not None:
        refuse("C1 unfunded allocation retains a funding outpoint")
    elif not present:
        return False
    if not present and record.get("minted_at") is not None:
        refuse("C1 funding cannot roll back beneath a recorded mint effect")
    if present and record.get("deposit_observed_at") is None:
        refuse("C1 funding cannot precede the Bitcoin deposit observation")

    record["funded_reserved_at"] = now if present else None
    record["funding_outpoint"] = outpoint if present else None
    allocation_ledger["events"].append({
        "action": ("funded_reservation_observed" if present
                   else "funded_reservation_reverted"),
        "at": now, "request_id": record["request_id"],
    })
    raw = (json.dumps(allocation_ledger, sort_keys=True,
                      separators=(",", ":")) + "\n").encode("utf-8")
    policy = c1_policy
    if policy is None:
        policy, ignored_hash = _load_signed_c1_policy(cfg)
        if ignored_hash != policy_sha256:
            refuse("C1 funded-reservation checkpoint policy changed")
    if not _c1_storage_allows(
            len(allocation_ledger["allocations"]) +
            len(allocation_ledger["events"]), len(raw), policy,
            new_admission=False):
        refuse("allocation lifecycle journal hard capacity reached")
    _require_restore_clear(paths)
    atomic_write(paths["allocations"], raw.decode("utf-8"))
    _checkpoint_allocation_ledger(
        cfg, allocation_ledger, policy_sha256, "store")
    return True


def _reconcile_c1_funded_reservation(cfg, paths, allocation_ledger,
                                     policy_sha256, record, beat, rpc, now,
                                     c1_policy=None):
    """Clear a stale FUNDED_RESERVED mirror after an exact shallow reorg.

    RPC uncertainty and every state other than the same active, final-depth
    exposure becoming canonically unfunded are HOLD conditions.  In
    particular, a different consumer or outpoint can never be converted into
    rollback authority by this reconciliation path.
    """
    old_outpoint = record.get("funding_outpoint")
    if record.get("funded_reserved_at") is None:
        if old_outpoint is not None:
            refuse("C1 unfunded allocation retains a funding outpoint")
        return False
    if record.get("minted_at") is not None:
        # _reconcile() must first prove and checkpoint any MNP2 reorg.  A
        # still-canonical monetary effect makes the funding layer immutable.
        return False
    if (not isinstance(old_outpoint, str) or
            not BTC_OUTPOINT_RE.fullmatch(old_outpoint)):
        refuse("C1 funded allocation lacks its persisted outpoint")
    try:
        supply_before = rpc.call("getbtcveldsupply")
        status = rpc.call("getbtcveldc1reservation", [
            record["consensus_allocation_id"]])
        mint_status = rpc.call("getbtcveldmintstatus", [old_outpoint])
        supply_after = rpc.call("getbtcveldsupply")
    except Exception as exc:
        refuse("canonical C1 funding reconciliation is unavailable: %s" % exc)

    expected_commitment = allocation_commitment(
        record["consensus_allocation_id"], record["veld_address"],
        record["amount_sats"], record["script_pubkey"],
        record["commitment_blind"])
    sequence = int(record["consensus_allocation_id"], 16)
    if (not isinstance(supply_before, dict) or
            supply_before != supply_after or
            set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
            supply_before.get("supply_sats") != beat.get("supply_sats") or
            supply_before.get("tip") != beat.get("tip") or
            supply_before.get("tip_hash") != beat.get("tip_hash") or
            not isinstance(status, dict) or
            status.get("allocation_id") != record["consensus_allocation_id"] or
            status.get("found") is not True or
            status.get("active") is not True or
            status.get("retired") is not False or
            status.get("sequence") != sequence or
            type(status.get("last_sequence")) is not int or
            status["last_sequence"] < sequence or
            status.get("recipient") != record["veld_address"] or
            status.get("amount_sats") != record["amount_sats"] or
            status.get("allocation_commitment") != expected_commitment or
            status.get("exposed") is not True or
            status.get("exposure_canonical_depth_reached") is not True or
            type(status.get("exposure_confirmations")) is not int or
            status["exposure_confirmations"] < MAX_REORG_DEPTH + 1 or
            status.get("required_confirmations") != MAX_REORG_DEPTH + 1 or
            status.get("canonical_depth_reached") is not True or
            status.get("tip") != beat.get("tip") or
            not isinstance(mint_status, dict) or
            mint_status.get("outpoint") != old_outpoint or
            mint_status.get("proof_version") != "MNP1" or
            not isinstance(mint_status.get("proof_hex"), str) or
            not re.fullmatch(r"[0-9a-f]+", mint_status["proof_hex"]) or
            len(mint_status["proof_hex"]) % 2 != 0 or
            not isinstance(mint_status.get("root"), str) or
            not sol.HASH256_RE.fullmatch(mint_status["root"]) or
            type(mint_status.get("count")) is not int or
            not 0 <= mint_status["count"] <= C1_UINT64_MAX or
            mint_status.get("tip") != beat.get("tip") or
            mint_status.get("tip_hash") != beat.get("tip_hash")):
        refuse("canonical C1 funding reconciliation is incoherent")

    if status.get("funded") is True:
        locator_names = (
            "accepted_txid", "consumer_txid", "accepted_block_hash",
            "consumer_block_hash")
        if (status.get("funding_outpoint") != old_outpoint or
                type(status.get("funding_confirmations")) is not int or
                status["funding_confirmations"] < 1 or
                type(status.get("funding_canonical_depth_reached")) is not bool or
                mint_status.get("consumed") is not True or
                mint_status.get("minted") is not False or
                mint_status.get("accepted_effect_kind") != "C1_FUND" or
                mint_status.get("c1_allocation_id") !=
                    record["consensus_allocation_id"] or
                any(not isinstance(mint_status.get(name), str) or
                    not sol.HASH256_RE.fullmatch(mint_status[name])
                    for name in locator_names) or
                mint_status.get("accepted_txid") !=
                    mint_status.get("consumer_txid") or
                mint_status.get("accepted_block_height") !=
                    mint_status.get("consumer_block_height") or
                mint_status.get("accepted_block_hash") !=
                    mint_status.get("consumer_block_hash") or
                mint_status.get("accepted_tx_index") !=
                    mint_status.get("consumer_tx_index") or
                mint_status.get("accepted_marker_vout") !=
                    mint_status.get("consumer_marker_vout") or
                any(mint_status.get(name) is not None for name in (
                    "credit_txid", "credit_block_height", "credit_block_hash",
                    "credit_tx_index", "credit_marker_vout"))):
            refuse("canonical C1 funding changed or has an invalid consumer")
        height = mint_status.get("consumer_block_height")
        if (type(height) is not int or not 0 <= height <= beat["tip"] or
                type(mint_status.get("consumer_tx_index")) is not int or
                mint_status["consumer_tx_index"] < 0 or
                type(mint_status.get("consumer_marker_vout")) is not int or
                mint_status["consumer_marker_vout"] < 0):
            refuse("canonical C1 funding consumer locator is malformed")
        try:
            if rpc.call("getblockhash", [height]) != mint_status[
                    "consumer_block_hash"]:
                refuse("canonical C1 funding consumer is not on the signed-tip chain")
        except SystemExit:
            raise
        except Exception as exc:
            refuse("canonical C1 funding consumer block is unavailable: %s" % exc)
        return False

    null_locators = (
        "accepted_txid", "accepted_block_height", "accepted_block_hash",
        "accepted_tx_index", "accepted_marker_vout", "accepted_effect_kind",
        "c1_allocation_id", "consumer_txid", "consumer_block_height",
        "consumer_block_hash", "consumer_tx_index", "consumer_marker_vout",
        "credit_txid", "credit_block_height", "credit_block_hash",
        "credit_tx_index", "credit_marker_vout")
    if (status.get("funded") is not False or
            status.get("funding_outpoint") is not None or
            status.get("funding_confirmations") is not None or
            status.get("funding_canonical_depth_reached") is not False or
            mint_status.get("consumed") is not False or
            mint_status.get("minted") is not False or
            any(mint_status.get(name) is not None for name in null_locators)):
        refuse("C1 funding rollback is not an exact unconsumed transition")
    return _checkpoint_funded_reservation(
        cfg, paths, allocation_ledger, policy_sha256, record,
        old_outpoint, False, now, c1_policy)


def _snapshot_object(ledger):
    return {
        "version": LEDGER_VERSION,
        "terminal_count": ledger["terminal_count"],
        "terminal_head_sha256": ledger["terminal_head_sha256"],
        "reservations": ledger["reservations"],
    }


def _state_free_bytes(path):
    try:
        stats = os.statvfs(path)
        return stats.f_bavail * stats.f_frsize
    except OSError as error:
        refuse("witness state free-space check failed: %s" % error)


def _require_write_capacity(paths, policy, additional_bytes=0):
    if type(additional_bytes) is not int or additional_bytes < 0:
        refuse("witness write-capacity request is invalid")
    free = _state_free_bytes(os.path.dirname(paths["ledger"]))
    if free < policy["min_free_bytes"] + additional_bytes:
        refuse("witness state volume is below its configured free-space reserve")


def _snapshot_text(ledger, policy):
    if len(ledger["reservations"]) > policy["max_active_rows"]:
        refuse("active reservation row limit reached")
    text = json.dumps(
        _snapshot_object(ledger), sort_keys=True, separators=(",", ":")) + "\n"
    if len(text.encode("utf-8")) > policy["max_active_bytes"]:
        refuse("active reservation byte limit reached")
    return text


def _persist_ledger(paths, ledger, policy):
    text = _snapshot_text(ledger, policy)
    _require_write_capacity(paths, policy, len(text.encode("utf-8")))
    _require_restore_clear(paths)
    atomic_write(paths["ledger"], text)
    ledger["_needs_checkpoint"] = False


def _terminal_archive_entry(entry, beat):
    return {
        "version": TERMINAL_ARCHIVE_VERSION,
        "kind": TERMINAL_ARCHIVE_KIND,
        "receipt": entry["receipt"],
        "txid": entry["txid"],
        "signed_tx_sha256": entry["signed_tx_sha256"],
        "block_height": entry["block_height"],
        "block_hash": entry["block_hash"],
        "finalized_at_tip": beat["tip"],
        "finalized_at_tip_hash": beat["tip_hash"],
    }


def _archive_terminal(entry, entry_sha256, policy):
    command = policy.get("terminal_archive_command")
    if not command:
        refuse("terminal reservation archive is unavailable")
    observed_at = int(time.time())
    if observed_at < 0 or observed_at > sol.MAX_WIRE_INT:
        refuse("terminal reservation archive clock is invalid")
    minimum_retention_until = (
        observed_at + TERMINAL_ARCHIVE_RETENTION_SECONDS)
    request = {
        "version": TERMINAL_ARCHIVE_VERSION,
        "action": "archive_terminal",
        "entry_sha256": entry_sha256,
        "minimum_retention_until": minimum_retention_until,
        "entry": entry,
    }
    run = run_bounded_subprocess(
        command, input_text=_canonical_json_bytes(request).decode("utf-8") + "\n",
        timeout=60, stdout_max=64 * 1024, stderr_max=64 * 1024,
        description="terminal reservation archive")
    if run.returncode != 0:
        refuse("terminal reservation archive refused: %s" % run.stderr.strip()[:240])
    try:
        answer = strict_json_loads(
            run.stdout.encode("utf-8"), "terminal reservation archive response")
    except Exception as error:
        refuse("terminal reservation archive returned invalid JSON: %s" % error)
    if (not isinstance(answer, dict) or set(answer) != {
            "version", "stored", "durable", "entry_sha256",
            "readback_sha256", "archive_id", "object_lock_mode",
            "retention_until"} or
            answer.get("version") != TERMINAL_ARCHIVE_VERSION or
            answer.get("stored") is not True or
            answer.get("durable") is not True or
            answer.get("entry_sha256") != entry_sha256 or
            answer.get("readback_sha256") != entry_sha256 or
            not isinstance(answer.get("archive_id"), str) or
            not 1 <= len(answer["archive_id"]) <= 512 or
            answer.get("object_lock_mode") != "COMPLIANCE" or
            type(answer.get("retention_until")) is not int or
            answer["retention_until"] < minimum_retention_until):
        refuse("terminal reservation archive acknowledgement is invalid")
    return answer


def _make_tombstone(entry, beat, sequence, previous, archive_sha256):
    receipt = entry["receipt"]
    c1 = receipt.get("v") == sol.C1_RESERVATION_VERSION
    identity_fields = (C1_TOMBSTONE_IDENTITY_FIELDS
                       if c1 else TOMBSTONE_IDENTITY_FIELDS)
    record = {
        "version": C1_TOMBSTONE_VERSION if c1 else TOMBSTONE_VERSION,
        "kind": TOMBSTONE_KIND,
        "sequence": sequence,
        "prev_record_sha256": previous,
        "txid": entry["txid"],
        "signed_tx_sha256": entry["signed_tx_sha256"],
        "block_height": entry["block_height"],
        "block_hash": entry["block_hash"],
        "finalized_at_tip": beat["tip"],
        "finalized_at_tip_hash": beat["tip_hash"],
        "receipt_sha256": _receipt_full_sha256(receipt),
        "archive_entry_sha256": archive_sha256,
    }
    for field in identity_fields:
        record[field] = receipt[field]
    record["record_sha256"] = hashlib.sha256(_tombstone_payload(record)).hexdigest()
    _validate_tombstone(record, sequence, previous)
    return record


def _append_tombstone(paths, ledger, record, policy):
    if ledger["terminal_count"] >= policy["max_terminal_rows"]:
        refuse("terminal reservation tombstone row limit reached")
    line = _canonical_json_bytes(record) + b"\n"
    if len(line) > 16 * 1024:
        refuse("terminal reservation tombstone row exceeds size limit")
    expected_size = ledger.get("_terminal_size")
    if type(expected_size) is not int or expected_size < 1:
        refuse("terminal reservation log size checkpoint is invalid")
    if expected_size + len(line) > policy["max_terminal_bytes"]:
        refuse("terminal reservation tombstone byte limit reached")
    _require_write_capacity(paths, policy, len(line))
    _require_restore_clear(paths)
    flags = (os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_CLOEXEC", 0))
    fd = os.open(paths["terminal"], flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or
                info.st_size != expected_size):
            refuse("terminal reservation log changed outside the witness lock")
        offset = 0
        while offset < len(line):
            written = os.write(fd, line[offset:])
            if written <= 0:
                refuse("terminal reservation tombstone append made no progress")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    ledger["_terminals"].append(record)
    ledger["_terminal_size"] = expected_size + len(line)
    ledger["terminal_count"] += 1
    ledger["terminal_head_sha256"] = record["record_sha256"]


def _compact_terminal(paths, ledger, entry, beat, cfg):
    policy = _reservation_ledger_policy(
        cfg, production=isinstance(cfg, dict) and cfg.get("production") is True)
    if entry not in ledger["reservations"]:
        refuse("terminal reservation is not active")
    archive_entry = _terminal_archive_entry(entry, beat)
    archive_sha = hashlib.sha256(_canonical_json_bytes(archive_entry)).hexdigest()
    receipt = entry.get("receipt", {})
    c1 = receipt.get("v") == sol.C1_RESERVATION_VERSION
    if (entry.get("status") != "final" or
            type(entry.get("block_height")) is not int or
            entry["block_height"] < 0 or
            not isinstance(entry.get("block_hash"), str) or
            not sol.HASH256_RE.fullmatch(entry["block_hash"]) or
            type(beat.get("tip")) is not int or
            beat["tip"] < entry["block_height"] or
            beat["tip"] - entry["block_height"] + 1 <= MAX_REORG_DEPTH or
            not isinstance(beat.get("tip_hash"), str) or
            not sol.HASH256_RE.fullmatch(beat["tip_hash"])):
        refuse("terminal reservation lacks deep canonical evidence")

    # Check every local bound before causing an external WORM side effect.
    prospective = dict(ledger)
    prospective["reservations"] = [row for row in ledger["reservations"]
                                    if row is not entry]
    snapshot = _snapshot_text(prospective, policy).encode("utf-8")
    if c1:
        # MNP2's exact accepted effect is the lifetime consensus replay
        # authority for a public allocation.  Once that effect is strictly
        # deeper than the reorg bound and the complete randomized receipt is
        # read back under ten-year COMPLIANCE retention, keeping one local
        # tombstone per historic public index would recreate a deterministic
        # lifetime ceiling.  A crash before the snapshot replacement simply
        # retries the idempotent archive; a failed replacement leaves the old
        # active snapshot intact.
        _require_write_capacity(paths, policy, len(snapshot))
        _archive_terminal(archive_entry, archive_sha, policy)
        original_index = ledger["reservations"].index(entry)
        ledger["reservations"].remove(entry)
        try:
            _persist_ledger(paths, ledger, policy)
        except BaseException:
            ledger["reservations"].insert(original_index, entry)
            raise
        return

    record = _make_tombstone(
        entry, beat, ledger["terminal_count"] + 1,
        ledger["terminal_head_sha256"], archive_sha)
    line = _canonical_json_bytes(record) + b"\n"
    if (ledger["terminal_count"] >= policy["max_terminal_rows"] or
            ledger["_terminal_size"] + len(line) > policy["max_terminal_bytes"]):
        refuse("terminal reservation storage capacity is exhausted")
    _require_write_capacity(paths, policy, len(snapshot) + len(line))
    _archive_terminal(archive_entry, archive_sha, policy)
    _append_tombstone(paths, ledger, record, policy)
    ledger["reservations"].remove(entry)
    # Append-before-checkpoint makes a crash conservative: the loader accepts
    # only a chained tail that still has the byte-exact full receipt in active.
    _persist_ledger(paths, ledger, policy)


def _reconcile(ledger, beat, rpc, cfg=None, paths=None,
               allocation_ledger=None, allocation_policy_sha256=None,
               now=None, c1_policy=None):
    outstanding = 0
    for entry in list(ledger["reservations"]):
        confirmation = _canonical_confirmation(entry, beat, rpc)
        receipt = entry.get("receipt", {})
        c1 = receipt.get("v") == sol.C1_RESERVATION_VERSION
        if c1 and confirmation is not None:
            if (cfg is None or paths is None or allocation_ledger is None or
                    not isinstance(allocation_policy_sha256, str)):
                refuse("C1 mint-effect confirmation lacks allocation authority")
            _checkpoint_allocation_effect(
                cfg, paths, allocation_ledger, allocation_policy_sha256,
                receipt, True,
                int(time.time()) if now is None else now, c1_policy)
        elif (c1 and confirmation is None and allocation_ledger is not None and
              any(row.get("consensus_allocation_id") ==
                  receipt.get("allocation_request_id") and
                  row.get("minted_at") is not None
                  for row in allocation_ledger.get("allocations", []))):
            # A shallow reorg restores both the signer/witness charge and the
            # allocator's live liability before another allocation can pass.
            _checkpoint_allocation_effect(
                cfg, paths, allocation_ledger, allocation_policy_sha256,
                receipt, False,
                int(time.time()) if now is None else now, c1_policy)
        if confirmation is None:
            entry["status"] = "reserved"
            entry.pop("block_height", None)
            entry.pop("block_hash", None)
            sats = entry["receipt"]["sats"]
            if outstanding > sol.MAX_WIRE_INT - sats:
                refuse("outstanding reservation sum overflows")
            outstanding += sats
            continue
        confirmations, height, block_hash = confirmation
        entry["block_height"] = height
        entry["block_hash"] = block_hash
        if confirmations > MAX_REORG_DEPTH:
            entry["status"] = "final"
            if cfg is not None and paths is not None:
                _compact_terminal(paths, ledger, entry, beat, cfg)
        else:
            entry["status"] = "confirmed"
    return outstanding


def _sign_receipt(core, cfg):
    signer = cfg.get("signer") or {}
    keygen = cfg.get("keygen") or os.path.join(HERE, "veld-keygen")
    keyfile = signer.get("beat_keyfile")
    if not keyfile:
        refuse("beat_keyfile is required for reservation receipts")
    _secure_file(os.path.abspath(keyfile), private=True)
    environment = dict(os.environ)
    passfile = signer.get("beat_passfile")
    if passfile:
        passfile = os.path.abspath(passfile)
        _secure_file(passfile, private=True)
        environment["VELD_VAULT_PASSPHRASE"] = _read_text_nofollow(passfile).strip()
    with tempfile.TemporaryDirectory(prefix="veld-reservation-sign-") as td:
        message = os.path.join(td, "receipt.json")
        signature = os.path.join(td, "receipt.sig")
        with open(message, "wb") as out:
            out.write(sol.canonical_reservation_bytes(core))
        run = subprocess.run([keygen, "sign-release", keyfile, message, signature],
                             capture_output=True, text=True, timeout=30,
                             env=environment)
        if run.returncode != 0:
            refuse("reservation receipt signing failed")
        sig = open(signature, "rb").read()
    if not sig:
        refuse("reservation receipt signature is empty")
    result = dict(core)
    result["sig_alg"] = "mldsa65"
    result["sig"] = sig.hex()
    return result


def _validate_request(req, cfg, beat):
    issuer_id = req.get("issuer_id")
    if issuer_id != cfg.get("issuer_id") or not isinstance(issuer_id, str):
        refuse("issuer_id does not match witness policy")
    witness_id = cfg.get("witness_id")
    if not isinstance(witness_id, str) or not sol.IDENTIFIER_RE.fullmatch(witness_id):
        refuse("witness_id policy is invalid")
    for field in ("request_id", "unsigned_tx_sha256"):
        if not isinstance(req.get(field), str) or not sol.HASH256_RE.fullmatch(req[field]):
            refuse("%s is malformed" % field)
    try:
        sats = sol._wire_uint(req.get("sats"), "sats", positive=True)
    except ValueError as e:
        refuse(str(e))
    recipient = req.get("recipient")
    if not isinstance(recipient, str) or not (1 <= len(recipient) <= 128):
        refuse("recipient is malformed")
    if (req.get("beat_seq") != beat["seq"] or req.get("tip") != beat["tip"] or
            req.get("tip_hash") != beat["tip_hash"]):
        refuse("request is not bound to the witness's latest fresh beat")
    return issuer_id, witness_id, sats, recipient


def _derive_unsigned_mint(req, cfg):
    try:
        raw = sol.validate_unsigned_template_hex(req.get("unsigned_tx_hex"))
    except Exception as e:
        refuse("unsigned mint template is invalid: %s" % e)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != req.get("unsigned_tx_sha256") or digest != req.get("request_id"):
        refuse("request identifiers do not match unsigned transaction bytes")
    issuer_script = cfg.get("issuer_p2pkh_hex")
    if not isinstance(issuer_script, str) or not re.fullmatch(r"[0-9a-f]{50}", issuer_script):
        refuse("witness issuer_p2pkh_hex policy is missing/malformed")
    keygen = cfg.get("keygen") or os.path.join(HERE, "veld-keygen")
    run = subprocess.run([keygen, "decode-mint", issuer_script,
                          req["unsigned_tx_hex"]], capture_output=True,
                         text=True, timeout=30)
    if run.returncode != 0:
        refuse("unsigned transaction is not a canonical mint")
    try:
        decoded = json.loads(run.stdout)
    except Exception:
        refuse("decode-mint returned invalid JSON")
    if decoded.get("from") != cfg.get("issuer_id"):
        refuse("unsigned mint issuer differs from witness policy")
    try:
        derived_sats = sol._wire_uint(decoded.get("sats"), "decoded sats", positive=True)
    except ValueError as e:
        refuse(str(e))
    derived_recipient = decoded.get("to")
    if not isinstance(derived_recipient, str) or not (1 <= len(derived_recipient) <= 128):
        refuse("decoded mint recipient is invalid")
    if req.get("sats") != derived_sats or req.get("recipient") != derived_recipient:
        refuse("caller mint amount/recipient differs from independently decoded template")
    outpoint = None
    memo = decoded.get("memo")
    if cfg.get("production") is True:
        match = MNP2_MEMO_RE.fullmatch(memo) if isinstance(memo, str) else None
        allocation = req.get("allocation", {})
        if match is None or not BTC_OUTPOINT_RE.fullmatch(match.group(4)):
            refuse("canonical mint does not carry an allocation Bitcoin outpoint")
        if (match.group(1) != allocation.get("consensus_allocation_id") or
                match.group(2) != allocation.get("script_pubkey") or
                match.group(3) != allocation.get("commitment_blind")):
            refuse("canonical C1 mint does not consume its consensus reservation")
        try:
            vout = int(match.group(4).split(":", 1)[1])
        except (ValueError, OverflowError):
            refuse("mint allocation outpoint is malformed")
        if vout > 0xffffffff:
            refuse("mint allocation outpoint is non-canonical")
        # MNP2 is deliberately proofless/root-neutral: C1F1 must already have
        # inserted this key. Requiring or accepting an MNP1 proof here would
        # recreate the stale-root deadlock that the two-phase design removes.
        outpoint = match.group(4)
    return derived_sats, derived_recipient, outpoint


def handle_reserve(req, cfg, paths, ledger, beat, rpc,
                   allocation_ledger=None, btc=None, binding=None,
                   spv_height=None, c1_policy=None,
                   allocation_policy_sha256=None):
    derived_sats, derived_recipient, outpoint = _derive_unsigned_mint(req, cfg)
    issuer_id, witness_id, sats, recipient = _validate_request(req, cfg, beat)
    if derived_sats != sats or derived_recipient != recipient:
        refuse("decoded mint fields changed during allocation validation")
    # C5 closes first-seen reservations at the hard threshold, but an exact
    # request already durably reserved before recovery-only is lifecycle work.
    # Its request_id is the SHA-256 of the immutable unsigned transaction, so a
    # same-id mutation cannot manufacture a different mint template.
    prior_reservation = next((
        item for item in ledger.get("reservations", [])
        if item.get("receipt", {}).get("request_id") == req["request_id"]),
        None)
    verified_allocation = None
    outstanding = None
    if cfg.get("production") is True:
        if allocation_ledger is None or btc is None or binding is None:
            refuse("production allocation authority is unavailable")
        try:
            verified_allocation = _verify_allocation_deposit(
                req.get("allocation"), recipient, sats, outpoint,
                allocation_ledger, btc, binding, spv_height,
                c1_policy=c1_policy,
                allocation_policy_sha256=allocation_policy_sha256,
                # Observe and durably record already-admitted funding even in
                # recovery-only. The first-seen reservation gate below still
                # refuses new mint liability at the hard threshold.
                allow_recovery_only_lifecycle=True)
        except SystemExit:
            raise
        except Exception as e:
            refuse("independent allocation/deposit verification failed: %s" % e)
        if c1_policy is not None:
            observed = int(time.time())
            changed = False
            if verified_allocation.get("deposit_observed_at") is None:
                if observed >= verified_allocation["expires_at"]:
                    refuse("LATE_DEPOSIT_MANUAL_RECOVERY: unfunded allocation expired")
                verified_allocation["deposit_observed_at"] = observed
                allocation_ledger["events"].append({
                    "action": "deposit_observed", "at": observed,
                    "request_id": verified_allocation["request_id"],
                })
                changed = True
            if changed:
                raw = (json.dumps(allocation_ledger, sort_keys=True,
                                  separators=(",", ":")) + "\n").encode()
                if not _c1_storage_allows(
                        len(allocation_ledger["allocations"]) +
                        len(allocation_ledger["events"]), len(raw), c1_policy,
                        new_admission=False):
                    refuse("allocation lifecycle journal hard capacity reached")
                _require_restore_clear(paths)
                atomic_write(paths["allocations"], raw.decode("utf-8"))
                _checkpoint_allocation_ledger(
                    cfg, allocation_ledger, allocation_policy_sha256, "store")

            # Reconcile the monetary phase first.  On a reorg that removes
            # both MNP2 and its underlying C1F1, this clears minted_at while
            # the exact signer reservation remains charged, before the funded
            # mirror is allowed to roll back.
            outstanding = _reconcile(
                ledger, beat, rpc, cfg, paths, allocation_ledger,
                allocation_policy_sha256, now=observed,
                c1_policy=c1_policy)
            _reconcile_c1_funded_reservation(
                cfg, paths, allocation_ledger, allocation_policy_sha256,
                verified_allocation, beat, rpc, observed, c1_policy)

            # This is the decisive phase boundary. A confirmed Bitcoin UTXO
            # alone cannot authorize MNP2; require canonical C1F1 and the exact
            # shared-nullifier consumer before reserving signer headroom.
            _verify_c1_funded_reservation(
                verified_allocation, outpoint, beat, rpc)
            if verified_allocation.get("funded_reserved_at") is None:
                _checkpoint_funded_reservation(
                    cfg, paths, allocation_ledger,
                    allocation_policy_sha256, verified_allocation, outpoint,
                    True, observed, c1_policy)
        if (getattr(btc, "last_c5_phase", None) == "RECOVERY_ONLY" and
                prior_reservation is None):
            refuse("RECOVERY_ONLY: new mint reservations are halted; "
                   "funding observation was preserved for recovery")
    # Receipt identity uses the monotonic consensus allocation id, not the
    # wallet's random retry capability.  The exact unsigned transaction hash
    # simultaneously binds the commitment blind carried by MNP2.
    allocation_request_id = (
        verified_allocation["consensus_allocation_id"]
        if verified_allocation is not None and c1_policy is not None
        else (verified_allocation["request_id"]
              if verified_allocation is not None else None))
    rid = sol.reservation_id(
        issuer_id, req["request_id"], req["unsigned_tx_sha256"], sats,
        recipient, outpoint, allocation_request_id)
    if outstanding is None:
        outstanding = _reconcile(
            ledger, beat, rpc, cfg, paths, allocation_ledger,
            allocation_policy_sha256, c1_policy=c1_policy)
    existing = next((x for x in ledger["reservations"]
                     if x["receipt"]["reservation_id"] == rid), None)
    terminal = next((x for x in ledger.get("_terminals", [])
                     if x["reservation_id"] == rid), None)
    if terminal is not None:
        refuse("reservation is already terminal; recover/replay its exact signed bytes")
    same_request = next((x for x in ledger["reservations"]
                         if x["receipt"]["request_id"] == req["request_id"]), None)
    terminal_request = next((x for x in ledger.get("_terminals", [])
                             if x["request_id"] == req["request_id"]), None)
    if same_request is not None and same_request["receipt"]["reservation_id"] != rid:
        refuse("request_id was reused with mutated mint parameters")
    if terminal_request is not None:
        refuse("request_id is already terminal and cannot be re-signed")
    if verified_allocation is not None:
        same_outpoint = next((x for x in ledger["reservations"]
                              if x["receipt"].get("deposit_outpoint") == outpoint), None)
        terminal_outpoint = next((x for x in ledger.get("_terminals", [])
                                  if x.get("deposit_outpoint") == outpoint), None)
        if same_outpoint is not None and same_outpoint["receipt"]["reservation_id"] != rid:
            refuse("Bitcoin deposit outpoint is already bound to a different mint request")
        if terminal_outpoint is not None:
            refuse("Bitcoin deposit outpoint is already terminal")
        same_allocation = next((x for x in ledger["reservations"]
                                if x["receipt"].get("allocation_request_id") ==
                                allocation_request_id), None)
        terminal_allocation = next((x for x in ledger.get("_terminals", [])
                                    if x.get("allocation_request_id") ==
                                    allocation_request_id), None)
        if (same_allocation is not None and
                same_allocation["receipt"]["reservation_id"] != rid):
            refuse("wrap allocation is already bound to a different mint request/outpoint")
        if terminal_allocation is not None:
            refuse("wrap allocation is already terminal")
    if outstanding > beat["headroom_sats"]:
        refuse("existing reservations exceed fresh watchtower headroom")
    if existing is None and outstanding + sats > beat["headroom_sats"]:
        refuse("reservation would exceed fresh watchtower headroom")
    policy = _reservation_ledger_policy(
        cfg, production=isinstance(cfg, dict) and cfg.get("production") is True)
    if existing is None and len(ledger["reservations"]) >= policy["max_active_rows"]:
        refuse("active reservation row limit reached")

    c1_receipt = verified_allocation is not None and c1_policy is not None
    core = {
        "v": (sol.C1_RESERVATION_VERSION if c1_receipt
              else sol.RESERVATION_VERSION),
        "kind": sol.RESERVATION_KIND,
        "issuer_id": issuer_id,
        "witness_id": witness_id,
        "request_id": req["request_id"],
        "unsigned_tx_sha256": req["unsigned_tx_sha256"],
        "reservation_id": rid,
        "sats": sats,
        "recipient": recipient,
        "beat_seq": beat["seq"],
        "tip": beat["tip"],
        "tip_hash": beat["tip_hash"],
        "headroom_sats": beat["headroom_sats"],
        "reserved_at": int(time.time()),
        "allocation_verified": verified_allocation is not None,
        "allocation_request_id": allocation_request_id,
        "allocation_descriptor_index": (verified_allocation["descriptor_index"]
                                         if verified_allocation is not None else None),
        "allocation_btc_address": (verified_allocation["btc_address"]
                                   if verified_allocation is not None else None),
        "allocation_script_pubkey": (verified_allocation["script_pubkey"]
                                     if verified_allocation is not None else None),
        "deposit_outpoint": outpoint,
    }
    if c1_receipt:
        if (not isinstance(allocation_policy_sha256, str) or
                not sol.HASH256_RE.fullmatch(allocation_policy_sha256) or
                not _c1_public_index_allowed(
                    verified_allocation["descriptor_index"], c1_policy)):
            refuse("C1 reservation policy/index binding is unavailable")
        core.update({
            "allocation_capacity_policy_sha256": allocation_policy_sha256,
            "allocation_public_descriptor_range_start":
                c1_policy["public_descriptor_range"][0],
            "allocation_public_descriptor_range_end":
                c1_policy["public_descriptor_range"][1],
        })
    receipt = _sign_receipt(core, cfg)
    if existing is None:
        ledger["reservations"].append({"receipt": receipt, "status": "reserved"})
    else:
        old = existing["receipt"]
        identity_fields = [
            "issuer_id", "request_id", "unsigned_tx_sha256", "sats", "recipient",
            "allocation_verified", "allocation_request_id",
            "allocation_descriptor_index", "allocation_btc_address",
            "allocation_script_pubkey", "deposit_outpoint",
        ]
        for field in identity_fields:
            if old[field] != receipt[field]:
                refuse("reservation identity was reused with mutated parameters")
        if c1_receipt and not _c1_receipt_policy_refresh_allowed(
                old, c1_policy, allocation_policy_sha256):
            refuse("active reservation C1 policy binding cannot be refreshed")
        existing["receipt"] = receipt
    _persist_ledger(paths, ledger, policy)
    return {"receipt": receipt, "idempotent": existing is not None}


def handle_commit(req, cfg, paths, ledger):
    rid = req.get("reservation_id")
    signed_hex = req.get("signed_tx_hex")
    if not isinstance(rid, str) or not sol.HASH256_RE.fullmatch(rid):
        refuse("commit reservation_id is malformed")
    entry = next((x for x in ledger["reservations"]
                  if x["receipt"]["reservation_id"] == rid), None)
    terminal = next((x for x in ledger.get("_terminals", [])
                     if x["reservation_id"] == rid), None)
    if entry is None and terminal is None:
        refuse("unknown reservation_id")
    try:
        unsigned_hex = sol.unsigned_template_from_signed_hex(signed_hex)
        unsigned_bytes = bytes.fromhex(unsigned_hex)
        signed_bytes = bytes.fromhex(signed_hex)
    except Exception as e:
        refuse("signed transaction binding failed: %s" % e)
    receipt = entry["receipt"] if entry is not None else terminal
    unsigned_sha256 = hashlib.sha256(unsigned_bytes).hexdigest()
    if (unsigned_sha256 != receipt["unsigned_tx_sha256"] or
            unsigned_sha256 != receipt["request_id"]):
        refuse("signed transaction does not reconstruct the reserved unsigned template")
    txid = hashlib.sha256(hashlib.sha256(signed_bytes).digest()).hexdigest()
    claimed_txid = req.get("txid")
    if claimed_txid != txid:
        refuse("commit txid does not match signed transaction bytes")
    issuer_script = cfg.get("issuer_p2pkh_hex")
    if not isinstance(issuer_script, str) or not re.fullmatch(r"[0-9a-f]{50}", issuer_script):
        refuse("witness issuer_p2pkh_hex policy is missing/malformed")
    keygen = cfg.get("keygen") or os.path.join(HERE, "veld-keygen")
    run = subprocess.run([keygen, "decode-mint", issuer_script, unsigned_hex],
                         capture_output=True, text=True, timeout=30)
    if run.returncode != 0:
        refuse("committed transaction is not a canonical reserved mint")
    try:
        decoded = json.loads(run.stdout)
    except Exception:
        refuse("decode-mint returned invalid JSON")
    if (decoded.get("from") != receipt["issuer_id"] or
            decoded.get("to") != receipt["recipient"] or
            decoded.get("sats") != receipt["sats"]):
        refuse("committed mint fields differ from reservation receipt")
    if receipt.get("allocation_verified") is True:
        memo = decoded.get("memo")
        match = MNP2_MEMO_RE.fullmatch(memo) if isinstance(memo, str) else None
        if (match is None or
                match.group(1) != receipt.get("allocation_request_id") or
                match.group(2) != receipt.get("allocation_script_pubkey") or
                match.group(4) != receipt.get("deposit_outpoint")):
            refuse("committed mint outpoint differs from reservation receipt")
    signed_digest = hashlib.sha256(signed_bytes).hexdigest()
    if terminal is not None:
        if (terminal["txid"] != txid or
                terminal["signed_tx_sha256"] != signed_digest):
            refuse("terminal reservation is bound to different exact signed bytes")
        return {"reservation_id": rid, "txid": txid, "committed": True,
                "terminal": True}
    if entry.get("txid") not in (None, txid):
        refuse("reservation is already bound to a different signed txid")
    entry["txid"] = txid
    entry["signed_tx_sha256"] = signed_digest
    policy = _reservation_ledger_policy(
        cfg, production=isinstance(cfg, dict) and cfg.get("production") is True)
    _persist_ledger(paths, ledger, policy)
    return {"reservation_id": rid, "txid": txid, "committed": True}


def main():
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw) > MAX_STDIN:
        refuse("request exceeds size limit")
    try:
        req = strict_json_loads(raw, "witness request")
        config_path = os.path.abspath(CONFIG)
        _secure_file(config_path, private=True)
        cfg = strict_json_loads(
            _read_text_nofollow(config_path), "witness configuration")
    except Exception as e:
        refuse("request/config decode failed: %s" % e)
    if not isinstance(req, dict) or not isinstance(cfg, dict):
        refuse("request/config root is invalid")
    _require_production_reservation_service(cfg)
    paths = _paths(cfg)
    _require_restore_clear(paths)
    with exclusive_witness_state_lock(paths):
        _require_restore_clear(paths)
        ledger = _load_ledger(paths["ledger"], cfg)
        policy = _reservation_ledger_policy(cfg, production=True)
        if ledger.get("_needs_checkpoint"):
            _persist_ledger(paths, ledger, policy)
        if req.get("action") == "commit":
            answer = handle_commit(req, cfg, paths, ledger)
        elif req.get("action") == "reserve":
            beat = _load_beat(paths["beat"], time.time())
            rpc = VeldRpc(cfg.get("veld_rpc"))
            if not _tip_matches(beat, rpc):
                refuse("fresh beat tip is not canonical on the witness node")
            # main() is production-only.  Keep these calls unconditional so a
            # future refactor cannot reintroduce a config-dependent bypass.
            c1_policy, allocation_policy_sha256 = _load_signed_c1_policy(cfg)
            binding = custody_binding.load_manifest(
                cfg.get("custody_spk_manifest_file"),
                cfg.get("custody_descriptor_sha256"),
                cfg.get("custody_manifest_sha256"),
                expected_range_end=c1_policy["public_descriptor_range"][1],
                expected_consensus_manifest_sha256=cfg.get(
                    "custody_consensus_manifest_sha256"))
            btc = BitcoinCli(cfg.get("btc"))
            custody_binding.verify_core_derivation(btc.call, binding)
            spv_height = _verify_forced_command_peg_policy(rpc, cfg, binding)
            allocation_ledger = _load_allocation_ledger(
                paths["allocations"], cfg, binding, c1_policy,
                allocation_policy_sha256)
            if not _activate_allocation_policy_update(
                    cfg, paths, allocation_ledger,
                    allocation_policy_sha256):
                _checkpoint_allocation_ledger(
                    cfg, allocation_ledger,
                    allocation_policy_sha256, "verify")
            answer = handle_reserve(
                req, cfg, paths, ledger, beat, rpc,
                allocation_ledger, btc, binding, spv_height,
                c1_policy, allocation_policy_sha256)
            if not _tip_matches(beat, rpc):
                refuse("canonical tip changed during reservation reconciliation")
        else:
            refuse("unknown action")
        _require_restore_clear(paths)
    sys.stdout.write(json.dumps(answer, sort_keys=True, separators=(",", ":")) + "\n")


def allocation_main(initialize=False):
    """Dedicated forced-command entry point for the public wrap allocator.

    The mint coordinator's SSH key cannot invoke this function: deployment uses
    a distinct authorized_keys forced command that runs ``veld_wt_allocate.py``.
    """
    try:
        config_path = os.path.abspath(CONFIG)
        _secure_file(config_path, private=True)
        cfg = strict_json_loads(
            _read_text_nofollow(config_path), "witness configuration")
    except Exception as e:
        refuse("allocation witness config decode failed: %s" % e)
    if not isinstance(cfg, dict) or cfg.get("production") is not True:
        refuse("allocation witness requires production=true")
    paths = _paths(cfg)
    _require_restore_clear(paths)
    c1_policy, policy_sha256 = _load_signed_c1_policy(cfg)
    _require_supported_allocation_range(c1_policy)
    binding = custody_binding.load_manifest(
        cfg.get("custody_spk_manifest_file"),
        cfg.get("custody_descriptor_sha256"),
        cfg.get("custody_manifest_sha256"),
        expected_range_end=c1_policy["public_descriptor_range"][1],
        expected_consensus_manifest_sha256=cfg.get(
            "custody_consensus_manifest_sha256"))
    btc = BitcoinCli(cfg.get("btc"))
    custody_binding.verify_core_derivation(btc.call, binding)
    policy = _allocation_policy(cfg, require_c1=True)
    _require_allocation_service_mode(policy, initialize)
    with exclusive_witness_state_lock(paths):
        _require_restore_clear(paths)
        if initialize:
            if os.path.lexists(paths["allocations"]):
                refuse("allocation authority ledger already exists")
            ledger = _empty_allocation_ledger(cfg, c1_policy, policy_sha256)
            _require_restore_clear(paths)
            atomic_write(paths["allocations"], json.dumps(
                ledger, sort_keys=True, separators=(",", ":")) + "\n")
            _checkpoint_allocation_ledger(
                cfg, ledger, policy_sha256, "store")
            answer = {"version": 2, "initialized": True,
                      "path": paths["allocations"],
                      "capacity_policy_sha256": policy_sha256}
        else:
            raw = sys.stdin.buffer.read(MAX_STDIN + 1)
            if len(raw) > MAX_STDIN:
                refuse("allocation registration exceeds size limit")
            try:
                req = strict_json_loads(raw, "allocation registration")
            except Exception as e:
                refuse("allocation registration decode failed: %s" % e)
            ledger = _load_allocation_ledger(
                paths["allocations"], cfg, binding, c1_policy, policy_sha256)
            if not _activate_allocation_policy_update(
                    cfg, paths, ledger, policy_sha256):
                _checkpoint_allocation_ledger(
                    cfg, ledger, policy_sha256, "verify")
            backend = None
            if req.get("action") in (
                    "preflight_allocation", "register_allocation"):
                observed = int(time.time())
                beat = _load_beat(paths["beat"], observed)
                rpc = VeldRpc(cfg.get("veld_rpc"))
                if not _tip_matches(beat, rpc):
                    refuse("fresh beat tip is not canonical before allocation reconciliation")
                backend = _verify_public_allocation_backend(
                    cfg, c1_policy, now=observed, rpc=rpc)
                if (backend["veld_tip"] != beat.get("tip") or
                        backend["veld_tip_hash"] != beat.get("tip_hash") or
                        backend["supply_sats"] != beat.get("supply_sats")):
                    refuse("signed beat and allocation capacity tuple differ")
                reservation_policy = _reservation_ledger_policy(
                    cfg, production=True)
                reservations = _load_ledger(paths["ledger"], cfg)
                if reservations.get("_needs_checkpoint"):
                    _persist_ledger(paths, reservations, reservation_policy)
                _reconcile(
                    reservations, beat, rpc, cfg, paths, ledger,
                    policy_sha256, now=observed, c1_policy=c1_policy)
                # Reservation status and every allocation effect reversal are
                # durable before an address can be admitted/returned.
                _persist_ledger(paths, reservations, reservation_policy)
                if (time.time() > float(beat["expires_at"]) or
                        not _tip_matches(beat, rpc)):
                    refuse("canonical tip changed during allocation reconciliation")
            answer = handle_register_allocation(
                req, cfg, paths, ledger, binding, c1_policy, policy_sha256,
                issuer_headroom_sats=(backend["issuer_headroom_sats"]
                                      if backend is not None else None),
                issuer_reserved_sats=(backend["issuer_reserved_sats"]
                                      if backend is not None else None))
            if (backend is not None and
                    (time.time() > float(beat["expires_at"]) or
                     not _tip_matches(beat, rpc))):
                refuse("canonical tip changed/beat expired during allocation admission")
        _require_restore_clear(paths)
    sys.stdout.write(json.dumps(
        answer, sort_keys=True, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    main()
