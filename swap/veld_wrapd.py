#!/usr/bin/env python3
"""
veld_wrapd.py - btcVELD WRAP-request service (the mint leg's front door).

Runs on the CUSTODY box next to veld_mintd.py. Given a VELD address, it records a
fresh, UNIQUE Bitcoin custody deposit address whose bitcoind LABEL is that VELD
address, then drives the issuer-signed C1R1 reservation and C1E1 exposure
markers.  The address and script never leave the service until C1E1 is 101-deep.
An exposed but unfunded lease has a finite consensus expiry. C1F1 proves the
exact Bitcoin funding and consumes its shared nullifier; that funded capacity
then remains occupied until the root-neutral matching MNP2 credits the user.

  POST /wrap   {"veld_address":"V...","amount_sats":62500}
      -> {"btc_address":"bc1p...","amount_sats":62500,"mint_path":"issuer",...}
  GET  /health                          -> {"ok":true,...}

`/wrap` is intentionally the issuer-authorized fallback only.  It never
constructs the fixed-index custody output + recipient OP_RETURN required by the
launch-live permissionless SPV path; operators use `veld_spvmint.py deposit`
for that explicit flow.

Hardened: strict VELD-address validation (no shell/label injection), a per-IP +
global rate limit (deposit-address issuance is cheap but must not be a DoS or a
custody-wallet address-bloat vector), bounded request body, localhost bind (the
wallet reaches it via an nginx TLS proxy, same pattern as swapd). It NEVER moves
BTC and holds no keys. Production selects from a ceremony-preissued descriptor
pool and applies an idempotent label; it never advances the descriptor cursor.
"""
from collections import OrderedDict, deque
import hashlib
import io
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qsl, urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_custody_binding as custody_binding  # noqa: E402
from btcveld_c1 import allocation_commitment, allocation_id  # noqa: E402
from rpc_url_policy import (load_bounded_json_response, open_rpc_request,
                            read_bounded_secret_file,
                            run_bounded_subprocess,
                            validate_backend_rpc_url)  # noqa: E402
from swapd_http_security import (BoundedThreadingTCPServer,
                                 HeaderBudgetReader, RequestSourceError,
                                 bounded_json_int, exact_json_bool,
                                 read_owner_file, request_source,
                                 strict_json_object)  # noqa: E402
from swap_admission import (ADMISSION_EPOCH_SECONDS as C1_ADMISSION_EPOCH_SECONDS,
                            ADMISSION_POW_BITS as C1_ADMISSION_POW_BITS,
                            AdmissionBeacon, has_leading_zero_bits,
                            principal_hash as admission_principal_hash,
                            verify_mldsa65_with_keygen)  # noqa: E402

# Strict validator: a VELD base58check address (same shape the daemons enforce).
VELD_ADDR_RE = re.compile(r'^V[1-9A-HJ-NP-Za-km-z]{25,49}$')
MAX_BODY = 16 * 1024
MAX_CONFIG_BYTES = 1_048_576
MAX_CLI_STDOUT = 8 * 1024 * 1024
MAX_CLI_STDERR = 16 * 1024
MAX_TOKEN_BYTES = 4096
MAX_MONEY_SATS = 2_100_000_000_000_000
ALLOCATION_JOURNAL_VERSION = 6
LEGACY_FIXTURE_JOURNAL_VERSION = 2
ALLOCATION_REQUEST_RE = re.compile(r"[0-9a-f]{32}")
PRINCIPAL_HASH_RE = re.compile(r"[0-9a-f]{64}")
HEX64_RE = re.compile(r"[0-9a-f]{64}")
MLDSA65_PUBLIC_KEY_RE = re.compile(r"[0-9a-f]{3904}")
MLDSA65_SIGNATURE_RE = re.compile(r"[0-9a-f]{6618}")
C1_POLICY_VERSION = 1
C1_OPERATOR_RANGE = [0, 999]
C1_PUBLIC_RANGE_START = 1000
C1_INITIAL_PUBLIC_RANGE_END = 10999
C1_MIN_ALLOCATION_SATS = 10_000
C1_PRINCIPAL_LIFETIME_SATS = 1_000_000_000
C1_DESTINATION_LIFETIME_SATS = 1_000_000_000
C1_CONSENSUS_CUSTODY_CEILING_SATS = 1_000_000_000
C1_GLOBAL_PER_EPOCH = 5
C1_GLOBAL_PER_DAY = 200
C1_EXPIRY_SECONDS = 7 * 24 * 60 * 60
C1_RESERVATION_FINALITY_DEPTH = 101
C1_RESERVATION_LIFETIME_BLOCKS = 7 * 480
C1_UINT64_MAX = (1 << 64) - 1
C1_JOURNAL_MAX_ROWS = 100_000
C1_JOURNAL_MAX_BYTES = 64 * 1024 * 1024
C1_LIFECYCLE_RESERVE_PERCENT = 10
C1_FRESHNESS_ALERT_SECONDS = 3_600
C1_FRESHNESS_RECOVERY_ONLY_SECONDS = 7_200
# F4 is deliberately a fail-closed launch boundary.  The current external
# checkpoint contract authenticates one complete local journal, but it does
# not provide authenticated keyed archive lookups.  Removing a terminal row
# without that lookup would lose exact request replay, lifetime quota, and
# random descriptor-index no-reuse authority.  Keep parsing successor policy
# records (so their signatures can be inspected), but do not activate an
# expanded range until the versioned F4 archive/index protocol exists.
C1_ALLOCATION_ROTATION_PROTOCOL_VERSION = 0
C1_CONSENSUS_CAPACITY_WARNING = (
    "the send cutoff is advisory: Bitcoin stalls or reorgs can require "
    "recovery; unfunded capacity expires at funding_expires_height, while "
    "C1F1-funded capacity remains held until the exact MNP2 mint"
)
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


class _JournalNotPublishedError(RuntimeError):
    """A journal save failed before atomic replacement became visible."""


class ExpiredAllocation(RuntimeError):
    """An exact retry reached the unfunded expiry boundary."""

    def __init__(self, expires_at):
        super().__init__("unfunded allocation has expired")
        self.expires_at = expires_at


class PendingConsensusReservation(RuntimeError):
    """The exact allocation is durable, but its C1E1 is not deep enough."""

    def __init__(self, status):
        super().__init__("consensus capacity reservation is pending")
        self.status = status


def load_configuration(path):
    """Read one strict, bounded, owner-only service configuration."""
    if path is None:
        return {}
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError("wrap configuration path must be absolute")
    try:
        return strict_json_object(
            read_owner_file(path, MAX_CONFIG_BYTES, "wrap configuration"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise RuntimeError("wrap configuration is not strict UTF-8 JSON: %s" % exc) from exc


def _command_argv(value, description):
    if (not isinstance(value, list) or not 1 <= len(value) <= 64
            or any(not isinstance(item, str) or not item
                   or len(item) > 4096 or "\x00" in item for item in value)):
        raise RuntimeError("%s must be a non-empty bounded argv list" % description)
    if not os.path.isabs(value[0]):
        raise RuntimeError("%s executable must be an absolute path" % description)
    return tuple(value)


def _cors_origin(value, production):
    # Same-origin reverse-proxy deployments need no CORS header.  If an operator
    # deliberately enables cross-origin access, bind it to one exact HTTPS origin.
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise RuntimeError("cors_origin must be null or one exact origin")
    if value == "*":
        if production:
            raise RuntimeError("production cors_origin must not be a wildcard")
        return value
    try:
        parsed = urlsplit(value)
        parsed.port
    except ValueError as exc:
        raise RuntimeError("cors_origin is malformed") from exc
    if (parsed.scheme not in (("https",) if production else ("http", "https"))
            or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.path or parsed.query
            or parsed.fragment or value != "%s://%s" %
            (parsed.scheme, parsed.netloc)):
        raise RuntimeError(
            "cors_origin must be one exact %s origin without credentials or a path" %
            ("HTTPS" if production else "HTTP(S)"))
    return value


def validate_c1_policy(policy):
    """Validate the exact production C1 contract.

    The public range end is the only raiseable scalar.  A deployed journal
    separately pins the highest sequence/range it has observed, preventing a
    locally replayed older signed record from lowering or reusing indices.
    """
    if not isinstance(policy, dict) or set(policy) != C1_POLICY_KEYS:
        raise RuntimeError("signed C1 capacity policy schema is not exact")
    exact = {
        "version": C1_POLICY_VERSION,
        "pow_bits": C1_ADMISSION_POW_BITS,
        "epoch_seconds": C1_ADMISSION_EPOCH_SECONDS,
        "global_allocations_per_epoch": C1_GLOBAL_PER_EPOCH,
        "global_allocations_per_day": C1_GLOBAL_PER_DAY,
        "principal_lifetime_sats": C1_PRINCIPAL_LIFETIME_SATS,
        "destination_lifetime_sats": C1_DESTINATION_LIFETIME_SATS,
        "consensus_custody_ceiling_sats": C1_CONSENSUS_CUSTODY_CEILING_SATS,
        "minimum_allocation_sats": C1_MIN_ALLOCATION_SATS,
        "unfunded_expiry_seconds": C1_EXPIRY_SECONDS,
        "operator_descriptor_range": C1_OPERATOR_RANGE,
        "journal_max_rows": C1_JOURNAL_MAX_ROWS,
        "journal_max_bytes": C1_JOURNAL_MAX_BYTES,
        "lifecycle_reserve_percent": C1_LIFECYCLE_RESERVE_PERCENT,
        "bitcoin_freshness_alert_seconds": C1_FRESHNESS_ALERT_SECONDS,
        "bitcoin_recovery_only_seconds": C1_FRESHNESS_RECOVERY_ONLY_SECONDS,
        "peg_unlock_required": True,
        "archive_ack_required": True,
    }
    for name, expected in exact.items():
        if policy.get(name) != expected or type(policy.get(name)) is not type(expected):
            raise RuntimeError("signed C1 policy field %s differs from owner record" % name)
    sequence = policy.get("record_sequence")
    previous = policy.get("previous_policy_sha256")
    public_range = policy.get("public_descriptor_range")
    authority = policy.get("archive_authority_id")
    if (type(sequence) is not int or sequence < 1 or sequence > 0xffffffff or
            not isinstance(previous, str) or not HEX64_RE.fullmatch(previous) or
            not isinstance(public_range, list) or len(public_range) != 2 or
            type(public_range[0]) is not int or type(public_range[1]) is not int or
            public_range[0] != C1_PUBLIC_RANGE_START or
            public_range[1] < C1_INITIAL_PUBLIC_RANGE_END or
            public_range[1] > 1_000_000 or
            not isinstance(authority, str) or not 8 <= len(authority) <= 256 or
            authority.startswith("REPLACE_")):
        raise RuntimeError("signed C1 policy record/range/archive authority is malformed")
    if sequence == 1 and (previous != "0" * 64 or
                          public_range[1] != C1_INITIAL_PUBLIC_RANGE_END):
        raise RuntimeError("initial signed C1 record must pin range 1000-10999")
    if sequence > 1 and previous == "0" * 64:
        raise RuntimeError("raised C1 policy record must link its predecessor")
    return dict(policy)


def _c1_public_index_allowed(index, policy):
    return (type(index) is int and isinstance(policy, dict) and
            isinstance(policy.get("public_descriptor_range"), list) and
            policy["public_descriptor_range"][0] <= index <=
            policy["public_descriptor_range"][1])


def require_supported_allocation_range(policy):
    """Refuse a range raise until F4 has an authenticated rotation index.

    This does not rewrite or lower a signed owner record.  It prevents a
    successor from being activated by code that would eventually forget used
    indexes, exact requests, and lifetime quotas at the fixed journal bound.
    """
    validated = validate_c1_policy(policy)
    if (C1_ALLOCATION_ROTATION_PROTOCOL_VERSION != 1 and
            validated["public_descriptor_range"][1] !=
            C1_INITIAL_PUBLIC_RANGE_END):
        raise RuntimeError(
            "C1_RANGE_ROTATION_REQUIRED: signed descriptor range expansion "
            "cannot activate until the audited F4 WORM archive/index "
            "protocol is implemented")
    return validated


def _absolute_config_path(conf, name):
    path = conf.get(name) if isinstance(conf, dict) else None
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        raise RuntimeError("%s must be one absolute path" % name)
    return path


def load_signed_c1_policy(conf):
    """Load and verify the one byte-identical allocator/witness policy file."""
    policy_path = _absolute_config_path(conf, "public_capacity_config_file")
    signature_path = _absolute_config_path(
        conf, "public_capacity_config_signature_file")
    public_key_path = _absolute_config_path(
        conf, "public_capacity_config_public_key_file")
    verifier = _absolute_config_path(conf, "admission_verifier")
    raw = read_owner_file(policy_path, MAX_CONFIG_BYTES, "signed C1 capacity policy")
    signature_raw = read_owner_file(
        signature_path, 16 * 1024, "signed C1 policy signature")
    public_key_raw = read_owner_file(
        public_key_path, 16 * 1024, "signed C1 policy public key")
    try:
        signature = signature_raw.decode("ascii", "strict").strip()
        public_key = public_key_raw.decode("ascii", "strict").strip()
    except UnicodeError as exc:
        raise RuntimeError("signed C1 policy identity is not canonical ASCII") from exc
    if (not MLDSA65_PUBLIC_KEY_RE.fullmatch(public_key or "") or
            not MLDSA65_SIGNATURE_RE.fullmatch(signature or "") or
            not verify_mldsa65_with_keygen(public_key, raw, signature, verifier)):
        raise RuntimeError("signed C1 capacity policy signature is invalid")
    try:
        policy = strict_json_object(raw)
    except ValueError as exc:
        raise RuntimeError("signed C1 capacity policy is not strict JSON") from exc
    return validate_c1_policy(policy), hashlib.sha256(raw).hexdigest()


def validate_configuration(conf):
    """Return exact scalar settings without permissive Python coercions."""
    if not isinstance(conf, dict):
        raise RuntimeError("wrap configuration must be a JSON object")
    production = exact_json_bool(conf.get("production", False), "production")
    unsafe_development = exact_json_bool(
        conf.get("development_only_allow_unsafe_allocator", False),
        "development_only_allow_unsafe_allocator")
    if production and unsafe_development:
        raise RuntimeError(
            "development_only_allow_unsafe_allocator must be false in production")
    if production:
        required_policy = {
            "public_capacity_policy_version", "rl_per_ip_per_min",
            "rl_global_per_min", "allocation_store",
            "allow_initial_allocation_store_creation",
            "allocation_witness_command",
            "allocation_checkpoint_command", "admission_verifier",
            "consensus_reservation_command",
            "public_capacity_config_file",
            "public_capacity_config_signature_file",
            "public_capacity_config_public_key_file",
        }
        missing = sorted(required_policy - set(conf))
        if missing:
            raise RuntimeError(
                "production public-capacity policy is incomplete: %s" %
                ",".join(missing))
        if conf.get("public_capacity_policy_version") != 2:
            raise RuntimeError(
                "public_capacity_policy_version must be the JSON integer 2")
    bind = conf.get("bind", "127.0.0.1")
    if bind != "127.0.0.1":
        raise RuntimeError("bind must be the exact loopback address 127.0.0.1")
    wallet = conf.get("wallet", "custody")
    if (not isinstance(wallet, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", wallet)):
        raise RuntimeError("wallet must be a bounded Bitcoin Core wallet name")
    allocation_store = conf.get(
        "allocation_store", "/var/lib/veld-wrapd/allocations.json")
    if (not isinstance(allocation_store, str) or not allocation_store
            or (production and not os.path.isabs(allocation_store))):
        raise RuntimeError(
            "production allocation_store must be one absolute non-empty path")
    allocation_witness_command = conf.get("allocation_witness_command")
    if production:
        allocation_witness_command = _command_argv(
            allocation_witness_command, "allocation_witness_command")
    elif allocation_witness_command is not None:
        allocation_witness_command = _command_argv(
            allocation_witness_command, "allocation_witness_command")
    checkpoint_command = conf.get("allocation_checkpoint_command")
    if production:
        checkpoint_command = _command_argv(
            checkpoint_command, "allocation_checkpoint_command")
        for name in ("admission_verifier", "public_capacity_config_file",
                     "public_capacity_config_signature_file",
                     "public_capacity_config_public_key_file"):
            _absolute_config_path(conf, name)
    elif checkpoint_command is not None:
        checkpoint_command = _command_argv(
            checkpoint_command, "allocation_checkpoint_command")
    consensus_reservation_command = conf.get(
        "consensus_reservation_command")
    if production:
        consensus_reservation_command = _command_argv(
            consensus_reservation_command,
            "consensus_reservation_command")
    elif consensus_reservation_command is not None:
        consensus_reservation_command = _command_argv(
            consensus_reservation_command,
            "consensus_reservation_command")
    return {
        "production": production,
        "development_only_allow_unsafe_allocator": unsafe_development,
        "cli_base": _command_argv(
            conf.get("cli_base", ["/usr/bin/sudo", "-u", "bitcoin",
                                  "/usr/bin/bitcoin-cli"]),
            "cli_base"),
        "wallet": wallet,
        "bind": bind,
        "port": bounded_json_int(conf.get("port", 8097), "port", 1, 65535),
        "rl_per_ip_per_min": bounded_json_int(
            conf.get("rl_per_ip_per_min", 6), "rl_per_ip_per_min", 1, 10_000),
        "rl_global_per_min": bounded_json_int(
            conf.get("rl_global_per_min", 60), "rl_global_per_min", 1, 100_000),
        "max_wrap_sats": bounded_json_int(
            conf.get("max_wrap_sats", 1_000_000_000), "max_wrap_sats",
            1, MAX_MONEY_SATS),
        "cors_origin": _cors_origin(conf.get("cors_origin"), production),
        "max_header_bytes": bounded_json_int(
            conf.get("max_header_bytes", 32768), "max_header_bytes", 4096, 131072),
        "http_max_workers": bounded_json_int(
            conf.get("http_max_workers", 32), "http_max_workers", 1, 256),
        "http_request_read_timeout_s": bounded_json_int(
            conf.get("http_request_read_timeout_s", 15),
            "http_request_read_timeout_s", 1, 60),
        "allocation_store": allocation_store,
        "allow_initial_allocation_store_creation": exact_json_bool(
            conf.get("allow_initial_allocation_store_creation", False),
            "allow_initial_allocation_store_creation"),
        "allocation_store_max_bytes": bounded_json_int(
            C1_JOURNAL_MAX_BYTES if production else
            conf.get("allocation_store_max_bytes", 1048576),
            "allocation_store_max_bytes", 65536, C1_JOURNAL_MAX_BYTES),
        "allocator_reserve_indices": 0,
        "max_issued_per_principal": C1_PRINCIPAL_LIFETIME_SATS,
        "max_issued_per_destination": C1_DESTINATION_LIFETIME_SATS,
        "admission_pow_bits": C1_ADMISSION_POW_BITS if production else 0,
        "admission_pow_max_age_s": bounded_json_int(
            C1_ADMISSION_EPOCH_SECONDS if production else
            conf.get("admission_pow_max_age_s", 300),
            "admission_pow_max_age_s", 30, 900),
        "allocation_witness_command": allocation_witness_command,
        "allocation_checkpoint_command": checkpoint_command,
        "consensus_reservation_command": consensus_reservation_command,
    }

if __name__ == "__main__" and len(sys.argv) > 2:
    raise RuntimeError("usage: veld_wrapd.py [absolute-config-path]")
CONF_PATH = sys.argv[1] if __name__ == "__main__" and len(sys.argv) == 2 else None
CONF = load_configuration(CONF_PATH)
SETTINGS = validate_configuration(CONF)
CLI_BASE = SETTINGS["cli_base"]
WALLET   = SETTINGS["wallet"]
BIND     = SETTINGS["bind"]
PORT     = SETTINGS["port"]
# Rate limits: address issuance is cheap but bound it (anti-DoS / anti-bloat).
RL_PER_IP_PER_MIN     = SETTINGS["rl_per_ip_per_min"]
RL_GLOBAL_PER_MIN     = SETTINGS["rl_global_per_min"]
PRODUCTION = SETTINGS["production"]
DEVELOPMENT_ONLY_ALLOW_UNSAFE_ALLOCATOR = SETTINGS[
    "development_only_allow_unsafe_allocator"]
CORS_ORIGIN = SETTINGS["cors_origin"]
MAX_HEADER_BYTES = SETTINGS["max_header_bytes"]
HTTP_MAX_WORKERS = SETTINGS["http_max_workers"]
HTTP_REQUEST_READ_TIMEOUT_S = SETTINGS["http_request_read_timeout_s"]
CONFIG_MAX_WRAP_SATS = SETTINGS["max_wrap_sats"]
ALLOCATION_STORE = SETTINGS["allocation_store"]
ALLOW_INITIAL_ALLOCATION_STORE_CREATION = SETTINGS[
    "allow_initial_allocation_store_creation"]
ALLOCATION_STORE_MAX_BYTES = SETTINGS["allocation_store_max_bytes"]
ALLOCATOR_RESERVE_INDICES = SETTINGS["allocator_reserve_indices"]
MAX_ISSUED_PER_PRINCIPAL = SETTINGS["max_issued_per_principal"]
MAX_ISSUED_PER_DESTINATION = SETTINGS["max_issued_per_destination"]
ADMISSION_POW_BITS = SETTINGS["admission_pow_bits"]
ADMISSION_POW_MAX_AGE_S = SETTINGS["admission_pow_max_age_s"]
ALLOCATION_WITNESS_COMMAND = SETTINGS["allocation_witness_command"]
ALLOCATION_CHECKPOINT_COMMAND = SETTINGS["allocation_checkpoint_command"]
CONSENSUS_RESERVATION_COMMAND = SETTINGS[
    "consensus_reservation_command"]

_custody = None
_veld_token = None
_veld_token_lock = threading.Lock()
_ALLOCATOR = None
_WRAP_INSTANCE_LOCK_FD = None
_C1_POLICY = None
_C1_POLICY_SHA256 = None
_ADMISSION_BEACON = AdmissionBeacon()


def _warn(message, error):
    detail = re.sub(r"[\x00-\x1f\x7f]", " ", str(error))[:500]
    print("[veld_wrapd] %s: %s" % (message, detail),
          file=sys.stderr, flush=True)


def _kill_process_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _run_bounded_command(argv, stdout_limit, stderr_limit, timeout_s,
                         description):
    """Run one argv command with hard memory, time and descendant bounds."""
    argv = _command_argv(list(argv), description)
    for value, name, maximum in (
            (stdout_limit, "stdout", MAX_CLI_STDOUT),
            (stderr_limit, "stderr", MAX_CLI_STDOUT),
            (timeout_s, "timeout", 60)):
        if type(value) is not int or value <= 0 or value > maximum:
            raise RuntimeError("%s %s limit is invalid" % (description, name))
    process = subprocess.Popen(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        close_fds=True, start_new_session=True)
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = []
    overflow_lock = threading.Lock()

    def drain(stream, name, limit):
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                room = limit + 1 - len(buffers[name])
                if room > 0:
                    buffers[name].extend(chunk[:room])
                if len(buffers[name]) > limit:
                    with overflow_lock:
                        overflow.append(name)
                    _kill_process_group(process)
                    return
        finally:
            try:
                stream.close()
            except OSError:
                pass

    readers = [
        threading.Thread(target=drain,
                         args=(process.stdout, "stdout", stdout_limit),
                         daemon=True),
        threading.Thread(target=drain,
                         args=(process.stderr, "stderr", stderr_limit),
                         daemon=True),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_process_group(process)
        process.wait()
    finally:
        for reader in readers:
            reader.join(2)
        if any(reader.is_alive() for reader in readers):
            _kill_process_group(process)
            raise RuntimeError("%s output reader did not terminate" % description)
    if timed_out:
        raise RuntimeError("%s timed out" % description)
    if overflow:
        raise RuntimeError("%s %s exceeds its byte limit" %
                           (description, overflow[0]))
    return process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def _btc_output(method, *args):
    if (not isinstance(method, str)
            or not re.fullmatch(r"[a-z][a-z0-9]{0,63}", method)):
        raise RuntimeError("invalid bitcoin-cli method")
    cmd = (list(CLI_BASE) + (["-rpcwallet=%s" % WALLET] if WALLET else [])
           + [method] + [str(arg) for arg in args])
    code, stdout, stderr = _run_bounded_command(
        cmd, MAX_CLI_STDOUT, MAX_CLI_STDERR, 30,
        "bitcoin-cli %s" % method)
    if code != 0:
        try:
            detail = stderr.decode("utf-8", "strict").strip()[:200]
        except UnicodeDecodeError:
            detail = "non-UTF-8 error output"
        raise RuntimeError("bitcoin-cli %s: %s" % (method, detail))
    return stdout.strip()


def _btc(method, *args):
    try:
        return _btc_output(method, *args).decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise RuntimeError("bitcoin-cli %s returned non-UTF-8 output" % method) from exc


def _btc_json(method, *args):
    return load_bounded_json_response(
        io.BytesIO(_btc_output(method, *args)), MAX_CLI_STDOUT,
        "bitcoin-cli %s response" % method)


def _load_veld_token(rpc):
    token_cmd = rpc.get("token_cmd")
    token_file = rpc.get("token_file")
    if token_cmd is not None and token_file is not None:
        raise RuntimeError("configure exactly one Veld RPC token source")
    if token_cmd is not None:
        command = _command_argv(token_cmd, "veld_rpc.token_cmd")
        code, stdout, _stderr = _run_bounded_command(
            command, MAX_TOKEN_BYTES, MAX_CLI_STDERR, 30,
            "Veld RPC token command")
        if code != 0:
            raise RuntimeError("Veld RPC token command failed")
        raw = stdout
    elif isinstance(token_file, str) and token_file:
        raw = read_bounded_secret_file(
            token_file, MAX_TOKEN_BYTES, "Veld RPC token")
    else:
        raise RuntimeError("production wrap service requires a Veld RPC token source")
    try:
        token = raw.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise RuntimeError("Veld RPC token is not ASCII") from exc
    if (not token or len(token) > MAX_TOKEN_BYTES
            or any(ord(char) < 0x21 or ord(char) > 0x7e for char in token)):
        raise RuntimeError("Veld RPC token is empty or contains unsafe characters")
    return token


def _veld(method, params=None):
    global _veld_token
    rpc = CONF.get("veld_rpc")
    if not isinstance(rpc, dict) or not isinstance(rpc.get("url"), str):
        raise RuntimeError("production wrap service requires veld_rpc")
    if _veld_token is None:
        with _veld_token_lock:
            if _veld_token is None:
                _veld_token = _load_veld_token(rpc)
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": method, "params": params or []},
                      separators=(",", ":"), allow_nan=False).encode("utf-8")
    rpc_url = validate_backend_rpc_url(rpc.get("url"), "veld_rpc.url")
    request = urllib.request.Request(rpc_url, data=body, headers={
        "Authorization": "Bearer " + _veld_token,
        "Content-Type": "application/json",
    })
    with open_rpc_request(request, timeout=20) as rpc_response:
        response = load_bounded_json_response(
            rpc_response, 32 * 1024 * 1024, "Veld RPC response")
    if not isinstance(response, dict):
        raise RuntimeError("%s: malformed JSON-RPC envelope" % method)
    if response.get("error") is not None:
        raise RuntimeError("%s: %s" % (method, response["error"]))
    return response.get("result")


def _configure_production():
    """Pin the address issuer to the compiled descriptor and exact manifest."""
    global _custody, _ALLOCATOR, _C1_POLICY, _C1_POLICY_SHA256
    if not PRODUCTION:
        return
    _C1_POLICY, _C1_POLICY_SHA256 = load_signed_c1_policy(CONF)
    require_supported_allocation_range(_C1_POLICY)
    peg = _veld("getpeginfo")
    if (not isinstance(peg, dict) or
            type(peg.get("issuer_max_per_mint_sats")) is not int or
            peg["issuer_max_per_mint_sats"] <
            _C1_POLICY["minimum_allocation_sats"]):
        raise RuntimeError(
            "C1 owner minimum exceeds compiled issuer_max_per_mint_sats")
    if (type(peg.get("issuer_static_custody_cap_sats")) is not int or
            peg["issuer_static_custody_cap_sats"] !=
            _C1_POLICY["consensus_custody_ceiling_sats"]):
        raise RuntimeError(
            "compiled issuer custody ceiling differs from signed C1 policy")
    _custody = custody_binding.load_manifest(
        CONF.get("custody_spk_manifest_file"),
        CONF.get("custody_descriptor_sha256"),
        CONF.get("custody_manifest_sha256"),
        expected_range_end=_C1_POLICY["public_descriptor_range"][1],
        expected_consensus_manifest_sha256=CONF.get(
            "custody_consensus_manifest_sha256"),
    )
    chain = _btc_json("getblockchaininfo")
    if not isinstance(chain, dict) or chain.get("chain") != "main":
        raise RuntimeError("production wrap service Bitcoin Core is not mainnet")
    listed = _btc_json("listdescriptors", "false")
    entries = listed.get("descriptors") if isinstance(listed, dict) else None
    if (not isinstance(entries, list) or len(entries) != 1 or
            not isinstance(entries[0], dict) or
            entries[0].get("desc") != _custody["descriptor"] or
            entries[0].get("internal") is not False or
            entries[0].get("active") is not False):
        raise RuntimeError(
            "wrap wallet must contain exactly the pinned inactive custody descriptor")
    required_range = [C1_OPERATOR_RANGE[0],
                      _C1_POLICY["public_descriptor_range"][1]]
    if (_custody.get("range") != required_range or
            entries[0].get("range") != required_range):
        raise RuntimeError(
            "C1 public range requires a ceremony-pinned custody manifest 0-%d" %
            required_range[1])
    custody_binding.verify_core_derivation(
        lambda method, *args: _btc_json(method, *args), _custody)
    _verify_descriptor_allocator_separation(entries[0], _custody)
    custody_binding.verify_peg_identity(peg, _custody)
    _ALLOCATOR = WrapAllocationJournal(
        ALLOCATION_STORE, _custody, None,
        max_bytes=ALLOCATION_STORE_MAX_BYTES,
        policy=_C1_POLICY, policy_sha256=_C1_POLICY_SHA256,
        register_allocation=_register_allocation_with_witness,
        preflight_allocation=_preflight_allocation_with_witness,
        ensure_consensus_reservation=_ensure_consensus_reservation,
        sequence_status=lambda allocation_id_value:
            _veld("getbtcveldc1reservation", [allocation_id_value]),
        allow_initialize=ALLOW_INITIAL_ALLOCATION_STORE_CREATION)
    if _ALLOCATOR.initialized_now:
        raise RuntimeError(
            "empty allocation journal initialized; set "
            "allow_initial_allocation_store_creation=false and restart")


def _verify_descriptor_allocator_separation(entry, binding):
    """Prove the public pool was pre-issued without per-user labels.

    Production never advances the public descriptor cursor per allocation:
    that would make public C1 sequence N identify public descriptor index
    999+N. The activation ceremony advances Core once to end+1, after which a
    private CSPRNG unused-index permutation supplies allocations.
    """
    if not isinstance(entry, dict) or not isinstance(binding, dict):
        raise RuntimeError("custody allocator state is malformed")
    legacy_fixture = _C1_POLICY is None and entry.get("range") == [0, 999]
    public_start = 1 if legacy_fixture else C1_PUBLIC_RANGE_START
    public_end = (999 if legacy_fixture else
                  _C1_POLICY["public_descriptor_range"][1]
                  if _C1_POLICY else C1_INITIAL_PUBLIC_RANGE_END)
    if legacy_fixture:
        next_index = entry.get("next")
        if type(next_index) is not int:
            raise RuntimeError("custody descriptor next index is malformed")
        if not public_start <= next_index <= public_end:
            raise RuntimeError(
                "custody descriptor next index must be in the public range [%d,%d]" %
                (public_start, public_end))
    elif entry.get("active") is not False:
        raise RuntimeError(
            "C1 custody pool descriptor must be inactive/non-cursor")
    addresses = _btc_json("deriveaddresses", binding.get("descriptor"), "[0,0]")
    if (not isinstance(addresses, list) or len(addresses) != 1
            or not isinstance(addresses[0], str)):
        raise RuntimeError("cannot derive the SPV-only custody address at index 0")
    info = _btc_json("getaddressinfo", addresses[0])
    labels = info.get("labels") if isinstance(info, dict) else None
    script = info.get("scriptPubKey") if isinstance(info, dict) else None
    if script != binding.get("spv_custody_spk_hex") or not isinstance(labels, list):
        raise RuntimeError("custody index-0 wallet metadata is malformed")
    names = []
    for label in labels:
        if isinstance(label, str):
            name = label
        elif isinstance(label, dict) and isinstance(label.get("name"), str):
            name = label["name"]
        else:
            raise RuntimeError("custody index-0 wallet label metadata is malformed")
        if len(name) > 256:
            raise RuntimeError("custody index-0 wallet label is oversized")
        names.append(name)
    if any(VELD_ADDR_RE.fullmatch(name) for name in names):
        raise RuntimeError(
            "custody index 0 has an issuer-recipient label; halt and reconcile migration")
    if not legacy_fixture:
        for index in (public_start, (public_start + public_end) // 2,
                      public_end):
            derived = _btc_json(
                "deriveaddresses", binding["descriptor"],
                "[%d,%d]" % (index, index))
            if (not isinstance(derived, list) or len(derived) != 1 or
                    not isinstance(derived[0], str)):
                raise RuntimeError(
                    "cannot derive pre-issued custody pool probe")
            probe = _btc_json("getaddressinfo", derived[0])
            if (not isinstance(probe, dict) or
                    probe.get("scriptPubKey") !=
                        binding["script_pubkeys"][index] or
                    probe.get("iswatchonly") is not True or
                    probe.get("solvable") is not True):
                raise RuntimeError(
                    "custody descriptor pool is not fully watched/solvable")


def _leading_zero_bits(digest, bits):
    whole, partial = divmod(bits, 8)
    return (digest[:whole] == b"\x00" * whole
            and (partial == 0
                 or digest[whole] >> (8 - partial) == 0))


def _canonical_wrap_request_body(request):
    request_id = request.get("request_id") if isinstance(request, dict) else None
    veld_address = request.get("veld_address") if isinstance(request, dict) else None
    amount_sats = request.get("amount_sats") if isinstance(request, dict) else None
    if (not isinstance(request_id, str) or
            not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
            not isinstance(veld_address, str) or
            not VELD_ADDR_RE.fullmatch(veld_address) or
            type(amount_sats) is not int or
            not 1 <= amount_sats <= MAX_MONEY_SATS):
        raise ValueError("wrap admission request body is malformed")
    return b"\x00".join((
        b"VELD-WRAP-ADMISSION-BODY-v2", request_id.encode("ascii"),
        veld_address.encode("ascii"), str(amount_sats).encode("ascii"),
    ))


def _verify_admission_pow(request, now=None, signature_verifier=None):
    """Verify current-only C1 work and the ML-DSA principal signature."""
    # Retain the old proof only for isolated non-production regression fixtures.
    # A production process always has the signed C1 policy and cannot enter it.
    if (not PRODUCTION and _C1_POLICY is None and isinstance(request, dict) and
            "admission_timestamp" in request):
        request_id = request.get("request_id")
        timestamp = request.get("admission_timestamp")
        nonce = request.get("admission_nonce")
        if (not isinstance(request_id, str) or
                not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
                type(timestamp) is not int or not isinstance(nonce, str) or
                not re.fullmatch(r"[0-9a-f]{16}", nonce)):
            raise ValueError("wrap admission proof is malformed")
        current = int(time.time()) if now is None else now
        if abs(current - timestamp) > ADMISSION_POW_MAX_AGE_S:
            raise ValueError("wrap admission proof is stale")
        message = "\x00".join((
            "VELD-WRAP-ADMISSION-POW-v1", request_id,
            request["veld_address"], str(request["amount_sats"]),
            str(timestamp), nonce,
        )).encode("ascii")
        if not _leading_zero_bits(
                hashlib.sha256(message).digest(), ADMISSION_POW_BITS):
            raise ValueError("wrap admission proof does not meet difficulty")
        return True
    if not PRODUCTION and ADMISSION_POW_BITS == 0:
        return _principal_hash("development")
    if _C1_POLICY is None or _C1_POLICY_SHA256 is None:
        raise RuntimeError("signed C1 capacity policy is unavailable")
    current = _ADMISSION_BEACON.current(now=now)
    beacon = request.get("admission_beacon")
    nonce = request.get("admission_nonce")
    public_key = request.get("admission_public_key")
    signature = request.get("admission_signature")
    if (beacon != current["beacon"] or
            not isinstance(nonce, str) or
            not re.fullmatch(r"[0-9a-f]{16}", nonce) or
            not isinstance(public_key, str) or
            not MLDSA65_PUBLIC_KEY_RE.fullmatch(public_key) or
            not isinstance(signature, str) or
            not MLDSA65_SIGNATURE_RE.fullmatch(signature)):
        raise ValueError("wrap admission proof is malformed or not current")
    canonical = _canonical_wrap_request_body(request)
    request_hash = hashlib.sha256(canonical).digest()
    digest = hashlib.sha256(
        bytes.fromhex(beacon) + bytes.fromhex(nonce) + request_hash).digest()
    if not has_leading_zero_bits(digest, _C1_POLICY["pow_bits"]):
        raise ValueError("wrap admission proof does not meet difficulty")
    message = (b"VELD-WRAP-ADMISSION-v2\x00" + bytes.fromhex(beacon) +
               bytes.fromhex(nonce) + request_hash)
    verifier = signature_verifier
    if verifier is None:
        verifier_path = _absolute_config_path(CONF, "admission_verifier")
        verifier = lambda key, msg, sig: verify_mldsa65_with_keygen(
            key, msg, sig, verifier_path)
    if verifier(public_key, message, signature) is not True:
        raise ValueError("wrap admission principal signature is invalid")
    return admission_principal_hash(public_key)


def _principal_hash(source):
    if not isinstance(source, str) or not source or len(source) > 64:
        raise ValueError("request source is malformed")
    return hashlib.sha256(
        b"VELD-WRAP-ADMISSION-PRINCIPAL-v1\x00"
        + source.encode("ascii", "strict")).hexdigest()


def _call_allocation_witness(action, record):
    """Call the independent allocation authority with policy-hash parity."""
    if action not in ("preflight_allocation", "register_allocation",
                      "verify_allocation"):
        raise RuntimeError("allocation witness action is invalid")
    if ALLOCATION_WITNESS_COMMAND is None or _C1_POLICY_SHA256 is None:
        raise RuntimeError("production allocation witness/policy is unavailable")
    fields = {
        key: record[key] for key in (
            "request_id", "principal_hash", "veld_address", "amount_sats",
            "descriptor_index", "btc_address", "script_pubkey",
            "commitment_blind", "consensus_allocation_id",
            "admitted_at", "expires_at")
    }
    request = json.dumps({
        "version": 4,
        "action": action,
        "capacity_policy_sha256": _C1_POLICY_SHA256,
        "allocation": fields,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False)
    completed = run_bounded_subprocess(
        list(ALLOCATION_WITNESS_COMMAND), input_text=request, timeout=45,
        stdout_max=64 * 1024, stderr_max=64 * 1024,
        description="allocation witness %s" % action)
    if completed.returncode != 0:
        raise RuntimeError(
            "allocation witness refused/unavailable: " +
            completed.stderr.strip()[:240])
    try:
        if not isinstance(completed.stdout, str):
            raise ValueError("allocation witness stdout is not text")
        response = strict_json_object(completed.stdout.encode("utf-8"))
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError("allocation witness returned invalid JSON") from exc
    required = {
        "version", "action", "request_id", "descriptor_index",
        "authorized", "idempotent", "capacity_policy_sha256",
        "commitment_blind", "consensus_allocation_id",
    }
    if action in ("register_allocation", "verify_allocation"):
        required |= {"expires_at", "deposit_observed_at",
                     "funded_reserved_at", "minted_at"}
    if (not isinstance(response, dict) or set(response) != required or
            response.get("version") != 4 or response.get("action") != action or
            response.get("request_id") != record["request_id"] or
            response.get("descriptor_index") != record["descriptor_index"] or
            response.get("commitment_blind") != record["commitment_blind"] or
            response.get("consensus_allocation_id") !=
                record["consensus_allocation_id"] or
            response.get("authorized") is not True or
            type(response.get("idempotent")) is not bool or
            response.get("capacity_policy_sha256") != _C1_POLICY_SHA256 or
            (action in ("register_allocation", "verify_allocation") and
             (response.get("expires_at") != record["expires_at"] or
              (response.get("deposit_observed_at") is not None and
               type(response.get("deposit_observed_at")) is not int) or
              (response.get("funded_reserved_at") is not None and
               type(response.get("funded_reserved_at")) is not int) or
              (response.get("minted_at") is not None and
               type(response.get("minted_at")) is not int))) or
            (action == "verify_allocation" and
             response.get("idempotent") is not True)):
        raise RuntimeError(
            "allocation witness policy hash/acknowledgement is not exact")
    return response


def _register_allocation_with_witness(record, verify_only=False):
    """Durably register one allocation on the independent mint witness.

    The command is a dedicated SSH forced-command identity, distinct from the
    minter/signer's reservation identity.  The public allocator does not return
    an address until that independent authority has fsync'd the exact immutable
    index/address/script/recipient/amount binding.
    """
    response = _call_allocation_witness(
        "verify_allocation" if verify_only else "register_allocation", record)
    return response


def _preflight_allocation_with_witness(record):
    return _call_allocation_witness("preflight_allocation", record)["authorized"]


def _ensure_consensus_reservation(record):
    """Progress C1R1 -> C1E1 and return only a deep canonical exposure.

    The coordinator holds no trust here: its acknowledgement can only prompt a
    fresh read from this service's authenticated node.  Every consensus field
    must match the independently journaled allocation, and the exposed marker
    itself must be beyond the configured bounded-reorg depth before the caller
    can obtain a Bitcoin address.
    """
    if not PRODUCTION:
        return None
    if CONSENSUS_RESERVATION_COMMAND is None:
        raise RuntimeError("consensus reservation coordinator is unavailable")
    allocation = {
        key: record[key] for key in (
            "request_id", "principal_hash", "veld_address", "amount_sats",
            "descriptor_index", "btc_address", "script_pubkey",
            "commitment_blind", "consensus_allocation_id",
            "admitted_at", "expires_at", "capacity_policy_sha256")
    }
    request = json.dumps({
        "version": 2,
        "action": "ensure_c1_lifecycle",
        "allocation": allocation,
        # The public address service has no authenticated Bitcoin proof before
        # disclosure.  mintd supplies the non-null CFP1 funding object through
        # this same coordinator contract after independently observing it.
        "funding": None,
    }, sort_keys=True, separators=(",", ":"), allow_nan=False)
    completed = run_bounded_subprocess(
        list(CONSENSUS_RESERVATION_COMMAND), input_text=request,
        timeout=120, stdout_max=64 * 1024, stderr_max=64 * 1024,
        description="C1 consensus reservation coordinator")
    if completed.returncode not in (0, 75):
        raise RuntimeError(
            "consensus reservation coordinator refused/unavailable: " +
            completed.stderr.strip()[:240])
    try:
        acknowledgement = strict_json_object(
            completed.stdout.encode("utf-8"))
    except Exception as exc:
        raise RuntimeError(
            "consensus reservation coordinator acknowledgement is malformed") from exc
    expected_ack = {
        "version", "allocation_id", "found", "active", "retired",
        "last_sequence", "exposed", "funded", "funding_outpoint",
        "confirmations",
        "required_confirmations", "canonical_depth_reached",
    }
    if (not isinstance(acknowledgement, dict) or
            set(acknowledgement) != expected_ack or
            acknowledgement.get("version") != 3 or
            acknowledgement.get("allocation_id") !=
                record["consensus_allocation_id"] or
            any(type(acknowledgement.get(key)) is not bool for key in
                ("found", "active", "retired", "exposed", "funded",
                 "canonical_depth_reached")) or
            any(type(acknowledgement.get(key)) is not int or
                acknowledgement[key] < 0 for key in
                ("last_sequence", "confirmations",
                 "required_confirmations")) or
            acknowledgement["required_confirmations"] !=
                C1_RESERVATION_FINALITY_DEPTH or
            (acknowledgement["funded"] and
             (not isinstance(acknowledgement["funding_outpoint"], str) or
              not re.fullmatch(
                  r"[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})",
                  acknowledgement["funding_outpoint"]))) or
            (not acknowledgement["funded"] and
             acknowledgement["funding_outpoint"] is not None)):
        raise RuntimeError(
            "consensus reservation coordinator acknowledgement is not exact")
    status = _veld("getbtcveldc1reservation",
                   [record["consensus_allocation_id"]])
    if (not isinstance(status, dict) or
            type(status.get("retired")) is not bool):
        raise RuntimeError("C1 consensus reservation status is malformed")
    found = status.get("found") is True
    retired = status["retired"]
    if found and retired:
        raise RuntimeError("C1 reservation is both active and retired")
    if found and (
            status.get("allocation_id") !=
                record["consensus_allocation_id"] or
            status.get("recipient") != record["veld_address"] or
            status.get("amount_sats") != record["amount_sats"] or
            status.get("allocation_commitment") != allocation_commitment(
                record["consensus_allocation_id"],
                record["veld_address"], record["amount_sats"],
                record["script_pubkey"], record["commitment_blind"]) or
            type(status.get("created_height")) is not int or
            type(status.get("expires_height")) is not int or
            status["expires_height"] - status["created_height"] + 1 !=
                C1_RESERVATION_LIFETIME_BLOCKS or
            type(status.get("confirmations")) is not int or
            status.get("required_confirmations") !=
                C1_RESERVATION_FINALITY_DEPTH):
        raise RuntimeError(
            "C1 consensus reservation differs from the allocation journal")
    if found and status.get("exposed") is True:
        for field in ("funding_starts_height", "funding_expires_height",
                      "funding_accepts_through_height",
                      "recommended_send_cutoff_height",
                      "exposure_confirmations"):
            if type(status.get(field)) is not int or status[field] < 0:
                raise RuntimeError(
                    "C1 consensus funding-window status is malformed")
        if not (status["funding_starts_height"] <=
                status["recommended_send_cutoff_height"] <
                status["funding_accepts_through_height"] <
                status["funding_expires_height"]):
            raise RuntimeError("C1 consensus funding boundaries are incoherent")
    if type(status.get("funded")) is not bool:
        raise RuntimeError("C1 consensus funded status is malformed")
    if status.get("funded") is True:
        if (not isinstance(status.get("funding_outpoint"), str) or
                not re.fullmatch(
                    r"[0-9a-f]{64}:(?:0|[1-9][0-9]{0,9})",
                    status["funding_outpoint"]) or
                type(status.get("funded_height")) is not int):
            raise RuntimeError("C1 funded reservation identity is malformed")
    elif status.get("funding_outpoint") is not None:
        raise RuntimeError("unfunded C1 reservation carries an outpoint")
    ready = (found and status.get("active") is True and
             status.get("exposed") is True and
             type(status.get("exposed_height")) is int and
             status.get("exposure_canonical_depth_reached") is True and
             status["exposure_confirmations"] >=
                C1_RESERVATION_FINALITY_DEPTH)
    if not ready:
        # Do not include btc_address/script_pubkey in the exception or HTTP
        # response.  A pre-exposure value is an internal allocator intent only.
        public_status = {
            "found": found,
            "active": status.get("active") is True,
            "retired": retired,
            "exposed": status.get("exposed") is True,
            "allocation_id": record["consensus_allocation_id"],
            "last_sequence": (status.get("last_sequence")
                              if type(status.get("last_sequence")) is int
                              else 0),
            "confirmations": (status.get("confirmations")
                              if type(status.get("confirmations")) is int
                              else 0),
            "required_confirmations": C1_RESERVATION_FINALITY_DEPTH,
        }
        raise PendingConsensusReservation(public_status)
    result = dict(status)
    result["send_starts_height"] = status["funding_starts_height"]
    # This is an advisory, conservative send cutoff (D-201), not a promise that
    # Bitcoin will produce K_BTC blocks or that Veld will include C1F1 in time.
    # The hard consensus C1F1 boundary is funding_accepts_through_height (D-100)
    # and the unfunded capacity lease expires at funding_expires_height (D).
    result["recommended_send_cutoff_height"] = status[
        "recommended_send_cutoff_height"]
    return result


def _open_journal_parent(path, create=False):
    path = os.path.abspath(path)
    parent, name = os.path.dirname(path), os.path.basename(path)
    if not name or name in (".", ".."):
        raise RuntimeError("allocation journal path has no file name")
    if create:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    flags = (os.O_RDONLY | os.O_NOFOLLOW
             | getattr(os, "O_DIRECTORY", 0)
             | getattr(os, "O_CLOEXEC", 0))
    dfd = os.open(parent, flags)
    try:
        info = os.fstat(dfd)
        if (not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077):
            raise RuntimeError(
                "allocation journal directory must be owner-only")
        return name, dfd
    except Exception:
        os.close(dfd)
        raise


class WrapAllocationJournal:
    """Crash-safe owner of a secret unused-index descriptor permutation.

    The complete public pool is pre-issued before activation. Each allocation
    CSPRNG-selects one unused index, fsyncs that private mapping, and only then
    labels/registers it. Consensus sequence is independent of descriptor index.
    """

    RECORD_KEYS = {
        "request_id", "principal_hash", "veld_address", "amount_sats",
        "descriptor_index", "btc_address", "script_pubkey", "state",
    }
    C1_RECORD_KEYS = RECORD_KEYS | {
        "admitted_at", "expires_at", "capacity_policy_sha256",
        "commitment_blind", "consensus_allocation_id",
    }

    def __init__(self, path, binding, initial_next, *, max_bytes,
                 register_allocation, allow_initialize=False, policy=None,
                 policy_sha256=None, preflight_allocation=None,
                 ensure_consensus_reservation=None,
                 sequence_status=None,
                 reserve_indices=None, per_principal=None,
                 per_destination=None, clock=lambda: int(time.time())):
        self.legacy_fixture = policy is None
        if self.legacy_fixture:
            binding_range = [0, 999]
            public_start = 1
            public_end = 999
            if (type(reserve_indices) is not int or
                    type(per_principal) is not int or
                    type(per_destination) is not int):
                raise RuntimeError("legacy fixture allocator policy is malformed")
            self.policy = None
            self.policy_sha256 = None
            self.policy_sequence = 0
            self.max_rows = 999
        else:
            self.policy = validate_c1_policy(policy)
            require_supported_allocation_range(self.policy)
            if (not isinstance(policy_sha256, str) or
                    not HEX64_RE.fullmatch(policy_sha256) or
                    not callable(preflight_allocation) or
                    not callable(ensure_consensus_reservation) or
                    not callable(sequence_status) or
                    max_bytes != self.policy["journal_max_bytes"]):
                raise RuntimeError("signed C1 allocator policy binding is malformed")
            binding_range = [0, self.policy["public_descriptor_range"][1]]
            public_start = self.policy["public_descriptor_range"][0]
            public_end = self.policy["public_descriptor_range"][1]
            reserve_indices = 0
            per_principal = self.policy["principal_lifetime_sats"]
            per_destination = self.policy["destination_lifetime_sats"]
            self.policy_sha256 = policy_sha256
            self.policy_sequence = self.policy["record_sequence"]
            self.max_rows = self.policy["journal_max_rows"]
        if (not isinstance(path, str) or not os.path.isabs(path)
                or not isinstance(binding, dict)
                or binding.get("range") != binding_range
                or (self.legacy_fixture and type(initial_next) is not int)
                or (self.legacy_fixture and
                    not public_start <= initial_next <= public_end)
                or (not self.legacy_fixture and initial_next is not None)
                or not callable(register_allocation)
                or (sequence_status is not None and
                    not callable(sequence_status))
                or type(allow_initialize) is not bool
                or not callable(clock)):
            raise RuntimeError("allocation journal initialization is malformed")
        self.path = path
        self.binding = binding
        self.max_bytes = max_bytes
        self.reserve_indices = reserve_indices
        self.per_principal = per_principal
        self.per_destination = per_destination
        self.public_start = public_start
        self.public_end = public_end
        self.preflight_allocation = preflight_allocation
        self.ensure_consensus_reservation = ensure_consensus_reservation
        self.sequence_status = sequence_status
        self.clock = clock
        self.lock = threading.RLock()
        self.records = {}
        self.events = []
        # Monotonic consensus identity authority.  It deliberately does not
        # derive from len(records): terminal-row compaction must never make an
        # old sequence available again.
        self.last_consensus_sequence = 0
        self.initial_next = initial_next
        self.last_next = initial_next
        self.allow_initialize = allow_initialize
        self.register_allocation = register_allocation
        self.initialized_now = False
        self._policy_advanced = False
        self._load_or_initialize()
        self._validate_record_sequence()
        self._validate_record_addresses()
        if not self.legacy_fixture and not self.initialized_now:
            self._checkpoint("verify")
        if self._policy_advanced:
            self._save()
        # Production Core cursor is a fixed activation-ceremony invariant. The
        # private journal, independent witness, and WORM authority own reuse.
        self._assert_core_cursor()

    def _document(self):
        if self.legacy_fixture:
            document = {
                "version": LEGACY_FIXTURE_JOURNAL_VERSION,
                "initial_next_index": self.initial_next,
                "records": [self.records[key]
                            for key in sorted(self.records)],
            }
        else:
            document = {
                "version": ALLOCATION_JOURNAL_VERSION,
                "pool_range_start": self.public_start,
                "records": [self.records[key]
                            for key in sorted(self.records)],
                "capacity_policy_sha256": self.policy_sha256,
                "capacity_policy_sequence": self.policy_sequence,
                "public_descriptor_range_end": self.public_end,
                "last_consensus_sequence": self.last_consensus_sequence,
                "events": list(self.events),
            }
        return document

    def _load_or_initialize(self):
        try:
            name, dfd = _open_journal_parent(self.path, create=False)
        except FileNotFoundError:
            if not self.allow_initialize:
                raise RuntimeError(
                    "allocation journal is absent; one-shot initialization "
                    "approval is required")
            self._save()
            self.initialized_now = True
            return
        fd = -1
        try:
            try:
                fd = os.open(
                    name, os.O_RDONLY | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0), dir_fd=dfd)
            except FileNotFoundError:
                os.close(dfd)
                if not self.allow_initialize:
                    raise RuntimeError(
                        "allocation journal is absent; one-shot initialization "
                        "approval is required")
                self._save()
                self.initialized_now = True
                return
            if self.allow_initialize:
                raise RuntimeError(
                    "allow_initial_allocation_store_creation must be false "
                    "after the journal exists")
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or info.st_size > self.max_bytes):
                raise RuntimeError("allocation journal file is unsafe or oversized")
            os.fchmod(fd, 0o600)
            raw = b""
            while len(raw) <= self.max_bytes:
                chunk = os.read(fd, min(65536, self.max_bytes + 1 - len(raw)))
                if not chunk:
                    break
                raw += chunk
            if len(raw) != info.st_size:
                raise RuntimeError("allocation journal changed while loading")
            document = strict_json_object(raw)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.close(dfd)
            except OSError:
                pass
        expected_document_keys = {"version", "initial_next_index", "records"}
        expected_version = LEGACY_FIXTURE_JOURNAL_VERSION
        if not self.legacy_fixture:
            expected_document_keys |= {
                "capacity_policy_sha256", "capacity_policy_sequence",
                "public_descriptor_range_end", "last_consensus_sequence",
                "events", "pool_range_start",
            }
            expected_document_keys.remove("initial_next_index")
            expected_version = ALLOCATION_JOURNAL_VERSION
        if (not isinstance(document, dict)
                or set(document) != expected_document_keys
                or document.get("version") != expected_version
                or (self.legacy_fixture and
                    type(document.get("initial_next_index")) is not int)
                or not isinstance(document.get("records"), list)):
            raise RuntimeError("allocation journal schema is invalid")
        if not self.legacy_fixture:
            stored_sequence = document.get("capacity_policy_sequence")
            stored_hash = document.get("capacity_policy_sha256")
            stored_end = document.get("public_descriptor_range_end")
            last_consensus_sequence = document.get(
                "last_consensus_sequence")
            events = document.get("events")
            if (type(stored_sequence) is not int or stored_sequence < 1 or
                    not isinstance(stored_hash, str) or
                    not HEX64_RE.fullmatch(stored_hash) or
                    type(stored_end) is not int or
                    stored_end < C1_INITIAL_PUBLIC_RANGE_END or
                    type(last_consensus_sequence) is not int or
                    not 0 <= last_consensus_sequence <= C1_UINT64_MAX or
                    not isinstance(events, list) or len(events) > self.max_rows or
                    any(not isinstance(event, dict) for event in events)):
                raise RuntimeError("allocation journal C1 policy/event state is invalid")
            if document.get("pool_range_start") != self.public_start:
                raise RuntimeError(
                    "allocation journal pool range start is inconsistent")
            if stored_sequence == self.policy_sequence:
                if stored_hash != self.policy_sha256 or stored_end != self.public_end:
                    raise RuntimeError("signed C1 config hash differs from allocator journal")
            elif (self.policy_sequence != stored_sequence + 1 or
                  self.policy["previous_policy_sha256"] != stored_hash or
                  self.public_end < stored_end):
                raise RuntimeError("signed C1 config is a rollback or unlinked range update")
            else:
                self._policy_advanced = True
            self.last_consensus_sequence = last_consensus_sequence
            self.events = events
            previous = "0" * 64
            for number, event in enumerate(self.events, 1):
                if (set(event) != {"sequence", "at", "action", "request_id",
                                   "previous_event_sha256", "event_sha256"} or
                        event.get("sequence") != number or
                        type(event.get("at")) is not int or event["at"] < 0 or
                        event.get("action") not in (
                            "reserved", "core_allocated", "witness_issued",
                            "deposit_observed", "funded_reservation_observed",
                            "minted", "expired") or
                        not isinstance(event.get("request_id"), str) or
                        not ALLOCATION_REQUEST_RE.fullmatch(event["request_id"]) or
                        event.get("previous_event_sha256") != previous or
                        not isinstance(event.get("event_sha256"), str) or
                        not HEX64_RE.fullmatch(event["event_sha256"])):
                    raise RuntimeError("allocation journal event chain is invalid")
                core = dict(event)
                claimed = core.pop("event_sha256")
                actual = hashlib.sha256(json.dumps(
                    core, sort_keys=True, separators=(",", ":"),
                    allow_nan=False).encode("utf-8")).hexdigest()
                if claimed != actual:
                    raise RuntimeError("allocation journal event hash is invalid")
                previous = claimed
        self.initial_next = (document["initial_next_index"]
                             if self.legacy_fixture else None)
        seen_indices = set()
        seen_blinds = set()
        reserved = 0
        for record in document["records"]:
            required_record_keys = (self.RECORD_KEYS if self.legacy_fixture
                                    else self.C1_RECORD_KEYS)
            if not isinstance(record, dict) or set(record) != required_record_keys:
                raise RuntimeError("allocation journal record schema is invalid")
            request_id = record["request_id"]
            principal = record["principal_hash"]
            index = record["descriptor_index"]
            if (not isinstance(request_id, str)
                    or not ALLOCATION_REQUEST_RE.fullmatch(request_id)
                    or request_id in self.records
                    or not isinstance(principal, str)
                    or not PRINCIPAL_HASH_RE.fullmatch(principal)
                    or not isinstance(record["veld_address"], str)
                    or not VELD_ADDR_RE.fullmatch(record["veld_address"])
                    or type(record["amount_sats"]) is not int
                    or not 1 <= record["amount_sats"] <= MAX_MONEY_SATS
                    or type(index) is not int
                    or (self.legacy_fixture and
                        not self.initial_next <= index <= self.public_end)
                    or (not self.legacy_fixture and
                        not self.public_start <= index <= self.public_end)
                    or index in seen_indices
                    or not isinstance(record["btc_address"], str)
                    or not 14 <= len(record["btc_address"]) <= 100
                    or record["script_pubkey"]
                    != self.binding["script_pubkeys"][index]
                    or record["state"] not in (
                        "reserved", "allocated", "issued")):
                raise RuntimeError("allocation journal record is invalid")
            if not self.legacy_fixture and (
                    type(record["admitted_at"]) is not int or
                    type(record["expires_at"]) is not int or
                    record["expires_at"] - record["admitted_at"] !=
                    self.policy["unfunded_expiry_seconds"] or
                    not isinstance(record["capacity_policy_sha256"], str) or
                    not HEX64_RE.fullmatch(record["capacity_policy_sha256"]) or
                    not isinstance(record["commitment_blind"], str) or
                    not HEX64_RE.fullmatch(record["commitment_blind"]) or
                    int(record["commitment_blind"], 16) == 0 or
                    record["commitment_blind"] in seen_blinds or
                    not isinstance(record["consensus_allocation_id"], str) or
                    not ALLOCATION_REQUEST_RE.fullmatch(
                        record["consensus_allocation_id"]) or
                    int(record["consensus_allocation_id"], 16) == 0 or
                    int(record["consensus_allocation_id"], 16) >
                        self.last_consensus_sequence):
                raise RuntimeError("allocation journal C1 admission metadata is invalid")
            reserved += record["state"] != "issued"
            seen_indices.add(index)
            if not self.legacy_fixture:
                seen_blinds.add(record["commitment_blind"])
            self.records[request_id] = record
        if reserved > 1:
            raise RuntimeError("allocation journal has multiple pending intents")

    def _ordered_records(self):
        if self.legacy_fixture:
            return sorted(self.records.values(),
                          key=lambda record: record["descriptor_index"])
        return sorted(self.records.values(), key=lambda record:
                      int(record["consensus_allocation_id"], 16))

    def _append_event(self, action, request_id, now=None):
        if self.legacy_fixture:
            return
        if len(self.records) + len(self.events) >= self.max_rows:
            raise RuntimeError("allocation journal lifecycle row capacity exhausted")
        core = {
            "sequence": len(self.events) + 1,
            "at": self.clock() if now is None else now,
            "action": action,
            "request_id": request_id,
            "previous_event_sha256": (
                self.events[-1]["event_sha256"] if self.events else "0" * 64),
        }
        core["event_sha256"] = hashlib.sha256(json.dumps(
            core, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8")).hexdigest()
        self.events.append(core)

    def _admission_capacity_available(self):
        if self.legacy_fixture:
            return True
        row_limit = (self.max_rows *
                     (100 - self.policy["lifecycle_reserve_percent"]) // 100)
        byte_limit = (self.max_bytes *
                      (100 - self.policy["lifecycle_reserve_percent"]) // 100)
        raw = (json.dumps(self._document(), sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
        return len(self.records) + len(self.events) < row_limit and len(raw) < byte_limit

    def _validate_record_sequence(self):
        """Prove monotonic sequence identities and a no-reuse mapping."""
        ordered = self._ordered_records()
        indices = [record["descriptor_index"] for record in ordered]
        if self.legacy_fixture:
            expected = list(range(self.initial_next,
                                  self.initial_next + len(ordered)))
            if indices != expected or (indices and indices[-1] > self.public_end):
                raise RuntimeError(
                    "allocation journal descriptor history is not contiguous")
        else:
            sequences = [int(record["consensus_allocation_id"], 16)
                         for record in ordered]
            if (sequences != sorted(set(sequences)) or
                    any(sequence > self.last_consensus_sequence
                        for sequence in sequences) or
                    len(indices) != len(set(indices)) or
                    any(not self.public_start <= index <= self.public_end
                        for index in indices)):
                raise RuntimeError(
                    "allocation sequence or private descriptor mapping is invalid")
        reserved = [record for record in ordered
                    if record["state"] != "issued"]
        if reserved and reserved != ordered[-1:]:
            raise RuntimeError(
                "allocation journal pending intent is not the final index")

    def _expected_core_next(self):
        if not self.legacy_fixture:
            return {self.public_end + 1}
        ordered = self._ordered_records()
        if not ordered:
            return {self.initial_next}
        final = ordered[-1]
        after = final["descriptor_index"] + 1
        if final["state"] == "reserved":
            # Crash may be immediately before or after Core advanced.
            return {final["descriptor_index"], after}
        return {after}

    def _validate_record_addresses(self):
        """Bind every persisted address to its exact descriptor index."""
        ordered = self._ordered_records()
        if not ordered:
            return
        first = (ordered[0]["descriptor_index"] if self.legacy_fixture
                 else self.public_start)
        last = (ordered[-1]["descriptor_index"] if self.legacy_fixture
                else self.public_end)
        derived = _btc_json(
            "deriveaddresses", self.binding["descriptor"],
            "[%d,%d]" % (first, last))
        if (not isinstance(derived, list)
                or len(derived) != last - first + 1
                or any(not isinstance(address, str)
                       or not 14 <= len(address) <= 100
                       for address in derived)):
            raise RuntimeError(
                "cannot rederive allocation journal address history")
        for record in ordered:
            if record["btc_address"] != derived[
                    record["descriptor_index"] - first]:
                raise RuntimeError(
                    "allocation journal address differs from descriptor index")

    def _save(self):
        raw = (json.dumps(self._document(), sort_keys=True,
                          separators=(",", ":"), allow_nan=False)
               + "\n").encode("utf-8")
        if (not self.legacy_fixture and
                len(self.records) + len(self.events) > self.max_rows):
            raise RuntimeError("allocation journal row quota exhausted")
        if len(raw) > self.max_bytes:
            raise RuntimeError("allocation journal quota exhausted")
        name, dfd = _open_journal_parent(self.path, create=True)
        fd = -1
        published = False
        tmp_name = "%s.%d.%s.tmp" % (
            name, os.getpid(), os.urandom(16).hex())
        try:
            fd = os.open(
                tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600, dir_fd=dfd)
            os.fchmod(fd, 0o600)
            view = memoryview(raw)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short allocation journal write")
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = -1
            os.replace(tmp_name, name, src_dir_fd=dfd, dst_dir_fd=dfd)
            published = True
            os.fsync(dfd)
        except Exception as exc:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(tmp_name, dir_fd=dfd)
            except FileNotFoundError:
                pass
            if not published:
                raise _JournalNotPublishedError(
                    "allocation journal update was not published") from exc
            # The replacement is visible but directory durability is uncertain.
            # Callers must keep the conservative in-memory intent and retry it;
            # rolling back would diverge from the visible journal.
            raise
        finally:
            os.close(dfd)
        if not self.legacy_fixture:
            self._checkpoint("store")

    def _checkpoint(self, action):
        if (action not in ("store", "verify") or
                ALLOCATION_CHECKPOINT_COMMAND is None):
            raise RuntimeError("allocation checkpoint authority is unavailable")
        raw = (json.dumps(self._document(), sort_keys=True,
                          separators=(",", ":"), allow_nan=False) + "\n").encode()
        digest = hashlib.sha256(raw).hexdigest()
        request = json.dumps({
            "version": 2, "action": action,
            "capacity_policy_sha256": self.policy_sha256,
            "journal_sha256": digest,
            "last_consensus_sequence": self.last_consensus_sequence,
            "allocation_rows": len(self.records),
            "event_rows": len(self.events),
            "last_descriptor_index": (
                max(record["descriptor_index"]
                    for record in self.records.values())
                if self.records else self.public_start - 1),
        }, sort_keys=True, separators=(",", ":"))
        completed = run_bounded_subprocess(
            list(ALLOCATION_CHECKPOINT_COMMAND), input_text=request,
            timeout=45, stdout_max=64 * 1024, stderr_max=64 * 1024,
            description="allocation monotonic/WORM checkpoint")
        try:
            answer = strict_json_object(completed.stdout.encode("utf-8"))
        except Exception as exc:
            raise RuntimeError(
                "allocation checkpoint acknowledgement is invalid") from exc
        if (completed.returncode != 0 or not isinstance(answer, dict) or
                set(answer) != {"version", "stored", "action",
                                "capacity_policy_sha256", "journal_sha256",
                                "last_consensus_sequence",
                                "monotonic_sequence"} or
                answer.get("version") != 2 or answer.get("stored") is not True or
                answer.get("action") != action or
                answer.get("capacity_policy_sha256") != self.policy_sha256 or
                answer.get("journal_sha256") != digest or
                answer.get("last_consensus_sequence") !=
                    self.last_consensus_sequence or
                type(answer.get("monotonic_sequence")) is not int or
                answer["monotonic_sequence"] < 1):
            raise RuntimeError(
                "allocation checkpoint authority refused/inexact acknowledgement")

    def _descriptor_entry(self):
        listed = _btc_json("listdescriptors", "false")
        entries = listed.get("descriptors") if isinstance(listed, dict) else None
        if (not isinstance(entries, list) or len(entries) != 1
                or not isinstance(entries[0], dict)
                or entries[0].get("desc") != self.binding["descriptor"]
                or entries[0].get("range") != self.binding["range"]
                or entries[0].get("active") is not self.legacy_fixture
                or entries[0].get("internal") is not False):
            raise RuntimeError("custody descriptor allocator identity changed")
        if not self.legacy_fixture:
            return None
        next_index = entries[0].get("next")
        if (type(next_index) is not int or
                not self.public_start <= next_index <= self.public_end + 1):
            raise RuntimeError("custody descriptor next index is invalid")
        return next_index

    def _assert_core_cursor(self):
        next_index = self._descriptor_entry()
        if not self.legacy_fixture:
            self.last_next = None
            return None
        if next_index not in self._expected_core_next():
            raise RuntimeError(
                "custody allocator cursor differs from durable journal history")
        self.last_next = next_index
        return next_index

    @staticmethod
    def _label_names(info):
        labels = info.get("labels") if isinstance(info, dict) else None
        if not isinstance(labels, list):
            raise RuntimeError("custody address label metadata is malformed")
        names = []
        for label in labels:
            name = label if isinstance(label, str) else (
                label.get("name") if isinstance(label, dict) else None)
            if not isinstance(name, str) or len(name) > 256:
                raise RuntimeError("custody address label metadata is malformed")
            names.append(name)
        return names

    def _lifecycle_result(self, record, response, observed):
        if self.legacy_fixture:
            return dict(record)
        if (not isinstance(response, dict) or
                response.get("expires_at") != record["expires_at"] or
                (response.get("deposit_observed_at") is not None and
                 type(response.get("deposit_observed_at")) is not int) or
                (response.get("funded_reserved_at") is not None and
                 type(response.get("funded_reserved_at")) is not int) or
                (response.get("minted_at") is not None and
                 type(response.get("minted_at")) is not int)):
            raise RuntimeError("allocation witness lifecycle status is malformed")
        deposit_observed_at = response["deposit_observed_at"]
        funded_reserved_at = response["funded_reserved_at"]
        minted_at = response["minted_at"]
        if ((funded_reserved_at is not None and
             deposit_observed_at is None) or
                (minted_at is not None and funded_reserved_at is None)):
            raise RuntimeError("allocation witness lifecycle status is inconsistent")
        # The independent witness is authoritative for the exact accepted MNP2
        # effect. Consensus removes the active lease while its monotonic
        # allocation sequence prevents replay, so progressing C1R1/C1E1 here
        # would be both unnecessary and dangerous. A minted retry is terminal and must
        # never invoke the coordinator or disclose the old deposit locator.
        if minted_at is not None:
            result = dict(record)
            result.update({
                "intent_expires_at": response["expires_at"],
                "deposit_observed_at": deposit_observed_at,
                "funded_reserved_at": funded_reserved_at,
                "minted_at": minted_at,
                "send_allowed": False,
                "lifecycle": "MINTED",
                "consensus_capacity_reserved": False,
            })
            return result
        # Always discover the canonical reservation state before applying the
        # wall-clock pre-reveal intent timeout.  Once C1E1 exists, expiring this
        # local row could disclose/reuse capacity while an address is becoming
        # canonical.  The coordinator is likewise forbidden to create C1E1
        # after this intent timeout.
        try:
            reservation = (self.ensure_consensus_reservation(record)
                           if self.ensure_consensus_reservation is not None
                           else None)
        except PendingConsensusReservation as pending:
            if (deposit_observed_at is None and
                    observed >= record["expires_at"] and
                    pending.status.get("exposed") is not True):
                # A canonical C1C1 is terminal evidence that the blinded,
                # never-revealed mapping cannot later reserve capacity. Keep
                # the request/id/index tombstone but return the same terminal
                # expiry contract; a future allocation may now advance.
                if pending.status.get("retired") is True and not any(
                        event["action"] == "expired" and
                        event["request_id"] == record["request_id"]
                        for event in self.events):
                    self._append_event("expired", record["request_id"], observed)
                    self._save()
                raise ExpiredAllocation(record["expires_at"])
            raise
        if (reservation is None and deposit_observed_at is None and
                observed >= record["expires_at"]):
            raise ExpiredAllocation(record["expires_at"])
        send_window_open = True
        canonical_funded = False
        if reservation is not None:
            tip = reservation.get("tip")
            if type(tip) is not int:
                raise RuntimeError("C1 reservation tip height is malformed")
            send_window_open = tip <= reservation[
                "recommended_send_cutoff_height"]
            canonical_funded = reservation.get("funded") is True
            if (funded_reserved_at is not None and not canonical_funded):
                raise RuntimeError(
                    "allocation witness funded state is absent from consensus")
        result = dict(record)
        lifecycle = (
            "FUNDED_RESERVED" if canonical_funded else
            "FUNDING_OBSERVED" if deposit_observed_at is not None else
            "UNFUNDED" if send_window_open else "RECOVERY_ONLY")
        result.update({
            # expires_at is an internal, pre-reveal intent deadline only.  It is
            # deliberately not returned by the public HTTP success response.
            "intent_expires_at": response["expires_at"],
            "deposit_observed_at": deposit_observed_at,
            "funded_reserved_at": funded_reserved_at,
            "minted_at": minted_at,
            "send_allowed": (deposit_observed_at is None and
                             not canonical_funded and send_window_open),
            "lifecycle": lifecycle,
        })
        if reservation is not None:
            result.update({
                "consensus_reservation_created_height":
                    reservation["created_height"],
                "consensus_reservation_exposed_height":
                    reservation["exposed_height"],
                "consensus_reservation_confirmations":
                    reservation["confirmations"],
                "send_starts_height": reservation["send_starts_height"],
                "recommended_send_cutoff_height":
                    reservation["recommended_send_cutoff_height"],
                "funding_accepts_through_height":
                    reservation["funding_accepts_through_height"],
                "funding_expires_height":
                    reservation["funding_expires_height"],
                "current_height": reservation["tip"],
                "consensus_capacity_reserved": True,
            })
        return result

    def _finish_reserved(self, record, observed):
        index = record["descriptor_index"]
        ordered = self._ordered_records()
        if (not ordered or ordered[-1] is not record
                or record["state"] not in ("reserved", "allocated")):
            raise RuntimeError("custody allocation intent ordering is invalid")
        next_index = self._assert_core_cursor()
        if not self.legacy_fixture and record["state"] == "reserved":
            # The address is already watched by the pre-issued ranged
            # descriptor. setlabel is idempotent and never changes `next`.
            _btc("setlabel", record["btc_address"], record["veld_address"])
            if self._descriptor_entry() is not None:
                raise RuntimeError("inactive custody descriptor gained a cursor")
        elif record["state"] == "reserved":
            if next_index == index:
                returned = _btc(
                    "getnewaddress", record["veld_address"], "bech32m")
                if returned != record["btc_address"]:
                    raise RuntimeError(
                        "Core advanced a different custody descriptor address")
                next_index = self._descriptor_entry()
                if next_index != index + 1:
                    raise RuntimeError(
                        "Core did not advance the reserved custody descriptor index")
            elif next_index != index + 1:
                raise RuntimeError(
                    "custody allocator advanced outside the durable intent")
        elif self.legacy_fixture and next_index != index + 1:
            raise RuntimeError(
                "allocated custody address differs from the Core cursor")
        info = _btc_json("getaddressinfo", record["btc_address"])
        if (not isinstance(info, dict)
                or info.get("scriptPubKey") != record["script_pubkey"]
                or (not self.legacy_fixture and
                    (info.get("iswatchonly") is not True or
                     info.get("solvable") is not True))
                or record["veld_address"] not in self._label_names(info)):
            raise RuntimeError("custody address ownership/label proof failed")
        self.last_next = next_index
        if record["state"] == "reserved":
            # Persist the post-label/pre-witness boundary. A witness outage can
            # never select a second descriptor index for the same request.
            record["state"] = "allocated"
            event_count = len(self.events)
            self._append_event("core_allocated", record["request_id"])
            try:
                self._save()
            except _JournalNotPublishedError:
                record["state"] = "reserved"
                del self.events[event_count:]
                raise
        lifecycle = self.register_allocation(dict(record), False)
        record["state"] = "issued"
        event_count = len(self.events)
        self._append_event("witness_issued", record["request_id"])
        try:
            self._save()
        except _JournalNotPublishedError:
            record["state"] = "allocated"
            del self.events[event_count:]
            raise
        return self._lifecycle_result(record, lifecycle, observed)

    def _verify_issued_record(self, record, observed):
        info = _btc_json("getaddressinfo", record["btc_address"])
        if (not isinstance(info, dict)
                or info.get("scriptPubKey") != record["script_pubkey"]
                or (not self.legacy_fixture and
                    (info.get("iswatchonly") is not True or
                     info.get("solvable") is not True))
                or record["veld_address"] not in self._label_names(info)):
            raise RuntimeError(
                "issued custody address ownership/label proof failed")
        # A syntactically valid local journal is not sufficient after an
        # independent-witness loss/rollback. Verification is non-mutating: an
        # absent authority row fails rather than silently recreating history.
        lifecycle = self.register_allocation(dict(record), True)
        return self._lifecycle_result(record, lifecycle, observed)

    def _synchronize_consensus_sequence(self):
        """Match the durable local high-water to the authenticated chain.

        A local value behind the chain is a rollback/failover incident.  A
        local value ahead of the chain is allowed only for its exact final
        durable intent, which must first progress through C1R1 or C1C1.  This
        remains valid if terminal allocation rows are later compacted because
        the high-water itself is persisted and externally checkpointed.
        """
        if self.legacy_fixture:
            return
        query_sequence = max(1, self.last_consensus_sequence)
        query_id = allocation_id(query_sequence)
        status = self.sequence_status(query_id)
        if (not isinstance(status, dict) or
                status.get("allocation_id") != query_id or
                type(status.get("last_sequence")) is not int or
                not 0 <= status["last_sequence"] <= C1_UINT64_MAX):
            raise RuntimeError("C1 sequence boundary status is malformed")
        chain_sequence = status["last_sequence"]
        if chain_sequence > self.last_consensus_sequence:
            raise RuntimeError(
                "C1 chain sequence is ahead of the durable allocator journal")
        if chain_sequence < self.last_consensus_sequence:
            pending = next((record for record in self.records.values()
                            if int(record["consensus_allocation_id"], 16) ==
                            self.last_consensus_sequence), None)
            if pending is None:
                raise RuntimeError(
                    "C1 unresolved sequence has no durable allocation intent")
            # Exact replay/progression may return pending while R/E is gaining
            # depth.  It may also broadcast C1C1 after an undisclosed timeout.
            self.ensure_consensus_reservation(dict(pending))
            status = self.sequence_status(query_id)
            if (not isinstance(status, dict) or
                    status.get("allocation_id") != query_id or
                    status.get("last_sequence") !=
                        self.last_consensus_sequence):
                raise RuntimeError(
                    "prior C1 allocation sequence is still unresolved")

    def allocate(self, request_id, principal, veld_address, amount_sats, now=None):
        if (not ALLOCATION_REQUEST_RE.fullmatch(request_id or "")
                or not PRINCIPAL_HASH_RE.fullmatch(principal or "")):
            raise ValueError("allocation request identity is malformed")
        with self.lock:
            admitted_at = self.clock() if now is None else now
            if type(admitted_at) is not int or admitted_at < 0:
                raise ValueError("allocation admission clock is malformed")
            existing = self.records.get(request_id)
            if existing is not None:
                # request_id is a 128-bit wallet-persisted capability.  Preserve
                # the original principal for quota accounting, but allow an
                # exact retry after a mobile client changes networks/IPs.
                if (existing["veld_address"] != veld_address
                        or existing["amount_sats"] != amount_sats):
                    raise ValueError("allocation request_id is already bound")
                if existing["state"] == "issued":
                    return self._verify_issued_record(existing, admitted_at)
                if (not self.legacy_fixture and
                        admitted_at >= existing["expires_at"]):
                    raise ExpiredAllocation(existing["expires_at"])
                return self._finish_reserved(existing, admitted_at)
            if any(record["state"] != "issued"
                   for record in self.records.values()):
                raise RuntimeError(
                    "a prior custody allocation needs exact retry/reconciliation")
            self._synchronize_consensus_sequence()
            if self.legacy_fixture:
                if sum(record["principal_hash"] == principal
                       for record in self.records.values()) >= self.per_principal:
                    raise RuntimeError("principal custody-address quota is full")
                if sum(record["veld_address"] == veld_address
                       for record in self.records.values()) >= self.per_destination:
                    raise RuntimeError("destination custody-address quota is full")
            else:
                epoch = admitted_at // self.policy["epoch_seconds"]
                day = admitted_at // 86_400
                if sum(record["admitted_at"] // self.policy["epoch_seconds"] == epoch
                       for record in self.records.values()) >= self.policy[
                           "global_allocations_per_epoch"]:
                    raise RuntimeError("AT_CAPACITY: C1 epoch allocation cap reached")
                if sum(record["admitted_at"] // 86_400 == day
                       for record in self.records.values()) >= self.policy[
                           "global_allocations_per_day"]:
                    raise RuntimeError("AT_CAPACITY: C1 daily allocation cap reached")
                live = [record for record in self.records.values()
                        if admitted_at < record["expires_at"]]
                principal_sats = sum(
                    record["amount_sats"] for record in live
                    if record["principal_hash"] == principal)
                destination_sats = sum(
                    record["amount_sats"] for record in live
                    if record["veld_address"] == veld_address)
                if principal_sats + amount_sats > self.per_principal:
                    raise RuntimeError("AT_CAPACITY: principal lifetime sat ceiling reached")
                if destination_sats + amount_sats > self.per_destination:
                    raise RuntimeError("AT_CAPACITY: destination lifetime sat ceiling reached")
                if amount_sats < self.policy["minimum_allocation_sats"]:
                    raise ValueError("allocation amount is below the C1 minimum")
            cursor = self._assert_core_cursor()
            public_end = (999 - self.reserve_indices
                          if self.legacy_fixture else self.public_end)
            if self.legacy_fixture:
                index = cursor
            else:
                used = {record["descriptor_index"]
                        for record in self.records.values()}
                remaining = [index for index in
                             range(self.public_start, self.public_end + 1)
                             if index not in used]
                if not remaining:
                    raise RuntimeError(
                        "AT_CAPACITY: public custody descriptor range exhausted")
                index = remaining[secrets.randbelow(len(remaining))]
            if (index > public_end or
                    (not self.legacy_fixture and
                     not _c1_public_index_allowed(index, self.policy))):
                raise RuntimeError(
                    ("public custody allocator reserve threshold reached"
                     if self.legacy_fixture else
                     "AT_CAPACITY: public custody descriptor range exhausted"))
            derived = _btc_json(
                "deriveaddresses", self.binding["descriptor"],
                "[%d,%d]" % (index, index))
            if (not isinstance(derived, list) or len(derived) != 1
                    or not isinstance(derived[0], str)
                    or not 14 <= len(derived[0]) <= 100):
                raise RuntimeError("cannot derive the reserved custody address")
            record = {
                "request_id": request_id,
                "principal_hash": principal,
                "veld_address": veld_address,
                "amount_sats": amount_sats,
                "descriptor_index": index,
                "btc_address": derived[0],
                "script_pubkey": self.binding["script_pubkeys"][index],
                "state": "reserved",
            }
            if not self.legacy_fixture:
                if self.last_consensus_sequence == C1_UINT64_MAX:
                    raise RuntimeError(
                        "AT_CAPACITY: C1 consensus allocation sequence exhausted")
                consensus_sequence = self.last_consensus_sequence + 1
                used_blinds = {row["commitment_blind"]
                               for row in self.records.values()}
                commitment_blind = secrets.token_hex(32)
                while (int(commitment_blind, 16) == 0 or
                       commitment_blind in used_blinds):
                    commitment_blind = secrets.token_hex(32)
                record.update({
                    # Persist the 256-bit hiding factor before the allocation
                    # leaves the journal. Descriptor scripts are enumerable;
                    # without this blind C1R1 would disclose which address is
                    # about to be funded despite omitting the script itself.
                    "commitment_blind": commitment_blind,
                    "consensus_allocation_id":
                        allocation_id(consensus_sequence),
                    "admitted_at": admitted_at,
                    "expires_at": admitted_at +
                    self.policy["unfunded_expiry_seconds"],
                    "capacity_policy_sha256": self.policy_sha256,
                })
                # The witness independently recomputes every cap before Core's
                # cursor is advanced, preventing a parity failure from burning
                # an otherwise usable public descriptor index.
                self.preflight_allocation(dict(record))
            self.records[request_id] = record
            prior_consensus_sequence = self.last_consensus_sequence
            if not self.legacy_fixture:
                self.last_consensus_sequence = consensus_sequence
            event_count = len(self.events)
            try:
                self._append_event("reserved", request_id, admitted_at)
            except Exception:
                self.records.pop(request_id, None)
                self.last_consensus_sequence = prior_consensus_sequence
                del self.events[event_count:]
                raise
            if not self._admission_capacity_available():
                self.records.pop(request_id, None)
                self.last_consensus_sequence = prior_consensus_sequence
                del self.events[event_count:]
                raise RuntimeError("AT_CAPACITY: C1 journal lifecycle reserve reached")
            try:
                self._save()
            except _JournalNotPublishedError:
                self.records.pop(request_id, None)
                self.last_consensus_sequence = prior_consensus_sequence
                del self.events[event_count:]
                raise
            return self._finish_reserved(record, admitted_at)

    def has_request(self, request_id):
        if not isinstance(request_id, str) or not ALLOCATION_REQUEST_RE.fullmatch(
                request_id):
            return False
        with self.lock:
            return request_id in self.records

    def capacity(self, refresh=False):
        with self.lock:
            if refresh:
                self._assert_core_cursor()
                ordered = self._ordered_records()
                if ordered and ordered[-1]["state"] != "issued":
                    raise RuntimeError(
                        "final custody allocation is not independently witnessed")
                if ordered:
                    self.register_allocation(dict(ordered[-1]), True)
            issued = sum(record["state"] == "issued"
                         for record in self.records.values())
            pending_witness = sum(record["state"] == "allocated"
                                  for record in self.records.values())
            public_end = (999 - self.reserve_indices
                          if self.legacy_fixture else self.public_end)
            answer = {
                "journal_records": len(self.records),
                "issued": issued,
                "pending_witness": pending_witness,
                "reserve_indices": self.reserve_indices,
                "public_index_end": public_end,
                "next_descriptor_index": self.last_next,
                "public_indices_remaining": (
                    max(0, public_end - self.last_next + 1)
                    if self.legacy_fixture else
                    (public_end - self.public_start + 1 -
                     len({record["descriptor_index"]
                          for record in self.records.values()}))),
                "reserve_threshold_reached": (
                    self.last_next > public_end if self.legacy_fixture else
                    len(self.records) >= public_end - self.public_start + 1),
            }
            if not self.legacy_fixture:
                answer.update({
                    "capacity_policy_sha256": self.policy_sha256,
                    "capacity_policy_sequence": self.policy_sequence,
                    "last_consensus_sequence":
                        self.last_consensus_sequence,
                    "journal_event_rows": len(self.events),
                    "journal_max_rows": self.max_rows,
                    "journal_max_bytes": self.max_bytes,
                    "new_admission_capacity": self._admission_capacity_available(),
                    "operator_descriptor_range": C1_OPERATOR_RANGE,
                    "public_descriptor_range": [self.public_start, self.public_end],
                })
            return answer


def _verify_production_identity():
    if PRODUCTION:
        if _custody is None:
            raise RuntimeError("production custody binding was not initialized")
        peg = _veld("getpeginfo")
        supply_before = _veld("getbtcveldsupply")
        tip = peg.get("tip") if isinstance(peg, dict) else None
        tip_hash_before = _veld("getblockhash", [tip])
        peg_after = _veld("getpeginfo")
        supply_after = _veld("getbtcveldsupply")
        tip_hash_after = _veld("getblockhash", [tip])
        custody_binding.verify_peg_identity(peg, _custody)
        fields = ("tip", "supply_sats", "issuer_max_per_mint_sats",
                  "issuer_effective_custody_cap_sats",
                  "issuer_reserved_sats",
                  "issuer_mint_headroom_sats")
        effective = peg.get("issuer_effective_custody_cap_sats")
        reserved = peg.get("issuer_reserved_sats")
        if (not isinstance(supply_before, dict) or
                supply_before != supply_after or
                set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
                type(supply_before.get("supply_sats")) is not int or
                supply_before["supply_sats"] < 0 or
                supply_before.get("tip") != tip or
                not isinstance(supply_before.get("tip_hash"), str) or
                not HEX64_RE.fullmatch(supply_before["tip_hash"]) or
                tip_hash_before != supply_before["tip_hash"] or
                tip_hash_after != tip_hash_before or
                any(peg.get(name) != peg_after.get(name) for name in fields) or
                peg.get("supply_sats") != supply_before["supply_sats"] or
                type(effective) is not int or effective < 0 or
                type(reserved) is not int or reserved < 0 or
                supply_before["supply_sats"] > effective or
                reserved > effective - supply_before["supply_sats"] or
                peg.get("issuer_mint_headroom_sats") != max(
                    0, effective - supply_before["supply_sats"] - reserved)):
            raise RuntimeError("issuer capacity/supply tuple changed or is incoherent")
        return peg
    return None


def _bitcoin_freshness(now=None):
    """Return the C5 phase from a coherent local Bitcoin Core tip snapshot."""
    if not PRODUCTION:
        return {"phase": "FRESH", "tip_age_seconds": 0}
    observed = int(time.time()) if now is None else now
    chain = _btc_json("getblockchaininfo")
    if (not isinstance(chain, dict) or chain.get("chain") != "main" or
            chain.get("initialblockdownload") is not False or
            type(chain.get("blocks")) is not int or
            chain.get("headers") != chain.get("blocks") or
            not isinstance(chain.get("bestblockhash"), str) or
            not HEX64_RE.fullmatch(chain["bestblockhash"])):
        raise RuntimeError("Bitcoin Core freshness snapshot is incoherent")
    header = _btc_json("getblockheader", chain["bestblockhash"])
    if (not isinstance(header, dict) or
            header.get("hash") != chain["bestblockhash"] or
            type(header.get("time")) is not int or header["time"] > observed + 120):
        raise RuntimeError("Bitcoin Core best-header freshness is malformed")
    age = max(0, observed - header["time"])
    if age >= C1_FRESHNESS_RECOVERY_ONLY_SECONDS:
        phase = "RECOVERY_ONLY"
    elif age >= C1_FRESHNESS_ALERT_SECONDS:
        phase = "ALERT"
    else:
        phase = "FRESH"
    return {"phase": phase, "tip_age_seconds": age}


def _public_allocation_gate(peg, freshness):
    """Fail closed unless consensus asserts candidate-height launch/liveness."""
    if (not isinstance(peg, dict) or peg.get("peg_unlocked") is not True or
            peg.get("mint_live") is not True):
        return "PEG_LOCKED"
    if (not isinstance(freshness, dict) or
            freshness.get("phase") == "RECOVERY_ONLY"):
        return "RECOVERY_ONLY"
    if freshness.get("phase") not in ("FRESH", "ALERT"):
        return "BACKEND_UNAVAILABLE"
    if PRODUCTION:
        try:
            if _max_wrap_sats(peg) < C1_MIN_ALLOCATION_SATS:
                return "AT_CAPACITY"
        except (TypeError, ValueError):
            return "BACKEND_UNAVAILABLE"
    return "OPEN"


def _allocation_recorded(request_id):
    if not PRODUCTION or _ALLOCATOR is None:
        return None
    try:
        return _ALLOCATOR.has_request(request_id)
    except Exception:
        return None


class AtomicDualWindowLimiter:
    """Atomic per-source + global limiter with hard memory/CPU ceilings."""

    def __init__(self, per_source, global_limit, *, capacity=4096,
                 maintenance_budget=256, clock=time.monotonic):
        for value, description in (
                (per_source, "per-source limit"),
                (global_limit, "global limit"),
                (capacity, "source capacity"),
                (maintenance_budget, "maintenance budget")):
            if type(value) is not int or value <= 0:
                raise ValueError("%s must be positive" % description)
        self.per_source = per_source
        self.global_limit = global_limit
        self.capacity = capacity
        self.maintenance_budget = maintenance_budget
        self.clock = clock
        self.sources = OrderedDict()
        self.global_hits = deque()
        self.lock = threading.Lock()

    def _prune_hits(self, hits, cutoff):
        if hits and hits[-1] <= cutoff:
            hits.clear()
            return
        work = 0
        while (hits and hits[0] <= cutoff
               and work < self.maintenance_budget):
            hits.popleft()
            work += 1

    def _prune_sources(self, cutoff):
        work = 0
        while self.sources and work < self.maintenance_budget:
            key, hits = next(iter(self.sources.items()))
            if hits and hits[-1] > cutoff:
                break
            self.sources.pop(key, None)
            work += 1

    def allow(self, source):
        if not isinstance(source, str) or not source or len(source) > 64:
            raise ValueError("invalid request source")
        now = self.clock()
        cutoff = now - 60
        with self.lock:
            self._prune_hits(self.global_hits, cutoff)
            hits = self.sources.get(source)
            if hits is not None:
                self._prune_hits(hits, cutoff)
                if not hits:
                    self.sources.pop(source, None)
                    hits = None
            self._prune_sources(cutoff)
            # If bounded maintenance could not remove every expired prefix,
            # fail closed for this call rather than doing attacker-sized work.
            if ((self.global_hits and self.global_hits[0] <= cutoff)
                    or (hits and hits[0] <= cutoff)):
                return False
            if (len(self.global_hits) >= self.global_limit
                    or (hits is not None and len(hits) >= self.per_source)):
                return False
            if hits is None:
                if len(self.sources) >= self.capacity:
                    return False
                hits = deque()
                self.sources[source] = hits
            hits.append(now)
            self.global_hits.append(now)
            self.sources.move_to_end(source)
            return True

    def source_count(self):
        with self.lock:
            return len(self.sources)

    def stored_hits(self):
        with self.lock:
            return len(self.global_hits) + sum(
                len(hits) for hits in self.sources.values())


_RATE_LIMITER = AtomicDualWindowLimiter(
    RL_PER_IP_PER_MIN, RL_GLOBAL_PER_MIN)


def _rate_ok(ip):
    return _RATE_LIMITER.allow(ip)


def _max_wrap_sats(peg):
    if not PRODUCTION:
        return bounded_json_int(
            CONFIG_MAX_WRAP_SATS, "max_wrap_sats",
            1, MAX_MONEY_SATS)
    if not isinstance(peg, dict):
        raise ValueError("issuer capacity response is malformed")
    # Retain the legacy field as a node/daemon compatibility assertion, but
    # do not use it as a second, per-address ceiling. In this release it must
    # equal the absolute custody cap; remaining aggregate headroom is the only
    # live maximum presented to a user.
    compatibility_max = bounded_json_int(
        peg.get("issuer_max_per_mint_sats"),
        "issuer_max_per_mint_sats", 1, MAX_MONEY_SATS)
    custody_cap = bounded_json_int(
        peg.get("issuer_static_custody_cap_sats"),
        "issuer_static_custody_cap_sats", 1, MAX_MONEY_SATS)
    if compatibility_max != custody_cap:
        raise ValueError("node still advertises an independent issuer per-mint ceiling")
    headroom = bounded_json_int(
        peg.get("issuer_mint_headroom_sats"),
        "issuer_mint_headroom_sats", 0, MAX_MONEY_SATS)
    if headroom > custody_cap:
        raise ValueError("issuer headroom exceeds the absolute custody cap")
    return headroom


def _confirmations(peg):
    if not PRODUCTION:
        return 6
    return bounded_json_int(
        peg.get("spv_k_btc") if isinstance(peg, dict) else None,
        "spv_k_btc", 1, 1_000_000)


def _validate_veld_destination(address):
    if not PRODUCTION:
        return True
    result = _veld("validateaddress", [address])
    if not isinstance(result, dict):
        raise RuntimeError("validateaddress returned a malformed result")
    return (result.get("isvalid") is True
            and result.get("address") == address
            and result.get("network") == "mainnet")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # CPython otherwise permits roughly 100 headers of almost 64 KiB each.
    def parse_request(self):
        raw = self.rfile
        self.rfile = HeaderBudgetReader(raw, MAX_HEADER_BYTES)
        try:
            return super().parse_request()
        finally:
            self.rfile = raw

    def _send(self, code, obj):
        body = (b"" if code == 204 else
                json.dumps(obj, separators=(",", ":"),
                           allow_nan=False).encode("utf-8"))
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        if CORS_ORIGIN is not None:
            self.send_header("Access-Control-Allow-Origin", CORS_ORIGIN)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if body:
            self.wfile.write(body)
        self.close_connection = True

    def _source(self):
        try:
            return request_source(self.client_address, self.headers)
        except RequestSourceError:
            self._send(400, {"error": "ambiguous or untrusted request source"})
            return None

    def _read_no_body(self):
        transfer = self.headers.get_all("Transfer-Encoding", [])
        lengths = self.headers.get_all("Content-Length", [])
        if transfer or len(lengths) > 1:
            self._send(400, {"error": "request body framing is not accepted"})
            return False
        if lengths and not re.fullmatch(r"0+", lengths[0].strip()):
            self._send(400, {"error": "this endpoint accepts no request body"})
            return False
        self.server.mark_request_read(self.request)
        return True

    def _read_json_body(self):
        transfer = self.headers.get_all("Transfer-Encoding", [])
        lengths = self.headers.get_all("Content-Length", [])
        content_types = self.headers.get_all("Content-Type", [])
        if transfer:
            self._send(400, {"error": "transfer encoding is not accepted"})
            return None
        if len(lengths) != 1:
            self._send(411 if not lengths else 400,
                       {"error": "one content length is required"})
            return None
        value = lengths[0].strip()
        if not re.fullmatch(r"[0-9]+", value):
            self._send(400, {"error": "bad content length"})
            return None
        length = int(value)
        if length <= 0 or length > MAX_BODY:
            self._send(413 if length > MAX_BODY else 400,
                       {"error": "bad body length"})
            return None
        if (len(content_types) != 1
                or content_types[0].split(";", 1)[0].strip().lower()
                != "application/json"):
            self._send(415, {"error": "application/json is required"})
            return None
        raw = self.rfile.read(length)
        self.server.mark_request_read(self.request)
        if len(raw) != length:
            self._send(400, {"error": "incomplete request body"})
            return None
        try:
            return strict_json_object(raw)
        except ValueError:
            self._send(400, {"error": "bad json"})
            return None

    def _target(self):
        try:
            target = urlsplit(self.path)
        except ValueError:
            return None
        if target.scheme or target.netloc or target.fragment:
            return None
        return target

    def do_OPTIONS(self):
        if self._source() is None or not self._read_no_body():
            return
        target = self._target()
        if (target is None or target.query
                or target.path not in (
                    "/health", "/spk", "/wrap", "/admission")):
            return self._send(404, {"error": "not found"})
        self._send(204, {})

    def do_GET(self):
        source = self._source()
        if source is None or not self._read_no_body():
            return
        parsed = self._target()
        if parsed is None:
            return self._send(404, {"error": "not found"})
        if parsed.path == "/health" and not parsed.query:
            # This probe performs authenticated Veld RPC plus Bitcoin Core
            # checks; keep it inside the same atomic backend-work budget as the
            # other public calls so health polling cannot occupy every worker.
            if not _rate_ok(source):
                return self._send(429, {"ok": False,
                                        "error": "rate limited — try again shortly"})
            try:
                peg = _verify_production_identity()
                freshness = _bitcoin_freshness()
                wallet_info = _btc_json("getwalletinfo")
                if not isinstance(wallet_info, dict):
                    raise RuntimeError("getwalletinfo returned a malformed result")
                return self._send(200, {"ok": True, "service": "veld_wrapd", "wallet": WALLET,
                                        "custody_bound": bool(_custody),
                                        "min_wrap_sats": (C1_MIN_ALLOCATION_SATS
                                                          if PRODUCTION else 1),
                                        "max_wrap_sats": _max_wrap_sats(peg),
                                        "admission_pow_bits": ADMISSION_POW_BITS,
                                        "admission_epoch_seconds": C1_ADMISSION_EPOCH_SECONDS,
                                        "capacity_policy_sha256": _C1_POLICY_SHA256,
                                        "bitcoin_freshness": freshness,
                                        "public_allocation_status":
                                            _public_allocation_gate(peg, freshness),
                                        "consensus_capacity_reservation":
                                            "C1R1_C1E1_C1C1_C1F1_MNP2",
                                        "allocator": (_ALLOCATOR.capacity(refresh=True)
                                                      if _ALLOCATOR else None)})
            except Exception as e:
                _warn("health check failed", e)
                return self._send(503, {"ok": False,
                                        "error": "backend health check failed"})
        if parsed.path == "/admission" and not parsed.query:
            answer = _ADMISSION_BEACON.current()
            answer["capacity_policy_sha256"] = _C1_POLICY_SHA256
            return self._send(200, answer)
        # Resolve a user's BTC destination address -> scriptPubKey (hex) for the
        # REDEEM leg. bitcoind's validateaddress is the AUTHORITATIVE decoder (every
        # address type: P2PKH/P2SH/P2WPKH/P2WSH/P2TR), so the wallet never hand-rolls
        # bech32 - and the SAME bitcoind that decodes here is the one that pays the
        # redeem, so decoder and payer can never disagree. Rejects invalid addresses.
        if parsed.path == "/spk":
            if not _rate_ok(source):
                return self._send(429, {"error": "rate limited — try again shortly"})
            try:
                fields = parse_qsl(parsed.query, keep_blank_values=True,
                                   strict_parsing=True, max_num_fields=2)
            except ValueError:
                fields = []
            if len(fields) != 1 or fields[0][0] != "address":
                return self._send(400, {"error": "one address query field is required"})
            addr = fields[0][1].strip()
            # conservative charset gate before it ever reaches bitcoin-cli (argv, not
            # a shell — but keep it clean): base58 + bech32 address characters only.
            if not addr or len(addr) > 100 or not re.match(r'^[0-9A-Za-z]+$', addr):
                return self._send(400, {"error": "invalid address"})
            try:
                info = _btc_json("validateaddress", addr)
            except Exception as e:
                _warn("Bitcoin address validation failed", e)
                return self._send(503, {"error": "Bitcoin address validation unavailable"})
            script = info.get("scriptPubKey") if isinstance(info, dict) else None
            if (not isinstance(info, dict) or info.get("isvalid") is not True
                    or not isinstance(script, str)
                    or not re.fullmatch(r"[0-9a-f]{4,1000}", script)
                    or len(script) % 2):
                return self._send(400, {"error": "not a valid Bitcoin address"})
            address_type = info.get("address_type") or info.get("type") or "?"
            if not isinstance(address_type, str) or len(address_type) > 32:
                address_type = "?"
            return self._send(200, {"address": addr, "scriptPubKey": script,
                                    "type": address_type})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        source = self._source()
        if source is None:
            return
        target = self._target()
        if target is None or target.path != "/wrap" or target.query:
            return self._send(404, {"error": "not found"})
        if not _rate_ok(source):
            return self._send(429, {"error": "rate limited — try again shortly"})
        req = self._read_json_body()
        if req is None:
            return
        required = ({"veld_address", "amount_sats", "request_id",
                     "admission_beacon", "admission_nonce",
                     "admission_public_key", "admission_signature"}
                    if PRODUCTION else {"veld_address", "amount_sats"})
        if set(req) != required:
            return self._send(400, {"error": "wrap body fields are malformed"})
        veld = req.get("veld_address")
        if not isinstance(veld, str) or not VELD_ADDR_RE.fullmatch(veld):
            return self._send(400, {"error": "invalid veld_address"})
        amount = req.get("amount_sats")
        if type(amount) is not int:
            return self._send(400, {"error": "amount_sats must be an exact integer"})
        if PRODUCTION:
            try:
                principal = _verify_admission_pow(req)
            except ValueError as e:
                return self._send(400, {"error": str(e)})
            except RuntimeError as e:
                _warn("wrap admission verifier unavailable", e)
                return self._send(503, {"error": "admission verifier unavailable"})
        try:
            peg = _verify_production_identity()
            freshness = _bitcoin_freshness()
            admission_status = _public_allocation_gate(peg, freshness)
            recorded_retry = (PRODUCTION and
                              _allocation_recorded(req.get("request_id")) is True)
            if (PRODUCTION and admission_status != "OPEN" and
                    not recorded_retry):
                return self._send(503, {
                    "error": "public wrap admission is unavailable",
                    "status": admission_status,
                    "bitcoin_freshness": freshness,
                    "request_recorded": _allocation_recorded(
                        req.get("request_id")),
                })
            max_sats = _max_wrap_sats(peg)
            min_sats = C1_MIN_ALLOCATION_SATS if PRODUCTION else 1
            if amount < min_sats or (amount > max_sats and not recorded_retry):
                return self._send(400, {
                    "error": "amount_sats outside issuer wrap range",
                    "min_sats": min_sats,
                    "max_sats": max_sats,
                    "request_recorded": _allocation_recorded(
                        req.get("request_id")),
                })
            if not _validate_veld_destination(veld):
                return self._send(400, {
                    "error": "invalid mainnet veld_address",
                    "request_recorded": _allocation_recorded(
                        req.get("request_id")),
                })
            if PRODUCTION:
                if _ALLOCATOR is None:
                    raise RuntimeError("custody allocation journal is unavailable")
                allocation = _ALLOCATOR.allocate(
                    req["request_id"], principal, veld, amount)
                # allocate() may spend up to two minutes waiting for the
                # coordinator/finality depth.  The launch gate sampled before
                # that wait is not authority to reveal an address afterwards:
                # finality can stall in the interval.  Re-sample the complete
                # coherent peg/capacity tuple and Bitcoin freshness immediately
                # before every address-bearing response.
                if (admission_status == "OPEN" and
                        allocation.get("send_allowed") is True):
                    response_peg = _verify_production_identity()
                    response_freshness = _bitcoin_freshness()
                    admission_status = _public_allocation_gate(
                        response_peg, response_freshness)
                # Exact retries remain available while the canonical mint gate
                # is closed so an undisclosed intent can reach C1C1 and already
                # observed funding can be reported/recovered.  They are not an
                # exception that may disclose an address or invite a new Bitcoin
                # send.  reservationd independently samples the same gate before
                # creating C1E1; this response-side check also covers an exposure
                # that became deep immediately before a later finality stall.
                if admission_status != "OPEN":
                    allocation["send_allowed"] = False
                    if allocation.get("lifecycle") == "UNFUNDED":
                        allocation["lifecycle"] = "RECOVERY_ONLY"
                if (type(allocation.get("send_allowed")) is not bool or
                        allocation.get("lifecycle") not in
                        ("UNFUNDED", "FUNDING_OBSERVED", "FUNDED_RESERVED",
                         "MINTED", "RECOVERY_ONLY") or
                        type(allocation.get("expires_at")) is not int):
                    raise RuntimeError(
                        "custody allocation lifecycle is unavailable")
                if not allocation["send_allowed"]:
                    return self._send(200, {
                        "veld_address": veld,
                        "mint_path": "issuer",
                        "request_id": req["request_id"],
                        "amount_sats": amount,
                        "min_sats": C1_MIN_ALLOCATION_SATS,
                        "max_sats": max_sats,
                        "confirmations": _confirmations(peg),
                        "deposit_observed_at": allocation.get(
                            "deposit_observed_at"),
                        "funded_reserved_at": allocation.get(
                            "funded_reserved_at"),
                        "minted_at": allocation.get("minted_at"),
                        "lifecycle": allocation["lifecycle"],
                        "send_allowed": False,
                        "consensus_capacity_reserved": (
                            allocation.get("consensus_capacity_reserved") is True),
                        "send_starts_height": allocation.get(
                            "send_starts_height"),
                        "recommended_send_cutoff_height": allocation.get(
                            "recommended_send_cutoff_height"),
                        "funding_accepts_through_height": allocation.get(
                            "funding_accepts_through_height"),
                        "funding_expires_height": allocation.get(
                            "funding_expires_height"),
                        "current_height": allocation.get("current_height"),
                        "capacity_warning": C1_CONSENSUS_CAPACITY_WARNING,
                        "note": ("deposit already observed; do not send again"
                                 if allocation["lifecycle"] in
                                 ("FUNDING_OBSERVED", "FUNDED_RESERVED", "MINTED")
                                 else "recommended send cutoff elapsed; Bitcoin stalls or reorgs may require operator recovery"),
                    })
                btc_addr = allocation["btc_address"]
                script = allocation["script_pubkey"]
            else:
                # Development-only legacy path. Production always reserves an
                # index durably before advancing Core through the journal above.
                btc_addr = _btc("getnewaddress", veld, "bech32m")
                if not isinstance(btc_addr, str) or not 14 <= len(btc_addr) <= 100:
                    raise RuntimeError("wallet issued a malformed address")
                address_info = _btc_json("getaddressinfo", btc_addr)
                script = (address_info.get("scriptPubKey")
                          if isinstance(address_info, dict) else None)
                if (not isinstance(script, str)
                        or not re.fullmatch(r"[0-9a-f]{4,1000}", script)
                        or len(script) % 2):
                    raise RuntimeError("wallet issued a malformed scriptPubKey")
        except PendingConsensusReservation as e:
            return self._send(202, {
                "status": "CONSENSUS_RESERVATION_PENDING",
                "request_id": req.get("request_id"),
                "amount_sats": amount,
                "send_allowed": False,
                "consensus_capacity_reserved": False,
                "reservation": e.status,
                "request_recorded": True,
            })
        except ExpiredAllocation as e:
            return self._send(410, {
                "error": "allocation expired",
                "request_id": req.get("request_id"),
                "amount_sats": amount,
                "expires_at": e.expires_at,
                "lifecycle": "EXPIRED",
                "send_allowed": False,
                "consensus_capacity_reserved": False,
                "capacity_warning": C1_CONSENSUS_CAPACITY_WARNING,
                "request_recorded": True,
            })
        except ValueError as e:
            _warn("wrap allocation identity conflict", e)
            return self._send(409, {
                "error": "allocation request identity conflict",
                "request_recorded": _allocation_recorded(
                    req.get("request_id")),
            })
        except Exception as e:
            _warn("wrap allocation failed", e)
            at_capacity = str(e).startswith("AT_CAPACITY:")
            return self._send(429 if at_capacity else 503, {
                "error": ("AT_CAPACITY" if at_capacity else
                          "custody wallet unavailable"),
                "detail": (str(e)[:200] if at_capacity else None),
                "request_recorded": _allocation_recorded(
                    req.get("request_id")),
            })
        return self._send(200, {"btc_address": btc_addr, "veld_address": veld,
                                "mint_path": "issuer",
                                "request_id": req.get("request_id"),
                                "amount_sats": amount,
                                "min_sats": (C1_MIN_ALLOCATION_SATS
                                             if PRODUCTION else 1),
                                "max_sats": max_sats,
                                "confirmations": _confirmations(peg),
                                "lifecycle": (allocation["lifecycle"]
                                              if PRODUCTION else "UNFUNDED"),
                                "send_allowed": True,
                                "consensus_capacity_reserved": (
                                    allocation.get(
                                        "consensus_capacity_reserved") is True
                                    if PRODUCTION else False),
                                "consensus_reservation_created_height": (
                                    allocation.get(
                                        "consensus_reservation_created_height")
                                    if PRODUCTION else None),
                                "consensus_reservation_exposed_height": (
                                    allocation.get(
                                        "consensus_reservation_exposed_height")
                                    if PRODUCTION else None),
                                "send_starts_height": (
                                    allocation.get("send_starts_height")
                                    if PRODUCTION else None),
                                "recommended_send_cutoff_height": (
                                    allocation.get(
                                        "recommended_send_cutoff_height")
                                    if PRODUCTION else None),
                                "funding_accepts_through_height": (
                                    allocation.get(
                                        "funding_accepts_through_height")
                                    if PRODUCTION else None),
                                "funding_expires_height": (
                                    allocation.get("funding_expires_height")
                                    if PRODUCTION else None),
                                "current_height": (
                                    allocation.get("current_height")
                                    if PRODUCTION else None),
                                "capacity_warning": C1_CONSENSUS_CAPACITY_WARNING,
                                "note": ("send exactly amount_sats before the recommended cutoff; "
                                         "Bitcoin stalls or reorgs can still force recovery, and a larger deposit cannot issuer-mint")})

    def log_message(self, *a):
        pass


def main():
    global _WRAP_INSTANCE_LOCK_FD
    if not PRODUCTION and not DEVELOPMENT_ONLY_ALLOW_UNSAFE_ALLOCATOR:
        raise RuntimeError(
            "non-production wrap allocator is disabled; an isolated fixture "
            "must explicitly set development_only_allow_unsafe_allocator=true")
    # Hold one OS-level single-writer lock before journal/Core reconciliation.
    # Port binding happens later and is not an allocator lock: a second service
    # could be configured on another port against the same wallet and journal.
    from instance_lock import acquire_instance_lock
    _WRAP_INSTANCE_LOCK_FD = acquire_instance_lock(ALLOCATION_STORE)
    _configure_production()
    print(f"veld_wrapd on {BIND}:{PORT} wallet={WALLET} rl_ip={RL_PER_IP_PER_MIN}/min", flush=True)
    with BoundedThreadingTCPServer(
            (BIND, PORT), Handler, max_workers=HTTP_MAX_WORKERS,
            request_read_timeout_s=HTTP_REQUEST_READ_TIMEOUT_S) as srv:
        srv.serve_forever()


if __name__ == "__main__":
    main()
