#!/usr/bin/env python3
"""
Automated btcVELD minter. Mirror of veld_redeemd.py.

A confirmed, FINAL, not-already-used BTC deposit to a request-issued custody address
mints exactly that many sats of btcVELD to the VELD address the deposit address is
bound to, automatically and fail-closed. Issuer-mint consensus does not verify BTC; the
issuer signature is the only on-chain gate), so the off-chain invariant
    btcVELD_supply + mint  <=  confirmed_BTC_in_custody
is the load-bearing guard and is re-checked before EVERY mint. See
docs/btcVELD-automated-minter-design.md for the full threat model (T1-T13).

  deposit binding : live C1 wrapd v3 journal plus independent watchtower authority
                    (exact address + script + recipient + admitted amount)
  state           : <state>/minted_deposits.json   (txid:vout -> mint; idempotent)
  kill-switch     : <state>/HALT (blocks ALL mints until a human removes it)
  lock            : <state>/mintd.lock (single-writer; no concurrent processing)

Every gate fails CLOSED: on any error, ambiguity, or unreachable dependency the
deposit is left unminted, logged, and alerted - the daemon never guesses.
"""
import hashlib, json, os, sys, struct, subprocess, time, re, stat, tempfile, urllib.request
from decimal import Decimal, InvalidOperation

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_custody_binding as custody_binding  # noqa: E402
from btcveld_c1 import allocation_commitment  # noqa: E402
from veld_spvmint import (MAX_BITCOIN_TX_BYTES, MAX_BLOCK_TXIDS,
                          be_to_le, build_merkle_branch, dsha, fold_merkle,
                          parse_and_strip_bitcoin_tx)  # noqa: E402
from rpc_url_policy import (load_bounded_json_file, load_bounded_json_response,
                            open_rpc_request,
                            read_bounded_secret_file,
                            run_bounded_subprocess,
                            strict_json_loads,
                            validate_backend_rpc_url)  # noqa: E402

try:
    import fcntl  # POSIX single-writer lock; the minter is a Linux daemon
except ImportError:
    fcntl = None

SATS = 100_000_000
# Strict validators (T9 injection): a VELD base58check address; a 64-hex txid.
VELD_ADDR_RE = re.compile(r'^V[1-9A-HJ-NP-Za-km-z]{25,49}$')
TXID_RE      = re.compile(r'^[0-9a-f]{64}$')
OUTPOINT_RE  = re.compile(r'^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$')
ALLOCATION_REQUEST_RE = re.compile(r'^[0-9a-f]{32}$')
PRINCIPAL_HASH_RE = re.compile(r'^[0-9a-f]{64}$')
MAX_CONFIG_BYTES = 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
MAX_ALLOCATION_STORE_BYTES = 64 * 1024 * 1024
MAX_CLI_OUTPUT_BYTES = 32 * 1024 * 1024
MAX_SIGNED_TX_BYTES = 4 * 1024 * 1024
MAX_MONEY_SATS = 21_000_000 * SATS
MAX_REORG_DEPTH = 100
MAX_ISSUER_PREVOUT_EXCLUSIONS = 64
ALLOCATION_JOURNAL_VERSION = 2
C1_ALLOCATION_JOURNAL_VERSION = 6
ALLOCATION_RECORD_KEYS = {
    "request_id", "principal_hash", "veld_address", "amount_sats",
    "descriptor_index", "btc_address", "script_pubkey", "state",
}
C1_ALLOCATION_RECORD_KEYS = ALLOCATION_RECORD_KEYS | {
    "admitted_at", "expires_at", "capacity_policy_sha256",
    "commitment_blind", "consensus_allocation_id",
}


def log(m):   sys.stdout.write("  " + m + "\n"); sys.stdout.flush()
def warn(m):  sys.stderr.write("  [WARN] " + m + "\n"); sys.stderr.flush()


def _config_int(value, field, minimum, maximum):
    if type(value) is not int or value < minimum or value > maximum:
        raise RuntimeError(
            "%s must be a JSON integer in [%d,%d]" %
            (field, minimum, maximum))
    return value


def _read_tx_varint(raw, pos):
    if pos >= len(raw):
        raise RuntimeError("truncated transaction varint")
    first = raw[pos]
    pos += 1
    if first < 0xfd:
        return first, pos
    width = {0xfd: 2, 0xfe: 4, 0xff: 8}[first]
    if pos + width > len(raw):
        raise RuntimeError("truncated transaction varint body")
    value = int.from_bytes(raw[pos:pos + width], "little")
    if ((first == 0xfd and value < 0xfd) or
            (first == 0xfe and value <= 0xffff) or
            (first == 0xff and value <= 0xffffffff)):
        raise RuntimeError("non-minimal transaction varint")
    return value, pos + width


def unsigned_input_outpoints(unsigned_tx_hex):
    if (not isinstance(unsigned_tx_hex, str) or not unsigned_tx_hex or
            len(unsigned_tx_hex) % 2 or
            not re.fullmatch(r"[0-9a-fA-F]+", unsigned_tx_hex)):
        raise RuntimeError("unsigned transaction is malformed hex")
    raw = bytes.fromhex(unsigned_tx_hex)
    if len(raw) < 10:
        raise RuntimeError("unsigned transaction is truncated")
    count, pos = _read_tx_varint(raw, 4)
    if not 1 <= count <= 10_000:
        raise RuntimeError("unsigned transaction input count is invalid")
    result = []
    for _ in range(count):
        if pos + 36 > len(raw):
            raise RuntimeError("unsigned transaction input is truncated")
        txid_hex = raw[pos:pos + 32].hex()
        vout = int.from_bytes(raw[pos + 32:pos + 36], "little")
        pos += 36
        script_len, pos = _read_tx_varint(raw, pos)
        if script_len != 0 or pos + 4 > len(raw):
            raise RuntimeError("transaction proposal is not exactly unsigned")
        pos += 4
        result.append("%s:%d" % (txid_hex, vout))
    return result


def validate_issuer_prevout_exclusions(value, *, candidate_inputs=None):
    if (not isinstance(value, list) or
            len(value) > MAX_ISSUER_PREVOUT_EXCLUSIONS or
            value != sorted(set(value)) or
            any(not isinstance(outpoint, str) or
                not OUTPOINT_RE.fullmatch(outpoint) or
                int(outpoint.rsplit(":", 1)[1]) > 0xffffffff
                for outpoint in value) or
            (candidate_inputs is not None and
             not set(value).issubset(set(candidate_inputs)))):
        raise RuntimeError("issuer prevout exclusion set is not exact")
    return list(value)


def issuer_prevout_exclusion_suffix(exclusions, *, force=False):
    validate_issuer_prevout_exclusions(exclusions)
    if not exclusions and not force:
        return None
    return "issuer-prevout-exclusions-v1:" + ",".join(exclusions)


def production_allocation_settings(cfg):
    """Return the explicit production allocation-journal policy.

    The public allocator and issuer minter must read one authority.  Defaults
    are deliberately forbidden here: a typo or a missing deployment mount must
    stop production instead of making labeled custody outputs mintable again.
    """
    if not isinstance(cfg, dict):
        raise RuntimeError("mintd configuration root must be an object")
    missing = [name for name in ("allocation_store",
                                 "allocation_store_max_bytes",
                                 "public_capacity_config_sha256",
                                 "public_descriptor_range_end",
                                 "custody_consensus_manifest_sha256",
                                 "consensus_reservation_command")
               if name not in cfg]
    if missing:
        raise RuntimeError(
            "production allocation policy is incomplete: %s" %
            ",".join(missing))
    path = cfg["allocation_store"]
    if (not isinstance(path, str) or not path or not os.path.isabs(path)):
        raise RuntimeError("production allocation_store must be an absolute path")
    maximum = _config_int(
        cfg["allocation_store_max_bytes"], "allocation_store_max_bytes",
        65536, MAX_ALLOCATION_STORE_BYTES)
    policy_hash = cfg["public_capacity_config_sha256"]
    if (not isinstance(policy_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", policy_hash)):
        raise RuntimeError("public_capacity_config_sha256 must be canonical 64-hex")
    if maximum != MAX_ALLOCATION_STORE_BYTES:
        raise RuntimeError("C1 production allocation_store_max_bytes must be 67108864")
    range_end = cfg["public_descriptor_range_end"]
    if (type(range_end) is not int or not 10999 <= range_end <= 1_000_000):
        raise RuntimeError(
            "public_descriptor_range_end must be an integer in [10999,1000000]")
    consensus_manifest_hash = cfg["custody_consensus_manifest_sha256"]
    if (not isinstance(consensus_manifest_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", consensus_manifest_hash)):
        raise RuntimeError(
            "custody_consensus_manifest_sha256 must be canonical 64-hex")
    command = cfg["consensus_reservation_command"]
    if (not isinstance(command, list) or not command or len(command) > 64 or
            any(not isinstance(part, str) or not part or "\x00" in part
                for part in command) or not os.path.isabs(command[0])):
        raise RuntimeError(
            "consensus_reservation_command must be an absolute bounded argv")
    return (path, maximum, policy_hash, range_end,
            consensus_manifest_hash, tuple(command))


# ------------------------------------------------------------------ RPC clients
class Btc:
    """Read-only bitcoin-cli wrapper for the custody wallet."""
    def __init__(self, cli_base, wallet):
        if (not isinstance(cli_base, list) or not cli_base or
                any(not isinstance(item, str) or not item or "\x00" in item
                    for item in cli_base)):
            raise RuntimeError("cli_base must be a non-empty argv string list")
        if wallet is not None and not isinstance(wallet, str):
            raise RuntimeError("wallet must be a string")
        self.base = list(cli_base) + ([f"-rpcwallet={wallet}"] if wallet else [])

    def call(self, method, *args):
        out = run_bounded_subprocess(
            self.base + [method] + [str(a) for a in args], timeout=60,
            stdout_max=MAX_CLI_OUTPUT_BYTES, stderr_max=1024 * 1024,
            description="bitcoin-cli %s" % method)
        if out.returncode != 0:
            raise RuntimeError(f"bitcoin-cli {method}: {out.stderr.strip()[:1000]}")
        s = out.stdout.strip()
        try:
            return strict_json_loads(s, "bitcoin-cli %s response" % method)
        except (json.JSONDecodeError, ValueError):
            return s


class Veld:
    """veld-node JSON-RPC over localhost with a bearer token. The node stores
    rpc.token encrypted, so the plaintext token is obtained via
    token_cmd = the `veld-node --print-rpc-token` helper, which decrypts it with
    VELD_VAULT_PASSPHRASE from the daemon's environment. token_file (a plaintext
    token) is only a fallback for dev/regtest."""
    def __init__(self, url, token_file=None, token_cmd=None):
        self.url = validate_backend_rpc_url(url, "veld_rpc.url")
        self.token = ""
        if token_cmd:
            if (not isinstance(token_cmd, list) or not token_cmd or
                    any(not isinstance(item, str) or not item or "\x00" in item
                        for item in token_cmd)):
                raise RuntimeError("veld_rpc.token_cmd must be a non-empty argv string list")
            out = run_bounded_subprocess(
                list(token_cmd), timeout=30, stdout_max=4096,
                stderr_max=64 * 1024, description="rpc token_cmd")
            if out.returncode != 0:
                raise RuntimeError("rpc token_cmd failed: " + out.stderr.strip()[:200])
            self.token = out.stdout.strip()
        elif token_file and os.path.exists(token_file):
            self.token = read_bounded_secret_file(
                token_file, 4096, "Veld RPC token").decode("ascii").strip()

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
            raise RuntimeError(f"{method}: malformed JSON-RPC envelope")
        if r.get("error"):
            raise RuntimeError(f"{method}: {r['error']}")
        return r.get("result")


# ------------------------------------------------------------------ helpers
def btc_to_sats(amount):
    """Exact BTC-decimal -> int sats (no float; bitcoin-cli emits decimal strings)."""
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


def _ensure_private_state_dir(path):
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError("state_dir must be an absolute path")
    if os.path.realpath(path) != os.path.abspath(path):
        raise RuntimeError("state_dir must not traverse symlinks")
    os.makedirs(path, mode=0o700, exist_ok=True)
    info = os.lstat(path)
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise RuntimeError(
            "state_dir must be a service-owned non-symlink mode-0700 directory")


def _validate_ledger(document):
    if not isinstance(document, dict):
        raise RuntimeError("mint ledger root must be an object")
    for oid, record in document.items():
        if (not isinstance(oid, str) or not OUTPOINT_RE.fullmatch(oid) or
                int(oid.rsplit(":", 1)[1]) > 0xffffffff):
            raise RuntimeError("mint ledger contains a malformed deposit outpoint")
        if not isinstance(record, dict) or record.get("status") not in (
                "reprepare", "prepared", "signed", "broadcast", "effect_confirmed",
                "hold", "minting", "minted"):
            raise RuntimeError("mint ledger contains a malformed status record")
        if not isinstance(record.get("recipient"), str) or not VELD_ADDR_RE.fullmatch(
                record["recipient"]):
            raise RuntimeError("mint ledger contains a malformed recipient")
        sats = record.get("sats")
        at = record.get("at")
        if (type(sats) is not int or sats <= 0 or sats > (1 << 63) - 1 or
                type(at) is not int or at < 0 or at > (1 << 63) - 1):
            raise RuntimeError("mint ledger contains malformed amount/time fields")
        txid = record.get("veld_txid")
        if txid is not None and (not isinstance(txid, str) or not TXID_RE.fullmatch(txid)):
            raise RuntimeError("mint ledger contains a malformed Veld txid")
        status = record["status"]
        common = {"status", "recipient", "sats", "at"}
        if status in ("reprepare", "prepared", "signed") and \
                "excluded_issuer_prevouts" in record:
            validate_issuer_prevout_exclusions(
                record["excluded_issuer_prevouts"])
        if status in ("minting", "minted"):
            # Read-only compatibility for explicit legacy/dev fixtures. Live
            # production writes only the strict states below.
            allowed = common | ({"veld_txid"} if txid is not None else set())
            if set(record) != allowed:
                raise RuntimeError("legacy mint ledger record has unexpected fields")
            continue
        unsigned_hex = record.get("unsigned_tx_hex")
        if status in ("prepared", "signed") and (
                not isinstance(unsigned_hex, str) or
                not re.fullmatch(r"[0-9a-fA-F]+", unsigned_hex) or
                len(unsigned_hex) > 2 * MAX_SIGNED_TX_BYTES or
                not isinstance(record.get("inputs"), list) or
                record.get("signer_allocation") is not None and
                not isinstance(record.get("signer_allocation"), dict)):
            raise RuntimeError("mint ledger prepared template is malformed")
        signed_hex = record.get("signed_tx_hex")
        if status in ("signed", "broadcast", "effect_confirmed", "hold") and (
                not isinstance(signed_hex, str) or
                not re.fullmatch(r"[0-9a-fA-F]+", signed_hex) or
                len(signed_hex) > 2 * MAX_SIGNED_TX_BYTES):
            raise RuntimeError("mint ledger signed transaction is malformed")
        schemas = {
            "reprepare": common | {"excluded_issuer_prevouts"},
            "prepared": common | {"unsigned_tx_hex", "inputs",
                                  "signer_allocation"},
            "signed": common | {"unsigned_tx_hex", "inputs",
                                "signer_allocation", "signed_tx_hex"},
            "broadcast": common | {"signed_tx_hex", "veld_txid",
                                   "broadcast_at"},
            "hold": common | {"signed_tx_hex", "veld_txid",
                              "broadcast_at", "hold_reason"},
            "effect_confirmed": common | {
                "signed_tx_hex", "veld_txid", "broadcast_at", "effect_at",
                "accepted_block_height", "accepted_block_hash"},
        }
        allowed_schemas = (schemas[status],)
        if status in ("prepared", "signed"):
            allowed_schemas += (
                schemas[status] | {"excluded_issuer_prevouts"},)
        if set(record) not in allowed_schemas:
            raise RuntimeError("mint ledger state schema is invalid")
        if status in ("broadcast", "hold", "effect_confirmed"):
            if (not isinstance(txid, str) or
                    type(record.get("broadcast_at")) is not int or
                    record["broadcast_at"] < record["at"]):
                raise RuntimeError("mint ledger broadcast identity is malformed")
        if status == "hold" and (
                not isinstance(record.get("hold_reason"), str) or
                not 1 <= len(record["hold_reason"]) <= 512):
            raise RuntimeError("mint ledger HOLD reason is malformed")
        if status == "effect_confirmed" and (
                type(record.get("effect_at")) is not int or
                record["effect_at"] < record["broadcast_at"] or
                type(record.get("accepted_block_height")) is not int or
                record["accepted_block_height"] < 0 or
                not isinstance(record.get("accepted_block_hash"), str) or
                not TXID_RE.fullmatch(record["accepted_block_hash"])):
            raise RuntimeError("mint ledger effect identity is malformed")
    return document


def load_ledger(path):
    if not os.path.lexists(path):
        return {}
    document = _validate_ledger(load_bounded_json_file(
        os.path.abspath(path), MAX_LEDGER_BYTES, "mint ledger"))
    # Safely tighten a legacy 0644 ledger created before explicit fchmod. Group or
    # world writable files were already rejected by the descriptor-based read.
    os.chmod(path, 0o600)
    return document


def save_json(path, obj):
    """Crash/power-SAFE atomic write (C-04): fsync the temp file AND its directory so a
    power cut can neither corrupt the mint ledger nor surface the rename before the data
    is on disk. Losing/rolling-back this ledger would risk re-minting every deposit, so
    durability here is load-bearing (the consensus one-time-outpoint gate is the ultimate
    backstop, but the ledger must not silently regress in the first place)."""
    _validate_ledger(obj)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                               suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            fd = -1
            json.dump(obj, f, sort_keys=True, separators=(",", ":"))
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        d = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def outpoint_id(txid, vout):
    return f"{txid}:{int(vout)}"


def load_issued_wrap_allocations(path, maximum, custody,
                                 expected_policy_sha256=None):
    """Load the exact wrapd allocator authority used by the issuer minter.

    A Bitcoin address label proves only a destination, not the amount the public
    request admitted.  Production minting therefore accepts an output only when
    this crash-safe allocator journal independently binds its address, recipient,
    descriptor script/index, and exact satoshi amount in an ``issued`` record.
    The complete document is validated on every read so truncation, rollback to
    a malformed prefix, schema drift, or a hand-edited sparse history fails closed.
    """
    if not isinstance(path, str) or not os.path.isabs(path):
        raise RuntimeError("production allocation_store must be an absolute path")
    if (type(maximum) is not int or maximum < 65536 or
            maximum > MAX_ALLOCATION_STORE_BYTES):
        raise RuntimeError("allocation_store_max_bytes is outside [65536,67108864]")
    c1 = expected_policy_sha256 is not None
    if (c1 and (not isinstance(expected_policy_sha256, str) or
                not re.fullmatch(r"[0-9a-f]{64}", expected_policy_sha256))):
        raise RuntimeError("expected C1 policy SHA-256 is malformed")
    custody_range = custody.get("range") if isinstance(custody, dict) else None
    if (not isinstance(custody_range, list) or len(custody_range) != 2 or
            custody_range[0] != 0 or type(custody_range[1]) is not int or
            (c1 and not 10999 <= custody_range[1] <= 1_000_000) or
            (not c1 and custody_range[1] != 999)):
        raise RuntimeError("custody manifest range is unavailable for allocation binding")
    range_end = custody_range[1]
    if (not isinstance(custody, dict) or custody.get("range") != [0, range_end] or
            not isinstance(custody.get("script_pubkeys"), tuple) or
            len(custody["script_pubkeys"]) != range_end + 1):
        raise RuntimeError("custody manifest is unavailable for allocation binding")
    document = load_bounded_json_file(
        path, maximum, "wrap allocation journal", private=True)
    document_keys = {"version", "initial_next_index", "records"}
    version = ALLOCATION_JOURNAL_VERSION
    initial_min = 1
    record_keys = ALLOCATION_RECORD_KEYS
    if c1:
        document_keys = {
            "version", "pool_range_start", "records",
            "capacity_policy_sha256", "capacity_policy_sequence",
            "public_descriptor_range_end", "last_consensus_sequence", "events",
        }
        version = C1_ALLOCATION_JOURNAL_VERSION
        initial_min = 1000
        record_keys = C1_ALLOCATION_RECORD_KEYS
    if (not isinstance(document, dict) or
            set(document) != document_keys or
            document.get("version") != version or
            (not c1 and
             (type(document.get("initial_next_index")) is not int or
              not initial_min <= document["initial_next_index"] <= range_end)) or
            not isinstance(document.get("records"), list) or
            len(document["records"]) > (100_000 if c1 else 999) or
            (c1 and (document.get("capacity_policy_sha256") !=
                     expected_policy_sha256 or
                     type(document.get("capacity_policy_sequence")) is not int or
                     document["capacity_policy_sequence"] < 1 or
                     document.get("pool_range_start") != 1000 or
                     document.get("public_descriptor_range_end") != range_end or
                     type(document.get("last_consensus_sequence")) is not int or
                     not 0 <= document["last_consensus_sequence"] <=
                         (1 << 64) - 1 or
                     not isinstance(document.get("events"), list) or
                     len(document["records"]) + len(document["events"]) > 100_000))):
        raise RuntimeError("wrap allocation journal schema is invalid")
    initial = (document["initial_next_index"] if not c1 else
               document["pool_range_start"])
    if c1:
        previous_event = "0" * 64
        for number, event in enumerate(document["events"], 1):
            if (not isinstance(event, dict) or set(event) != {
                    "sequence", "at", "action", "request_id",
                    "previous_event_sha256", "event_sha256"}
                    or event.get("sequence") != number
                    or type(event.get("at")) is not int or event["at"] < 0
                    or event.get("action") not in (
                        "reserved", "core_allocated", "witness_issued",
                        "deposit_observed", "funded_reservation_observed",
                        "minted", "expired")
                    or not isinstance(event.get("request_id"), str)
                    or not ALLOCATION_REQUEST_RE.fullmatch(event["request_id"])
                    or event.get("previous_event_sha256") != previous_event
                    or not isinstance(event.get("event_sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}",
                                        event["event_sha256"])):
                raise RuntimeError("wrap allocation event chain is invalid")
            core = dict(event)
            claimed = core.pop("event_sha256")
            actual = hashlib.sha256(json.dumps(
                core, sort_keys=True, separators=(",", ":"),
                allow_nan=False).encode("utf-8")).hexdigest()
            if claimed != actual:
                raise RuntimeError("wrap allocation event hash is invalid")
            previous_event = claimed
    records = []
    seen_requests, seen_indices, seen_addresses = set(), set(), set()
    seen_blinds, seen_consensus_ids = set(), set()
    reserved = []
    for record in document["records"]:
        if not isinstance(record, dict) or set(record) != record_keys:
            raise RuntimeError("wrap allocation record schema is invalid")
        request_id = record["request_id"]
        principal = record["principal_hash"]
        recipient = record["veld_address"]
        amount = record["amount_sats"]
        index = record["descriptor_index"]
        address = record["btc_address"]
        script = record["script_pubkey"]
        state = record["state"]
        if (not isinstance(request_id, str) or
                not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
                request_id in seen_requests or
                not isinstance(principal, str) or
                not PRINCIPAL_HASH_RE.fullmatch(principal) or
                not isinstance(recipient, str) or
                not VELD_ADDR_RE.fullmatch(recipient) or
                type(amount) is not int or not 1 <= amount <= MAX_MONEY_SATS or
                type(index) is not int or not initial <= index <= range_end or
                index in seen_indices or
                not isinstance(address, str) or not 14 <= len(address) <= 100 or
                address in seen_addresses or
                script != custody["script_pubkeys"][index] or
                state not in ("reserved", "allocated", "issued")):
            raise RuntimeError("wrap allocation record is invalid")
        if c1 and (
                type(record.get("admitted_at")) is not int or
                type(record.get("expires_at")) is not int or
                record["expires_at"] - record["admitted_at"] != 604_800 or
                not isinstance(record.get("capacity_policy_sha256"), str) or
                not re.fullmatch(r"[0-9a-f]{64}",
                                 record["capacity_policy_sha256"]) or
                not isinstance(record.get("commitment_blind"), str) or
                not re.fullmatch(r"[0-9a-f]{64}",
                                 record["commitment_blind"]) or
                int(record["commitment_blind"], 16) == 0 or
                record["commitment_blind"] in seen_blinds or
                not isinstance(record.get("consensus_allocation_id"), str) or
                not re.fullmatch(r"0{16}[0-9a-f]{16}",
                                 record["consensus_allocation_id"]) or
                int(record["consensus_allocation_id"], 16) == 0 or
                int(record["consensus_allocation_id"], 16) >
                    document["last_consensus_sequence"] or
                record["consensus_allocation_id"] in seen_consensus_ids):
            raise RuntimeError("wrap allocation C1 metadata is invalid")
        try:
            address_script = custody_binding._bech32m_spk(address)
        except RuntimeError as exc:
            raise RuntimeError(
                "wrap allocation address is not canonical custody P2TR") from exc
        if address_script != script:
            raise RuntimeError(
                "wrap allocation address does not match its custody script")
        seen_requests.add(request_id)
        seen_indices.add(index)
        seen_addresses.add(address)
        if c1:
            seen_blinds.add(record["commitment_blind"])
            seen_consensus_ids.add(record["consensus_allocation_id"])
        records.append(record)
        if state != "issued":
            reserved.append(record)
    records.sort(key=(lambda record: int(record["consensus_allocation_id"], 16))
                 if c1 else (lambda record: record["descriptor_index"]))
    if (((not c1) and
         [record["descriptor_index"] for record in records] !=
         list(range(initial, initial + len(records)))) or
            (records and max(record["descriptor_index"] for record in records) >
             range_end) or len(reserved) > 1 or
            (reserved and reserved != records[-1:])):
        raise RuntimeError("wrap allocation descriptor history is not contiguous")
    return {record["btc_address"]: dict(record) for record in records
            if record["state"] == "issued"}


class UnsignedMintCarrierAbandoned(RuntimeError):
    def __init__(self, conflicting_input_outpoints):
        super().__init__("signer durably revoked conflicting unsigned carrier")
        self.conflicting_input_outpoints = list(conflicting_input_outpoints)


class RemoteSigner:
    """Calls the ISOLATED signer box over SSH (an authorized_keys FORCED-COMMAND that
    runs veld_signerd.py). The minter NEVER holds the issuer key: the key + passphrase
    live only on the signer box, which independently re-validates every mint (recipient
    + amount re-derived from the tx bytes, its own caps + kill-switch) before signing.
    The signer forwards the allocation claim to an independent watchtower, which
    verifies its own immutable registration and Bitcoin Core outpoint. A
    fully-compromised minter can at most ask; it cannot redirect or oversize a mint."""
    def __init__(self, ssh_target, ssh_key, remote_cmd):
        self.ssh_target = ssh_target      # e.g. an access-controlled ssh_config alias
        self.ssh_key    = ssh_key         # identity file for the signer box
        self.remote_cmd = remote_cmd      # ignored if a forced-command is configured

    def sign(self, unsigned_tx_hex, inputs, recipient, sats, allocation=None):
        # N-01: the isolated signer parses input outpoints from unsigned_tx_hex and
        # resolves value/script/confirmations from its own trusted Veld node.  Do not
        # transmit the preparer's advisory inputs[] as if it were signer authority.
        _ = inputs   # retained in this local API only for prepared-response compatibility
        req = json.dumps({"unsigned_tx_hex": unsigned_tx_hex,
                          "recipient": recipient, "sats": int(sats)})
        if allocation is not None:
            required = {
                "request_id", "btc_address", "script_pubkey",
                "deposit_outpoint", "descriptor_index",
                "capacity_policy_sha256", "commitment_blind",
                "consensus_allocation_id",
                "public_descriptor_range_start",
                "public_descriptor_range_end",
            }
            if not isinstance(allocation, dict) or set(allocation) != required:
                raise RuntimeError("mint allocation signer claim is malformed")
            envelope = {"unsigned_tx_hex": unsigned_tx_hex,
                        "recipient": recipient, "sats": int(sats),
                        "allocation": allocation}
            req = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
        cmd = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=/var/lib/veld-peg/.ssh/known_hosts",
        ]
        if self.ssh_key:
            cmd += ["-i", self.ssh_key]
        cmd += [self.ssh_target, self.remote_cmd]
        out = run_bounded_subprocess(
            cmd, input_text=req, timeout=60,
            stdout_max=MAX_SIGNED_TX_BYTES, stderr_max=1024 * 1024,
            description="remote mint signer")
        if out.returncode == 75 and allocation is not None:
            try:
                answer = strict_json_loads(
                    out.stdout, "remote signer unsigned abandonment")
            except Exception as exc:
                raise RuntimeError(
                    "remote signer returned a malformed abandonment") from exc
            expected = {"version", "action", "capability", "owner_id",
                        "allocation_id", "deposit_outpoint",
                        "unsigned_sha256", "conflicting_input_outpoints",
                        "reason"}
            allocation_id = allocation["consensus_allocation_id"]
            unsigned_sha256 = hashlib.sha256(
                bytes.fromhex(unsigned_tx_hex)).hexdigest()
            try:
                conflicts = validate_issuer_prevout_exclusions(
                    answer.get("conflicting_input_outpoints")
                    if isinstance(answer, dict) else None,
                    candidate_inputs=unsigned_input_outpoints(
                        unsigned_tx_hex))
            except Exception as exc:
                raise RuntimeError(
                    "remote signer abandonment does not bind this exact carrier") \
                    from exc
            if (not isinstance(answer, dict) or set(answer) != expected or
                    answer.get("version") != 1 or
                    answer.get("action") != "unsigned_carrier_abandoned" or
                    answer.get("capability") != "mint" or
                    answer.get("owner_id") != "mint:" + allocation_id or
                    answer.get("allocation_id") != allocation_id or
                    answer.get("deposit_outpoint") !=
                        allocation["deposit_outpoint"] or
                    answer.get("unsigned_sha256") != unsigned_sha256 or
                    answer.get("reason") != "issuer_prevout_conflict"):
                raise RuntimeError(
                    "remote signer abandonment does not bind this exact carrier")
            raise UnsignedMintCarrierAbandoned(conflicts)
        if out.returncode != 0:
            raise RuntimeError("remote signer refused/unreachable: " + out.stderr.strip()[:200])
        signed = out.stdout.strip()
        if not re.match(r'^[0-9a-fA-F]+$', signed) or len(signed) < 100:
            raise RuntimeError("remote signer returned no valid signed tx")
        return signed


# ------------------------------------------------------------------ the minter
class Minter:
    def __init__(self, cfg):
        if not isinstance(cfg, dict):
            raise RuntimeError("mintd configuration root must be an object")
        self.cfg   = cfg
        self.state = cfg["state_dir"]
        _ensure_private_state_dir(self.state)
        if "production" in cfg and type(cfg["production"]) is not bool:
            raise RuntimeError("production must be the JSON boolean true or false")
        self.production = cfg.get("production", False)
        self.allocation_store = None
        self.allocation_store_max_bytes = None
        self.allocation_policy_sha256 = None
        self.public_descriptor_range_end = None
        self.custody_consensus_manifest_sha256 = None
        self.consensus_reservation_command = None
        if self.production:
            (self.allocation_store,
             self.allocation_store_max_bytes,
             self.allocation_policy_sha256,
             self.public_descriptor_range_end,
             self.custody_consensus_manifest_sha256,
             self.consensus_reservation_command) = (
                production_allocation_settings(cfg))
        self.btc   = Btc(cfg["cli_base"], cfg.get("wallet", "custody"))
        self.veld  = Veld(cfg["veld_rpc"]["url"], cfg["veld_rpc"].get("token_file"),
                          cfg["veld_rpc"].get("token_cmd"))
        self.issuer_addr = cfg["issuer_addr"]
        if not isinstance(self.issuer_addr, str) or not VELD_ADDR_RE.fullmatch(
                self.issuer_addr):
            raise RuntimeError("issuer_addr is malformed")
        sc = cfg["signer"]   # {"ssh_target", "ssh_key"?, "remote_cmd"?}
        self.signer = RemoteSigner(sc["ssh_target"], sc.get("ssh_key", ""),
                                   sc.get("remote_cmd",
                                          "veld_signerd --capability mint"))
        # tunables (config overrides; conservative defaults)
        self.K_BTC = _config_int(
            cfg.get("k_btc_confirmations", 6),
            "k_btc_confirmations", 1, 1_000_000)
        self.MAX_SINGLE_SATS = _config_int(
            cfg.get("max_single_mint_sats", 5 * SATS),
            "max_single_mint_sats", 1, (1 << 63) - 1)       # dev default only
        self.MAX_WINDOW_SATS = _config_int(
            cfg.get("max_window_mint_sats", 25 * SATS),
            "max_window_mint_sats", 1, (1 << 63) - 1)       # dev default only
        self.WINDOW_SECS = _config_int(
            cfg.get("window_secs", 3600), "window_secs", 1, 31_536_000)
        self.RECONCILE_TOL_SATS = _config_int(
            cfg.get("reconcile_tolerance_sats", 0),
            "reconcile_tolerance_sats", 0, (1 << 63) - 1)
        self.ledger_path = os.path.join(self.state, "minted_deposits.json")
        self.halt_path   = os.path.join(self.state, "HALT")
        self.ledger = load_ledger(self.ledger_path)
        self._halted_memory = False
        self._halt_marker_durable = False
        self.custody = None
        self.peg_identity = None
        if self.production:
            self.custody = custody_binding.load_manifest(
                cfg.get("custody_spk_manifest_file"),
                cfg.get("custody_descriptor_sha256"),
                cfg.get("custody_manifest_sha256"),
                expected_range_end=self.public_descriptor_range_end,
                expected_consensus_manifest_sha256=(
                    self.custody_consensus_manifest_sha256),
            )
            # Prove the exact allocator authority is present and readable before
            # any network or signer work can begin.  Empty is valid; absent,
            # unsafe, malformed, or schema-drifted is not.
            self._issued_allocations()
            self._configure_production()

    # --- kill-switch (T7/T8): any HALT blocks all minting until a human clears it ---
    def halted(self):
        if self._halted_memory:
            # Preserve the documented operator recovery path: after a durable
            # marker is deliberately removed, a later pass may resume. If marker
            # creation itself failed, memory remains sticky until process restart.
            if self._halt_marker_durable and not os.path.lexists(self.halt_path):
                self._halted_memory = False
                self._halt_marker_durable = False
            else:
                return True
        if not os.path.lexists(self.halt_path):
            return False
        try:
            info = os.lstat(self.halt_path)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                    info.st_uid not in (0, os.geteuid()) or
                    stat.S_IMODE(info.st_mode) & 0o022):
                warn("HALT path is not a trusted regular file; failing closed")
        except OSError:
            pass
        return True

    def trip_halt(self, reason):
        # Stop this process immediately even if the disk is full and the sticky
        # marker cannot be created. The next startup also scans the durable ledger
        # for any unfinished mint before considering new work.
        self._halted_memory = True
        try:
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            fd = os.open(self.halt_path, flags, 0o600)
            try:
                os.write(fd, f"{int(time.time())} {reason}\n".encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)
            dfd = os.open(self.state, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
            self._halt_marker_durable = True
        except FileExistsError:
            self._halt_marker_durable = True
        except Exception:
            pass
        warn(f"*** HALT tripped: {reason} - all minting stopped until {self.halt_path} is removed ***")

    # --- the load-bearing invariant (T7): btcVELD supply must never exceed custody ---
    def btcveld_supply_sats(self):
        s = self.veld.rpc("getbtcveldsupply")          # {"supply_sats": <int>}  (node RPC)
        value = s.get("supply_sats") if isinstance(s, dict) else s
        if type(value) is not int or value < 0 or value > (1 << 63) - 1:
            raise RuntimeError("getbtcveldsupply returned a malformed integer")
        return value

    def _verify_production_identity(self, *, completion=False):
        if not self.production:
            return None
        peg = self.veld.rpc("getpeginfo")
        supply_before = self.veld.rpc("getbtcveldsupply")
        tip = peg.get("tip") if isinstance(peg, dict) else None
        tip_hash_before = self.veld.rpc("getblockhash", [tip])
        peg_after = self.veld.rpc("getpeginfo")
        supply_after = self.veld.rpc("getbtcveldsupply")
        tip_hash_after = self.veld.rpc("getblockhash", [tip])
        custody_binding.verify_peg_identity(peg, self.custody)
        required_gate = "completion_live" if completion else "mint_live"
        if (not isinstance(peg, dict) or
                peg.get("peg_unlocked") is not True or
                peg.get(required_gate) is not True):
            raise RuntimeError(
                "btcVELD %s is closed by the canonical launch/liveness gate" %
                ("completion" if completion else "minting"))
        if peg.get("issuer") != self.issuer_addr:
            raise RuntimeError("configured issuer differs from the compiled btcVELD issuer")
        try:
            values = [peg.get(name) for name in (
                "spv_k_btc", "issuer_max_per_mint_sats",
                "issuer_static_custody_cap_sats",
                "issuer_effective_custody_cap_sats",
                "issuer_reserved_sats",
                "issuer_mint_headroom_sats")]
            if any(type(value) is not int for value in values):
                raise ValueError("issuer policy values are not exact integers")
            (k_btc, issuer_max, issuer_static_cap,
             issuer_effective_cap, issuer_reserved, issuer_headroom) = values
        except (TypeError, ValueError):
            raise RuntimeError("getpeginfo omitted canonical production mint policy")
        if self.K_BTC != k_btc or k_btc < 1:
            raise RuntimeError("production Bitcoin confirmations differ from compiled spv_k_btc")
        if self.MAX_SINGLE_SATS != issuer_max or issuer_max <= 0:
            raise RuntimeError("production max_single_mint_sats differs from consensus")
        if (self.MAX_WINDOW_SATS <= 0 or
                self.MAX_WINDOW_SATS > issuer_static_cap or
                issuer_effective_cap > issuer_static_cap or issuer_effective_cap < 0 or
                issuer_reserved < 0 or issuer_reserved > issuer_static_cap or
                issuer_headroom < 0 or issuer_headroom > issuer_effective_cap):
            raise RuntimeError("production mint window/cap policy exceeds consensus")
        capacity_fields = (
            "tip", "supply_sats", "issuer_effective_custody_cap_sats",
            "issuer_reserved_sats",
            "issuer_mint_headroom_sats", "issuer_max_per_mint_sats",
            "issuer_static_custody_cap_sats")
        if (not isinstance(supply_before, dict) or
                supply_before != supply_after or
                set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
                type(supply_before.get("supply_sats")) is not int or
                supply_before["supply_sats"] < 0 or
                supply_before.get("tip") != tip or
                not isinstance(supply_before.get("tip_hash"), str) or
                not TXID_RE.fullmatch(supply_before["tip_hash"]) or
                tip_hash_before != supply_before["tip_hash"] or
                tip_hash_after != tip_hash_before or
                any(peg.get(name) != peg_after.get(name)
                    for name in capacity_fields) or
                peg.get("supply_sats") != supply_before["supply_sats"] or
                issuer_headroom != max(
                    0, issuer_effective_cap - supply_before["supply_sats"] -
                    issuer_reserved)):
            raise RuntimeError(
                "production issuer capacity/supply tuple changed or is incoherent")
        self.peg_identity = peg
        return peg

    def _configure_production(self):
        if self.RECONCILE_TOL_SATS != 0:
            raise RuntimeError("production reconcile_tolerance_sats must be exactly zero")
        chain = self.btc.call("getblockchaininfo")
        if not isinstance(chain, dict) or chain.get("chain") != "main":
            raise RuntimeError("production custody Bitcoin Core is not mainnet")
        descriptor_info = self.btc.call("getdescriptorinfo", self.custody["descriptor"])
        if (not isinstance(descriptor_info, dict) or
                descriptor_info.get("hasprivatekeys") is not False or
                descriptor_info.get("isrange") is not True):
            raise RuntimeError("production custody descriptor is private or non-ranged")
        wallet_descriptors = self.btc.call("listdescriptors", "false")
        entries = (wallet_descriptors.get("descriptors")
                   if isinstance(wallet_descriptors, dict) else None)
        if (not isinstance(entries, list) or len(entries) != 1 or
                entries[0].get("desc") != self.custody["descriptor"] or
                entries[0].get("internal") is not False or
                entries[0].get("active") is not False or
                entries[0].get("range") != self.custody["range"]):
            raise RuntimeError("minter wallet must contain exactly the pinned custody descriptor")
        custody_binding.verify_core_derivation(self.btc.call, self.custody)
        # Production defaults come from consensus, never from permissive dev
        # constants. Explicit config is allowed only when it is no wider.
        peg = self.veld.rpc("getpeginfo")
        custody_binding.verify_peg_identity(peg, self.custody)
        try:
            issuer_max = peg.get("issuer_max_per_mint_sats")
            issuer_static_cap = peg.get("issuer_static_custody_cap_sats")
            if type(issuer_max) is not int or type(issuer_static_cap) is not int:
                raise ValueError("issuer caps are not exact integers")
        except (TypeError, ValueError):
            raise RuntimeError("getpeginfo omitted issuer mint caps")
        if "max_single_mint_sats" not in self.cfg:
            self.MAX_SINGLE_SATS = issuer_max
        if "max_window_mint_sats" not in self.cfg:
            self.MAX_WINDOW_SATS = issuer_static_cap
        # This daemon only advances issued C1 allocations in production.  It
        # must remain startable during the narrowly scoped post-unlock
        # completion exception; every carrier is still rebound below to a
        # deep, exposed C1 reservation before C1F1/MNP2 is constructed.
        self._verify_production_identity(completion=True)

    def _production_wallet_rows(self):
        rows = self.btc.call("listunspent", self.K_BTC, 9999999)
        if not isinstance(rows, list):
            raise RuntimeError("production custody listunspent returned invalid data")
        for row in rows:
            if not isinstance(row, dict):
                raise RuntimeError("production custody UTXO row is invalid")
            script = str(row.get("scriptPubKey", "")).lower()
            if script not in self.custody["script_pubkey_set"]:
                raise RuntimeError("custody wallet returned an output outside the pinned manifest")
        return rows

    def _issued_allocations(self):
        if not self.production:
            return {}
        return load_issued_wrap_allocations(
            self.allocation_store, self.allocation_store_max_bytes,
            self.custody, self.allocation_policy_sha256)

    def _require_current_issued_allocation(self, deposit):
        """Re-read and exactly bind one production deposit immediately pre-mint."""
        if not self.production:
            return None
        if not isinstance(deposit, dict):
            raise RuntimeError("production deposit candidate is not an object")
        address = deposit.get("deposit_address")
        request_id = deposit.get("allocation_request_id")
        script = deposit.get("script_pubkey")
        recipient = deposit.get("recipient")
        sats = deposit.get("sats")
        if (not isinstance(address, str) or
                not isinstance(request_id, str) or
                not ALLOCATION_REQUEST_RE.fullmatch(request_id) or
                not isinstance(script, str) or
                not isinstance(recipient, str) or
                not VELD_ADDR_RE.fullmatch(recipient) or
                type(sats) is not int or sats <= 0):
            raise RuntimeError("production deposit allocation fields are malformed")
        allocation = self._issued_allocations().get(address)
        if (allocation is None or
                allocation.get("request_id") != request_id or
                allocation.get("btc_address") != address or
                allocation.get("script_pubkey") != script or
                allocation.get("veld_address") != recipient or
                allocation.get("amount_sats") != sats):
            raise RuntimeError(
                "deposit is not exactly bound to a current issued wrap allocation")
        return allocation

    def _require_canonical_c1_reservation(self, allocation, peg,
                                          outpoint=None,
                                          require_funded=False):
        """Validate MNP2's occupied capacity; unreserved headroom is irrelevant."""
        if not isinstance(allocation, dict) or not isinstance(peg, dict):
            raise RuntimeError("C1 reservation boundary is malformed")
        allocation_id = allocation.get("consensus_allocation_id")
        status = self.veld.rpc("getbtcveldc1reservation", [allocation_id])
        supply = peg.get("supply_sats")
        static_cap = peg.get("issuer_static_custody_cap_sats")
        reserved = peg.get("issuer_reserved_sats")
        amount = allocation.get("amount_sats")
        if (not isinstance(status, dict) or
                status.get("allocation_id") != allocation_id or
                status.get("found") is not True or
                status.get("active") is not True or
                status.get("exposed") is not True or
                status.get("exposure_canonical_depth_reached") is not True or
                type(status.get("exposure_confirmations")) is not int or
                status["exposure_confirmations"] < 101 or
                status.get("recipient") != allocation.get("veld_address") or
                status.get("amount_sats") != amount or
                status.get("allocation_commitment") != allocation_commitment(
                    allocation_id, allocation.get("veld_address"), amount,
                    allocation.get("script_pubkey"),
                    allocation.get("commitment_blind")) or
                status.get("tip") != peg.get("tip") or
                type(status.get("funded")) is not bool or
                (require_funded and status.get("funded") is not True) or
                (require_funded and status.get("funding_outpoint") != outpoint) or
                (not require_funded and status.get("funded") is True and
                 outpoint is not None and status.get("funding_outpoint") != outpoint) or
                type(supply) is not int or type(static_cap) is not int or
                type(reserved) is not int or type(amount) is not int or
                reserved < amount or supply < 0 or amount <= 0 or
                supply > static_cap - amount):
            raise RuntimeError(
                "matching canonical exposed C1 capacity is unavailable")
        return status

    def _build_c1_funding_proof(self, deposit, allocation):
        """Build canonical CFP1 from this daemon's independent Bitcoin Core."""
        if not self.production:
            raise RuntimeError("CFP1 is production C1 lifecycle data")
        txid = deposit.get("txid")
        vout = deposit.get("vout")
        outpoint = outpoint_id(txid, vout)
        if (not isinstance(txid, str) or not TXID_RE.fullmatch(txid) or
                type(vout) is not int or not 0 <= vout <= 0xffffffff):
            raise RuntimeError("CFP1 deposit outpoint is malformed")

        verbose = self.btc.call("getrawtransaction", txid, "true")
        block_hash = verbose.get("blockhash") if isinstance(verbose, dict) else None
        confirmations = (verbose.get("confirmations")
                         if isinstance(verbose, dict) else None)
        if (not isinstance(block_hash, str) or not TXID_RE.fullmatch(block_hash) or
                type(confirmations) is not int or confirmations < self.K_BTC + 1 or
                verbose.get("txid") not in (None, txid)):
            raise RuntimeError("Bitcoin funding transaction is not final/canonical")
        header = self.btc.call("getblockheader", block_hash, "true")
        if (not isinstance(header, dict) or header.get("hash") != block_hash or
                type(header.get("height")) is not int or header["height"] < 0 or
                type(header.get("confirmations")) is not int or
                header["confirmations"] < self.K_BTC + 1):
            raise RuntimeError("Bitcoin funding block is not on the final best chain")
        block_height = header["height"]
        if self.btc.call("getblockhash", block_height) != block_hash:
            raise RuntimeError("Bitcoin funding height mapping changed")
        relay = self.veld.rpc("getbtcheaderinfo")
        if (not isinstance(relay, dict) or relay.get("spv_active") is not True or
                relay.get("k_btc") != self.K_BTC or
                type(relay.get("best_height")) is not int or
                relay["best_height"] < block_height + self.K_BTC):
            raise RuntimeError("Veld Bitcoin-header relay has not finalized funding")

        block = self.btc.call("getblock", block_hash, 1)
        txids = block.get("tx") if isinstance(block, dict) else None
        if (not isinstance(txids, list) or not txids or
                len(txids) > MAX_BLOCK_TXIDS or txids.count(txid) != 1 or
                any(not isinstance(item, str) or not TXID_RE.fullmatch(item)
                    for item in txids) or
                block.get("hash") not in (None, block_hash) or
                block.get("height") not in (None, block_height)):
            raise RuntimeError("Bitcoin funding block transaction order is malformed")
        branch, directions, root = build_merkle_branch(
            [be_to_le(item) for item in txids], txids.index(txid))
        merkle_root = block.get("merkleroot")
        if (not isinstance(merkle_root, str) or
                not TXID_RE.fullmatch(merkle_root) or
                root != be_to_le(merkle_root) or
                fold_merkle(be_to_le(txid), branch, directions) != root):
            raise RuntimeError("locally built CFP1 Merkle proof is inconsistent")

        raw_hex = self.btc.call("getrawtransaction", txid, "false", block_hash)
        if (not isinstance(raw_hex, str) or len(raw_hex) % 2 or
                not re.fullmatch(r"[0-9a-f]+", raw_hex) or
                len(raw_hex) > MAX_BITCOIN_TX_BYTES * 2):
            raise RuntimeError("Bitcoin funding transaction bytes are malformed")
        parsed = parse_and_strip_bitcoin_tx(bytes.fromhex(raw_hex))
        legacy = parsed["legacy"]
        if (not 64 < len(legacy) <= 8000 or dsha(legacy)[::-1].hex() != txid):
            raise RuntimeError("CFP1 stripped transaction identity is invalid")
        exact_script = bytes.fromhex(allocation["script_pubkey"])
        exact_outputs = [row for row in parsed["outputs"]
                         if row["script"] == exact_script and
                         row["value_sats"] == allocation["amount_sats"]]
        if (len(exact_outputs) != 1 or exact_outputs[0]["vout"] != vout or
                deposit.get("sats") != allocation["amount_sats"]):
            raise RuntimeError("CFP1 does not open the exact allocation output")

        nullifier = self.mint_outpoint_status(outpoint)
        if (nullifier["consumed"] or nullifier["minted"] or
                not isinstance(nullifier.get("proof_hex"), str) or
                not re.fullmatch(r"[0-9a-f]+", nullifier["proof_hex"]) or
                not isinstance(nullifier.get("root"), str) or
                not TXID_RE.fullmatch(nullifier["root"]) or
                type(nullifier.get("count")) is not int or
                nullifier["count"] < 0):
            raise RuntimeError("CFP1 parent nullifier state is unavailable")
        proof = (b"CFP1" + be_to_le(block_hash) +
                 struct.pack("<I", directions) + bytes([len(branch)]) +
                 b"".join(branch) + struct.pack("<I", len(legacy)) + legacy +
                 bytes.fromhex(nullifier["proof_hex"]))
        proof_hex = proof.hex()
        if not 174 <= len(proof_hex) <= 38_000:
            raise RuntimeError("CFP1 exceeds the consensus funding carrier bound")

        # Final reorg/root barrier after every proof byte has been constructed.
        if self.btc.call("getblockhash", block_height) != block_hash:
            raise RuntimeError("Bitcoin funding reorged during CFP1 construction")
        fresh = self.mint_outpoint_status(outpoint)
        if (fresh["consumed"] or fresh.get("root") != nullifier["root"] or
                fresh.get("count") != nullifier["count"] or
                fresh.get("proof_hex") != nullifier["proof_hex"]):
            raise RuntimeError("mint-nullifier root changed during CFP1 construction")
        return {
            "outpoint": outpoint,
            "proof_hex": proof_hex,
            "proof_parent_root": nullifier["root"],
            "proof_parent_count": nullifier["count"],
        }

    def _ensure_c1_funded(self, allocation, funding):
        request_allocation = {key: allocation[key] for key in (
            "request_id", "principal_hash", "veld_address", "amount_sats",
            "descriptor_index", "btc_address", "script_pubkey",
            "commitment_blind", "consensus_allocation_id", "admitted_at",
            "expires_at", "capacity_policy_sha256")}
        request = json.dumps({
            "version": 2, "action": "ensure_c1_lifecycle",
            "allocation": request_allocation, "funding": funding,
        }, sort_keys=True, separators=(",", ":"), allow_nan=False)
        completed = run_bounded_subprocess(
            list(self.consensus_reservation_command), input_text=request,
            timeout=120, stdout_max=64 * 1024, stderr_max=64 * 1024,
            description="C1 funding coordinator")
        if completed.returncode not in (0, 75):
            raise RuntimeError("C1 funding coordinator refused: " +
                               completed.stderr.strip()[:240])
        answer = strict_json_loads(completed.stdout,
                                   "C1 funding coordinator response")
        expected = {"version", "allocation_id", "found", "active", "retired",
                    "last_sequence", "exposed", "funded", "funding_outpoint",
                    "confirmations", "required_confirmations",
                    "canonical_depth_reached"}
        if (not isinstance(answer, dict) or set(answer) != expected or
                answer.get("version") != 3 or
                answer.get("allocation_id") !=
                    allocation["consensus_allocation_id"] or
                any(type(answer.get(key)) is not bool for key in
                    ("found", "active", "retired", "exposed", "funded",
                     "canonical_depth_reached")) or
                any(type(answer.get(key)) is not int or answer[key] < 0
                    for key in ("last_sequence", "confirmations",
                                "required_confirmations")) or
                answer["required_confirmations"] != 101 or
                (answer["funded"] and
                 answer.get("funding_outpoint") != funding["outpoint"]) or
                (not answer["funded"] and
                 answer.get("funding_outpoint") is not None)):
            raise RuntimeError("C1 funding coordinator acknowledgement is inexact")
        return completed.returncode == 0 and answer["funded"]

    def custody_confirmed_sats(self):
        # Peg reserve = confirmed balance of the custody wallet at >= K_BTC confs.
        if self.production:
            return sum(btc_to_sats(row.get("amount"))
                       for row in self._production_wallet_rows()
                       if (type(row.get("confirmations")) is int and
                           row["confirmations"] >= self.K_BTC))
        bal = self.btc.call("getbalance", "*", self.K_BTC)
        return btc_to_sats(bal)

    def reconcile_ok(self, mint_sats):
        supply  = self.btcveld_supply_sats()
        custody = self.custody_confirmed_sats()
        if supply + mint_sats > custody + self.RECONCILE_TOL_SATS:
            self.trip_halt(f"reconcile: supply {supply} + mint {mint_sats} > custody {custody}")
            return False
        return True

    # --- rate cap (T8): bound mint volume per rolling window ---
    def window_minted_sats(self):
        cutoff = time.time() - self.WINDOW_SECS
        return sum(r["sats"] for r in self.ledger.values()
                   if r.get("status") in (
                       "signed", "broadcast", "effect_confirmed", "hold",
                       "minted") and r.get("at", 0) >= cutoff)

    def mint_outpoint_status(self, outpoint):
        """Return a strict consensus-effect status for one deposit outpoint."""
        if not isinstance(outpoint, str) or not OUTPOINT_RE.fullmatch(outpoint):
            raise RuntimeError("mint outpoint status query is malformed")
        supply_before = (self.veld.rpc("getbtcveldsupply")
                         if getattr(self, "production", False) else None)
        status = self.veld.rpc("getbtcveldmintstatus", [outpoint])
        supply_after = (self.veld.rpc("getbtcveldsupply")
                        if getattr(self, "production", False) else None)
        if (not isinstance(status, dict) or status.get("outpoint") != outpoint or
                type(status.get("consumed")) is not bool or
                type(status.get("minted")) is not bool or
                status.get("proof_version") != "MNP1" or
                not isinstance(status.get("proof_hex"), str) or
                not re.fullmatch(r"[0-9a-f]+", status["proof_hex"]) or
                not isinstance(status.get("root"), str) or
                not TXID_RE.fullmatch(status["root"]) or
                type(status.get("count")) is not int or status["count"] < 0 or
                type(status.get("tip")) is not int or status["tip"] < 0 or
                not isinstance(status.get("tip_hash"), str) or
                not TXID_RE.fullmatch(status["tip_hash"])):
            raise RuntimeError(
                "getbtcveldmintstatus returned an invalid response")
        if getattr(self, "production", False) and (
                not isinstance(supply_before, dict) or
                supply_before != supply_after or
                set(supply_before) != {"supply_sats", "tip", "tip_hash"} or
                status["tip"] != supply_before.get("tip") or
                status["tip_hash"] != supply_before.get("tip_hash")):
            raise RuntimeError(
                "mint effect status changed across coherent supply tuple")
        def exact_locator(prefix):
            return (isinstance(status.get(prefix + "_txid"), str) and
                    TXID_RE.fullmatch(status[prefix + "_txid"]) and
                    type(status.get(prefix + "_block_height")) is int and
                    status[prefix + "_block_height"] >= 0 and
                    isinstance(status.get(prefix + "_block_hash"), str) and
                    TXID_RE.fullmatch(status[prefix + "_block_hash"]) and
                    type(status.get(prefix + "_tx_index")) is int and
                    status[prefix + "_tx_index"] >= 0 and
                    type(status.get(prefix + "_marker_vout")) is int and
                    status[prefix + "_marker_vout"] >= 0)

        def null_locator(prefix):
            return all(status.get(prefix + suffix) is None for suffix in (
                "_txid", "_block_height", "_block_hash", "_tx_index",
                "_marker_vout"))

        if status["consumed"]:
            if (not exact_locator("accepted") or
                    status.get("accepted_effect_kind") not in
                        ("MINT", "C1_FUND", "C1_MINT")):
                raise RuntimeError(
                    "consumed mint outpoint lacks an exact accepted effect locator")
            if status.get("accepted_effect_kind") in ("C1_FUND", "C1_MINT"):
                if (not isinstance(status.get("c1_allocation_id"), str) or
                        not re.fullmatch(r"0{16}[0-9a-f]{16}",
                                         status["c1_allocation_id"]) or
                        not exact_locator("consumer")):
                    raise RuntimeError("C1 mint status lacks its FUND consumer")
            elif (status.get("c1_allocation_id") is not None or
                  not null_locator("consumer")):
                raise RuntimeError("direct mint carries C1 consumer metadata")
            if status["minted"]:
                if not exact_locator("credit"):
                    raise RuntimeError("minted outpoint lacks its credit locator")
            elif not null_locator("credit"):
                raise RuntimeError("funded-only outpoint carries a credit locator")
        elif (status["minted"] or not null_locator("accepted") or
              not null_locator("consumer") or not null_locator("credit") or
              status.get("accepted_effect_kind") is not None or
              status.get("c1_allocation_id") is not None):
            raise RuntimeError(
                "unconsumed mint outpoint unexpectedly has effect metadata")
        return status

    def mint_outpoint_consumed(self, outpoint):
        """Read the consensus one-time mint-id authority for one BTC deposit."""
        return self.mint_outpoint_status(outpoint)["consumed"]

    def exact_mint_effect(self, outpoint, expected_txid):
        status = self.mint_outpoint_status(outpoint)
        if not status["minted"]:
            return None
        if (status.get("credit_txid") != expected_txid or
                status.get("accepted_txid") != expected_txid or
                status.get("accepted_effect_kind") not in ("MINT", "C1_MINT")):
            raise RuntimeError(
                "deposit outpoint was consumed by a different accepted mint txid")
        return status

    def _prune_settled_ledger(self):
        """Bound local history after its rate-window job is finished.

        Consensus, not this JSON file, is the permanent replay authority.  Once
        a minted row is outside the rolling cap window and the canonical token
        ledger still reports its BTC outpoint consumed, retaining it forever
        only creates an eventual fixed-size-file outage.
        """
        cutoff = time.time() - self.WINDOW_SECS
        removable = []
        for outpoint, record in self.ledger.items():
            if record.get("status") not in ("effect_confirmed", "minted"):
                continue
            if record.get("at", 0) >= cutoff:
                continue
            if record.get("status") == "minted":
                # Legacy/dev fixture compatibility only. Production never
                # creates this state and cannot retire it by raw inclusion.
                if (not getattr(self, "production", False) and
                        self.mint_outpoint_consumed(outpoint)):
                    removable.append(outpoint)
                continue
            effect = self.exact_mint_effect(outpoint, record["veld_txid"])
            if (effect is not None and
                    effect["tip"] - effect["accepted_block_height"] + 1 >
                    MAX_REORG_DEPTH):
                removable.append(outpoint)
        if not removable:
            return 0
        for outpoint in removable:
            del self.ledger[outpoint]
        save_json(self.ledger_path, self.ledger)
        return len(removable)

    def _save_record(self):
        save_json(self.ledger_path, self.ledger)

    def _advance_unresolved(self, outpoint, record):
        """Advance exactly one immutable carrier; never create a replacement."""
        status = record.get("status")
        if status == "reprepare":
            # The exact prior unsigned hash was durably revoked before this
            # state was written. process_one() may now request a replacement
            # carrying the persisted issuer-prevout exclusion suffix.
            return True
        if status == "minting":
            if not self.production:
                # Explicit compatibility for old unit/dev fixtures only.
                if self.mint_outpoint_consumed(outpoint):
                    record["status"] = "minted"
                    self._save_record()
                    return True
                self.trip_halt(
                    f"{outpoint}: legacy mint intent requires manual review")
                return False
            raise RuntimeError(
                "legacy production mint intent requires offline reconciliation")
        if status == "minted":
            if not self.production:
                return self.mint_outpoint_consumed(outpoint)
            raise RuntimeError(
                "legacy production minted state requires offline exact-effect reconciliation")

        expected_txid = record.get("veld_txid")
        if expected_txid is not None:
            effect = self.exact_mint_effect(outpoint, expected_txid)
            if effect is not None:
                if (status == "effect_confirmed" and
                        record.get("accepted_block_height") ==
                        effect["accepted_block_height"] and
                        record.get("accepted_block_hash") ==
                        effect["accepted_block_hash"]):
                    # Preserve the original settlement time for rate-window
                    # accounting. Re-polling an unchanged canonical effect
                    # must not continuously refresh its lifecycle timestamp.
                    return True
                record.update({
                    "status": "effect_confirmed",
                    "effect_at": int(time.time()),
                    "accepted_block_height": effect["accepted_block_height"],
                    "accepted_block_hash": effect["accepted_block_hash"],
                })
                record.pop("hold_reason", None)
                self._save_record()
                log(f"{outpoint}: exact accepted mint effect confirmed "
                    f"txid={expected_txid}")
                return True

        # A shallow reorg returns an effect-confirmed carrier to pending. Keep
        # its byte-identical signed bytes and rebroadcast only that carrier.
        if status == "effect_confirmed":
            record["status"] = "broadcast"
            record.pop("effect_at", None)
            record.pop("accepted_block_height", None)
            record.pop("accepted_block_hash", None)
            self._save_record()
            status = "broadcast"

        if status == "prepared":
            allocation = record["signer_allocation"]
            try:
                signed = self.signer.sign(
                    record["unsigned_tx_hex"], record["inputs"],
                    record["recipient"], record["sats"], allocation)
            except UnsignedMintCarrierAbandoned as abandonment:
                # The isolated signer fsynced a never-sign revocation for these
                # exact unsigned bytes before returning exit 75. Only that exact
                # acknowledgement makes unsigned-only replacement safe. Generic
                # SSH errors and lost replies never reach this branch.
                prior = dict(record)
                exclusions = sorted(set(
                    record.get("excluded_issuer_prevouts", []) +
                    abandonment.conflicting_input_outpoints))
                if len(exclusions) > MAX_ISSUER_PREVOUT_EXCLUSIONS:
                    raise RuntimeError(
                        "issuer prevout exclusion ceiling requires operator review")
                record.clear()
                record.update({
                    "status": "reprepare", "recipient": prior["recipient"],
                    "sats": prior["sats"], "at": prior["at"],
                    "excluded_issuer_prevouts": exclusions,
                })
                try:
                    self._save_record()
                except Exception:
                    record.clear()
                    record.update(prior)
                    raise
                warn(f"{outpoint}: signer revoked conflicting unsigned fee "
                     "carrier; persisted exclusions for a fresh template")
                return False
            record["signed_tx_hex"] = signed
            record["status"] = "signed"
            self._save_record()
            status = "signed"

        if status == "signed":
            signed = record["signed_tx_hex"]
            calculated_txid = hashlib.sha256(
                hashlib.sha256(bytes.fromhex(signed)).digest()).hexdigest()
            recipient = record["recipient"]
            sats = record["sats"]
            admitted_at = record["at"]
            try:
                txid = self.veld.rpc("sendrawtransaction", [signed])
            except Exception as exc:
                warn(f"{outpoint}: exact signed carrier broadcast pending: {exc}")
                return False
            if not isinstance(txid, str) or not TXID_RE.fullmatch(txid):
                raise RuntimeError("sendrawtransaction returned a malformed txid")
            if txid != calculated_txid:
                raise RuntimeError(
                    "sendrawtransaction txid differs from exact signed carrier")
            record.clear()
            record.update({
                "status": "broadcast", "recipient": recipient,
                "sats": sats, "at": admitted_at,
                "signed_tx_hex": signed, "veld_txid": txid,
                "broadcast_at": int(time.time()),
            })
            self._save_record()
            log(f"{outpoint}: broadcast exact mint carrier txid={txid}; "
                "awaiting accepted consensus effect")
            return False

        if status in ("broadcast", "hold"):
            try:
                if self.veld.rpc("getmempoolentry", [record["veld_txid"]]) is not None:
                    if status == "hold":
                        record["status"] = "broadcast"
                        record.pop("hold_reason", None)
                        self._save_record()
                    return False
            except Exception:
                pass
            try:
                txid = self.veld.rpc("sendrawtransaction", [record["signed_tx_hex"]])
                if txid != record["veld_txid"]:
                    raise RuntimeError("exact rebroadcast returned a different txid")
                record["status"] = "broadcast"
                record.pop("hold_reason", None)
                self._save_record()
            except Exception as exc:
                record["status"] = "hold"
                record["hold_reason"] = (
                    "exact carrier absent/unrebroadcastable: " + str(exc)[:400])
                self._save_record()
                warn(f"{outpoint}: HOLD exact carrier; operator should inspect/rebroadcast "
                     "the recorded signed_tx_hex (no replacement authorized)")
            return False
        return status == "effect_confirmed"

    # --- eligible confirmed deposits: exact request-issued allocations only (T5/T13) ---
    def eligible_deposits(self):
        # In development, the legacy VELD-address label is the binding. Production
        # additionally requires an exact live ``issued`` allocation-journal match.
        utxos = (self._production_wallet_rows() if self.production else
                 self.btc.call("listunspent", self.K_BTC, 9999999))
        allocations = self._issued_allocations() if self.production else {}
        deps = []
        for u in utxos:
            if not isinstance(u, dict):
                raise RuntimeError("custody listunspent returned a malformed row")
            label = (u.get("label") or "").strip()
            if not VELD_ADDR_RE.match(label):
                continue                                  # change / internal / unlabeled -> not a deposit
            if (not isinstance(u.get("txid"), str) or
                    not TXID_RE.fullmatch(u["txid"]) or
                    type(u.get("vout")) is not int or
                    not (0 <= u["vout"] <= 0xffffffff)):
                continue
            sats = btc_to_sats(u["amount"])
            if sats <= 0:
                continue
            confirmations = u.get("confirmations", 0)
            if type(confirmations) is not int or confirmations < 0:
                raise RuntimeError("custody UTXO confirmations are malformed")
            deposit = {"txid": u["txid"], "vout": u["vout"],
                       "recipient": label, "sats": sats,
                       "confs": confirmations}
            if self.production:
                address = u.get("address")
                script = u.get("scriptPubKey")
                allocation = (allocations.get(address)
                              if isinstance(address, str) else None)
                if (allocation is None or
                        not isinstance(script, str) or
                        allocation["btc_address"] != address or
                        allocation["script_pubkey"] != script or
                        allocation["veld_address"] != label or
                        allocation["amount_sats"] != sats):
                    warn(
                        "%s: custody output does not exactly match an issued "
                        "wrap allocation - HOLD" %
                        outpoint_id(u["txid"], u["vout"]))
                    continue
                deposit.update({
                    "allocation_request_id": allocation["request_id"],
                    "deposit_address": address,
                    "script_pubkey": script,
                })
            deps.append(deposit)
        # deterministic order (T10): sort by (txid, vout)
        return sorted(deps, key=lambda d: (d["txid"], d["vout"]))

    def process_one(self, d):
        oid = outpoint_id(d["txid"], d["vout"])
        rec = self.ledger.get(oid)
        replacing = False
        exclusions = []

        # Gate 3/4: idempotency + crash recovery
        if rec:
            if rec.get("status") != "reprepare":
                self._advance_unresolved(oid, rec)
                return
            if (rec.get("recipient") != d.get("recipient") or
                    rec.get("sats") != d.get("sats")):
                raise RuntimeError(
                    "replacement deposit differs from durable mint owner")
            exclusions = validate_issuer_prevout_exclusions(
                rec.get("excluded_issuer_prevouts"))
            replacing = True

        # Serialize issuer carriers against the one MNP1 accumulator root. A
        # second prepare while another exact carrier is unresolved would likely
        # embed the same parent proof and become an avoidable paid no-op.
        unresolved = [
            other for other, row in self.ledger.items()
            if other != oid and
            row.get("status") not in ("effect_confirmed", "minted")]
        if unresolved:
            warn(f"{oid}: HOLD while exact mint carrier {unresolved[0]} resolves")
            return

        # Gate 2: recipient sanity (already regex-checked in eligible_deposits, re-assert)
        if not VELD_ADDR_RE.match(d["recipient"]):
            warn(f"{oid}: bad recipient label {d['recipient']!r} - skip"); return

        # Gate 5: finality
        if d["confs"] < self.K_BTC:
            log(f"{oid}: confs {d['confs']} < K_BTC {self.K_BTC} - HOLD (not final)"); return

        # Gate 6: amount bound
        if not (0 < d["sats"] <= self.MAX_SINGLE_SATS):
            self.trip_halt(f"{oid}: amount {d['sats']} outside (0, {self.MAX_SINGLE_SATS}]"); return
        # A pruned/rebuilt local ledger must still never ask the signer to replay
        # a deposit already consumed by consensus.
        initial_mint_status = self.mint_outpoint_status(oid)
        if not self.production and initial_mint_status["consumed"]:
            log(f"{oid}: consensus mint-id already consumed - NO re-mint")
            return
        if self.production and initial_mint_status["minted"]:
            log(f"{oid}: canonical mint credit already exists - NO re-mint")
            return
        if (self.production and initial_mint_status["consumed"] and
                initial_mint_status.get("accepted_effect_kind") != "C1_FUND"):
            self.trip_halt(
                f"{oid}: outpoint consumed outside the expected C1_FUND lifecycle")
            return
        if self.production:
            try:
                self._verify_production_identity(completion=True)
            except Exception as e:
                self.trip_halt("custody/cap identity mismatch: " + str(e)[:160])
                return

        # Gate 7: rate cap
        if self.window_minted_sats() + d["sats"] > self.MAX_WINDOW_SATS:
            self.trip_halt(f"{oid}: window cap - {self.window_minted_sats()}+{d['sats']} > {self.MAX_WINDOW_SATS}")
            return

        # Gate 8: RECONCILE (load-bearing) - supply + mint <= custody
        if not self.reconcile_ok(d["sats"]):
            return  # trip_halt already fired

        # The allocation journal may have been atomically replaced after
        # eligible_deposits() enumerated Core.  Re-read it at the last safe
        # boundary, before persisting mint intent or asking either signer/node
        # to construct a mint.  An authority mismatch is an incident, not a
        # reason to fall back to the Bitcoin wallet label.
        current_allocation = None
        if self.production:
            try:
                current_allocation = self._require_current_issued_allocation(d)
                late_peg = self._verify_production_identity(completion=True)
                reservation = self._require_canonical_c1_reservation(
                    current_allocation, late_peg, outpoint=oid,
                    require_funded=initial_mint_status["consumed"])
            except Exception as exc:
                self.trip_halt(
                    "%s: wrap allocation binding unavailable/mismatched: %s" %
                    (oid, str(exc)[:160]))
                return

            if not initial_mint_status["consumed"]:
                try:
                    funding = self._build_c1_funding_proof(
                        d, current_allocation)
                    if funding["outpoint"] != oid:
                        raise RuntimeError("CFP1 builder changed the deposit outpoint")
                    if not self._ensure_c1_funded(current_allocation, funding):
                        log(f"{oid}: C1F1 submitted/pending canonical inclusion")
                        return
                    initial_mint_status = self.mint_outpoint_status(oid)
                    late_peg = self._verify_production_identity(
                        completion=True)
                    reservation = self._require_canonical_c1_reservation(
                        current_allocation, late_peg, outpoint=oid,
                        require_funded=True)
                except Exception as exc:
                    warn(f"{oid}: C1F1 funding lifecycle HOLD: {str(exc)[:240]}")
                    return
            if (initial_mint_status.get("consumed") is not True or
                    initial_mint_status.get("minted") is not False or
                    initial_mint_status.get("accepted_effect_kind") != "C1_FUND" or
                    initial_mint_status.get("c1_allocation_id") !=
                        current_allocation["consensus_allocation_id"]):
                self.trip_halt(f"{oid}: canonical C1_FUND identity is incoherent")
                return

        # C-04: bind the funding BTC deposit outpoint into the mint as its memo so consensus
        # records it as a one-time mint id and rejects any re-mint of this deposit on-chain,
        # regardless of what our local minted_deposits.json contains after a restore/loss.
        deposit_outpoint = outpoint_id(d["txid"], d["vout"])
        mint_params = [self.issuer_addr, d["recipient"], str(d["sats"]),
                       deposit_outpoint]
        if self.production:
            mint_params.extend([
                current_allocation["consensus_allocation_id"],
                current_allocation["script_pubkey"],
                current_allocation["commitment_blind"]])
        suffix = issuer_prevout_exclusion_suffix(
            exclusions, force=replacing)
        if suffix is not None:
            mint_params.append(suffix)
        prep = self.veld.rpc("preparetokenmint", mint_params)
        if (not isinstance(prep, dict) or
                not isinstance(prep.get("unsigned_tx_hex"), str) or
                not isinstance(prep.get("inputs"), list) or
                prep.get("excluded_issuer_prevouts") != exclusions or
                (self.production and
                 (prep.get("c1_allocation_id") !=
                      current_allocation["consensus_allocation_id"] or
                  prep.get("recipient") != d["recipient"] or
                  prep.get("mint_sats") != d["sats"] or
                  prep.get("deposit_outpoint") != deposit_outpoint or
                  prep.get("c1_script_pubkey_hex") !=
                      current_allocation["script_pubkey"] or
                  prep.get("c1_commitment_blind_hex") !=
                      current_allocation["commitment_blind"]))):
            raise RuntimeError("preparetokenmint returned a malformed transaction template")
        if set(exclusions).intersection(
                unsigned_input_outpoints(prep["unsigned_tx_hex"])):
            raise RuntimeError(
                "preparetokenmint reused an excluded issuer prevout")
        signer_allocation = None
        if self.production:
            signer_allocation = {
                "request_id": current_allocation["request_id"],
                "btc_address": current_allocation["btc_address"],
                "script_pubkey": current_allocation["script_pubkey"],
                "deposit_outpoint": deposit_outpoint,
                "descriptor_index": current_allocation["descriptor_index"],
                "capacity_policy_sha256": self.allocation_policy_sha256,
                "commitment_blind": current_allocation["commitment_blind"],
                "consensus_allocation_id":
                    current_allocation["consensus_allocation_id"],
                "public_descriptor_range_start": 1000,
                "public_descriptor_range_end": self.public_descriptor_range_end,
            }
        # Persist the immutable prepared root before contacting the randomized
        # signer. A crash can only request the same unsigned bytes again; the
        # signer returns its durable byte-identical retry.
        self.ledger[oid] = {
            "status": "prepared", "recipient": d["recipient"],
            "sats": d["sats"],
            "at": (rec["at"] if replacing else int(time.time())),
            "unsigned_tx_hex": prep["unsigned_tx_hex"],
            "inputs": prep["inputs"],
            "signer_allocation": signer_allocation,
            "excluded_issuer_prevouts": exclusions,
        }
        try:
            self._save_record()
        except Exception:
            if replacing:
                self.ledger[oid] = rec
            else:
                del self.ledger[oid]
            raise
        self._advance_unresolved(oid, self.ledger[oid])

    def run_once(self):
        if self.halted():
            warn(f"HALT present ({self.halt_path}) - not minting. Remove it to resume."); return
        if self.production and any(
                record.get("status") in ("minting", "minted")
                for record in self.ledger.values()):
            warn("legacy production mint ledger requires offline exact-effect "
                 "reconciliation before new carriers")
            return
        # Revalidate every shallow settled effect before looking at any newly
        # eligible Bitcoin deposit. Otherwise a new deposit that sorts first
        # could prepare against the stale child root before a reorged earlier
        # effect is returned to its immutable pending carrier.
        for oid in sorted(
                oid for oid, record in self.ledger.items()
                if record.get("status") == "effect_confirmed"):
            try:
                if not self._advance_unresolved(oid, self.ledger[oid]):
                    return
            except Exception as exc:
                warn(f"{oid}: settled mint-effect reconciliation HOLD: "
                     f"{str(exc)[:240]}")
                return
        unfinished = sorted(
            oid for oid, record in self.ledger.items()
            if record.get("status") not in ("effect_confirmed", "minted"))
        if unfinished:
            if len(unfinished) > 1:
                warn("multiple unresolved mint carriers require operator review; "
                     "no new carrier will be prepared")
                return
            try:
                oid = unfinished[0]
                if not self._advance_unresolved(oid, self.ledger[oid]):
                    # Propagation and ordinary confirmation latency are expected
                    # pending states, never an automatic global HALT.
                    return
            except Exception as e:
                if self.ledger[unfinished[0]].get("status") == "minting":
                    self.trip_halt(
                        "legacy unfinished mint intent requires manual reconciliation: " +
                        str(e)[:160])
                    return
                warn("unfinished exact mint carrier is HOLD: " + str(e)[:240])
                return
        if self.production:
            try:
                self._verify_production_identity(completion=True)
            except Exception as e:
                self.trip_halt("custody identity mismatch/unavailable: " + str(e)[:160])
                return
        try:
            pruned = self._prune_settled_ledger()
            if pruned:
                log(f"[mintd] pruned {pruned} settled mint record(s) after the rate window")
        except Exception as e:
            self.trip_halt("mint ledger consensus reconciliation failed: " + str(e)[:160])
            return
        # (the issuer key lives ONLY on the signer box, which self-checks + independently
        #  re-validates every mint. The minter holds no key material of its own.)
        deps = self.eligible_deposits()
        log(f"[mintd] issuer={self.issuer_addr} K_BTC={self.K_BTC} eligible_deposits={len(deps)} "
            f"effect_confirmed_ledger={sum(1 for r in self.ledger.values() if r.get('status') in ('effect_confirmed','minted'))}")
        for d in deps:
            if self.halted():
                warn("HALT became active during this pass - stopping immediately")
                break
            try:
                self.process_one(d)
            except Exception as e:
                # Fail closed: never let one deposit's error mint or crash the loop.
                warn(f"{outpoint_id(d['txid'], d['vout'])}: {type(e).__name__}: {e} - left unminted")
                record = self.ledger.get(outpoint_id(d["txid"], d["vout"]))
                if isinstance(record, dict):
                    warn("%s: exact carrier remains in durable %s state" %
                         (outpoint_id(d["txid"], d["vout"]),
                          record.get("status")))
            if self.halted():
                warn("HALT became active during this pass - stopping immediately")
                break
        log("[mintd] pass complete")


def die(msg, code=64):
    sys.stderr.write("veld_mintd: " + msg + "\n")
    raise SystemExit(code)


def main():
    if len(sys.argv) < 2:
        die("usage: veld_mintd.py <config.json>  (loop with --loop <secs>)")
    cfg = load_bounded_json_file(
        os.path.abspath(sys.argv[1]), MAX_CONFIG_BYTES, "mintd configuration")
    if not isinstance(cfg, dict):
        die("configuration root must be an object")
    _ensure_private_state_dir(cfg.get("state_dir"))

    # single-writer lock (T10): refuse to run two minters over one state dir.
    lock_path = os.path.join(cfg["state_dir"], "mintd.lock")
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
                  getattr(os, "O_CLOEXEC", 0))
    lock_fd = os.open(lock_path, lock_flags, 0o600)
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
            lock_info.st_uid != os.geteuid() or
            stat.S_IMODE(lock_info.st_mode) & 0o022):
        os.close(lock_fd)
        die("mintd lock must be a trusted service-owned regular file")
    os.fchmod(lock_fd, 0o600)
    lock_fh = os.fdopen(lock_fd, "a+")
    if fcntl:
        try:
            fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            die("another veld_mintd holds the lock - refusing concurrent run")

    m = Minter(cfg)
    loop_secs = 0
    if "--loop" in sys.argv:
        try:
            loop_secs = int(sys.argv[sys.argv.index("--loop") + 1])
        except (IndexError, ValueError):
            die("--loop requires a positive integer interval")
        if not (1 <= loop_secs <= 31_536_000):
            die("--loop interval is outside [1,31536000]")
    while True:
        try:
            m.run_once()
        except Exception as e:
            warn(f"pass error (fail-closed, no mint): {type(e).__name__}: {e}")
        if loop_secs <= 0:
            break
        time.sleep(loop_secs)
        m.ledger = load_ledger(m.ledger_path)


if __name__ == "__main__":
    main()
