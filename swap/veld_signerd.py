#!/usr/bin/env python3
"""
veld_signerd.py - btcVELD issuer signing service. Runs ONLY inside the dedicated
signer boundary, reached by the minter over an authenticated SSH forced-command.
Network coordinates belong in the access-controlled operations inventory.

INDEPENDENT GATEKEEPER (design doc §6): given a mint request (the node's
preparetokenmint output) on stdin, it RE-DERIVES the mint's parameters from the tx
bytes themselves - NOT the caller's JSON claims - cross-checks them, enforces its OWN
caps + kill-switch, and only then signs with the issuer key. These checks depend
on the integrity of the signer, its independently operated node, reviewed chain
pins, witness, and durable authorization state.

  request (stdin JSON) : {"unsigned_tx_hex","recipient","sats","allocation"}
  response (stdout)    : signed tx hex        (exit != 0 + stderr on ANY refusal)
  key material         : issuer.key + passphrase.txt, 0600, never leave this box
  kill-switch          : ./HALT blocks all signing until a human removes it

The caller's legacy `inputs` field is rejected. Prevout identity comes from
unsigned_tx_hex; value/script/confirmations come only from the signer's
authenticated, independently operated Veld RPC. The wrap allocation claim is
separately authorized by the shared witness and its own Bitcoin Core.
"""

import hashlib, json, os, sys, subprocess, time, re, stat, tempfile, fcntl, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KEYGEN = os.path.join(HERE, "veld-keygen")
KEYFILE = os.path.join(HERE, "issuer.key")
PASSFILE = os.path.join(HERE, "passphrase.txt")
ADDRFILE = os.path.join(HERE, "issuer-address.txt")
STATEF = os.path.join(HERE, "signer-state.json")
C1_STATEF = os.path.join(HERE, "c1-reservation-signer-state.json")
PREVOUT_STATEF = os.path.join(HERE, "issuer-prevout-leases.json")
SIGNING_STAGE_DIR = os.path.join(HERE, ".issuer-signing-staging")
HALTF = os.path.join(HERE, "HALT")
LOGF = os.path.join(HERE, "signer.log")
# F1 independent watchtower: presence of this marker arms the fail-closed
# solvency gate (go-live creates it); the heartbeat is written by veld_wt_recv.py.
HEARTBEATF = os.path.join(HERE, "signer-heartbeat.json")
WT_REQUIRED = os.path.join(HERE, "watchtower-required")
BEAT_PUBKEY = os.path.join(HERE, "watchtower-beat-pubkey.hex")
ACTIVE_MINT_SIGNERF = os.path.join(HERE, "active-mint-signer")
# Fail-safe opt-out: with the peg live, "no marker at all" is treated as a MISCONFIGURED
# production signer (refuse), NOT as permission to sign unbacked. A dev/regtest signer
# must EXPLICITLY drop this file to sign in caps-only mode with no watchtower.
CAPS_ONLY_OK = os.path.join(HERE, "caps-only-ok")

sys.path.insert(0, HERE)
import veld_peg_solvency as sol
from rpc_url_policy import (
    load_bounded_json_response,
    open_rpc_request,
    read_bounded_regular_file,
    read_bounded_secret_file,
    run_bounded_subprocess,
    strict_json_loads,
    validate_backend_rpc_url,
)

SATS = 100_000_000
MINT_MARKER = b"VELD_TOKEN|MINT|btcVELD|"
VELD_ADDR_RE = re.compile(r'^V[1-9A-HJ-NP-Za-km-z]{25,49}$')
# C-04: canonical funding BTC deposit outpoint (txid:vout) carried in the mint memo. The
# signer independently requires it, matching the consensus one-time-mint-id gate.
BTC_OUTPOINT_RE = re.compile(r'^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$')
MNP1_MEMO_RE = re.compile(r'^MNP1;([0-9a-f]{64}:(?:0|[1-9][0-9]{0,9}));([0-9a-f]+)$')
MNP2_MEMO_RE = re.compile(
    r'^MNP2;(0{16}[0-9a-f]{16});(5120[0-9a-f]{64});'
    r'([0-9a-f]{64});([0-9a-f]{64}:(?:0|[1-9][0-9]{0,9}))$'
)
CONSENSUS_ALLOCATION_RE = re.compile(r'^0{16}[0-9a-f]{16}$')

# The custody ceiling is the only amount ceiling. These compatibility bounds
# intentionally mirror the compiled 10 BTC absolute cap, so neither a single
# mint nor the rolling window is independently narrower than chain custody.
# main() also queries getpeginfo and refuses if node and signer ever drift.
MAX_SINGLE_SATS = 1_000_000_000
MAX_WINDOW_SATS = 1_000_000_000
WINDOW_SECS = 3600
# The node's preparetokenmint template funds exactly the default relay-policy
# MIN_TX_FEE. A ceiling
# is insufficient here: every other fee is a different transaction than the signer
# policy approved.  Keep this literal in the isolated signer config/code and make a
# deliberate signer rollout if the node's mint-template policy ever changes.
EXPECTED_MINT_FEE_UNITS = 100_000
DEFAULT_MIN_PREVOUT_CONFIRMATIONS = 1
MINT_ACCOUNTING_VERSION = 2
# Must match include/core/constants.h. Entries stay under canonical reorg watch
# through this depth and are pruned only once they are strictly deeper.
MAX_REORG_DEPTH = 100
MAX_ACCOUNTING_SATS = (1 << 63) - 1
MAX_REQUEST_BYTES = 4 * 1024 * 1024
MAX_CHILD_OUTPUT_BYTES = 4 * 1024 * 1024
SIGNER_STATE_MAX_BYTES = 16 * 1024 * 1024
C1_FINALITY_DEPTH = 101
C1_LIFETIME_BLOCKS = 7 * 480
C1_MAX_CACHE_ROWS = 120_000
C1_STATE_MAX_BYTES = 64 * 1024 * 1024
C1_STATE_RESERVE_BYTES = C1_STATE_MAX_BYTES * 9 // 10
C1_ARCHIVE_RETENTION_SECONDS = 10 * 365 * 24 * 60 * 60
C1_MAX_SIGNED_TX_BYTES = 128 * 1024
PREVOUT_JOURNAL_VERSION = 4
PREVOUT_JOURNAL_MAX_BYTES = 64 * 1024 * 1024
PREVOUT_JOURNAL_MAX_OWNERS = 120_000
PREVOUT_MAX_REVOKED_PER_OWNER = 64
SIGNER_CONFIG = os.environ.get("VELD_SIGNER_CONFIG", os.path.join(HERE, "signer-config.json"))

from btcveld_c1 import allocation_commitment
from veld_chain_identity import parse_expected_chain, verify_expected_chain
from issuer_signing_evidence import prepare_evidence, MAX_EVIDENCE_BYTES


class UnsignedCarrierAbandoned(Exception):
    """Exact signer attestation that one unsigned carrier can never be signed."""

    def __init__(self, answer):
        super().__init__("issuer prevout conflict")
        self.answer = answer


def emit_unsigned_carrier_abandoned(error):
    sys.stdout.write(
        json.dumps(error.answer, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    )
    raise SystemExit(75)


def _secure_regular(path, private=False, exact_mode=None, executable=False):
    """Validate a security-sensitive local file without following symlinks."""
    if not os.path.isabs(path):
        raise ValueError("security-sensitive path is not absolute: %s" % path)
    try:
        info = os.lstat(path)
    except OSError as error:
        raise ValueError("required file unavailable: %s" % error)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("security-sensitive path is not a regular non-symlink file: %s" % path)
    if info.st_uid not in (0, os.geteuid()):
        raise ValueError("security-sensitive file has an unexpected owner: %s" % path)
    mode = stat.S_IMODE(info.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise ValueError("%s mode is %04o, expected %04o" % (path, mode, exact_mode))
    if private and mode & 0o077:
        raise ValueError("private file has group/world permissions: %s" % path)
    if mode & 0o022:
        raise ValueError("security-sensitive file is group/world writable: %s" % path)
    if executable and not mode & 0o100:
        raise ValueError("security-sensitive program is not owner-executable: %s" % path)
    return info


def _secure_service_directory(path):
    """Require the signer deployment directory itself to be substitution-safe."""
    path = os.path.abspath(path)
    if os.path.realpath(path) != path:
        raise ValueError("signer service directory must not traverse symlinks")
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("signer service directory must be root/service-owned and non-writable")
    return path


def _secure_text(path, private=False, exact_mode=None, max_bytes=16 * 1024 * 1024):
    info = _secure_regular(path, private=private, exact_mode=exact_mode)
    if info.st_size > max_bytes:
        raise ValueError("security-sensitive file exceeds size limit: %s" % path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or opened.st_uid != info.st_uid
            or stat.S_IMODE(opened.st_mode) != stat.S_IMODE(info.st_mode)
        ):
            raise ValueError("security-sensitive file changed while opening: %s" % path)
        chunks = []
        remaining = info.st_size + 1
        while remaining:
            chunk = os.read(fd, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > max_bytes:
            raise ValueError("security-sensitive file exceeds size limit: %s" % path)
        return raw.decode("utf-8")
    finally:
        os.close(fd)


def _trusted_marker_exists(path, label):
    """Return marker presence, rejecting links or writable/unowned substitutes."""
    if not os.path.lexists(path):
        return False
    try:
        _secure_regular(os.path.abspath(path))
    except Exception as exc:
        raise ValueError("%s marker is unsafe: %s" % (label, exc)) from exc
    return True


def _read_bounded_stdin(maximum):
    """Read one forced-command request with an explicit byte ceiling."""
    stream = getattr(sys.stdin, "buffer", None)
    if stream is not None:
        raw = stream.read(maximum + 1)
        if not isinstance(raw, (bytes, bytearray)):
            raise ValueError("stdin did not return bytes")
        return bytes(raw)
    # Unit-test and embedded text streams have no ``buffer``.  Bound characters
    # first, then enforce the real UTF-8 byte limit below as well.
    text = sys.stdin.read(maximum + 1)
    if not isinstance(text, str):
        raise ValueError("stdin did not return text")
    return text.encode("utf-8")


class TrustedVeldRpc:
    """Authenticated RPC client for the signer's own independently operated node.

    The mint preparer is adversarial by design.  In particular, no value or script
    in its request is used for policy.  Every referenced UTXO is resolved here.
    """

    def __init__(self, cfg):
        if not isinstance(cfg, dict) or not cfg.get("url"):
            raise RuntimeError("trusted veld_rpc.url is required")
        if not isinstance(cfg["url"], str):
            raise RuntimeError("trusted veld_rpc.url must be a string")
        self.expected_chain = parse_expected_chain(cfg.get("expected_chain"))
        self.url = validate_backend_rpc_url(cfg["url"], "veld_rpc.url")
        token = ""
        if cfg.get("token_cmd"):
            cmd = cfg["token_cmd"]
            if not isinstance(cmd, list) or not cmd:
                raise RuntimeError("veld_rpc.token_cmd must be a non-empty argv list")
            out = run_bounded_subprocess(
                cmd,
                timeout=30,
                stdout_max=4096,
                stderr_max=64 * 1024,
                description="trusted RPC token_cmd",
            )
            if out.returncode != 0:
                raise RuntimeError("trusted RPC token_cmd failed: " + out.stderr.strip()[:200])
            token = out.stdout.strip()
        elif cfg.get("token_file"):
            token = (
                read_bounded_secret_file(cfg["token_file"], 4096, "trusted Veld RPC token")
                .decode("ascii")
                .strip()
            )
        if not token:
            raise RuntimeError("trusted Veld RPC bearer token is missing")
        self.token = token
        self.verify_chain_identity()

    def verify_chain_identity(self):
        return verify_expected_chain(self.call, self.expected_chain)

    def call(self, method, params=None):
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []},
            separators=(",", ":"),
        ).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            headers={"Content-Type": "application/json", "Authorization": "Bearer " + self.token},
        )
        with open_rpc_request(req, timeout=15) as resp:
            env = load_bounded_json_response(resp, 32 * 1024 * 1024, "trusted Veld RPC response")
        if not isinstance(env, dict):
            raise RuntimeError("trusted RPC %s returned a non-object" % method)
        if env.get("error"):
            raise RuntimeError("trusted RPC %s: %s" % (method, env["error"]))
        result = env.get("result")
        if isinstance(result, str):
            try:
                result = strict_json_loads(result, "nested trusted Veld RPC result")
            except ValueError:
                pass
        return result


def _read_varint(raw, pos):
    if pos >= len(raw):
        raise ValueError("truncated varint")
    first = raw[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    widths = {0xFD: 2, 0xFE: 4, 0xFF: 8}
    width = widths[first]
    if pos + width > len(raw):
        raise ValueError("truncated varint body")
    value = int.from_bytes(raw[pos : pos + width], "little")
    # Reject non-minimal encodings so the Python policy view is canonical.
    if (
        (first == 0xFD and value < 0xFD)
        or (first == 0xFE and value <= 0xFFFF)
        or (first == 0xFF and value <= 0xFFFFFFFF)
    ):
        raise ValueError("non-minimal varint")
    return value, pos + width


def parse_unsigned_tx_inputs(unsigned_tx_hex):
    """Return the exact ordered (txid, vout) list committed by a Veld tx.

    This deliberately does not consult the request's `inputs[]` array.  Hash bytes
    use Veld's serialized/display order (HashToHex does not byte-reverse them).
    """
    if not isinstance(unsigned_tx_hex, str) or not re.fullmatch(r"[0-9a-fA-F]+", unsigned_tx_hex):
        raise ValueError("unsigned transaction is not hex")
    if len(unsigned_tx_hex) % 2:
        raise ValueError("unsigned transaction hex has odd length")
    raw = bytes.fromhex(unsigned_tx_hex)
    if len(raw) < 4:
        raise ValueError("unsigned transaction is truncated")
    pos = 4
    count, pos = _read_varint(raw, pos)
    if count < 1 or count > 10_000:
        raise ValueError("unsigned transaction input count out of range")
    out, seen = [], set()
    for _ in range(count):
        if pos + 36 > len(raw):
            raise ValueError("unsigned transaction input is truncated")
        txid = raw[pos : pos + 32].hex()
        pos += 32
        vout = int.from_bytes(raw[pos : pos + 4], "little")
        pos += 4
        slen, pos = _read_varint(raw, pos)
        if slen > 32_768 or pos + slen + 4 > len(raw):
            raise ValueError("unsigned transaction scriptSig is truncated/oversized")
        # A proposal must actually be unsigned.  Otherwise parsing one byte stream
        # while sign-tx later canonicalizes/replaces scripts creates policy ambiguity.
        if slen != 0:
            raise ValueError("mint proposal contains a non-empty scriptSig")
        pos += slen + 4  # scriptSig + sequence
        key = (txid, vout)
        if key in seen:
            raise ValueError("mint proposal repeats an input")
        seen.add(key)
        out.append(key)
    return out


def issuer_p2pkh_from_address(address):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    try:
        for c in address:
            n = n * 58 + alphabet.index(c)
    except ValueError:
        raise ValueError("issuer address is not base58")
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    body = b"\x00" * (len(address) - len(address.lstrip("1"))) + body
    if len(body) != 25:
        raise ValueError("issuer address payload length is not 25 bytes")
    payload, check = body[:-4], body[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if check != want or len(payload) != 21:
        raise ValueError("issuer address checksum/payload is invalid")
    return (b"\x76\xa9\x14" + payload[1:] + b"\x88\xac").hex()


def _strict_uint(value, field, maximum=(1 << 63) - 1):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > maximum:
        raise ValueError("trusted prevout %s is not a bounded unsigned integer" % field)
    return value


def resolve_mint_prevouts(
    unsigned_tx_hex, rpc, issuer_script_hex, min_confirmations=DEFAULT_MIN_PREVOUT_CONFIRMATIONS
):
    """Resolve and validate every exact tx input against a trusted Veld node."""
    if not re.fullmatch(r"[0-9a-f]{50}", str(issuer_script_hex)):
        raise ValueError("issuer P2PKH script is malformed")
    if isinstance(min_confirmations, bool) or int(min_confirmations) < 1:
        raise ValueError("min_prevout_confirmations must be >= 1")
    total = 0
    resolved = []
    for txid, vout in parse_unsigned_tx_inputs(unsigned_tx_hex):
        u = rpc.call("gettxout", [txid, vout])
        if not isinstance(u, dict):
            raise ValueError("prevout %s:%d is missing or spent" % (txid, vout))
        if u.get("txid") != txid or _strict_uint(u.get("vout"), "vout", 0xFFFFFFFF) != vout:
            raise ValueError("trusted RPC returned the wrong prevout identity")
        script = u.get("script_pubkey_hex")
        if script != issuer_script_hex:
            raise ValueError("prevout %s:%d is not owned by the issuer script" % (txid, vout))
        value = _strict_uint(u.get("value_units"), "value_units")
        confs = _strict_uint(u.get("confirmations"), "confirmations")
        height = _strict_uint(u.get("block_height"), "block_height")
        if confs < int(min_confirmations):
            raise ValueError(
                "prevout %s:%d has %d confirmations; need %d"
                % (txid, vout, confs, int(min_confirmations))
            )
        if total > (1 << 63) - 1 - value:
            raise ValueError("prevout value sum overflow")
        total += value
        resolved.append(
            {
                "txid": txid,
                "vout": vout,
                "value_units": value,
                "script_pubkey_hex": script,
                "confirmations": confs,
                "block_height": height,
            }
        )
    return total, resolved


def enforce_exact_mint_fee(total_in, total_out, expected=EXPECTED_MINT_FEE_UNITS):
    total_in = _strict_uint(total_in, "total_in")
    total_out = _strict_uint(total_out, "total_out")
    expected = _strict_uint(expected, "expected_fee")
    if total_out > total_in:
        raise ValueError("mint outputs %d exceed inputs %d" % (total_out, total_in))
    fee = total_in - total_out
    if fee != expected:
        raise ValueError("mint fee %d != exact policy fee %d" % (fee, expected))
    return fee


def _log(msg):
    try:
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        fd = os.open(LOGF, flags, 0o600)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            os.close(fd)
            return
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(f"{int(time.time())} {msg}\n")
    except Exception:
        pass


def refuse(msg):
    _log("REFUSE " + msg)
    sys.stderr.write("veld_signerd REFUSE: " + msg + "\n")
    sys.exit(2)


def issuer_addr():
    try:
        a = _secure_text(ADDRFILE, max_bytes=1024).strip()
    except Exception as e:
        refuse("issuer-address.txt unavailable: %s" % e)
    if not VELD_ADDR_RE.match(a):
        refuse("issuer-address.txt malformed")
    return a


def validate_compiled_mint_policy(rpc, issuer, *, completion=False):
    rpc.verify_chain_identity()
    peg = rpc.call("getpeginfo", [])
    if not isinstance(peg, dict) or peg.get("active") is not True:
        raise ValueError("getpeginfo does not report a registered btcVELD asset")
    required_gate = "completion_live" if completion else "mint_live"
    if peg.get("peg_unlocked") is not True or peg.get(required_gate) is not True:
        raise ValueError(
            "getpeginfo reports btcVELD %s closed by the launch/liveness gate"
            % ("completion" if completion else "minting")
        )
    if peg.get("issuer") != issuer:
        raise ValueError("compiled btcVELD issuer differs from this signer")
    try:
        values = [
            peg.get(name)
            for name in (
                "issuer_max_per_mint_sats",
                "issuer_static_custody_cap_sats",
                "issuer_effective_custody_cap_sats",
                "issuer_mint_headroom_sats",
            )
        ]
        if any(type(value) is not int for value in values):
            raise ValueError("getpeginfo issuer policy fields must be exact integers")
        per_mint, static_cap, effective_cap, headroom = values
    except (TypeError, ValueError):
        raise ValueError("getpeginfo omitted canonical issuer mint policy")
    if per_mint != MAX_SINGLE_SATS:
        raise ValueError("isolated signer MAX_SINGLE differs from consensus")
    if (
        MAX_WINDOW_SATS <= 0
        or MAX_WINDOW_SATS > static_cap
        or effective_cap < 0
        or effective_cap > static_cap
        or headroom < 0
        or headroom > effective_cap
    ):
        raise ValueError("isolated signer window/cap policy exceeds consensus")
    return peg


def _exact_effect_locator(status, prefix):
    txid = status.get(prefix + "_txid")
    height = status.get(prefix + "_block_height")
    block_hash = status.get(prefix + "_block_hash")
    tx_index = status.get(prefix + "_tx_index")
    marker_vout = status.get(prefix + "_marker_vout")
    return (
        isinstance(txid, str)
        and re.fullmatch(r"[0-9a-f]{64}", txid)
        and type(height) is int
        and height >= 0
        and isinstance(block_hash, str)
        and re.fullmatch(r"[0-9a-f]{64}", block_hash)
        and type(tx_index) is int
        and tx_index >= 0
        and type(marker_vout) is int
        and marker_vout >= 0
    )


def _null_locator(status, prefix):
    return all(
        status.get(prefix + suffix) is None
        for suffix in ("_txid", "_block_height", "_block_hash", "_tx_index", "_marker_vout")
    )


def validate_fresh_mint_boundary(
    rpc,
    issuer,
    sats,
    deposit_outpoint,
    proof_hex,
    retry_txid=None,
    reservation_allocation_id=None,
    recipient=None,
    reservation_script_pubkey=None,
    reservation_commitment_blind=None,
):
    """Bind one signing/replay boundary to fresh consensus mint authority.

    A canonical transaction carrier is not proof that its token operation took
    effect: invalid protocol operations are included as paid no-ops.  New
    signatures therefore require the exact current MNP1 nonmembership witness
    embedded in the unsigned transaction and enough live issuer headroom.  An
    exact cached retry is also allowed after effect only when the derived index
    identifies that byte-identical signed txid as the accepted transition.
    """
    if (
        type(sats) is not int
        or sats <= 0
        or not BTC_OUTPOINT_RE.fullmatch(deposit_outpoint or "")
        or ((reservation_allocation_id is None) != isinstance(proof_hex, str))
        or (proof_hex is not None and not re.fullmatch(r"[0-9a-f]+", proof_hex))
        or (
            retry_txid is not None
            and (not isinstance(retry_txid, str) or not re.fullmatch(r"[0-9a-f]{64}", retry_txid))
        )
        or (
            reservation_allocation_id is not None
            and (
                not isinstance(reservation_allocation_id, str)
                or not CONSENSUS_ALLOCATION_RE.fullmatch(reservation_allocation_id)
                or int(reservation_allocation_id, 16) == 0
            )
        )
        or (
            recipient is not None
            and (not isinstance(recipient, str) or not VELD_ADDR_RE.fullmatch(recipient))
        )
        or (
            reservation_script_pubkey is not None
            and (
                not isinstance(reservation_script_pubkey, str)
                or not re.fullmatch(r"5120[0-9a-f]{64}", reservation_script_pubkey)
            )
        )
        or (
            reservation_commitment_blind is not None
            and (
                not isinstance(reservation_commitment_blind, str)
                or not re.fullmatch(r"[0-9a-f]{64}", reservation_commitment_blind)
                or int(reservation_commitment_blind, 16) == 0
            )
        )
        or ((reservation_allocation_id is None) != (reservation_script_pubkey is None))
        or ((reservation_allocation_id is None) != (reservation_commitment_blind is None))
    ):
        raise ValueError("mint boundary identity is malformed")
    completion = reservation_allocation_id is not None
    peg = validate_compiled_mint_policy(rpc, issuer, completion=completion)
    supply_before = rpc.call("getbtcveldsupply", [])
    status = rpc.call("getbtcveldmintstatus", [deposit_outpoint])
    supply_after = rpc.call("getbtcveldsupply", [])
    peg_after = validate_compiled_mint_policy(rpc, issuer, completion=completion)
    capacity_fields = (
        "tip",
        "supply_sats",
        "issuer_effective_custody_cap_sats",
        "issuer_reserved_sats",
        "issuer_mint_headroom_sats",
        "issuer_max_per_mint_sats",
        "issuer_static_custody_cap_sats",
    )
    if any(peg.get(name) != peg_after.get(name) for name in capacity_fields):
        raise ValueError("issuer capacity changed during final mint boundary")
    if (
        not isinstance(supply_before, dict)
        or not isinstance(supply_after, dict)
        or supply_before != supply_after
        or set(supply_before) != {"supply_sats", "tip", "tip_hash"}
        or type(supply_before.get("supply_sats")) is not int
        or supply_before["supply_sats"] < 0
        or type(supply_before.get("tip")) is not int
        or supply_before["tip"] < 0
        or not isinstance(supply_before.get("tip_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", supply_before["tip_hash"])
    ):
        raise ValueError("coherent btcVELD supply tuple changed/is malformed")
    effective = peg.get("issuer_effective_custody_cap_sats")
    reserved = peg.get("issuer_reserved_sats")
    headroom = peg.get("issuer_mint_headroom_sats")
    supply_sats = supply_before["supply_sats"]
    if type(effective) is not int or effective < 0:
        raise ValueError("getpeginfo effective capacity is malformed")
    if type(reserved) is not int or reserved < 0:
        raise ValueError("getpeginfo reserved capacity is malformed")
    expected_headroom = max(0, effective - supply_sats - reserved)
    if (
        peg.get("tip") != supply_before["tip"]
        or peg.get("supply_sats") != supply_sats
        or type(headroom) is not int
        or headroom != expected_headroom
    ):
        raise ValueError("getpeginfo capacity differs from coherent supply tuple")
    if (
        not isinstance(status, dict)
        or status.get("outpoint") != deposit_outpoint
        or type(status.get("consumed")) is not bool
        or type(status.get("minted")) is not bool
        or status.get("proof_version") != "MNP1"
        or not isinstance(status.get("proof_hex"), str)
        or not re.fullmatch(r"[0-9a-f]+", status["proof_hex"])
        or not isinstance(status.get("root"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", status["root"])
        or type(status.get("count")) is not int
        or status["count"] < 0
        or type(status.get("tip")) is not int
        or status["tip"] < 0
        or not isinstance(status.get("tip_hash"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", status["tip_hash"])
        or type(peg.get("tip")) is not int
        or peg["tip"] != status["tip"]
        or status["tip_hash"] != supply_before["tip_hash"]
    ):
        raise ValueError("fresh mint-nullifier status is malformed/incoherent")
    consumed = status["consumed"]
    accepted_metadata = ("accepted_effect_kind", "c1_allocation_id")
    if consumed:
        if not _exact_effect_locator(status, "accepted"):
            raise ValueError("consumed mint-nullifier lacks exact effect locator")
    else:
        if (
            status["minted"]
            or not _null_locator(status, "accepted")
            or not _null_locator(status, "consumer")
            or not _null_locator(status, "credit")
            or any(status.get(name) is not None for name in accepted_metadata)
        ):
            raise ValueError("unconsumed mint-nullifier unexpectedly has effect metadata")

    if reservation_allocation_id is not None:
        if not consumed:
            raise ValueError("C1 MNP2 requires a canonical C1_FUND consumer")
        if status.get("c1_allocation_id") != reservation_allocation_id or not _exact_effect_locator(
            status, "consumer"
        ):
            raise ValueError("C1 funding consumer identity is unavailable")
        if not status["minted"]:
            if status.get("accepted_effect_kind") != "C1_FUND" or not _null_locator(
                status, "credit"
            ):
                raise ValueError("C1 outpoint is not in the funded-only state")
        else:
            if (
                status.get("accepted_effect_kind") != "C1_MINT"
                or not _exact_effect_locator(status, "credit")
                or retry_txid is None
                or status.get("credit_txid") != retry_txid
                or status.get("accepted_txid") != retry_txid
            ):
                raise ValueError("C1 outpoint was minted by another carrier")
            return {"effect_confirmed_retry": True, "peg": peg, "status": status}

        reservation = rpc.call("getbtcveldc1reservation", [reservation_allocation_id])
        if (
            not isinstance(reservation, dict)
            or reservation.get("allocation_id") != reservation_allocation_id
            or reservation.get("tip") != supply_before["tip"]
            or reservation.get("found") is not True
            or reservation.get("active") is not True
            or reservation.get("exposed") is not True
            or reservation.get("funded") is not True
            or reservation.get("funding_outpoint") != deposit_outpoint
            or reservation.get("recipient") != recipient
            or reservation.get("amount_sats") != sats
            or reservation.get("allocation_commitment")
            != allocation_commitment(
                reservation_allocation_id,
                recipient,
                sats,
                reservation_script_pubkey,
                reservation_commitment_blind,
            )
        ):
            raise ValueError("matching funded C1 consensus reservation is unavailable")
    else:
        if consumed:
            if (
                status.get("minted") is not True
                or status.get("accepted_effect_kind") != "MINT"
                or retry_txid is None
                or status.get("accepted_txid") != retry_txid
            ):
                raise ValueError("BTC deposit outpoint is already consumed by another mint")
            return {"effect_confirmed_retry": True, "peg": peg, "status": status}
        if status["proof_hex"] != proof_hex:
            raise ValueError("unsigned MNP1 proof differs from fresh trusted status")
    if reservation_allocation_id is None and (type(headroom) is not int or sats > headroom):
        raise ValueError("mint amount exceeds fresh issuer_mint_headroom_sats")
    return {"effect_confirmed_retry": False, "peg": peg, "status": status}


def mint_params_from_tx(unsigned_tx_hex, issuer, issuer_p2pkh_hex):
    """Re-derive (recipient, sats, total_out) from the tx via the CONSENSUS deserializer
    (veld-keygen decode-mint). decode-mint fully parses the transaction and enforces the
    canonical single-mint output template — every spendable output is issuer change and
    there is exactly one canonical VELD_TOKEN|MINT|btcVELD OP_RETURN, no other stateful
    marker. This replaces the old raw.find(MINT_MARKER) byte-substring search, which a
    marker smuggled behind OP_PUSHDATA1 in an unrelated script could defeat (C-06).
    Fail-closed on ANY policy violation."""
    r = run_bounded_subprocess(
        [KEYGEN, "decode-mint", issuer_p2pkh_hex, unsigned_tx_hex],
        input_text="",
        timeout=30,
        stdout_max=MAX_CHILD_OUTPUT_BYTES,
        stderr_max=1024 * 1024,
        description="decode-mint",
    )
    if r.returncode != 0:
        refuse("mint policy: " + (r.stderr.strip()[:200] or "decode-mint refused"))
    try:
        d = strict_json_loads(r.stdout.strip(), "decode-mint response")
        frm = d["from"]
        to = d["to"]
        sats = d["sats"]
        total_out = d["total_out_sats"]
        memo = d.get("memo", "")
    except Exception:
        refuse("decode-mint produced no/invalid JSON")
    if (
        type(sats) is not int
        or type(total_out) is not int
        or total_out < 0
        or total_out > MAX_ACCOUNTING_SATS
    ):
        refuse("decode-mint produced non-canonical integer fields")
    # Fresh-genesis MNP1: decode-mint has already run the shared C++ canonical
    # sparse-Merkle decoder (including default-sibling rejection).  Independently
    # require the explicit envelope, bounded bitmap/hash shape, and uint32 vout
    # before the isolated key signs it.
    direct = MNP1_MEMO_RE.fullmatch(memo)
    reserved = MNP2_MEMO_RE.fullmatch(memo)
    if (direct is None) == (reserved is None):
        refuse(f"MINT memo is not exactly one canonical MNP1/MNP2 form: {memo!r}")
    if direct is not None:
        outpoint = direct.group(1)
        proof_hex = direct.group(2)
        reservation_allocation_id = None
        reservation_script_pubkey = None
        reservation_commitment_blind = None
    else:
        reservation_allocation_id = reserved.group(1)
        reservation_script_pubkey = reserved.group(2)
        reservation_commitment_blind = reserved.group(3)
        outpoint = reserved.group(4)
        proof_hex = None
    if not BTC_OUTPOINT_RE.fullmatch(outpoint or ""):
        refuse("MINT memo carries a non-canonical Bitcoin outpoint")
    try:
        vout = int(outpoint.split(':', 1)[1])
        proof = bytes.fromhex(proof_hex) if proof_hex is not None else None
    except (ValueError, OverflowError):
        refuse("MINT MNP memo is not decodable")
    if vout > 0xFFFFFFFF:
        refuse("MINT outpoint vout is out of range")
    if proof is not None:
        if not (32 <= len(proof) <= 32 + 256 * 32):
            refuse("MINT MNP1 proof is out of range")
        if len(proof) != 32 + sum(byte.bit_count() for byte in proof[:32]) * 32:
            refuse("MINT MNP1 proof bitmap/hash count is non-canonical")
    elif int(reservation_allocation_id, 16) == 0 or int(reservation_commitment_blind, 16) == 0:
        refuse("MINT MNP2 allocation id/blind must be nonzero")
    if frm != issuer:
        refuse(f"MINT from={frm!r} != issuer={issuer!r}")
    if not VELD_ADDR_RE.match(to):
        refuse(f"MINT recipient={to!r} not a valid VELD address")
    if sats <= 0:
        refuse("MINT amount non-positive")
    return (
        to,
        sats,
        total_out,
        outpoint,
        proof_hex,
        reservation_allocation_id,
        reservation_script_pubkey,
        reservation_commitment_blind,
    )


def validate_mint_allocation_claim(value, recipient, sats, deposit_outpoint):
    """Validate the coordinator's claim before sending it to the witness.

    This claim is never authority by itself.  The independent witness looks up
    the request in its own append-only allocation ledger and resolves the exact
    Bitcoin outpoint through its own mainnet Core before reserving headroom.
    """
    required = {
        "request_id",
        "btc_address",
        "script_pubkey",
        "deposit_outpoint",
        "descriptor_index",
        "capacity_policy_sha256",
        "commitment_blind",
        "consensus_allocation_id",
        "public_descriptor_range_start",
        "public_descriptor_range_end",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("mint allocation claim has an invalid schema")
    request_id = value.get("request_id")
    address = value.get("btc_address")
    script = value.get("script_pubkey")
    outpoint = value.get("deposit_outpoint")
    descriptor_index = value.get("descriptor_index")
    policy_sha256 = value.get("capacity_policy_sha256")
    commitment_blind = value.get("commitment_blind")
    consensus_allocation_id = value.get("consensus_allocation_id")
    range_start = value.get("public_descriptor_range_start")
    range_end = value.get("public_descriptor_range_end")
    if (
        not isinstance(request_id, str)
        or not re.fullmatch(r"[0-9a-f]{32}", request_id)
        or not isinstance(address, str)
        or not re.fullmatch(r"bc1p[023456789ac-hj-np-z]{58}", address)
        or not isinstance(script, str)
        or not re.fullmatch(r"5120[0-9a-f]{64}", script)
        or not isinstance(commitment_blind, str)
        or not re.fullmatch(r"[0-9a-f]{64}", commitment_blind)
        or int(commitment_blind, 16) == 0
        or not isinstance(consensus_allocation_id, str)
        or not CONSENSUS_ALLOCATION_RE.fullmatch(consensus_allocation_id)
        or int(consensus_allocation_id, 16) == 0
        or not isinstance(outpoint, str)
        or not BTC_OUTPOINT_RE.fullmatch(outpoint)
        or outpoint != deposit_outpoint
        or type(descriptor_index) is not int
        or type(range_start) is not int
        or range_start != 1000
        or type(range_end) is not int
        or not 10999 <= range_end <= 1_000_000
        or not range_start <= descriptor_index <= range_end
        or not isinstance(policy_sha256, str)
        or not sol.HASH256_RE.fullmatch(policy_sha256)
        or not isinstance(recipient, str)
        or not VELD_ADDR_RE.fullmatch(recipient)
        or type(sats) is not int
        or sats <= 0
    ):
        raise ValueError("mint allocation claim is malformed or mismatched")
    return dict(value)


def window_signed_sats(state):
    cutoff = time.time() - WINDOW_SECS
    records = _validate_signed_audit_records(state)
    total = 0
    for record in records:
        if record["at"] < cutoff:
            continue
        if total > MAX_ACCOUNTING_SATS - record["sats"]:
            raise ValueError("rolling signed-mint sum overflows")
        total += record["sats"]
    return total


def _accounting_sats(value, field, allow_zero=True):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_ACCOUNTING_SATS
        or (not allow_zero and value == 0)
    ):
        raise ValueError(
            "%s is not a bounded %sinteger"
            % (field, "positive " if not allow_zero else "non-negative ")
        )
    return value


def _validate_signed_audit_records(state):
    """Validate every durable idempotency/rate record, not only a cache hit.

    An unrelated corrupt row must never contribute a negative amount, an old
    timestamp, or duplicate identity that undercounts the rolling issuance cap.
    The signed bytes are the randomized-signature retry authority, so their
    transaction id is recomputed for every loaded journal entry.
    """
    if not isinstance(state, dict):
        raise ValueError("signer state is not an object")
    records = state.get("signed", [])
    if not isinstance(records, list):
        raise ValueError("signed audit records are not a list")
    clean = []
    seen = set()
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("signed audit record %d is not an object" % index)
        request_id = record.get("request_id")
        txid = record.get("txid")
        signed_hex = record.get("signed_tx_hex")
        recipient = record.get("to")
        if (
            not isinstance(request_id, str)
            or not re.fullmatch(r"[0-9a-f]{64}", request_id)
            or request_id in seen
        ):
            raise ValueError("signed audit record %d has an invalid/duplicate request_id" % index)
        if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
            raise ValueError("signed audit record %d has an invalid txid" % index)
        if (
            not isinstance(signed_hex, str)
            or len(signed_hex) % 2
            or len(signed_hex) > MAX_CHILD_OUTPUT_BYTES * 2
            or not re.fullmatch(r"[0-9a-fA-F]+", signed_hex)
        ):
            raise ValueError("signed audit record %d has invalid signed bytes" % index)
        if not isinstance(recipient, str) or not VELD_ADDR_RE.fullmatch(recipient):
            raise ValueError("signed audit record %d has an invalid recipient" % index)
        sats = _accounting_sats(record.get("sats"), "signed[%d].sats" % index, allow_zero=False)
        signed_at = _accounting_sats(record.get("at"), "signed[%d].at" % index)
        calculated = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed_hex)).digest()).hexdigest()
        if calculated != txid:
            raise ValueError(
                "signed audit record %d does not bind its bytes to the recorded txid" % index
            )
        normalized = {
            "request_id": request_id,
            "txid": txid,
            "signed_tx_hex": signed_hex.lower(),
            "sats": sats,
            "to": recipient,
            "at": signed_at,
        }
        receipt = record.get("witness_receipt")
        if receipt is not None:
            ok, why = sol.validate_reservation_receipt(receipt)
            if not ok:
                raise ValueError("signed audit record %d witness receipt: %s" % (index, why))
            if (
                receipt["request_id"] != request_id
                or receipt["sats"] != sats
                or receipt["recipient"] != recipient
            ):
                raise ValueError(
                    "signed audit record %d witness receipt does not bind record" % index
                )
            committed = record.get("witness_committed", False)
            if not isinstance(committed, bool):
                raise ValueError("signed audit record %d witness_committed is not boolean" % index)
            normalized["witness_receipt"] = receipt
            normalized["witness_committed"] = committed
        elif "witness_committed" in record:
            raise ValueError("signed audit record %d commits a missing witness receipt" % index)
        clean.append(normalized)
        seen.add(request_id)
    state["signed"] = clean
    return clean


def _legacy_pending_entries(state):
    """Conservatively migrate the pre-accounting signer state.

    Legacy state retained recent signed mints but did not durably distinguish a
    confirmed mint from an in-flight one.  Treat every retained entry as pending:
    over-counting can pause issuance, while under-counting can reuse backing.  The
    retained records alone may be incomplete because the old journal was capped
    at 500 entries. The caller also converts the old cumulative ``total_signed``
    value into an unresolved fail-closed floor against the first coherent supply
    heartbeat; burns may over-count that floor, but can never under-count backing.
    """
    records = state.get("signed", [])
    if not isinstance(records, list):
        raise ValueError("legacy signed records are not a list")
    pending = []
    for i, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("legacy signed record %d is not an object" % i)
        sats = _accounting_sats(record.get("sats"), "legacy signed[%d].sats" % i, allow_zero=False)
        material = json.dumps(record, sort_keys=True, separators=(",", ":"))
        request_id = record.get("request_id")
        if not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{64}", request_id):
            request_id = "legacy-" + hashlib.sha256((str(i) + ":" + material).encode()).hexdigest()
        entry = {
            "request_id": request_id,
            "sats": sats,
            "signed_at": int(record.get("at", 0)),
        }
        txid = record.get("txid")
        if isinstance(txid, str) and re.fullmatch(r"[0-9a-f]{64}", txid):
            entry["txid"] = txid
        pending.append(entry)
    return pending


def _validate_mint_entries(entries, field, require_txid=False):
    if not isinstance(entries, list):
        raise ValueError("mint_accounting.%s is not a list" % field)
    clean, seen, total = [], set(), 0
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError("%s mint %d is not an object" % (field, i))
        request_id = entry.get("request_id")
        if (
            not isinstance(request_id, str)
            or not request_id
            or len(request_id) > 128
            or request_id in seen
        ):
            raise ValueError("%s mint %d has an invalid/duplicate request_id" % (field, i))
        sats = _accounting_sats(entry.get("sats"), "%s[%d].sats" % (field, i), allow_zero=False)
        txid = entry.get("txid")
        if txid is not None and (
            not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid)
        ):
            raise ValueError("%s mint %d has an invalid txid" % (field, i))
        if require_txid and txid is None:
            raise ValueError("%s mint %d has no txid" % (field, i))
        if total > MAX_ACCOUNTING_SATS - sats:
            raise ValueError("%s mint sum overflows" % field)
        total += sats
        seen.add(request_id)
        normalized = {
            "request_id": request_id,
            "sats": sats,
            "signed_at": _accounting_sats(
                entry.get("signed_at", 0), "%s[%d].signed_at" % (field, i)
            ),
        }
        if txid is not None:
            normalized["txid"] = txid
        if field == "confirmed":
            normalized["block_height"] = _accounting_sats(
                entry.get("block_height"), "confirmed block_height"
            )
            block_hash = entry.get("block_hash")
            if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
                raise ValueError("confirmed mint %d has invalid block_hash" % i)
            normalized["block_hash"] = block_hash
        receipt = entry.get("witness_receipt")
        if receipt is not None:
            ok, why = sol.validate_reservation_receipt(receipt)
            if not ok:
                raise ValueError("%s mint %d witness receipt: %s" % (field, i, why))
            if receipt["request_id"] != request_id or receipt["sats"] != sats:
                raise ValueError("%s mint %d witness receipt does not bind entry" % (field, i))
            normalized["witness_receipt"] = receipt
            committed = entry.get("witness_committed", False)
            if not isinstance(committed, bool):
                raise ValueError("%s mint %d witness_committed is not boolean" % (field, i))
            normalized["witness_committed"] = committed
        clean.append(normalized)
    return clean, total


def _initialize_mint_accounting(state):
    if not isinstance(state, dict):
        raise ValueError("signer state is not an object")
    accounting = state.get("mint_accounting")
    migrated = accounting is None
    if migrated:
        # A legacy journal lacks exact signed bytes/txids and may have dropped
        # entries at the old 500-row cap. Silently upgrading it can either pause
        # forever or undercount an omitted signature. Only the offline,
        # two-operator reconciliation tool may produce a versioned state.
        if state.get("signed") or "total_signed" in state:
            raise ValueError("legacy signer state requires offline mint-state reconciliation")
        accounting = {"version": MINT_ACCOUNTING_VERSION, "pending": [], "confirmed": []}
        state["mint_accounting"] = accounting
    if not isinstance(accounting, dict):
        raise ValueError("mint_accounting is not an object")
    if accounting.get("version") != MINT_ACCOUNTING_VERSION:
        raise ValueError("unsupported mint_accounting version")
    if "legacy_total_signed" in accounting:
        accounting["legacy_total_signed"] = _accounting_sats(
            accounting["legacy_total_signed"], "legacy total_signed"
        )
    pending, ignored_pending_total = _validate_mint_entries(accounting.get("pending"), "pending")
    confirmed, ignored_confirmed_total = _validate_mint_entries(
        accounting.get("confirmed"), "confirmed", require_txid=True
    )
    pending_ids = {x["request_id"] for x in pending}
    if pending_ids.intersection(x["request_id"] for x in confirmed):
        raise ValueError("mint request appears in both pending and confirmed sets")
    accounting["pending"] = pending
    accounting["confirmed"] = confirmed
    # Every still-outstanding entry that already has signed bytes must be backed
    # by the exact immutable retry record.  Old, deeply confirmed audit rows may
    # legitimately outlive their accounting row, but the reverse is never safe.
    audit_by_id = {record["request_id"]: record for record in _validate_signed_audit_records(state)}
    for entry in pending + confirmed:
        if "txid" not in entry:
            continue  # a durably reserved request may not have been signed yet
        audit = audit_by_id.get(entry["request_id"])
        if audit is None or audit["txid"] != entry["txid"] or audit["sats"] != entry["sats"]:
            raise ValueError("signed outstanding mint is missing/mismatched in audit journal")
        entry_receipt = entry.get("witness_receipt")
        audit_receipt = audit.get("witness_receipt")
        if (entry_receipt or None) != (audit_receipt or None) or entry.get(
            "witness_committed", False
        ) != audit.get("witness_committed", False):
            raise ValueError("outstanding mint witness state differs from audit journal")
    return accounting, migrated


def _copy_accounting_entry(entry):
    keys = ("request_id", "sats", "signed_at", "txid", "witness_receipt", "witness_committed")
    return {key: entry[key] for key in keys if key in entry}


def _heartbeat_tip_matches_rpc(hb, rpc):
    if rpc is None:
        return False, "trusted Veld RPC is required for heartbeat tip binding"
    try:
        tip = _accounting_sats(hb.get("tip"), "heartbeat tip")
        tip_hash = hb.get("tip_hash")
        if not isinstance(tip_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", tip_hash):
            return False, "heartbeat tip_hash is malformed"
        actual = rpc.call("getblockhash", [tip])
    except Exception as e:
        return False, "canonical heartbeat-tip lookup failed: %s" % str(e)[:160]
    if actual != tip_hash:
        return False, "heartbeat tip hash differs from signer's canonical chain"
    return True, "ok"


def _canonical_mint_confirmation(rpc, entry, hb):
    """Return canonical confirmation metadata, or None on absence/uncertainty."""
    txid = entry.get("txid")
    if txid is None or rpc is None:
        return None
    try:
        receipt = entry.get("witness_receipt")
        if isinstance(receipt, dict) and receipt.get("v") == sol.C1_RESERVATION_VERSION:
            outpoint = receipt.get("deposit_outpoint")
            supply_before = rpc.call("getbtcveldsupply", [])
            status = rpc.call("getbtcveldmintstatus", [outpoint])
            supply_after = rpc.call("getbtcveldsupply", [])
            if (
                not isinstance(supply_before, dict)
                or supply_before != supply_after
                or set(supply_before) != {"supply_sats", "tip", "tip_hash"}
                or supply_before.get("supply_sats") != hb.get("supply_sats")
                or supply_before.get("tip") != hb.get("tip")
                or supply_before.get("tip_hash") != hb.get("tip_hash")
                or not isinstance(status, dict)
                or status.get("outpoint") != outpoint
                or type(status.get("consumed")) is not bool
                or status.get("proof_version") != "MNP1"
                or status.get("tip") != hb.get("tip")
                or status.get("tip_hash") != supply_before["tip_hash"]
            ):
                return None
            if not status["consumed"]:
                return None
            if (
                status.get("accepted_txid") != txid
                or type(status.get("accepted_block_height")) is not int
                or status["accepted_block_height"] < 0
                or not isinstance(status.get("accepted_block_hash"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", status["accepted_block_hash"])
            ):
                return None
            height = status["accepted_block_height"]
            block_hash = status["accepted_block_hash"]
            heartbeat_tip = _accounting_sats(hb.get("tip"), "heartbeat tip")
            if height > heartbeat_tip or rpc.call("getblockhash", [height]) != block_hash:
                return None
            return {
                "confirmations": heartbeat_tip - height + 1,
                "block_height": height,
                "block_hash": block_hash,
            }
        info = rpc.call("getrawtransaction", [txid])
        if not isinstance(info, dict) or info.get("txid") != txid:
            return None
        reported_confirmations = _accounting_sats(
            info.get("confirmations"), "mint confirmations", allow_zero=False
        )
        height = _accounting_sats(info.get("block_height"), "mint block_height")
        block_hash = info.get("block_hash")
        if not isinstance(block_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", block_hash):
            return None
        # The heartbeat's supply snapshot can cover only ancestors at or below its
        # exact canonical tip. The caller checks that tip hash before and after all
        # lookups, closing same-height-fork and concurrent-reorg races.
        heartbeat_tip = _accounting_sats(hb.get("tip"), "heartbeat tip")
        if height > heartbeat_tip:
            return None
        # Bind the transaction's own block, not merely the enclosing heartbeat
        # tip. This closes an A-tip -> transient-B lookup -> A-tip ABA race.
        if rpc.call("getblockhash", [height]) != block_hash:
            return None
        # The RPC count is relative to its live tip and can exceed the signed
        # heartbeat snapshot during the heartbeat TTL.  Derive the only count
        # that is coherent with the supply/headroom snapshot instead of pruning
        # reorg protection early on a fast-moving chain.
        snapshot_confirmations = heartbeat_tip - height + 1
        if reported_confirmations < snapshot_confirmations:
            return None
        return {
            "confirmations": snapshot_confirmations,
            "block_height": height,
            "block_hash": block_hash,
        }
    except Exception:
        return None


def reconcile_mint_accounting(state, hb, rpc=None):
    """Refresh explicit signed-tx confirmation state and return outstanding sats.

    Aggregate supply changes never retire a signature: burns and reorgs make that
    inference unsafe. A pending mint moves out of headroom only when the trusted
    signer node finds its exact txid in the canonical chain covered by the signed
    heartbeat tip. It remains in a separate reorg-watch set through the consensus
    MAX_REORG_DEPTH; disappearance returns it to pending fail-closed.
    """
    if not isinstance(hb, dict):
        raise ValueError("heartbeat is not an object")
    _accounting_sats(hb.get("supply_sats"), "heartbeat supply_sats")
    accounting, migrated = _initialize_mint_accounting(state)
    pending = accounting["pending"]
    confirmed = accounting["confirmed"]

    # The legacy count-capped journal may omit still-unconfirmed tiny mints. Its
    # cumulative counter cannot identify exact transactions, but at the first
    # coherent heartbeat it supplies a conservative lower bound on unresolved
    # issuance: total_signed - canonical_supply. Burns only increase this value,
    # so any error is a safe pause. The synthetic entry is never auto-retired;
    # an operator must reconcile the lost exact history before clearing it.
    legacy_total = accounting.pop("legacy_total_signed", None)
    if legacy_total is not None:
        legacy_floor = max(
            0, legacy_total - _accounting_sats(hb.get("supply_sats"), "heartbeat supply_sats")
        )
        retained_total = sum(entry["sats"] for entry in pending)
        if legacy_floor > retained_total:
            material = "%d:%d" % (legacy_total, legacy_floor)
            pending.append(
                {
                    "request_id": "legacy-floor-" + hashlib.sha256(material.encode()).hexdigest(),
                    "sats": legacy_floor - retained_total,
                    "signed_at": 0,
                }
            )

    refreshed_confirmed = []
    reorged = []
    for entry in confirmed:
        info = _canonical_mint_confirmation(rpc, entry, hb)
        if info is None:
            restored = _copy_accounting_entry(entry)
            reorged.append(restored)
        elif info["confirmations"] > MAX_REORG_DEPTH:
            # Consensus cannot reorganize this transaction any longer.
            continue
        else:
            kept = _copy_accounting_entry(entry)
            kept.update({"block_height": info["block_height"], "block_hash": info["block_hash"]})
            refreshed_confirmed.append(kept)

    refreshed_pending = []
    newly_confirmed = []
    for entry in pending + reorged:
        info = _canonical_mint_confirmation(rpc, entry, hb)
        if info is None:
            refreshed_pending.append(entry)
        elif info["confirmations"] > MAX_REORG_DEPTH:
            continue
        else:
            watched = dict(entry)
            watched.update({"block_height": info["block_height"], "block_hash": info["block_hash"]})
            newly_confirmed.append(watched)

    accounting["pending"] = refreshed_pending
    accounting["confirmed"] = refreshed_confirmed + newly_confirmed
    accounting["last_heartbeat_tip"] = _accounting_sats(hb.get("tip"), "heartbeat tip")
    accounting["last_heartbeat_tip_hash"] = hb.get("tip_hash")
    pending, total = _validate_mint_entries(accounting["pending"], "pending")
    confirmed, ignored = _validate_mint_entries(
        accounting["confirmed"], "confirmed", require_txid=True
    )
    accounting["pending"] = pending
    accounting["confirmed"] = confirmed
    return total, migrated


def find_signed_mint(state, request_id, sats, recipient):
    signed = _validate_signed_audit_records(state)
    for record in signed:
        if record["request_id"] != request_id:
            continue
        if record.get("sats") != sats or record.get("to") != recipient:
            raise ValueError("mint request_id was reused with different parameters")
        return record
    return None


def classify_mint_request(state, request_id, sats, recipient):
    """Return (cached_record, incremental_sats) for cap/headroom accounting."""
    cached = find_signed_mint(state, request_id, sats, recipient)
    return cached, 0 if cached is not None else sats


def prune_finalized_signed_audits(state, keep_request_id=None, now=None):
    """Drop retry bytes only after both of their safety jobs are complete.

    The accounting reconciler removes a mint only once its exact transaction is
    canonically deeper than ``MAX_REORG_DEPTH``.  A signed audit row outside the
    rolling rate window and absent from both outstanding accounting sets is then
    no longer a solvency, reorg, or rate authority: its spent issuer inputs and
    consensus one-time BTC outpoint make a second accepted mint impossible.  The
    request currently being serviced is retained so an exact retry can still be
    returned in this invocation.
    """
    accounting, _ = _initialize_mint_accounting(state)
    outstanding = {
        entry["request_id"] for field in ("pending", "confirmed") for entry in accounting[field]
    }
    cutoff = (time.time() if now is None else float(now)) - WINDOW_SECS
    records = _validate_signed_audit_records(state)
    kept = [
        record
        for record in records
        if (
            record["request_id"] == keep_request_id
            or record["request_id"] in outstanding
            or record["at"] >= cutoff
        )
    ]
    removed = len(records) - len(kept)
    if removed:
        state["signed"] = kept
    return removed


def record_signed_mint(state, request_id, txid, signed_tx_hex, sats, recipient, signed_at=None):
    """Charge one newly returned signature to both rate and solvency accounting.

    A retry of the same unsigned transaction is idempotent while its audit record
    is retained, avoiding a crash-after-fsync retry from consuming headroom twice.
    """
    if not isinstance(request_id, str) or not re.fullmatch(r"[0-9a-f]{64}", request_id):
        raise ValueError("mint request_id is not a sha256 hex digest")
    if not isinstance(txid, str) or not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise ValueError("signed mint txid is malformed")
    if not isinstance(signed_tx_hex, str) or not re.fullmatch(r"[0-9a-fA-F]+", signed_tx_hex):
        raise ValueError("signed mint bytes are malformed")
    calculated = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed_tx_hex)).digest()).hexdigest()
    if calculated != txid:
        raise ValueError("signed mint txid does not match signed bytes")
    sats = _accounting_sats(sats, "signed mint sats", allow_zero=False)
    accounting = state.get("mint_accounting")
    if not isinstance(accounting, dict):
        raise ValueError("mint accounting was not initialized")
    signed = _validate_signed_audit_records(state)
    existing = find_signed_mint(state, request_id, sats, recipient)
    if existing is not None:
        if existing["txid"] != txid or existing["signed_tx_hex"].lower() != signed_tx_hex.lower():
            raise ValueError("retry produced different signed transaction bytes")
        return False
    pending, total = _validate_mint_entries(accounting.get("pending"), "pending")
    now = (
        int(time.time())
        if signed_at is None
        else _accounting_sats(signed_at, "signed mint timestamp")
    )
    reservation = next((x for x in pending if x["request_id"] == request_id), None)
    if reservation is None:
        # Only explicit caps-only development mode may reach this branch. A
        # production caller invokes record_mint_reservation and fsyncs it first.
        if total > MAX_ACCOUNTING_SATS - sats:
            raise ValueError("pending mint sum overflows")
        pending.append({"request_id": request_id, "txid": txid, "sats": sats, "signed_at": now})
    else:
        if reservation["sats"] != sats:
            raise ValueError("reserved mint amount differs from signed mint")
        reservation["txid"] = txid
        reservation["signed_at"] = now
    accounting["pending"] = pending
    audit = {
        "request_id": request_id,
        "txid": txid,
        "signed_tx_hex": signed_tx_hex.lower(),
        "sats": sats,
        "to": recipient,
        "at": now,
    }
    if reservation is not None and reservation.get("witness_receipt"):
        audit["witness_receipt"] = reservation["witness_receipt"]
        audit["witness_committed"] = False
    signed.append(audit)
    # Never count-truncate this journal.  Entries are retired only by
    # prune_finalized_signed_audits after the exact mint has left both the
    # consensus reorg horizon and the rolling rate window.
    state["signed"] = signed
    return True


def load_signer_state(path=None):
    path = STATEF if path is None else path
    if not os.path.lexists(path):
        raise FileNotFoundError("signer authority state is missing; never auto-initialize")
    state = strict_json_loads(
        _secure_text(os.path.abspath(path), private=True, max_bytes=SIGNER_STATE_MAX_BYTES),
        "signer state",
    )
    if not isinstance(state, dict):
        raise ValueError("signer state root is not an object")
    _validate_signed_audit_records(state)
    return state


def save_signer_state_durable(state, path=None, max_bytes=SIGNER_STATE_MAX_BYTES):
    """Atomically persist state and fsync both the file and containing directory."""
    path = STATEF if path is None else path
    encoded = (
        json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    if max_bytes is not None and len(encoded) > max_bytes:
        raise ValueError("signer state exceeds the symmetric byte ceiling")
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if os.path.realpath(directory) != directory:
        raise ValueError("signer state directory must not traverse symlinks")
    dir_info = os.lstat(directory)
    if (
        not stat.S_ISDIR(dir_info.st_mode)
        or stat.S_ISLNK(dir_info.st_mode)
        or dir_info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(dir_info.st_mode) & 0o022
    ):
        raise ValueError("signer state directory must be root/service-owned and non-writable")
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".", suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            fd = -1
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        dirfd = os.open(directory, flags)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def mint_prevout_owner_id(allocation_id):
    if not CONSENSUS_ALLOCATION_RE.fullmatch(str(allocation_id)):
        raise ValueError("mint prevout owner allocation id is malformed")
    return "mint:" + allocation_id


def direct_mint_prevout_owner_id(deposit_outpoint):
    if (
        not BTC_OUTPOINT_RE.fullmatch(str(deposit_outpoint))
        or int(deposit_outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
    ):
        raise ValueError("direct mint prevout owner deposit is malformed")
    return "mint-direct:" + deposit_outpoint


def c1_prevout_owner_id(allocation_id, phase, funding_sha256=None):
    if (
        not CONSENSUS_ALLOCATION_RE.fullmatch(str(allocation_id))
        or phase not in ("RESERVE", "EXPOSE", "CANCEL", "FUND")
        or ((phase == "FUND") != (funding_sha256 is not None))
        or (funding_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}", str(funding_sha256)))
    ):
        raise ValueError("C1 prevout owner identity is malformed")
    owner = "c1:" + allocation_id + ":" + phase
    if funding_sha256 is not None:
        owner += ":" + funding_sha256
    return owner


def _parse_prevout_owner_id(owner_id):
    mint = re.fullmatch(r"mint:(0{16}[0-9a-f]{16})", str(owner_id))
    if mint:
        return "mint", mint.group(1)
    direct = re.fullmatch(r"mint-direct:([0-9a-f]{64}:(?:0|[1-9][0-9]{0,9}))", str(owner_id))
    if direct and int(direct.group(1).rsplit(":", 1)[1]) <= 0xFFFFFFFF:
        return "mint-direct", None
    c1 = re.fullmatch(
        r"c1:(0{16}[0-9a-f]{16}):(RESERVE|EXPOSE|CANCEL|FUND)"
        r"(?::([0-9a-f]{64}))?",
        str(owner_id),
    )
    if c1 and ((c1.group(2) == "FUND") == (c1.group(3) is not None)):
        return "c1-reservation", c1.group(1)
    raise ValueError("issuer prevout owner id is malformed")


def _empty_prevout_journal():
    return {
        "version": PREVOUT_JOURNAL_VERSION,
        "owners": {},
        "terminal_observations": {},
        "scan_cursor": None,
        "cleanup_staging_ids": [],
    }


def _validate_prevout_journal(state):
    if (
        not isinstance(state, dict)
        or set(state)
        != {"version", "owners", "terminal_observations", "scan_cursor", "cleanup_staging_ids"}
        or state.get("version") != PREVOUT_JOURNAL_VERSION
        or not isinstance(state.get("owners"), dict)
        or len(state["owners"]) > PREVOUT_JOURNAL_MAX_OWNERS
        or not isinstance(state.get("terminal_observations"), dict)
        or len(state["terminal_observations"]) > PREVOUT_JOURNAL_MAX_OWNERS
        or not isinstance(state.get("cleanup_staging_ids"), list)
        or len(state["cleanup_staging_ids"]) > PREVOUT_JOURNAL_MAX_OWNERS
        or len(set(state["cleanup_staging_ids"])) != len(state["cleanup_staging_ids"])
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(staging_id))
            for staging_id in state["cleanup_staging_ids"]
        )
        or (state.get("scan_cursor") is not None and not isinstance(state["scan_cursor"], str))
    ):
        raise ValueError("issuer prevout journal schema is invalid")
    if state["scan_cursor"] is not None:
        _parse_prevout_owner_id(state["scan_cursor"])
    occupied = {}
    for owner_id, owner in state["owners"].items():
        capability, allocation_id = _parse_prevout_owner_id(owner_id)
        if (
            not isinstance(owner, dict)
            or set(owner)
            != {
                "capability",
                "allocation_id",
                "deposit_outpoint",
                "active",
                "revoked_unsigned_sha256",
                "revoked_conflicting_input_outpoints",
            }
            or owner.get("capability") != capability
            or owner.get("allocation_id") != allocation_id
            or (
                (capability in ("mint", "mint-direct"))
                != isinstance(owner.get("deposit_outpoint"), str)
            )
            or (
                owner.get("deposit_outpoint") is not None
                and (
                    not BTC_OUTPOINT_RE.fullmatch(owner["deposit_outpoint"])
                    or int(owner["deposit_outpoint"].rsplit(":", 1)[1]) > 0xFFFFFFFF
                )
            )
            or not isinstance(owner.get("revoked_unsigned_sha256"), list)
            or len(owner["revoked_unsigned_sha256"]) > PREVOUT_MAX_REVOKED_PER_OWNER
            or len(set(owner["revoked_unsigned_sha256"])) != len(owner["revoked_unsigned_sha256"])
            or any(
                not re.fullmatch(r"[0-9a-f]{64}", str(item))
                for item in owner["revoked_unsigned_sha256"]
            )
            or not isinstance(owner.get("revoked_conflicting_input_outpoints"), dict)
            or set(owner["revoked_conflicting_input_outpoints"])
            != set(owner["revoked_unsigned_sha256"])
        ):
            raise ValueError("issuer prevout owner record is invalid")
        for revoked_hash, conflicts in owner["revoked_conflicting_input_outpoints"].items():
            # Migrated v1-v3 never-sign hashes use an exact empty list.  The
            # durable revocation itself authorizes replacement; there is no
            # need to invent a historical intersection that the old journal
            # never recorded.
            if (
                not isinstance(conflicts, list)
                or len(conflicts) > PREVOUT_MAX_REVOKED_PER_OWNER
                or conflicts != sorted(set(conflicts))
                or any(
                    not BTC_OUTPOINT_RE.fullmatch(str(outpoint))
                    or int(outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
                    for outpoint in conflicts
                )
            ):
                raise ValueError("issuer prevout revocation conflict set is invalid")
        active = owner["active"]
        if active is None:
            continue
        if (
            not isinstance(active, dict)
            or set(active)
            != {
                "unsigned_sha256",
                "input_outpoints",
                "txid",
                "created_at",
                "signing_state",
                "staging_id",
            }
            or not re.fullmatch(r"[0-9a-f]{64}", str(active.get("unsigned_sha256")))
            or active["unsigned_sha256"] in owner["revoked_unsigned_sha256"]
            or not isinstance(active.get("input_outpoints"), list)
            or not active["input_outpoints"]
            or len(active["input_outpoints"]) > 10_000
            or len(set(active["input_outpoints"])) != len(active["input_outpoints"])
            or any(
                not BTC_OUTPOINT_RE.fullmatch(str(outpoint))
                or int(outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
                for outpoint in active["input_outpoints"]
            )
            or (
                active.get("txid") is not None
                and not re.fullmatch(r"[0-9a-f]{64}", str(active["txid"]))
            )
            or active.get("signing_state") not in ("LEASED", "SIGNING", "SIGNED")
            or ((active.get("signing_state") == "SIGNED") != (active.get("txid") is not None))
            or not re.fullmatch(r"[0-9a-f]{64}", str(active.get("staging_id")))
            or active["staging_id"]
            != hashlib.sha256(
                (owner_id + "\x00" + active["unsigned_sha256"]).encode("utf-8")
            ).hexdigest()
            or type(active.get("created_at")) is not int
            or active["created_at"] < 0
        ):
            raise ValueError("issuer prevout active lease is invalid")
        for outpoint in active["input_outpoints"]:
            if outpoint in occupied:
                raise ValueError("issuer prevout is leased by more than one carrier")
            occupied[outpoint] = owner_id
    for allocation_id, observation in state["terminal_observations"].items():
        if (
            not CONSENSUS_ALLOCATION_RE.fullmatch(str(allocation_id))
            or not isinstance(observation, dict)
            or set(observation) != {"tip", "tip_hash"}
            or type(observation.get("tip")) is not int
            or observation["tip"] < 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(observation.get("tip_hash")))
        ):
            raise ValueError("issuer prevout terminal observation is invalid")
    return state


def load_prevout_journal():
    if not os.path.lexists(PREVOUT_STATEF):
        raise FileNotFoundError("issuer prevout journal is missing; never auto-initialize")
    state = strict_json_loads(
        _secure_text(PREVOUT_STATEF, private=True, max_bytes=PREVOUT_JOURNAL_MAX_BYTES),
        "issuer prevout journal",
    )
    return _validate_prevout_journal(state)


def save_prevout_journal(state):
    _validate_prevout_journal(state)
    return save_signer_state_durable(state, PREVOUT_STATEF, max_bytes=PREVOUT_JOURNAL_MAX_BYTES)


def _unsigned_input_outpoints(unsigned_tx_hex):
    return ["%s:%d" % item for item in parse_unsigned_tx_inputs(unsigned_tx_hex)]


def _unsigned_abandonment(owner_id, owner, unsigned_sha256):
    conflicts = owner["revoked_conflicting_input_outpoints"].get(unsigned_sha256)
    if conflicts is None:
        raise ValueError("issuer prevout revocation identity is unavailable")
    return UnsignedCarrierAbandoned(
        {
            "version": 1,
            "action": "unsigned_carrier_abandoned",
            "capability": owner["capability"],
            "owner_id": owner_id,
            "allocation_id": owner["allocation_id"],
            "deposit_outpoint": owner["deposit_outpoint"],
            "unsigned_sha256": unsigned_sha256,
            "conflicting_input_outpoints": list(conflicts),
            "reason": "issuer_prevout_conflict",
        }
    )


def _conflicting_issuer_prevouts(state, owner_id, input_outpoints):
    occupied = set()
    for other_id, other in state["owners"].items():
        if other_id == owner_id or other["active"] is None:
            continue
        occupied.update(other["active"]["input_outpoints"])
    conflicts = sorted(set(input_outpoints).intersection(occupied))
    if len(conflicts) > PREVOUT_MAX_REVOKED_PER_OWNER:
        raise ValueError("issuer prevout conflict set exceeds bounded response")
    return conflicts


def _promote_legacy_revocation_inputs(state, owner, unsigned_sha256, input_outpoints):
    """Give migrated never-sign hashes a deterministic replacement input set."""
    conflicts = owner["revoked_conflicting_input_outpoints"][unsigned_sha256]
    if conflicts:
        return
    conservative = sorted(set(input_outpoints))
    if not 1 <= len(conservative) <= PREVOUT_MAX_REVOKED_PER_OWNER:
        raise ValueError("legacy revoked carrier input set requires operator reconciliation")
    owner["revoked_conflicting_input_outpoints"][unsigned_sha256] = conservative
    save_prevout_journal(state)


def _bind_prevout_owner(state, owner_id, capability, allocation_id, deposit_outpoint):
    parsed_capability, parsed_allocation = _parse_prevout_owner_id(owner_id)
    if (
        capability != parsed_capability
        or allocation_id != parsed_allocation
        or ((capability in ("mint", "mint-direct")) != isinstance(deposit_outpoint, str))
        or (
            deposit_outpoint is not None
            and (
                not BTC_OUTPOINT_RE.fullmatch(deposit_outpoint)
                or int(deposit_outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
            )
        )
    ):
        raise ValueError("issuer prevout owner claim is malformed")
    owner = state["owners"].get(owner_id)
    if owner is None:
        if len(state["owners"]) >= PREVOUT_JOURNAL_MAX_OWNERS:
            raise ValueError("issuer prevout owner ceiling reached")
        owner = {
            "capability": capability,
            "allocation_id": allocation_id,
            "deposit_outpoint": deposit_outpoint,
            "active": None,
            "revoked_unsigned_sha256": [],
            "revoked_conflicting_input_outpoints": {},
        }
        state["owners"][owner_id] = owner
    elif (
        owner["capability"] != capability
        or owner["allocation_id"] != allocation_id
        or owner["deposit_outpoint"] != deposit_outpoint
    ):
        raise ValueError("issuer prevout owner identity changed")
    return owner


def reject_conflicting_issuer_prevouts(
    state, owner_id, capability, allocation_id, deposit_outpoint, unsigned_tx_hex
):
    """Durably revoke a prepared template if another carrier owns an input."""
    unsigned_sha256 = hashlib.sha256(bytes.fromhex(unsigned_tx_hex)).hexdigest()
    input_outpoints = _unsigned_input_outpoints(unsigned_tx_hex)
    owner = _bind_prevout_owner(state, owner_id, capability, allocation_id, deposit_outpoint)
    if unsigned_sha256 in owner["revoked_unsigned_sha256"]:
        _promote_legacy_revocation_inputs(state, owner, unsigned_sha256, input_outpoints)
        raise _unsigned_abandonment(owner_id, owner, unsigned_sha256)
    active = owner["active"]
    if active is not None:
        if (
            active["unsigned_sha256"] != unsigned_sha256
            or active["input_outpoints"] != input_outpoints
        ):
            raise ValueError("issuer prevout owner already has another exact carrier")
        return False
    conflicts = _conflicting_issuer_prevouts(state, owner_id, input_outpoints)
    if not conflicts:
        # A newly materialized empty owner is not safety authority yet and need
        # not consume durable space unless it is leased or carries a revocation.
        if not owner["revoked_unsigned_sha256"]:
            state["owners"].pop(owner_id, None)
        return False
    if len(owner["revoked_unsigned_sha256"]) >= PREVOUT_MAX_REVOKED_PER_OWNER:
        raise ValueError("issuer prevout revocation ceiling reached")
    owner["revoked_unsigned_sha256"].append(unsigned_sha256)
    owner["revoked_conflicting_input_outpoints"][unsigned_sha256] = conflicts
    save_prevout_journal(state)
    raise _unsigned_abandonment(owner_id, owner, unsigned_sha256)


def reserve_issuer_prevouts(
    state, owner_id, capability, allocation_id, deposit_outpoint, unsigned_tx_hex
):
    """Fsync one cross-capability input lease before any issuer key operation.

    A conflicting unsigned template is first durably revoked.  Its authenticated
    exit-75 acknowledgement is therefore authority for the preparer to discard
    only that never-signed template; a lost response remains exactly retryable.
    """
    unsigned_sha256 = hashlib.sha256(bytes.fromhex(unsigned_tx_hex)).hexdigest()
    input_outpoints = _unsigned_input_outpoints(unsigned_tx_hex)
    owner = _bind_prevout_owner(state, owner_id, capability, allocation_id, deposit_outpoint)
    if unsigned_sha256 in owner["revoked_unsigned_sha256"]:
        _promote_legacy_revocation_inputs(state, owner, unsigned_sha256, input_outpoints)
        raise _unsigned_abandonment(owner_id, owner, unsigned_sha256)
    active = owner["active"]
    if active is not None:
        if (
            active["unsigned_sha256"] != unsigned_sha256
            or active["input_outpoints"] != input_outpoints
        ):
            raise ValueError("issuer prevout owner already has another exact carrier")
        return active, False
    conflicts = _conflicting_issuer_prevouts(state, owner_id, input_outpoints)
    if conflicts:
        if len(owner["revoked_unsigned_sha256"]) >= PREVOUT_MAX_REVOKED_PER_OWNER:
            raise ValueError("issuer prevout revocation ceiling reached")
        owner["revoked_unsigned_sha256"].append(unsigned_sha256)
        owner["revoked_conflicting_input_outpoints"][unsigned_sha256] = conflicts
        save_prevout_journal(state)
        raise _unsigned_abandonment(owner_id, owner, unsigned_sha256)
    active = {
        "unsigned_sha256": unsigned_sha256,
        "input_outpoints": input_outpoints,
        "txid": None,
        "created_at": int(time.time()),
        "signing_state": "LEASED",
        "staging_id": hashlib.sha256(
            (owner_id + "\x00" + unsigned_sha256).encode("utf-8")
        ).hexdigest(),
    }
    owner["active"] = active
    save_prevout_journal(state)
    return active, True


def mark_issuer_prevout_signature(state, owner_id, unsigned_tx_hex, txid):
    owner = state["owners"].get(owner_id)
    unsigned_sha256 = hashlib.sha256(bytes.fromhex(unsigned_tx_hex)).hexdigest()
    if (
        owner is None
        or owner["active"] is None
        or owner["active"]["unsigned_sha256"] != unsigned_sha256
        or owner["active"]["input_outpoints"] != _unsigned_input_outpoints(unsigned_tx_hex)
        or not re.fullmatch(r"[0-9a-f]{64}", str(txid))
    ):
        raise ValueError("issuer prevout signature has no exact durable lease")
    prior = owner["active"]["txid"]
    if prior is not None and prior != txid:
        raise ValueError("issuer prevout exact lease changed signed txid")
    if prior is None:
        owner["active"]["txid"] = txid
        owner["active"]["signing_state"] = "SIGNED"
        save_prevout_journal(state)
        cleanup_signing_stage(owner["active"]["staging_id"])
        return True
    cleanup_signing_stage(owner["active"]["staging_id"])
    return False


def _ensure_signing_stage_directory():
    if not os.path.lexists(SIGNING_STAGE_DIR):
        try:
            os.mkdir(SIGNING_STAGE_DIR, 0o700)
        except FileExistsError:
            pass
    info = os.lstat(SIGNING_STAGE_DIR)
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid not in (0, os.geteuid())
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("issuer signing staging directory is unsafe")
    return SIGNING_STAGE_DIR


def _signing_stage_paths(staging_id):
    if not re.fullmatch(r"[0-9a-f]{64}", str(staging_id)):
        raise ValueError("issuer signing staging id is malformed")
    directory = _ensure_signing_stage_directory()
    return (
        os.path.join(directory, staging_id + ".prepared.json"),
        os.path.join(directory, staging_id + ".signed"),
    )


def _fsync_regular_file(path):
    info = _secure_regular(path, private=True)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(fd)
        if (
            opened.st_dev != info.st_dev
            or opened.st_ino != info.st_ino
            or not stat.S_ISREG(opened.st_mode)
        ):
            raise ValueError("issuer signing stage changed while opening")
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(os.path.dirname(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _precreate_private_signing_output(path):
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    directory_fd = os.open(os.path.dirname(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def cleanup_signing_stage(staging_id):
    if not re.fullmatch(r"[0-9a-f]{64}", str(staging_id)):
        raise ValueError("issuer signing cleanup id is malformed")
    if not os.path.lexists(SIGNING_STAGE_DIR):
        return
    prepared_path, signed_path = _signing_stage_paths(staging_id)
    changed = False
    for path in (
        prepared_path,
        signed_path,
        prepared_path + ".intent.json",
        prepared_path + ".transaction.json",
    ):
        try:
            os.unlink(path)
            changed = True
        except FileNotFoundError:
            pass
    if changed:
        directory_fd = os.open(SIGNING_STAGE_DIR, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)


def drain_signing_cleanup_queue(state):
    if not state["cleanup_staging_ids"]:
        return False
    for staging_id in list(state["cleanup_staging_ids"]):
        cleanup_signing_stage(staging_id)
    state["cleanup_staging_ids"].clear()
    save_prevout_journal(state)
    return True


def sign_or_recover_staged_carrier(
    prevout_state,
    owner_id,
    unsigned_tx_hex,
    prev_script_hex,
    description,
    maximum_signed_hex_bytes=MAX_CHILD_OUTPUT_BYTES,
    *,
    build_evidence=None,
    revalidate=None,
):
    """Perform at most one randomized signing attempt for an exact owner/hash.

    ``SIGNING`` is fsynced before the key subprocess. A restart in that state
    may return only a complete deterministic-path output. Missing or malformed
    output is an incident requiring offline reconciliation; it is never re-signed.
    """
    owner = prevout_state["owners"].get(owner_id)
    if owner is None or owner["active"] is None:
        raise ValueError("issuer signing attempt has no active prevout lease")
    active = owner["active"]
    unsigned_sha256 = hashlib.sha256(bytes.fromhex(unsigned_tx_hex)).hexdigest()
    if active["unsigned_sha256"] != unsigned_sha256 or active[
        "input_outpoints"
    ] != _unsigned_input_outpoints(unsigned_tx_hex):
        raise ValueError("issuer signing attempt differs from exact lease")
    prepared_path, signed_path = _signing_stage_paths(active["staging_id"])
    transaction_path = prepared_path + ".transaction.json"
    intent_path = prepared_path + ".intent.json"
    started_here = False
    if active["signing_state"] == "LEASED":
        if os.path.lexists(signed_path):
            raise ValueError("unexpected issuer signed stage before SIGNING")
        if not callable(build_evidence) or not callable(revalidate):
            raise ValueError("complete independently verified signing evidence is required")
        evidence = build_evidence()
        if (
            type(evidence) is not dict
            or set(evidence) != {"version", "prepared", "authorization"}
            or type(evidence["version"]) is not int
            or evidence["version"] != 2
            or type(evidence["prepared"]) is not dict
            or evidence["prepared"].get("unsigned_tx_hex") != unsigned_tx_hex
            or type(evidence["authorization"]) is not dict
        ):
            raise ValueError("independent signing evidence is malformed")
        save_signer_state_durable(evidence, prepared_path, max_bytes=MAX_EVIDENCE_BYTES)
        save_signer_state_durable(
            evidence["prepared"], transaction_path, max_bytes=MAX_EVIDENCE_BYTES
        )
        authorization = evidence["authorization"]
        required = {
            "operation_type",
            "recipient",
            "amount",
            "change_destination",
            "operation_identity_digest",
            "maximum_absolute_fee",
            "maximum_fee_rate",
        }
        if (
            set(authorization) != required
            or authorization["maximum_absolute_fee"] != EXPECTED_MINT_FEE_UNITS
            or authorization["maximum_fee_rate"] != 19
        ):
            raise ValueError("independent signing authorization is malformed")
        if os.path.lexists(intent_path):
            _secure_regular(intent_path, private=True)
            os.unlink(intent_path)
        revalidate()
        passphrase = _secure_text(PASSFILE, private=True, max_bytes=4096).strip()
        run = run_bounded_subprocess(
            [
                KEYGEN,
                "authorize-intent",
                KEYFILE,
                transaction_path,
                "--operation-type",
                authorization["operation_type"],
                "--recipient",
                authorization["recipient"],
                "--amount",
                str(authorization["amount"]),
                "--change-destination",
                authorization["change_destination"],
                "--operation-identity-digest",
                authorization["operation_identity_digest"],
                "--maximum-absolute-fee",
                str(authorization["maximum_absolute_fee"]),
                "--maximum-fee-rate",
                str(authorization["maximum_fee_rate"]),
                "--out",
                intent_path,
            ],
            input_text="",
            timeout=60,
            stdout_max=64 * 1024,
            stderr_max=1024 * 1024,
            description="issuer detached-intent authorization",
            env={**os.environ, "VELD_VAULT_PASSPHRASE": passphrase},
        )
        passphrase = None
        if run.returncode:
            raise ValueError("issuer detached-intent authorization refused")
        _fsync_regular_file(intent_path)
        revalidate()
        active["signing_state"] = "SIGNING"
        try:
            save_prevout_journal(prevout_state)
        except Exception:
            active["signing_state"] = "LEASED"
            raise
        started_here = True
    elif active["signing_state"] == "SIGNED":
        raise ValueError("issuer carrier is already signed in durable cache")
    prepared = strict_json_loads(
        _secure_text(prepared_path, private=True, max_bytes=MAX_EVIDENCE_BYTES),
        "issuer signing prepared stage",
    )
    if (
        type(prepared) is not dict
        or prepared.get("version") != 2
        or type(prepared.get("prepared")) is not dict
        or prepared["prepared"].get("unsigned_tx_hex") != unsigned_tx_hex
    ):
        raise ValueError("legacy or mismatched signing stage requires reconciliation")
    if not os.path.lexists(signed_path):
        if not started_here:
            raise ValueError("indeterminate prior issuer signing attempt; exact output missing")
        # keygen's C++ ofstream honors the mode of an existing inode. Create it
        # O_EXCL/0600 inside the private deterministic directory so an sshd
        # umask of 022 can never expose randomized signature bytes as 0644.
        _precreate_private_signing_output(signed_path)
        if not callable(revalidate):
            raise ValueError("fresh issuer signing gate is required")
        revalidate()
        passphrase = _secure_text(PASSFILE, private=True, max_bytes=4096).strip()
        run = run_bounded_subprocess(
            [
                KEYGEN,
                "sign-tx",
                KEYFILE,
                transaction_path,
                "--intent",
                intent_path,
                "--out",
                signed_path,
            ],
            input_text="",
            timeout=60,
            stdout_max=64 * 1024,
            stderr_max=1024 * 1024,
            description=description,
            env={**os.environ, "VELD_VAULT_PASSPHRASE": passphrase},
        )
        passphrase = None
        if run.returncode != 0:
            raise ValueError(description + " refused: " + run.stderr.strip()[:200])
    signed_hex = _secure_text(
        os.path.abspath(signed_path),
        private=True,
        # veld-keygen terminates its hex line with one newline. Preserve the
        # exact carrier ceiling while allowing that one transport byte.
        max_bytes=maximum_signed_hex_bytes + 1,
    ).strip()
    if (
        not re.fullmatch(r"[0-9a-fA-F]+", signed_hex)
        or len(signed_hex) > maximum_signed_hex_bytes
        or sol.unsigned_template_from_signed_hex(signed_hex) != unsigned_tx_hex
    ):
        raise ValueError("issuer staged signature differs from exact template")
    _fsync_regular_file(signed_path)
    return signed_hex.lower()


def _coherent_c1_terminal_status(rpc, allocation_id):
    supply_before = rpc.call("getbtcveldsupply", [])
    status = rpc.call("getbtcveldc1reservation", [allocation_id])
    supply_after = rpc.call("getbtcveldsupply", [])
    if (
        not isinstance(supply_before, dict)
        or set(supply_before) != {"supply_sats", "tip", "tip_hash"}
        or supply_before != supply_after
        or type(supply_before.get("tip")) is not int
        or supply_before["tip"] < 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(supply_before.get("tip_hash")))
        or not isinstance(status, dict)
        or status.get("allocation_id") != allocation_id
        or type(status.get("retired")) is not bool
        or status.get("tip") != supply_before["tip"]
    ):
        raise ValueError("issuer prevout C1 terminal snapshot is incoherent")
    return status, supply_before


def _direct_mint_lease_is_final(rpc, owner):
    active = owner["active"]
    if active is None or active["txid"] is None:
        return False
    supply_before = rpc.call("getbtcveldsupply", [])
    status = rpc.call("getbtcveldmintstatus", [owner["deposit_outpoint"]])
    supply_after = rpc.call("getbtcveldsupply", [])
    if (
        not isinstance(supply_before, dict)
        or set(supply_before) != {"supply_sats", "tip", "tip_hash"}
        or supply_before != supply_after
        or not isinstance(status, dict)
        or status.get("outpoint") != owner["deposit_outpoint"]
        or status.get("tip") != supply_before.get("tip")
        or status.get("tip_hash") != supply_before.get("tip_hash")
        or type(status.get("consumed")) is not bool
    ):
        raise ValueError("direct mint lease snapshot is incoherent")
    if not status["consumed"]:
        return False
    if (
        status.get("accepted_txid") != active["txid"]
        or status.get("accepted_effect_kind") != "MINT"
        or type(status.get("accepted_block_height")) is not int
        or status["accepted_block_height"] < 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(status.get("accepted_block_hash")))
        or supply_before["tip"] < status["accepted_block_height"]
        or supply_before["tip"] - status["accepted_block_height"] + 1 <= MAX_REORG_DEPTH
        or rpc.call("getblockhash", [status["accepted_block_height"]])
        != status["accepted_block_hash"]
    ):
        return False
    return True


def maintain_prevout_journal(rpc, state, scan_limit=8):
    """Fairly release all leases for a >100-block-stable terminal allocation."""
    if type(scan_limit) is not int or not 1 <= scan_limit <= 256:
        raise ValueError("issuer prevout scan limit is invalid")
    owner_ids = sorted(state["owners"])
    if not owner_ids:
        if state["terminal_observations"] or state["scan_cursor"] is not None:
            state["terminal_observations"].clear()
            state["scan_cursor"] = None
            save_prevout_journal(state)
        return 0
    cursor = state["scan_cursor"]
    start = 0
    if cursor is not None:
        while start < len(owner_ids) and owner_ids[start] <= cursor:
            start += 1
        if start == len(owner_ids):
            start = 0
    selected = []
    seen_allocations = set()
    offset = 0
    while offset < len(owner_ids) and len(selected) < scan_limit:
        owner_id = owner_ids[(start + offset) % len(owner_ids)]
        owner = state["owners"][owner_id]
        allocation_id = owner["allocation_id"]
        identity = allocation_id if allocation_id is not None else owner_id
        if identity not in seen_allocations:
            selected.append((owner_id, allocation_id))
            seen_allocations.add(identity)
        offset += 1
    released = 0
    # Advance the fair cursor before any remote lookup. A wedged/malformed first
    # allocation can fail this invocation, but cannot pin every later owner.
    state["scan_cursor"] = selected[-1][0]
    save_prevout_journal(state)
    changed = False
    for owner_id, allocation_id in selected:
        owner = state["owners"].get(owner_id)
        if owner is None:
            continue
        if owner["capability"] == "mint-direct":
            if _direct_mint_lease_is_final(rpc, owner):
                staging_id = owner["active"]["staging_id"]
                if staging_id not in state["cleanup_staging_ids"]:
                    state["cleanup_staging_ids"].append(staging_id)
                del state["owners"][owner_id]
                released += 1
                changed = True
            continue
        status, supply = _coherent_c1_terminal_status(rpc, allocation_id)
        observed = state["terminal_observations"].get(allocation_id)
        if not status["retired"]:
            if observed is not None:
                del state["terminal_observations"][allocation_id]
                changed = True
            continue
        if observed is None:
            state["terminal_observations"][allocation_id] = {
                "tip": supply["tip"],
                "tip_hash": supply["tip_hash"],
            }
            changed = True
            continue
        observed_hash = rpc.call("getblockhash", [observed["tip"]])
        if observed_hash != observed["tip_hash"] or supply["tip"] < observed["tip"]:
            # A shallow reorg restarts the terminal observation horizon.
            state["terminal_observations"][allocation_id] = {
                "tip": supply["tip"],
                "tip_hash": supply["tip_hash"],
            }
            changed = True
            continue
        if supply["tip"] - observed["tip"] + 1 <= MAX_REORG_DEPTH:
            continue
        for stale_owner in [
            key for key, owner in state["owners"].items() if owner["allocation_id"] == allocation_id
        ]:
            active = state["owners"][stale_owner]["active"]
            if active is not None:
                if active["staging_id"] not in state["cleanup_staging_ids"]:
                    state["cleanup_staging_ids"].append(active["staging_id"])
            del state["owners"][stale_owner]
            released += 1
            changed = True
        del state["terminal_observations"][allocation_id]
        changed = True
    if changed:
        save_prevout_journal(state)
        drain_signing_cleanup_queue(state)
    return released


def validate_mint_authority_config(cfg, issuer):
    """Require an explicitly activated single mint signer and shared witness."""
    policy = cfg.get("mint_authority") if isinstance(cfg, dict) else None
    if not isinstance(policy, dict):
        raise ValueError("mint_authority policy is required")
    if policy.get("topology") != "single-active-shared-witness":
        raise ValueError("mint_authority.topology must be single-active-shared-witness")
    signer_id = policy.get("signer_id")
    active_id = policy.get("active_signer_id")
    if (
        not isinstance(signer_id, str)
        or not sol.IDENTIFIER_RE.fullmatch(signer_id)
        or active_id != signer_id
    ):
        raise ValueError("this signer is not the configured single active mint signer")
    if policy.get("issuer_id") != issuer:
        raise ValueError("mint_authority issuer_id differs from compiled issuer")
    if policy.get("wrap_allocation_witness_required") is not True:
        raise ValueError("mint_authority.wrap_allocation_witness_required must be true")
    try:
        marker = _secure_text(
            ACTIVE_MINT_SIGNERF, private=True, exact_mode=0o600, max_bytes=1024
        ).strip()
    except Exception as e:
        raise ValueError("active-mint-signer marker unavailable: %s" % e)
    if marker != signer_id:
        raise ValueError("active-mint-signer marker does not name this signer")
    witness = policy.get("witness")
    if not isinstance(witness, dict):
        raise ValueError("shared reservation witness policy is required")
    command = witness.get("command")
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(x, str) or not x or "\x00" in x for x in command)
        or not os.path.isabs(command[0])
    ):
        raise ValueError("reservation witness command must be absolute argv")
    _secure_regular(command[0], executable=True)
    witness_id = witness.get("witness_id")
    if not isinstance(witness_id, str) or not sol.IDENTIFIER_RE.fullmatch(witness_id):
        raise ValueError("reservation witness_id is invalid")
    _secure_regular(BEAT_PUBKEY)
    return policy, witness


def _call_witness(command, payload):
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    run = run_bounded_subprocess(
        command,
        input_text=encoded,
        timeout=45,
        stdout_max=MAX_CHILD_OUTPUT_BYTES,
        stderr_max=1024 * 1024,
        description="reservation witness",
    )
    if run.returncode != 0:
        raise ValueError(
            "reservation witness unavailable/refused: "
            + (run.stderr.strip()[:180] or "exit %d" % run.returncode)
        )
    try:
        answer = strict_json_loads(run.stdout, "reservation witness response")
    except Exception as e:
        raise ValueError("reservation witness returned invalid JSON: %s" % e)
    if not isinstance(answer, dict):
        raise ValueError("reservation witness response is not an object")
    return answer


def verify_reservation_receipt(
    receipt, issuer, witness, request_id, unsigned_tx_sha256, sats, recipient, heartbeat, allocation
):
    ok, why = sol.validate_reservation_receipt(receipt)
    if not ok:
        raise ValueError(why)
    expected = {
        "issuer_id": issuer,
        "witness_id": witness["witness_id"],
        "request_id": request_id,
        "unsigned_tx_sha256": unsigned_tx_sha256,
        "sats": sats,
        "recipient": recipient,
        "beat_seq": heartbeat["seq"],
        "tip": heartbeat["tip"],
        "tip_hash": heartbeat["tip_hash"],
        "headroom_sats": heartbeat["headroom_sats"],
        "allocation_verified": True,
        # The public witness receipt binds the consensus sequence identifier.
        # The private random request_id is an admission/idempotency secret and
        # must never be substituted for the on-chain allocation identity.
        "allocation_request_id": allocation["consensus_allocation_id"],
        "allocation_descriptor_index": allocation["descriptor_index"],
        "allocation_btc_address": allocation["btc_address"],
        "allocation_script_pubkey": allocation["script_pubkey"],
        "deposit_outpoint": allocation["deposit_outpoint"],
        "allocation_capacity_policy_sha256": allocation["capacity_policy_sha256"],
        "allocation_public_descriptor_range_start": allocation["public_descriptor_range_start"],
        "allocation_public_descriptor_range_end": allocation["public_descriptor_range_end"],
    }
    for key, value in expected.items():
        if receipt.get(key) != value:
            raise ValueError("reservation receipt does not bind %s" % key)
    with tempfile.TemporaryDirectory(prefix="veld-reservation-verify-") as td:
        message = os.path.join(td, "receipt.json")
        signature = os.path.join(td, "receipt.sig")
        with open(message, "wb") as out:
            out.write(sol.canonical_reservation_bytes(receipt))
        with open(signature, "wb") as out:
            out.write(bytes.fromhex(receipt["sig"]))
        pinned = _secure_text(BEAT_PUBKEY, max_bytes=1024 * 1024).encode("utf-8")
        public_key = os.path.join(td, "watchtower-pubkey.hex")
        with open(public_key, "wb") as out:
            out.write(pinned)
        run = run_bounded_subprocess(
            [KEYGEN, "verify-release", "@" + public_key, message, signature],
            timeout=30,
            stdout_max=64 * 1024,
            stderr_max=64 * 1024,
            description="reservation signature verifier",
        )
    if run.returncode != 0:
        raise ValueError("reservation receipt signature is invalid")
    return receipt


def reserve_witness_headroom(
    witness,
    issuer,
    request_id,
    unsigned_tx_sha256,
    unsigned_tx_hex,
    sats,
    recipient,
    heartbeat,
    allocation,
):
    payload = {
        "action": "reserve",
        "issuer_id": issuer,
        "request_id": request_id,
        "unsigned_tx_sha256": unsigned_tx_sha256,
        "unsigned_tx_hex": unsigned_tx_hex,
        "sats": sats,
        "recipient": recipient,
        "allocation": allocation,
        "beat_seq": heartbeat["seq"],
        "tip": heartbeat["tip"],
        "tip_hash": heartbeat["tip_hash"],
    }
    answer = _call_witness(witness["command"], payload)
    return verify_reservation_receipt(
        answer.get("receipt"),
        issuer,
        witness,
        request_id,
        unsigned_tx_sha256,
        sats,
        recipient,
        heartbeat,
        allocation,
    )


def record_mint_reservation(state, receipt, signed_at=None):
    accounting, _ = _initialize_mint_accounting(state)
    pending, total = _validate_mint_entries(accounting.get("pending"), "pending")
    request_id = receipt["request_id"]
    for entry in pending:
        if entry["request_id"] != request_id:
            continue
        if (
            entry["sats"] != receipt["sats"]
            or entry.get("witness_receipt", {}).get("reservation_id") != receipt["reservation_id"]
        ):
            raise ValueError("request_id already has a different reservation")
        entry["witness_receipt"] = receipt
        accounting["pending"] = pending
        return False
    sats = receipt["sats"]
    if total > MAX_ACCOUNTING_SATS - sats:
        raise ValueError("pending reservation sum overflows")
    pending.append(
        {
            "request_id": request_id,
            "sats": sats,
            "signed_at": int(time.time() if signed_at is None else signed_at),
            "witness_receipt": receipt,
            "witness_committed": False,
        }
    )
    accounting["pending"] = pending
    return True


def _accounting_entry(state, request_id):
    accounting = state.get("mint_accounting")
    if not isinstance(accounting, dict):
        return None
    for field in ("pending", "confirmed"):
        for entry in accounting.get(field, []):
            if isinstance(entry, dict) and entry.get("request_id") == request_id:
                return entry
    return None


def _witness_entry(state, request_id):
    entry = _accounting_entry(state, request_id)
    if entry is not None:
        return entry
    for record in state.get("signed", []):
        if isinstance(record, dict) and record.get("request_id") == request_id:
            return record
    return None


def commit_witness_transaction(witness, state, request_id, txid, signed_tx_hex):
    entry = _witness_entry(state, request_id)
    if not entry or not entry.get("witness_receipt"):
        raise ValueError("signed mint has no durable witness reservation")
    rid = entry["witness_receipt"]["reservation_id"]
    answer = _call_witness(
        witness["command"],
        {"action": "commit", "reservation_id": rid, "txid": txid, "signed_tx_hex": signed_tx_hex},
    )
    if (
        answer.get("reservation_id") != rid
        or answer.get("txid") != txid
        or answer.get("committed") is not True
    ):
        raise ValueError("witness commit acknowledgement is invalid")
    entry["witness_committed"] = True
    for record in state.get("signed", []):
        if isinstance(record, dict) and record.get("request_id") == request_id:
            record["witness_committed"] = True
    return True


def require_witnessed_outstanding(state):
    accounting, _ = _initialize_mint_accounting(state)
    for field in ("pending", "confirmed"):
        for entry in accounting.get(field, []):
            if not entry.get("witness_receipt"):
                raise ValueError("unwitnessed outstanding mint requires offline reconciliation")


def validate_c1_allocation_claim(value):
    required = {
        "request_id",
        "principal_hash",
        "veld_address",
        "amount_sats",
        "descriptor_index",
        "btc_address",
        "script_pubkey",
        "admitted_at",
        "expires_at",
        "capacity_policy_sha256",
        "commitment_blind",
        "consensus_allocation_id",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("C1 allocation claim schema is not canonical")
    if (
        not isinstance(value["request_id"], str)
        or not re.fullmatch(r"[0-9a-f]{32}", value["request_id"])
        or not isinstance(value["principal_hash"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["principal_hash"])
        or not isinstance(value["veld_address"], str)
        or not VELD_ADDR_RE.fullmatch(value["veld_address"])
        or type(value["amount_sats"]) is not int
        or not 10_000 <= value["amount_sats"] <= MAX_SINGLE_SATS
        or type(value["descriptor_index"]) is not int
        or not 1000 <= value["descriptor_index"] <= 10_999
        or not isinstance(value["btc_address"], str)
        or not re.fullmatch(r"bc1p[023456789ac-hj-np-z]{58}", value["btc_address"])
        or not isinstance(value["script_pubkey"], str)
        or not re.fullmatch(r"5120[0-9a-f]{64}", value["script_pubkey"])
        or not isinstance(value["commitment_blind"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["commitment_blind"])
        or int(value["commitment_blind"], 16) == 0
        or not isinstance(value["consensus_allocation_id"], str)
        or not CONSENSUS_ALLOCATION_RE.fullmatch(value["consensus_allocation_id"])
        or int(value["consensus_allocation_id"], 16) == 0
        or type(value["admitted_at"]) is not int
        or value["admitted_at"] < 0
        or type(value["expires_at"]) is not int
        or value["expires_at"] - value["admitted_at"] != 7 * 24 * 60 * 60
        or not isinstance(value["capacity_policy_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["capacity_policy_sha256"])
    ):
        raise ValueError("C1 allocation claim is malformed")
    return dict(value)


def decode_c1_reservation(unsigned_tx_hex, issuer, issuer_script_hex):
    run = run_bounded_subprocess(
        [KEYGEN, "decode-c1-reservation", issuer_script_hex, unsigned_tx_hex],
        input_text="",
        timeout=30,
        stdout_max=MAX_CHILD_OUTPUT_BYTES,
        stderr_max=1024 * 1024,
        description="decode-c1-reservation",
    )
    if run.returncode != 0:
        raise ValueError("C1 carrier policy: " + (run.stderr.strip()[:200] or "decoder refused"))
    decoded = strict_json_loads(run.stdout, "decode-c1-reservation response")
    required = {
        "action",
        "from",
        "to",
        "sats",
        "allocation_id",
        "allocation_commitment",
        "fund_script_pubkey_hex",
        "fund_commitment_blind_hex",
        "fund_outpoint",
        "funding_proof_hex",
        "total_out_sats",
        "num_inputs",
    }
    if (
        not isinstance(decoded, dict)
        or set(decoded) != required
        or decoded.get("action") not in ("RESERVE", "EXPOSE", "CANCEL", "FUND")
        or decoded.get("from") != issuer
        or type(decoded.get("sats")) is not int
        or type(decoded.get("total_out_sats")) is not int
        or type(decoded.get("num_inputs")) is not int
        or decoded["num_inputs"] < 1
    ):
        raise ValueError("decoded C1 carrier is malformed")
    fund_fields = (
        "fund_script_pubkey_hex",
        "fund_commitment_blind_hex",
        "fund_outpoint",
        "funding_proof_hex",
    )
    if (
        decoded["action"] == "FUND"
        and any(not isinstance(decoded.get(field), str) for field in fund_fields)
    ) or (
        decoded["action"] != "FUND" and any(decoded.get(field) is not None for field in fund_fields)
    ):
        raise ValueError("decoded C1 funding fields are phase-incoherent")
    return decoded


def verify_c1_allocation_witness(cfg, allocation):
    policy = cfg.get("c1_reservation_authority")
    if (
        not isinstance(policy, dict)
        or set(policy) != {"enabled", "allocation_witness_command", "durable_archive_command"}
        or policy.get("enabled") is not True
    ):
        raise ValueError("c1_reservation_authority is not explicitly enabled")
    command = policy["allocation_witness_command"]
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part or "\x00" in part for part in command)
        or not os.path.isabs(command[0])
    ):
        raise ValueError("C1 allocation witness command is not an absolute argv")
    _c1_archive_command(cfg)
    fields = {
        key: allocation[key]
        for key in (
            "request_id",
            "principal_hash",
            "veld_address",
            "amount_sats",
            "descriptor_index",
            "btc_address",
            "script_pubkey",
            "admitted_at",
            "expires_at",
            "commitment_blind",
            "consensus_allocation_id",
        )
    }
    request = json.dumps(
        {
            "version": 4,
            "action": "verify_allocation",
            "capacity_policy_sha256": allocation["capacity_policy_sha256"],
            "allocation": fields,
        },
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    completed = run_bounded_subprocess(
        list(command),
        input_text=request,
        timeout=45,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="independent C1 allocation witness",
    )
    if completed.returncode != 0:
        raise ValueError("C1 allocation witness refused: " + completed.stderr.strip()[:200])
    answer = strict_json_loads(completed.stdout, "C1 allocation witness response")
    required_answer = {
        "version",
        "action",
        "request_id",
        "descriptor_index",
        "authorized",
        "idempotent",
        "capacity_policy_sha256",
        "expires_at",
        "commitment_blind",
        "consensus_allocation_id",
        "deposit_observed_at",
        "funded_reserved_at",
        "minted_at",
    }
    if (
        not isinstance(answer, dict)
        or set(answer) != required_answer
        or answer.get("version") != 4
        or answer.get("action") != "verify_allocation"
        or answer.get("request_id") != allocation["request_id"]
        or answer.get("descriptor_index") != allocation["descriptor_index"]
        or answer.get("commitment_blind") != allocation["commitment_blind"]
        or answer.get("consensus_allocation_id") != allocation["consensus_allocation_id"]
        or answer.get("authorized") is not True
        or answer.get("idempotent") is not True
        or answer.get("capacity_policy_sha256") != allocation["capacity_policy_sha256"]
        or answer.get("expires_at") != allocation["expires_at"]
        or (
            answer.get("deposit_observed_at") is not None
            and type(answer.get("deposit_observed_at")) is not int
        )
        or (
            answer.get("funded_reserved_at") is not None
            and type(answer.get("funded_reserved_at")) is not int
        )
        or (answer.get("minted_at") is not None and type(answer.get("minted_at")) is not int)
    ):
        raise ValueError("C1 allocation witness acknowledgement is not exact")
    return answer


def validate_c1_signing_boundary(rpc, issuer, allocation, phase, funding=None, retry_txid=None):
    completion = phase in ("CANCEL", "FUND")
    peg_before = validate_compiled_mint_policy(rpc, issuer, completion=completion)
    allocation_id = allocation["consensus_allocation_id"]
    status = rpc.call("getbtcveldc1reservation", [allocation_id])
    peg_after = validate_compiled_mint_policy(rpc, issuer, completion=completion)
    fields = (
        "tip",
        "supply_sats",
        "issuer_effective_custody_cap_sats",
        "issuer_reserved_sats",
        "issuer_mint_headroom_sats",
    )
    if any(peg_before.get(field) != peg_after.get(field) for field in fields):
        raise ValueError("C1 capacity changed during signer boundary")
    if (
        not isinstance(status, dict)
        or status.get("allocation_id") != allocation_id
        or type(status.get("found")) is not bool
        or type(status.get("retired")) is not bool
        or type(status.get("last_sequence")) is not int
        or type(status.get("sequence_history_count")) is not int
        or not 0 <= status.get("last_sequence", -1) <= (1 << 64) - 1
        or not 0 <= status.get("sequence_history_count", -1) <= (1 << 64) - 1
        or status["sequence_history_count"] != status["last_sequence"]
    ):
        raise ValueError("C1 reservation status is malformed")
    if (
        type(status.get("tip")) is not int
        or status["tip"] < 0
        or type(peg_before.get("tip")) is not int
        or status["tip"] != peg_before["tip"]
        or status["tip"] != peg_after.get("tip")
    ):
        raise ValueError("C1 reservation tip differs from both capacity snapshots")
    found = status.get("found") is True
    if found and int(allocation_id, 16) > status["last_sequence"]:
        raise ValueError("C1 found sequence exceeds the canonical high-water")
    if found and (
        status.get("recipient") != allocation["veld_address"]
        or status.get("amount_sats") != allocation["amount_sats"]
        or status.get("allocation_commitment")
        != allocation_commitment(
            allocation_id,
            allocation["veld_address"],
            allocation["amount_sats"],
            allocation["script_pubkey"],
            allocation["commitment_blind"],
        )
    ):
        raise ValueError("C1 reservation status differs from allocation")
    if phase == "RESERVE":
        if found:
            if retry_txid is None:
                raise ValueError("C1 request id already exists")
        else:
            if status["retired"] or int(allocation_id, 16) != status["last_sequence"] + 1:
                raise ValueError("C1 reserve sequence is not exactly next")
            headroom = peg_before.get("issuer_mint_headroom_sats")
            if type(headroom) is not int or headroom < allocation["amount_sats"]:
                raise ValueError("C1 reservation exceeds fresh issuer headroom")
    elif phase == "EXPOSE":
        if (
            not found
            or status.get("active") is not True
            or (status.get("exposed") is True and retry_txid is None)
            or (
                status.get("exposed") is not True
                and (
                    status.get("reserve_canonical_depth_reached") is not True
                    or type(status.get("reserve_confirmations")) is not int
                    or status["reserve_confirmations"] < C1_FINALITY_DEPTH
                )
            )
        ):
            raise ValueError("C1R1 is not an exact canonical exposure authority")
    elif phase == "CANCEL":
        if found or status["retired"] or int(allocation_id, 16) != status["last_sequence"] + 1:
            raise ValueError("C1 cancellation is not the exact next missing sequence")
    elif phase == "FUND":
        if (
            not isinstance(funding, dict)
            or set(funding) != {"outpoint", "proof_hex", "proof_parent_root", "proof_parent_count"}
            or not BTC_OUTPOINT_RE.fullmatch(str(funding.get("outpoint", "")))
            or not isinstance(funding.get("proof_hex"), str)
            or not re.fullmatch(r"[0-9a-f]+", funding["proof_hex"])
            or not isinstance(funding.get("proof_parent_root"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", funding["proof_parent_root"])
            or type(funding.get("proof_parent_count")) is not int
            or funding["proof_parent_count"] < 0
        ):
            raise ValueError("C1 funding boundary object is malformed")
        if (
            not found
            or status.get("active") is not True
            or status.get("exposed") is not True
            or status.get("exposure_canonical_depth_reached") is not True
        ):
            raise ValueError("C1 funding lacks a deep exposed reservation")
        if status.get("funded") is True:
            if retry_txid is None or status.get("funding_outpoint") != funding["outpoint"]:
                raise ValueError("C1 reservation is already funded differently")
            mint_status = rpc.call("getbtcveldmintstatus", [funding["outpoint"]])
            if (
                not isinstance(mint_status, dict)
                or mint_status.get("tip") != status["tip"]
                or mint_status.get("consumed") is not True
                or mint_status.get("minted") is not False
                or mint_status.get("accepted_effect_kind") != "C1_FUND"
                or mint_status.get("c1_allocation_id") != allocation_id
                or mint_status.get("consumer_txid") != retry_txid
            ):
                raise ValueError("cached C1F1 does not match the canonical consumer")
            return status
        if type(status.get("tip")) is not int or status["tip"] < 0:
            raise ValueError("C1 funding tip is malformed")
        target_height = status["tip"] + 1
        if (
            type(status.get("funding_starts_height")) is not int
            or type(status.get("funding_accepts_through_height")) is not int
            or target_height < status["funding_starts_height"]
            or target_height > status["funding_accepts_through_height"]
        ):
            raise ValueError("C1F1 target is outside the consensus funding window")
        mint_status = rpc.call("getbtcveldmintstatus", [funding["outpoint"]])
        if (
            not isinstance(mint_status, dict)
            or mint_status.get("outpoint") != funding["outpoint"]
            or mint_status.get("tip") != status["tip"]
            or mint_status.get("consumed") is not False
            or mint_status.get("minted") is not False
            or mint_status.get("root") != funding["proof_parent_root"]
            or mint_status.get("count") != funding["proof_parent_count"]
            or not isinstance(mint_status.get("proof_hex"), str)
            or not funding["proof_hex"].endswith(mint_status["proof_hex"])
        ):
            raise ValueError("C1F1 proof parent changed at signer boundary")
    else:
        raise ValueError("unknown C1 signing phase")
    return status


C1_CACHE_KEY_RE = re.compile(
    r"^(0{16}[0-9a-f]{16}):(RESERVE|EXPOSE|CANCEL|FUND)(?::([0-9a-f]{64}))?$"
)


def _empty_c1_signer_state():
    return {
        "version": 3,
        "records": {},
        "terminal_observations": {},
        "tombstones": {},
        "compaction_cursor": None,
    }


def _c1_stage_metadata_valid(key, record):
    match = C1_CACHE_KEY_RE.fullmatch(str(key))
    if match is None or (match.group(2) == "FUND") != (match.group(3) is not None):
        return False
    if (
        not re.fullmatch(r"[0-9a-f]{64}", str(record.get("allocation_sha256")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("unsigned_sha256")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("txid")))
        or type(record.get("signed_at")) is not int
        or record["signed_at"] < 0
        or (
            (match.group(2) == "FUND")
            != (
                isinstance(record.get("funding_sha256"), str)
                and isinstance(record.get("semantic_sha256"), str)
            )
        )
        or (
            record.get("funding_sha256") is not None
            and (
                not re.fullmatch(r"[0-9a-f]{64}", record["funding_sha256"])
                or record["funding_sha256"] != match.group(3)
            )
        )
        or (
            record.get("semantic_sha256") is not None
            and not re.fullmatch(r"[0-9a-f]{64}", record["semantic_sha256"])
        )
    ):
        return False
    return True


def _validate_c1_cache_record(key, record):
    if not isinstance(record, dict) or not _c1_stage_metadata_valid(key, record):
        raise ValueError("C1 signer cache record is invalid")
    common = {
        "kind",
        "allocation_sha256",
        "unsigned_sha256",
        "txid",
        "signed_at",
        "funding_sha256",
        "semantic_sha256",
    }
    with_inputs = common | {"input_outpoints"}
    if "input_outpoints" in record and (
        not isinstance(record["input_outpoints"], list)
        or not record["input_outpoints"]
        or len(record["input_outpoints"]) > 10_000
        or len(set(record["input_outpoints"])) != len(record["input_outpoints"])
        or any(
            not BTC_OUTPOINT_RE.fullmatch(str(outpoint))
            or int(str(outpoint).rsplit(":", 1)[1]) > 0xFFFFFFFF
            for outpoint in record["input_outpoints"]
        )
    ):
        raise ValueError("C1 signer cache input outpoints are invalid")
    if record.get("kind") == "raw":
        if set(record) != with_inputs | {"signed_tx_hex"}:
            raise ValueError("C1 raw signer cache record is invalid")
        signed_hex = record["signed_tx_hex"]
        if (
            not isinstance(signed_hex, str)
            or not re.fullmatch(r"[0-9a-f]+", signed_hex)
            or hashlib.sha256(hashlib.sha256(bytes.fromhex(signed_hex)).digest()).hexdigest()
            != record["txid"]
        ):
            raise ValueError("C1 raw signer cache bytes are invalid")
        return
    durable = with_inputs | {
        "signed_tx_sha256",
        "archive_record_sha256",
        "archive_id",
        "archived_at",
        "coordinator_sequence",
        "coordinator_state_sha256",
    }
    legacy_durable = durable - {"input_outpoints"}
    if (
        record.get("kind") != "durable"
        or set(record) not in (durable, legacy_durable)
        or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("signed_tx_sha256")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("archive_record_sha256")))
        or not isinstance(record.get("archive_id"), str)
        or not 1 <= len(record["archive_id"]) <= 256
        or type(record.get("archived_at")) is not int
        or record["archived_at"] < 0
        or type(record.get("coordinator_sequence")) is not int
        or record["coordinator_sequence"] <= 0
        or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("coordinator_state_sha256")))
    ):
        raise ValueError("C1 durable signer tombstone is invalid")


def load_c1_signer_state():
    if not os.path.lexists(C1_STATEF):
        raise FileNotFoundError("C1 signer authority state is missing; never auto-initialize")
    state = strict_json_loads(
        _secure_text(C1_STATEF, private=True, max_bytes=C1_STATE_MAX_BYTES), "C1 signer state"
    )
    migrated_on_read = False
    # One-way in-memory migration. The next successful mutation durably writes
    # v3; no signature bytes are discarded by migration itself.
    if (
        isinstance(state, dict)
        and set(state) == {"version", "records"}
        and state.get("version") == 2
        and isinstance(state.get("records"), dict)
    ):
        migrated = _empty_c1_signer_state()
        for key, record in state["records"].items():
            if not isinstance(record, dict):
                raise ValueError("C1 signer v2 cache record is invalid")
            signed_hex = record.get("signed_tx_hex")
            unsigned = sol.unsigned_template_from_signed_hex(signed_hex)
            migrated["records"][key] = {
                "kind": "raw",
                **record,
                "input_outpoints": _unsigned_input_outpoints(unsigned),
            }
        state = migrated
        migrated_on_read = True
    if (
        isinstance(state, dict)
        and state.get("version") == 3
        and set(state) == {"version", "records", "terminal_observations", "tombstones"}
    ):
        state["compaction_cursor"] = None
        migrated_on_read = True
    if (
        not isinstance(state, dict)
        or set(state)
        != {"version", "records", "terminal_observations", "tombstones", "compaction_cursor"}
        or state.get("version") != 3
        or not isinstance(state.get("records"), dict)
        or not isinstance(state.get("terminal_observations"), dict)
        or not isinstance(state.get("tombstones"), dict)
        or (
            state.get("compaction_cursor") is not None
            and not CONSENSUS_ALLOCATION_RE.fullmatch(str(state.get("compaction_cursor")))
        )
        or len(state["records"]) > C1_MAX_CACHE_ROWS
        or len(state["terminal_observations"]) > 10_000
        or len(state["tombstones"]) > 10_000
    ):
        raise ValueError("C1 signer state schema is invalid")
    for record in state["records"].values():
        if record.get("kind") == "raw" and "input_outpoints" not in record:
            unsigned = sol.unsigned_template_from_signed_hex(record.get("signed_tx_hex"))
            record["input_outpoints"] = _unsigned_input_outpoints(unsigned)
            migrated_on_read = True
    for key, record in state["records"].items():
        _validate_c1_cache_record(key, record)
    for allocation_id, observed_tip in state["terminal_observations"].items():
        if (
            not CONSENSUS_ALLOCATION_RE.fullmatch(str(allocation_id))
            or type(observed_tip) is not int
            or observed_tip < 0
        ):
            raise ValueError("C1 terminal observation is invalid")
    for allocation_id, tombstone in state["tombstones"].items():
        if (
            not CONSENSUS_ALLOCATION_RE.fullmatch(str(allocation_id))
            or not isinstance(tombstone, dict)
            or set(tombstone)
            != {"allocation_sha256", "terminal_tip", "bundle_sha256", "archive_id", "archived_at"}
            or not re.fullmatch(r"[0-9a-f]{64}", str(tombstone.get("allocation_sha256")))
            or type(tombstone.get("terminal_tip")) is not int
            or tombstone["terminal_tip"] < 0
            or not re.fullmatch(r"[0-9a-f]{64}", str(tombstone.get("bundle_sha256")))
            or not isinstance(tombstone.get("archive_id"), str)
            or not 1 <= len(tombstone["archive_id"]) <= 256
            or type(tombstone.get("archived_at")) is not int
            or tombstone["archived_at"] < 0
        ):
            raise ValueError("C1 terminal signer tombstone is invalid")
    if migrated_on_read:
        save_c1_signer_state(state)
    return state


def save_c1_signer_state(state):
    # Validate a serialized round-trip before replacement so the writer can
    # never create a file the symmetric reader will reject on restart.
    raw = (json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
        "utf-8"
    )
    if len(raw) > C1_STATE_MAX_BYTES:
        raise ValueError("C1 signer state exceeds the symmetric byte ceiling")
    return save_signer_state_durable(state, C1_STATEF, max_bytes=C1_STATE_MAX_BYTES)


def c1_signer_state_size(state):
    return len(
        (json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode(
            "utf-8"
        )
    )


def require_c1_signer_lifecycle_capacity(state, reserve_bytes=None):
    if reserve_bytes is None:
        reserve_bytes = 2 * C1_MAX_SIGNED_TX_BYTES + 2048
    if (
        type(reserve_bytes) is not int
        or reserve_bytes < 0
        or c1_signer_state_size(state) + reserve_bytes > C1_STATE_RESERVE_BYTES
    ):
        raise ValueError("C1 signer lifecycle admission reserve is exhausted")


def _c1_archive_command(cfg):
    policy = cfg.get("c1_reservation_authority")
    command = policy.get("durable_archive_command") if isinstance(policy, dict) else None
    if (
        not isinstance(command, list)
        or not command
        or any(not isinstance(part, str) or not part or "\x00" in part for part in command)
        or not os.path.isabs(command[0])
    ):
        raise ValueError("C1 durable archive command is not absolute argv")
    _secure_regular(command[0], executable=True)
    return list(command)


def _archive_c1_payload(cfg, allocation_id, action, payload):
    archived_at = int(time.time())
    record_sha256 = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    ).hexdigest()
    request = {
        "version": 1,
        "action": action,
        "allocation_id": allocation_id,
        "archived_at": archived_at,
        "record_sha256": record_sha256,
        "record": payload,
    }
    completed = run_bounded_subprocess(
        _c1_archive_command(cfg),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False),
        timeout=120,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="C1 signer COMPLIANCE archive",
    )
    if completed.returncode != 0:
        raise RuntimeError("C1 signer archive refused: " + completed.stderr.strip()[:240])
    answer = strict_json_loads(completed.stdout, "C1 signer archive acknowledgement")
    required = {
        "version",
        "archived",
        "allocation_id",
        "record_sha256",
        "readback_sha256",
        "archive_id",
        "object_lock_mode",
        "retention_until",
    }
    if (
        not isinstance(answer, dict)
        or set(answer) != required
        or answer.get("version") != 1
        or answer.get("archived") is not True
        or answer.get("allocation_id") != allocation_id
        or answer.get("record_sha256") != record_sha256
        or answer.get("readback_sha256") != record_sha256
        or answer.get("object_lock_mode") != "COMPLIANCE"
        or type(answer.get("retention_until")) is not int
        or answer["retention_until"] < archived_at + C1_ARCHIVE_RETENTION_SECONDS
        or not isinstance(answer.get("archive_id"), str)
        or not 1 <= len(answer["archive_id"]) <= 256
    ):
        raise RuntimeError("C1 signer archive acknowledgement is not exact/durable")
    return record_sha256, answer["archive_id"], archived_at


def _read_archived_c1_cache_record(cfg, allocation_id, key, durable):
    request = {
        "version": 1,
        "action": "read_c1_signer_record",
        "allocation_id": allocation_id,
        "archive_id": durable["archive_id"],
        "record_sha256": durable["archive_record_sha256"],
    }
    completed = run_bounded_subprocess(
        _c1_archive_command(cfg),
        input_text=json.dumps(request, sort_keys=True, separators=(",", ":"), allow_nan=False),
        timeout=120,
        stdout_max=8 * 1024 * 1024,
        stderr_max=64 * 1024,
        description="C1 signer COMPLIANCE archive readback",
    )
    if completed.returncode != 0:
        raise RuntimeError("C1 signer archive readback refused: " + completed.stderr.strip()[:240])
    answer = strict_json_loads(completed.stdout, "C1 signer archive readback response")
    expected = {"version", "found", "allocation_id", "archive_id", "record_sha256", "record"}
    if (
        not isinstance(answer, dict)
        or set(answer) != expected
        or answer.get("version") != 1
        or answer.get("found") is not True
        or answer.get("allocation_id") != allocation_id
        or answer.get("archive_id") != durable["archive_id"]
        or answer.get("record_sha256") != durable["archive_record_sha256"]
        or not isinstance(answer.get("record"), dict)
        or hashlib.sha256(
            json.dumps(
                answer["record"], sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
        ).hexdigest()
        != durable["archive_record_sha256"]
    ):
        raise RuntimeError("C1 signer archive readback is not exact")
    payload = answer["record"]
    if (
        set(payload) != {"cache_key", "cache_record", "coordinator_receipt"}
        or payload.get("cache_key") != key
        or not isinstance(payload.get("cache_record"), dict)
    ):
        raise RuntimeError("C1 signer archived cache payload is malformed")
    raw = dict(payload["cache_record"])
    if raw.get("kind") != "raw" or "signed_tx_hex" not in raw:
        raise RuntimeError("C1 signer archive lacks raw signed bytes")
    if "input_outpoints" not in raw:
        unsigned = sol.unsigned_template_from_signed_hex(raw["signed_tx_hex"])
        raw["input_outpoints"] = _unsigned_input_outpoints(unsigned)
    _validate_c1_cache_record(key, raw)
    if (
        raw["allocation_sha256"] != durable["allocation_sha256"]
        or raw["unsigned_sha256"] != durable["unsigned_sha256"]
        or raw["txid"] != durable["txid"]
    ):
        raise RuntimeError("C1 archived raw record differs from durable cache")
    return raw


def _c1_receipt_key(receipt):
    phase = receipt["phase"]
    key = receipt["allocation_id"] + ":" + phase
    if phase == "FUND":
        key += ":" + receipt["funding_sha256"]
    return key


def acknowledge_c1_signature_durable(req, cfg):
    required = {
        "version",
        "action",
        "allocation_id",
        "phase",
        "funding_sha256",
        "allocation_sha256",
        "unsigned_sha256",
        "signed_tx_sha256",
        "txid",
        "coordinator_sequence",
        "coordinator_state_sha256",
    }
    if (
        not isinstance(req, dict)
        or set(req) != required
        or req.get("version") != 1
        or req.get("action") != "ack_c1_signature_durable"
        or not CONSENSUS_ALLOCATION_RE.fullmatch(str(req.get("allocation_id", "")))
        or req.get("phase") not in ("RESERVE", "EXPOSE", "CANCEL", "FUND")
        or ((req.get("phase") == "FUND") != isinstance(req.get("funding_sha256"), str))
        or (
            req.get("funding_sha256") is not None
            and not re.fullmatch(r"[0-9a-f]{64}", req["funding_sha256"])
        )
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(req.get(field, "")))
            for field in (
                "allocation_sha256",
                "unsigned_sha256",
                "signed_tx_sha256",
                "txid",
                "coordinator_state_sha256",
            )
        )
        or type(req.get("coordinator_sequence")) is not int
        or req["coordinator_sequence"] <= 0
    ):
        raise ValueError("C1 durable receipt schema is not canonical")
    state = load_c1_signer_state()
    key = _c1_receipt_key(req)
    record = state["records"].get(key)
    if record is None:
        raise ValueError("C1 durable receipt has no exact local signature")
    if (
        record["allocation_sha256"] != req["allocation_sha256"]
        or record["unsigned_sha256"] != req["unsigned_sha256"]
        or record["txid"] != req["txid"]
    ):
        raise ValueError("C1 durable receipt differs from local signature")
    if record["kind"] == "durable":
        if (
            record["signed_tx_sha256"] != req["signed_tx_sha256"]
            or record["coordinator_sequence"] != req["coordinator_sequence"]
            or record["coordinator_state_sha256"] != req["coordinator_state_sha256"]
        ):
            raise ValueError("C1 durable receipt replay changed")
        return {
            "version": 1,
            "action": "c1_signature_durable",
            "allocation_id": req["allocation_id"],
            "phase": req["phase"],
            "funding_sha256": req["funding_sha256"],
            "record_sha256": record["archive_record_sha256"],
            "archive_id": record["archive_id"],
            "idempotent": True,
        }
    signed_tx_sha256 = hashlib.sha256(bytes.fromhex(record["signed_tx_hex"])).hexdigest()
    if signed_tx_sha256 != req["signed_tx_sha256"]:
        raise ValueError("C1 durable receipt signed-byte hash differs")
    payload = {"cache_key": key, "cache_record": record, "coordinator_receipt": req}
    record_sha256, archive_id, archived_at = _archive_c1_payload(
        cfg, req["allocation_id"], "archive_c1_signer_record", payload
    )
    state["records"][key] = {
        "kind": "durable",
        "allocation_sha256": record["allocation_sha256"],
        "unsigned_sha256": record["unsigned_sha256"],
        "signed_tx_sha256": signed_tx_sha256,
        "txid": record["txid"],
        "signed_at": record["signed_at"],
        "funding_sha256": record["funding_sha256"],
        "semantic_sha256": record["semantic_sha256"],
        "input_outpoints": record["input_outpoints"],
        "archive_record_sha256": record_sha256,
        "archive_id": archive_id,
        "archived_at": archived_at,
        "coordinator_sequence": req["coordinator_sequence"],
        "coordinator_state_sha256": req["coordinator_state_sha256"],
    }
    save_c1_signer_state(state)
    return {
        "version": 1,
        "action": "c1_signature_durable",
        "allocation_id": req["allocation_id"],
        "phase": req["phase"],
        "funding_sha256": req["funding_sha256"],
        "record_sha256": record_sha256,
        "archive_id": archive_id,
        "idempotent": False,
    }


def compact_c1_signer_state(rpc, cfg, state, scan_limit=1):
    """Compact stable terminal allocations without ever dropping sole bytes.

    Raw carriers are ineligible. Durable stage tombstones already name an exact
    COMPLIANCE object, and the aggregate terminal archive binds that complete
    set before local rows are removed. Consensus remains the lifetime replay
    authority, avoiding one local tombstone per historic range index.
    """
    if type(scan_limit) is not int or scan_limit <= 0:
        raise ValueError("C1 signer compaction scan limit is invalid")
    legacy_cleared = bool(state["tombstones"])
    if legacy_cleared:
        # Every legacy tombstone contains the exact COMPLIANCE archive id and
        # digest that authorized its original compaction. Consensus is the
        # lifetime replay authority; retaining these rows would reintroduce a
        # fixed lifetime ceiling after a signed range expansion.
        state["tombstones"].clear()
    allocation_ids = sorted({key.split(":", 1)[0] for key in state["records"]})
    if not allocation_ids:
        if state["compaction_cursor"] is not None or legacy_cleared:
            state["compaction_cursor"] = None
            save_c1_signer_state(state)
        return 0
    cursor = state["compaction_cursor"]
    start = 0
    if cursor is not None:
        while start < len(allocation_ids) and allocation_ids[start] <= cursor:
            start += 1
        if start == len(allocation_ids):
            start = 0
    selected = []
    for offset in range(min(scan_limit, len(allocation_ids))):
        selected.append(allocation_ids[(start + offset) % len(allocation_ids)])
    state["compaction_cursor"] = selected[-1]
    changed = True
    compacted = 0
    for allocation_id in selected:
        status = rpc.call("getbtcveldc1reservation", [allocation_id])
        if (
            not isinstance(status, dict)
            or status.get("allocation_id") != allocation_id
            or type(status.get("retired")) is not bool
            or type(status.get("tip")) is not int
            or status["tip"] < 0
        ):
            raise ValueError("C1 signer compaction status is malformed")
        observed = state["terminal_observations"].get(allocation_id)
        if status["retired"] is not True:
            if observed is not None:
                del state["terminal_observations"][allocation_id]
            continue
        if observed is None or status["tip"] < observed:
            state["terminal_observations"][allocation_id] = status["tip"]
            continue
        if status["tip"] - observed + 1 <= MAX_REORG_DEPTH:
            continue
        keys = sorted(key for key in state["records"] if key.startswith(allocation_id + ":"))
        records = {key: state["records"][key] for key in keys}
        if not records or any(record["kind"] != "durable" for record in records.values()):
            # A coordinator receipt has not yet made every raw carrier
            # externally replayable. Keep every byte and try again later.
            continue
        allocation_hashes = {record["allocation_sha256"] for record in records.values()}
        if len(allocation_hashes) != 1:
            raise ValueError("terminal C1 signer records disagree on allocation")
        payload = {
            "allocation_id": allocation_id,
            "terminal_observed_tip": observed,
            "terminal_tip": status["tip"],
            "records": records,
        }
        _bundle_sha256, _archive_id, _archived_at = _archive_c1_payload(
            cfg, allocation_id, "archive_c1_signer_terminal", payload
        )
        for key in keys:
            del state["records"][key]
        del state["terminal_observations"][allocation_id]
        compacted += 1
    if changed:
        save_c1_signer_state(state)
    return compacted


def _upgrade_prevout_journal_v1(legacy):
    if (
        not isinstance(legacy, dict)
        or set(legacy) != {"version", "owners", "terminal_observations", "scan_cursor"}
        or legacy.get("version") != 1
        or not isinstance(legacy.get("owners"), dict)
        or not isinstance(legacy.get("terminal_observations"), dict)
    ):
        raise ValueError("legacy issuer prevout journal is malformed")
    upgraded = _empty_prevout_journal()
    upgraded["terminal_observations"] = legacy["terminal_observations"]
    upgraded["scan_cursor"] = legacy.get("scan_cursor")
    for owner_id, owner in legacy["owners"].items():
        capability, allocation_id = _parse_prevout_owner_id(owner_id)
        if (
            not isinstance(owner, dict)
            or set(owner)
            != {
                "capability",
                "allocation_id",
                "deposit_outpoint",
                "active",
                "revoked_unsigned_sha256",
            }
            or owner.get("capability") != capability
            or owner.get("allocation_id") != allocation_id
        ):
            raise ValueError("legacy issuer prevout owner is malformed")
        converted = dict(owner)
        converted["revoked_conflicting_input_outpoints"] = {
            unsigned_hash: [] for unsigned_hash in owner["revoked_unsigned_sha256"]
        }
        if owner["active"] is not None:
            active = owner["active"]
            if not isinstance(active, dict) or set(active) != {
                "unsigned_sha256",
                "input_outpoints",
                "txid",
                "created_at",
            }:
                raise ValueError("legacy issuer prevout lease is malformed")
            active = dict(active)
            active["signing_state"] = "SIGNED" if active["txid"] is not None else "SIGNING"
            active["staging_id"] = hashlib.sha256(
                (owner_id + "\x00" + active["unsigned_sha256"]).encode("utf-8")
            ).hexdigest()
            converted["active"] = active
        upgraded["owners"][owner_id] = converted
    return _validate_prevout_journal(upgraded)


def _upgrade_prevout_journal_v2(legacy):
    if (
        not isinstance(legacy, dict)
        or set(legacy) != {"version", "owners", "terminal_observations", "scan_cursor"}
        or legacy.get("version") != 2
    ):
        raise ValueError("v2 issuer prevout journal is malformed")
    upgraded = dict(legacy)
    upgraded["version"] = PREVOUT_JOURNAL_VERSION
    upgraded["cleanup_staging_ids"] = []
    upgraded["owners"] = {
        owner_id: dict(
            owner,
            revoked_conflicting_input_outpoints={
                unsigned_hash: [] for unsigned_hash in owner.get("revoked_unsigned_sha256", [])
            },
        )
        for owner_id, owner in legacy["owners"].items()
    }
    return _validate_prevout_journal(upgraded)


def _upgrade_prevout_journal_v3(legacy):
    if (
        not isinstance(legacy, dict)
        or set(legacy)
        != {"version", "owners", "terminal_observations", "scan_cursor", "cleanup_staging_ids"}
        or legacy.get("version") != 3
    ):
        raise ValueError("v3 issuer prevout journal is malformed")
    upgraded = dict(legacy)
    upgraded["version"] = PREVOUT_JOURNAL_VERSION
    upgraded["owners"] = {
        owner_id: dict(
            owner,
            revoked_conflicting_input_outpoints={
                unsigned_hash: [] for unsigned_hash in owner.get("revoked_unsigned_sha256", [])
            },
        )
        for owner_id, owner in legacy["owners"].items()
    }
    return _validate_prevout_journal(upgraded)


def _merge_reconciled_signed_lease(
    state,
    owner_id,
    capability,
    allocation_id,
    deposit_outpoint,
    unsigned_sha256,
    input_outpoints,
    txid,
    occupied=None,
):
    owner = _bind_prevout_owner(state, owner_id, capability, allocation_id, deposit_outpoint)
    if (
        not re.fullmatch(r"[0-9a-f]{64}", str(unsigned_sha256))
        or not isinstance(input_outpoints, list)
        or not input_outpoints
        or not re.fullmatch(r"[0-9a-f]{64}", str(txid))
    ):
        raise ValueError("reconciled issuer signature metadata is malformed")
    if occupied is None:
        occupied = {}
        for other_id, other in state["owners"].items():
            if other["active"] is None:
                continue
            for outpoint in other["active"]["input_outpoints"]:
                occupied[outpoint] = other_id
    conflict = next(
        (
            occupied[outpoint]
            for outpoint in input_outpoints
            if outpoint in occupied and occupied[outpoint] != owner_id
        ),
        None,
    )
    if conflict is not None:
        raise ValueError(
            "existing signed issuer carriers overlap fee inputs: %s / %s" % (conflict, owner_id)
        )
    active = owner["active"]
    if active is not None:
        if (
            active["unsigned_sha256"] != unsigned_sha256
            or active["input_outpoints"] != input_outpoints
            or active["txid"] not in (None, txid)
        ):
            raise ValueError("issuer prevout journal differs from signed cache")
        active["txid"] = txid
        active["signing_state"] = "SIGNED"
        for outpoint in input_outpoints:
            occupied[outpoint] = owner_id
        return
    owner["active"] = {
        "unsigned_sha256": unsigned_sha256,
        "input_outpoints": list(input_outpoints),
        "txid": txid,
        "created_at": int(time.time()),
        "signing_state": "SIGNED",
        "staging_id": hashlib.sha256(
            (owner_id + "\x00" + unsigned_sha256).encode("utf-8")
        ).hexdigest(),
    }
    for outpoint in input_outpoints:
        occupied[outpoint] = owner_id


def _reject_orphan_signing_stages(state):
    if not os.path.lexists(SIGNING_STAGE_DIR):
        return
    _ensure_signing_stage_directory()
    referenced = {
        owner["active"]["staging_id"]
        for owner in state["owners"].values()
        if owner["active"] is not None
    }
    referenced.update(state["cleanup_staging_ids"])
    for name in os.listdir(SIGNING_STAGE_DIR):
        match = re.fullmatch(
            r"([0-9a-f]{64})\.(?:prepared\.json(?:\.(?:intent|transaction)\.json)?|signed)", name
        )
        if match is None or match.group(1) not in referenced:
            raise ValueError("orphan/unknown issuer signing stage requires review")


def _cleanup_reconciled_signed_stages(state, confirmed_staging_ids):
    """Delete crash staging only when a current primary cache proves custody.

    A surviving SIGNED journal lease is not proof that the mint/C1 primary
    cache survived the same restore.  Keeping an unconfirmed stage is harmless;
    deleting it could destroy the only exact randomized signed bytes while the
    journal correctly prevents a second signature.
    """
    if not isinstance(confirmed_staging_ids, set) or any(
        not re.fullmatch(r"[0-9a-f]{64}", str(staging_id)) for staging_id in confirmed_staging_ids
    ):
        raise ValueError("reconciled signing-stage authority is malformed")
    if not os.path.lexists(SIGNING_STAGE_DIR):
        return 0
    _ensure_signing_stage_directory()
    signed_ids = {
        owner["active"]["staging_id"]
        for owner in state["owners"].values()
        if owner["active"] is not None
        and owner["active"]["signing_state"] == "SIGNED"
        and owner["active"]["staging_id"] in confirmed_staging_ids
    }
    present_ids = set()
    for name in os.listdir(SIGNING_STAGE_DIR):
        match = re.fullmatch(
            r"([0-9a-f]{64})\.(?:prepared\.json(?:\.(?:intent|transaction)\.json)?|signed)", name
        )
        if match:
            present_ids.add(match.group(1))
    for staging_id in sorted(signed_ids.intersection(present_ids)):
        cleanup_signing_stage(staging_id)
    return len(signed_ids.intersection(present_ids))


def load_or_reconcile_prevout_journal(cfg, issuer, issuer_script_hex):
    """Restore the lease union from every durable signer authority on startup."""
    existed = os.path.lexists(PREVOUT_STATEF)
    needs_save = not existed
    if existed:
        raw = strict_json_loads(
            _secure_text(PREVOUT_STATEF, private=True, max_bytes=PREVOUT_JOURNAL_MAX_BYTES),
            "issuer prevout journal",
        )
        if isinstance(raw, dict) and raw.get("version") == 1:
            state = _upgrade_prevout_journal_v1(raw)
            needs_save = True
        elif isinstance(raw, dict) and raw.get("version") == 2:
            state = _upgrade_prevout_journal_v2(raw)
            needs_save = True
        elif isinstance(raw, dict) and raw.get("version") == 3:
            state = _upgrade_prevout_journal_v3(raw)
            needs_save = True
        else:
            state = _validate_prevout_journal(raw)
    else:
        raise FileNotFoundError(
            "issuer prevout journal is missing; never reconstruct a partial authority restore"
        )
    if state["cleanup_staging_ids"]:
        drain_signing_cleanup_queue(state)
    before = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
    occupied = {}
    confirmed_staging_ids = set()
    for owner_id, owner in state["owners"].items():
        if owner["active"] is None:
            continue
        for outpoint in owner["active"]["input_outpoints"]:
            occupied[outpoint] = owner_id

    mint_state = load_signer_state()
    for record in _validate_signed_audit_records(mint_state):
        unsigned = sol.unsigned_template_from_signed_hex(record["signed_tx_hex"])
        if hashlib.sha256(bytes.fromhex(unsigned)).hexdigest() != record["request_id"]:
            raise ValueError("signed mint cache unsigned hash differs")
        (
            _recipient,
            _sats,
            _total_out,
            deposit_outpoint,
            _proof,
            allocation_id,
            _script,
            _blind,
        ) = mint_params_from_tx(unsigned, issuer, issuer_script_hex)
        if allocation_id is None:
            owner_id = direct_mint_prevout_owner_id(deposit_outpoint)
            capability = "mint-direct"
        else:
            owner_id = mint_prevout_owner_id(allocation_id)
            capability = "mint"
        _merge_reconciled_signed_lease(
            state,
            owner_id,
            capability,
            allocation_id,
            deposit_outpoint,
            record["request_id"],
            _unsigned_input_outpoints(unsigned),
            record["txid"],
            occupied,
        )
        confirmed_staging_ids.add(state["owners"][owner_id]["active"]["staging_id"])

    c1_state = load_c1_signer_state()
    c1_upgraded = False
    for key, record in c1_state["records"].items():
        allocation_id = key.split(":", 1)[0]
        source = record
        if "input_outpoints" not in source:
            source = _read_archived_c1_cache_record(cfg, allocation_id, key, record)
            record["input_outpoints"] = list(source["input_outpoints"])
            c1_upgraded = True
        _merge_reconciled_signed_lease(
            state,
            "c1:" + key,
            "c1-reservation",
            allocation_id,
            None,
            source["unsigned_sha256"],
            source["input_outpoints"],
            source["txid"],
            occupied,
        )
        confirmed_staging_ids.add(state["owners"]["c1:" + key]["active"]["staging_id"])

    if c1_upgraded:
        # Make archive readback a one-time migration. The retained exact input
        # set is small safety metadata; raw randomized bytes remain WORM-only.
        save_c1_signer_state(c1_state)

    _validate_prevout_journal(state)
    after = json.dumps(state, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if needs_save or before != after:
        save_prevout_journal(state)
    _cleanup_reconciled_signed_stages(state, confirmed_staging_ids)
    _reject_orphan_signing_stages(state)
    return state


def handle_c1_reservation_request(req, issuer, issuer_script_hex, cfg):
    if (
        not isinstance(req, dict)
        or set(req) != {"version", "action", "phase", "allocation", "funding", "unsigned_tx_hex"}
        or req.get("version") != 2
        or req.get("action") != "sign_c1_reservation"
        or req.get("phase") not in ("RESERVE", "EXPOSE", "CANCEL", "FUND")
        or not isinstance(req.get("unsigned_tx_hex"), str)
        or not re.fullmatch(r"[0-9a-f]+", req["unsigned_tx_hex"])
        or len(req["unsigned_tx_hex"]) > 2 * C1_MAX_SIGNED_TX_BYTES
    ):
        raise ValueError("C1 signer request schema is not canonical")
    phase = req["phase"]
    allocation = validate_c1_allocation_claim(req["allocation"])
    funding = req["funding"]
    funding_required = {"outpoint", "proof_hex", "proof_parent_root", "proof_parent_count"}
    if phase == "FUND":
        if (
            not isinstance(funding, dict)
            or set(funding) != funding_required
            or not isinstance(funding.get("outpoint"), str)
            or not BTC_OUTPOINT_RE.fullmatch(funding["outpoint"])
            or int(funding["outpoint"].rsplit(":", 1)[1]) > 0xFFFFFFFF
            or not isinstance(funding.get("proof_hex"), str)
            or not re.fullmatch(r"[0-9a-f]+", funding["proof_hex"])
            or len(funding["proof_hex"]) % 2
            or not 174 <= len(funding["proof_hex"]) <= 38_000
            or not isinstance(funding.get("proof_parent_root"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", funding["proof_parent_root"])
            or type(funding.get("proof_parent_count")) is not int
            or not 0 <= funding["proof_parent_count"] <= (1 << 64) - 1
        ):
            raise ValueError("C1 FUND request object is malformed")
    elif funding is not None:
        raise ValueError("non-FUND C1 signer request carries funding authority")
    decoded = decode_c1_reservation(req["unsigned_tx_hex"], issuer, issuer_script_hex)
    expected_commitment = allocation_commitment(
        allocation["consensus_allocation_id"],
        allocation["veld_address"],
        allocation["amount_sats"],
        allocation["script_pubkey"],
        allocation["commitment_blind"],
    )
    if (
        decoded["action"] != phase
        or decoded["to"] != allocation["veld_address"]
        or decoded["sats"] != allocation["amount_sats"]
        or decoded["allocation_id"] != allocation["consensus_allocation_id"]
        or decoded["allocation_commitment"] != expected_commitment
        or (
            phase == "FUND"
            and (
                decoded["fund_script_pubkey_hex"] != allocation["script_pubkey"]
                or decoded["fund_commitment_blind_hex"] != allocation["commitment_blind"]
                or decoded["fund_outpoint"] != funding["outpoint"]
                or decoded["funding_proof_hex"] != funding["proof_hex"]
            )
        )
    ):
        raise ValueError("C1 transaction differs from exact allocation")
    # Reuse the active-signer topology/marker so the reservation path cannot
    # operate as a hidden second issuer signer.
    rpc = TrustedVeldRpc(cfg.get("veld_rpc"))
    validate_mint_authority_config(cfg, issuer)
    verify_c1_allocation_witness(cfg, allocation)
    state = load_c1_signer_state()
    compact_c1_signer_state(rpc, cfg, state)
    if allocation["consensus_allocation_id"] in state["tombstones"]:
        raise ValueError("C1 allocation is terminally archived at signer")
    funding_sha = (
        hashlib.sha256(
            json.dumps(funding, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
                "utf-8"
            )
        ).hexdigest()
        if funding is not None
        else None
    )
    semantic_sha = None
    if funding is not None:
        semantic_sha = hashlib.sha256(
            json.dumps(
                {
                    "allocation_id": allocation["consensus_allocation_id"],
                    "recipient": allocation["veld_address"],
                    "amount_sats": allocation["amount_sats"],
                    "script_pubkey": allocation["script_pubkey"],
                    "commitment_blind": allocation["commitment_blind"],
                    "outpoint": funding["outpoint"],
                },
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        ).hexdigest()
    key = allocation["consensus_allocation_id"] + ":" + phase
    if phase == "FUND":
        key += ":" + funding_sha
    prevout_owner_id = c1_prevout_owner_id(
        allocation["consensus_allocation_id"], phase, funding_sha
    )
    prevout_state = load_or_reconcile_prevout_journal(cfg, issuer, issuer_script_hex)
    maintain_prevout_journal(rpc, prevout_state)
    reject_conflicting_issuer_prevouts(
        prevout_state,
        prevout_owner_id,
        "c1-reservation",
        allocation["consensus_allocation_id"],
        None,
        req["unsigned_tx_hex"],
    )
    allocation_sha = hashlib.sha256(
        json.dumps(allocation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
            "utf-8"
        )
    ).hexdigest()
    unsigned_sha = hashlib.sha256(bytes.fromhex(req["unsigned_tx_hex"])).hexdigest()
    cached = state["records"].get(key)
    if cached is not None and (
        cached["allocation_sha256"] != allocation_sha or cached["unsigned_sha256"] != unsigned_sha
    ):
        raise ValueError("C1 signer idempotency key was reused with changed bytes")
    if cached is not None and cached["kind"] == "durable":
        raise ValueError("exact C1 signature replay is delegated to durable coordinator state")
    if phase == "FUND" and cached is None:
        prefix = allocation["consensus_allocation_id"] + ":FUND:"
        prior = [
            record for other_key, record in state["records"].items() if other_key.startswith(prefix)
        ]
        if len(prior) >= 8:
            raise ValueError("bounded C1F1 signer variant ceiling reached")
        if any(record["semantic_sha256"] != semantic_sha for record in prior):
            raise ValueError("C1F1 semantic identity changed across variants")
    validate_c1_signing_boundary(
        rpc,
        issuer,
        allocation,
        phase,
        funding=funding,
        retry_txid=(cached["txid"] if cached is not None else None),
    )
    if cached is None:
        min_confs = cfg.get("min_prevout_confirmations", DEFAULT_MIN_PREVOUT_CONFIRMATIONS)
        if type(min_confs) is not int or not 1 <= min_confs <= 1_000_000:
            raise ValueError("min_prevout_confirmations is malformed")
        total_in, _resolved = resolve_mint_prevouts(
            req["unsigned_tx_hex"], rpc, issuer_script_hex, min_confs
        )
        enforce_exact_mint_fee(total_in, decoded["total_out_sats"])
    # Claim the exact inputs only after their independent value/script/depth
    # validation, but before any randomized key operation. Cached retries heal
    # a crash after the signature cache fsync and before this journal's txid mark.
    reserve_issuer_prevouts(
        prevout_state,
        prevout_owner_id,
        "c1-reservation",
        allocation["consensus_allocation_id"],
        None,
        req["unsigned_tx_hex"],
    )
    if _trusted_marker_exists(HALTF, "HALT"):
        raise ValueError("HALT present at C1 signing boundary")
    validate_c1_signing_boundary(
        rpc,
        issuer,
        allocation,
        phase,
        funding=funding,
        retry_txid=(cached["txid"] if cached is not None else None),
    )
    if cached is None:
        if len(state["records"]) >= C1_MAX_CACHE_ROWS:
            raise ValueError("C1 signer cache row ceiling reached")
        # Keep ten percent of the byte budget unavailable to new lifecycles so
        # already-admitted EXPOSE/CANCEL/FUND paths can still complete. The
        # actual hard ceiling is enforced transactionally on every phase.
        if phase == "RESERVE":
            require_c1_signer_lifecycle_capacity(state)
        signed_hex = sign_or_recover_staged_carrier(
            prevout_state,
            prevout_owner_id,
            req["unsigned_tx_hex"],
            issuer_script_hex,
            "C1 issuer sign-tx",
            maximum_signed_hex_bytes=2 * C1_MAX_SIGNED_TX_BYTES,
            build_evidence=lambda: prepare_evidence(
                KEYGEN,
                rpc.call,
                rpc.expected_chain,
                req["unsigned_tx_hex"],
                issuer_script_hex,
                _resolved,
                issuer=issuer,
                operation_type="BTCVELD_C1_" + phase,
                recipient=allocation["veld_address"],
                amount=allocation["amount_sats"],
            ),
            revalidate=lambda: revalidate_c1_key_boundary(
                rpc,
                issuer,
                allocation,
                phase,
                funding,
                req["unsigned_tx_hex"],
                issuer_script_hex,
                min_confs,
            ),
        )
        signed_txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed_hex)).digest()).hexdigest()
        state["records"][key] = {
            "kind": "raw",
            "allocation_sha256": allocation_sha,
            "unsigned_sha256": unsigned_sha,
            "signed_tx_hex": signed_hex,
            "txid": signed_txid,
            "signed_at": int(time.time()),
            "funding_sha256": funding_sha,
            "semantic_sha256": semantic_sha,
            "input_outpoints": _unsigned_input_outpoints(req["unsigned_tx_hex"]),
        }
        save_c1_signer_state(state)
        cached = state["records"][key]
    mark_issuer_prevout_signature(
        prevout_state, prevout_owner_id, req["unsigned_tx_hex"], cached["txid"]
    )
    if _trusted_marker_exists(HALTF, "HALT"):
        raise ValueError("HALT present before C1 signature release")
    return {
        "version": 2,
        "action": "signed_c1_reservation",
        "phase": phase,
        "request_id": allocation["request_id"],
        "allocation_id": allocation["consensus_allocation_id"],
        "signed_tx_hex": cached["signed_tx_hex"],
        "txid": cached["txid"],
    }


def revalidate_c1_key_boundary(
    rpc, issuer, allocation, phase, funding, unsigned_hex, script, min_confs
):
    if _trusted_marker_exists(HALTF, "HALT"):
        raise ValueError("HALT present at C1 key boundary")
    rpc.verify_chain_identity()
    validate_c1_signing_boundary(rpc, issuer, allocation, phase, funding=funding)
    resolve_mint_prevouts(unsigned_hex, rpc, script, min_confs)


def watchtower_gate(sats_tx, state, rpc=None, is_retry=False):
    """FAIL-CLOSED independent-solvency gate (F1). When the watchtower-required
    marker exists, the signer refuses to sign unless it holds a FRESH heartbeat
    from the independent peg watchtower whose headroom still covers this mint PLUS
    every exact signed transaction not yet confirmed in the heartbeat's canonical
    supply snapshot. So even a fully compromised custody box cannot mint past what
    an independent observer just confirmed is backed by real BTC.
    No marker => FAIL-SAFE refuse, unless an explicit caps-only-ok opt-out exists."""
    if not _trusted_marker_exists(WT_REQUIRED, "watchtower-required"):
        # Fail-safe: the peg is live, so a signer with neither the watchtower armed
        # nor an explicit dev opt-out is a misconfiguration — refuse rather than sign
        # unbacked. Production arms 'watchtower-required'; dev drops 'caps-only-ok'.
        if _trusted_marker_exists(CAPS_ONLY_OK, "caps-only-ok"):
            try:
                _initialize_mint_accounting(state)
            except Exception as e:
                refuse("signer mint accounting: " + str(e)[:200])
            _log("WT-GATE off (caps-only-ok opt-out present) - caps-only signing")
            return 0, None
        refuse(
            "solvency watchtower not armed and no caps-only-ok opt-out present "
            "(fail-safe): create 'watchtower-required' (+ run the watchtower) for "
            "production, or 'caps-only-ok' for dev/regtest"
        )
    try:
        hb = strict_json_loads(
            read_bounded_regular_file(
                os.path.abspath(HEARTBEATF), 64 * 1024, "signer heartbeat", private=True
            ),
            "signer heartbeat",
        )
    except FileNotFoundError:
        refuse("watchtower enforcement armed but no heartbeat present (fail-closed)")
    except Exception as e:
        refuse("heartbeat unreadable: %s" % e)
    # Bind the signed supply/headroom snapshot to this signer's canonical view at
    # exactly the same height. Check both before and after tx lookups so a concurrent
    # reorg or same-height competing tip cannot mix views.
    ok, why = _heartbeat_tip_matches_rpc(hb, rpc)
    if not ok:
        refuse("watchtower: " + why)
    try:
        used, migrated = reconcile_mint_accounting(state, hb, rpc)
    except Exception as e:
        refuse("signer mint accounting: " + str(e)[:200])
    ok, why = _heartbeat_tip_matches_rpc(hb, rpc)
    if not ok:
        refuse("watchtower: canonical tip changed during mint confirmation checks: " + why)

    if is_retry:
        allow, why = sol.validate_heartbeat(hb)
        if allow and time.time() > float(hb["expires_at"]):
            allow, why = False, "heartbeat expired (watchtower stale/down; fail-closed)"
        if allow and used > int(hb["headroom_sats"]):
            allow, why = (
                False,
                (
                    "outstanding signed mints %d exceed watchtower headroom %d"
                    % (used, int(hb["headroom_sats"]))
                ),
            )
    else:
        allow, why = sol.heartbeat_gate(hb, time.time(), used, sats_tx)
    if not allow:
        refuse("watchtower: " + why)
    _log(
        "WT-GATE ok headroom=%s outstanding=%d mint=%d retry=%s migrated=%s tip=%s"
        % (
            hb.get("headroom_sats"),
            used,
            0 if is_retry else sats_tx,
            is_retry,
            migrated,
            hb.get("tip_hash", "")[:16],
        )
    )
    return used, hb


def load_signer_configuration():
    cfg = strict_json_loads(
        _secure_text(os.path.abspath(SIGNER_CONFIG), private=True), "signer configuration"
    )
    if not isinstance(cfg, dict):
        raise ValueError("signer configuration root is not an object")
    rpc_cfg = cfg.get("veld_rpc")
    if not isinstance(rpc_cfg, dict):
        raise ValueError("signer configuration requires veld_rpc")
    parse_expected_chain(rpc_cfg.get("expected_chain"))
    marker = cfg.get("authority_state_activation_marker")
    if (
        not isinstance(marker, str)
        or not os.path.isabs(marker)
        or os.path.dirname(marker) != os.path.abspath(HERE)
        or os.path.basename(marker) != "signer-authority-state.json"
    ):
        raise ValueError(
            "authority_state_activation_marker must be the signer-local "
            "signer-authority-state.json path"
        )
    return cfg


def _authority_state_marker_document(cfg):
    return {
        "version": 2,
        "expected_chain": parse_expected_chain(cfg.get("veld_rpc", {}).get("expected_chain")),
        "state_files": {
            "mint": os.path.abspath(STATEF),
            "c1_reservation": os.path.abspath(C1_STATEF),
            "issuer_prevout_leases": os.path.abspath(PREVOUT_STATEF),
        },
    }


def require_signer_authority_state_set(cfg):
    marker = cfg["authority_state_activation_marker"]
    document = strict_json_loads(
        _secure_text(marker, private=True, max_bytes=4096), "signer authority activation marker"
    )
    expected = _authority_state_marker_document(cfg)
    if (
        not isinstance(document, dict)
        or type(document.get("version")) is not int
        or document.get("version") != 2
    ):
        raise ValueError("unbound signer authority marker requires offline reconciliation")
    parse_expected_chain(document.get("expected_chain"))
    if document != expected:
        raise ValueError(
            "signer authority activation marker does not bind the exact chain; "
            "offline reconciliation is required"
        )
    for path in expected["state_files"].values():
        if not os.path.lexists(path):
            raise ValueError("activated signer authority state set is incomplete: " + path)
        _secure_regular(path, private=True)
    return True


def _write_authority_activation_marker(path, document):
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _validate_and_reconcile_signer_authority_members(cfg):
    """Fully parse all authorities and reconcile their shared prevout union."""
    load_signer_state()
    load_c1_signer_state()
    issuer = issuer_addr()
    issuer_script = issuer_p2pkh_from_address(issuer)
    return load_or_reconcile_prevout_journal(cfg, issuer, issuer_script)


def initialize_signer_authority_state():
    """One-shot local ceremony creating one chain-bound authority set.

    The activation marker is committed last. A crash before it is an explicit
    partial-initialization incident. Existing unbound state requires independent
    chain reconciliation; it is never adopted or overwritten by initialization.
    """
    _secure_service_directory(HERE)
    cfg = load_signer_configuration()
    marker = cfg["authority_state_activation_marker"]
    state_paths = (STATEF, C1_STATEF, PREVOUT_STATEF)
    lock_path = os.path.join(HERE, ".signerd.lock")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    lock_fd = os.open(lock_path, flags, 0o600)
    lock = os.fdopen(lock_fd, "a+")
    try:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        present = [os.path.lexists(path) for path in state_paths]
        if os.path.lexists(marker):
            require_signer_authority_state_set(cfg)
            _validate_and_reconcile_signer_authority_members(cfg)
            return _authority_state_marker_document(cfg)
        if any(present) and not all(present):
            raise ValueError(
                "signer authority state set is partial; restore/reconcile the "
                "complete set and never fill a missing member"
            )
        if all(present):
            raise ValueError(
                "unbound signer authority state requires offline chain "
                "reconciliation; initialization cannot adopt it"
            )
        else:
            save_signer_state_durable({"signed": []})
            save_c1_signer_state(_empty_c1_signer_state())
            save_prevout_journal(_empty_prevout_journal())
        document = _authority_state_marker_document(cfg)
        _write_authority_activation_marker(marker, document)
        require_signer_authority_state_set(cfg)
        return document
    finally:
        lock.close()


def main(capability="mint"):
    if capability not in ("mint", "c1-reservation"):
        refuse("signer capability must be exactly mint or c1-reservation")
    try:
        _secure_service_directory(HERE)
    except Exception as e:
        refuse("signer directory policy: " + str(e)[:200])
    try:
        if _trusted_marker_exists(HALTF, "HALT"):
            refuse(f"HALT present ({HALTF})")
    except Exception as e:
        refuse("HALT path policy: " + str(e)[:200])
    try:
        _secure_regular(KEYGEN, executable=True)
        _secure_regular(KEYFILE, private=True)
        _secure_regular(PASSFILE, private=True)
        _secure_regular(ADDRFILE)
    except Exception as e:
        refuse("signer file policy: " + str(e)[:240])
    try:
        authority_cfg = load_signer_configuration()
        require_signer_authority_state_set(authority_cfg)
    except Exception as e:
        refuse("signer authority state set: " + str(e)[:240])

    # single-writer: serialize signing so the rate window can't be raced.
    lock_path = os.path.join(HERE, ".signerd.lock")
    lock_flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        lock_fd = os.open(lock_path, lock_flags, 0o600)
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_nlink != 1
            or lock_info.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(lock_info.st_mode) & 0o022
        ):
            os.close(lock_fd)
            refuse("signer lock is not a trusted regular file")
        os.fchmod(lock_fd, 0o600)
        lock = os.fdopen(lock_fd, "a+")
    except Exception as e:
        refuse("signer lock unavailable: " + str(e)[:200])
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        refuse("another signer holds the lock")

    try:
        require_signer_authority_state_set(authority_cfg)
    except Exception as e:
        refuse("locked signer authority state set: " + str(e)[:240])

    try:
        raw_request = _read_bounded_stdin(MAX_REQUEST_BYTES)
        if len(raw_request) > MAX_REQUEST_BYTES:
            refuse("request exceeds %d-byte limit" % MAX_REQUEST_BYTES)
        req = strict_json_loads(raw_request, "mint signing request")
    except Exception as e:
        refuse(f"bad request json: {e}")
    if not isinstance(req, dict):
        refuse("bad request json: root must be an object")
    if req.get("action") == "rtp1_mint":
        if capability != "mint":
            refuse("C1 reservation capability cannot sign RTP1 mints")
        try:
            from rtp1_service_runtime import issuer_request

            issuer = issuer_addr()
            signed = issuer_request(
                sys.modules[__name__], req, authority_cfg, issuer, issuer_p2pkh_from_address(issuer)
            )
        except Exception as exc:
            refuse("RTP1 issuance refused: " + str(exc)[:240])
        sys.stdout.write(signed + "\n")
        lock.close()
        return
    if "rtp1_service" in authority_cfg:
        refuse("legacy issuance is closed after RTP1 migration")
    if req.get("action") == "ack_c1_signature_durable":
        if capability != "c1-reservation":
            refuse("mint capability cannot acknowledge C1 reservation carriers")
        try:
            cfg = authority_cfg
            answer = acknowledge_c1_signature_durable(req, cfg)
        except Exception as e:
            refuse("C1 durable acknowledgement: " + str(e)[:240])
        sys.stdout.write(
            json.dumps(answer, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        )
        lock.close()
        return
    if req.get("action") == "sign_c1_reservation":
        if capability != "c1-reservation":
            refuse("mint capability cannot sign C1 reservation carriers")
        try:
            issuer = issuer_addr()
            issuer_script = issuer_p2pkh_from_address(issuer)
            cfg = authority_cfg
            answer = handle_c1_reservation_request(req, issuer, issuer_script, cfg)
        except UnsignedCarrierAbandoned as e:
            emit_unsigned_carrier_abandoned(e)
        except SystemExit:
            raise
        except Exception as e:
            refuse("C1 reservation signing: " + str(e)[:240])
        sys.stdout.write(
            json.dumps(answer, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        )
        lock.close()
        return
    if capability != "mint":
        refuse("C1 reservation capability cannot sign token mints")
    base_fields = {"unsigned_tx_hex", "recipient", "sats"}
    if set(req) not in (base_fields, base_fields | {"allocation"}):
        refuse("mint signing request fields are not canonical")
    utx = req.get("unsigned_tx_hex")
    if not isinstance(utx, str):
        refuse("request missing unsigned_tx_hex")

    issuer = issuer_addr()

    # Parse the immutable transaction policy first. This lets an exact cached
    # retry be recognized before querying prevouts that the original transaction
    # may already have spent. A retry is never re-signed; it can only replay the
    # byte-identical transaction durably cached after the original full checks.
    try:
        prev_script_hex = issuer_p2pkh_from_address(issuer)
    except Exception as e:
        refuse("issuer policy: " + str(e)[:240])

    # 1) INDEPENDENT: derive the mint from the tx via the consensus deserializer
    #    (full parse + canonical single-mint template), not the caller's claim.
    (
        to_tx,
        sats_tx,
        total_out,
        deposit_outpoint,
        nullifier_proof_hex,
        consensus_reservation_id,
        consensus_reservation_script_pubkey,
        consensus_reservation_commitment_blind,
    ) = mint_params_from_tx(utx, issuer, prev_script_hex)

    # 2) the caller's claimed recipient/sats must MATCH the tx (catches a lying caller).
    if "recipient" in req and req["recipient"] != to_tx:
        refuse(f"claimed recipient {req['recipient']!r} != tx {to_tx!r}")
    if "sats" in req:
        if type(req["sats"]) is not int or req["sats"] != sats_tx:
            refuse(f"claimed sats {req['sats']} != tx {sats_tx}")
    allocation_claim = None
    if "allocation" in req:
        try:
            allocation_claim = validate_mint_allocation_claim(
                req["allocation"], to_tx, sats_tx, deposit_outpoint
            )
        except Exception as e:
            refuse("allocation claim: " + str(e)[:200])
        if consensus_reservation_id != allocation_claim["consensus_allocation_id"]:
            refuse("MNP2 reservation id differs from consensus allocation id")
        if consensus_reservation_script_pubkey != allocation_claim["script_pubkey"]:
            refuse("MNP2 commitment opening differs from allocation script")
        if consensus_reservation_commitment_blind != allocation_claim["commitment_blind"]:
            refuse("MNP2 commitment opening differs from allocation blind")
    elif consensus_reservation_id is not None:
        refuse("MNP2 mint requires the exact allocation claim")
    # 3) independent caps.
    if sats_tx > MAX_SINGLE_SATS:
        refuse(f"sats {sats_tx} > MAX_SINGLE {MAX_SINGLE_SATS}")
    try:
        state = load_signer_state()
    except Exception as e:
        refuse("signer state unreadable: " + str(e)[:200])
    request_id = hashlib.sha256(bytes.fromhex(utx)).hexdigest()
    try:
        retry_record, incremental_sats = classify_mint_request(state, request_id, sats_tx, to_tx)
        window_used = window_signed_sats(state)
        if retry_record is not None and not retry_record.get("witness_receipt"):
            raise ValueError("pre-witness cached signature requires offline reconciliation")
    except Exception as e:
        refuse("signer state audit records invalid: " + str(e)[:200])
    if window_used + incremental_sats > MAX_WINDOW_SATS:
        refuse(f"window cap: {window_used}+{incremental_sats} > {MAX_WINDOW_SATS}")

    # Construct the trusted RPC only after classifying the exact request. New
    # requests resolve and verify every prevout/fee. Cached retries skip only that
    # now-impossible spent-prevout lookup; they still pass tx policy, caller claims,
    # rate policy, and fresh tip-bound watchtower checks before exact-byte replay.
    try:
        cfg = authority_cfg
        rpc = TrustedVeldRpc(cfg.get("veld_rpc"))
        authority, witness = validate_mint_authority_config(cfg, issuer)
        if allocation_claim is None:
            raise ValueError("independent wrap allocation claim is required")
        validate_fresh_mint_boundary(
            rpc,
            issuer,
            sats_tx,
            deposit_outpoint,
            nullifier_proof_hex,
            retry_record.get("txid") if retry_record is not None else None,
            consensus_reservation_id,
            to_tx,
            allocation_claim["script_pubkey"],
            allocation_claim["commitment_blind"],
        )
        require_witnessed_outstanding(state)
    except Exception as e:
        refuse("trusted RPC setup: " + str(e)[:240])
    prevout_owner_id = mint_prevout_owner_id(allocation_claim["consensus_allocation_id"])
    try:
        prevout_state = load_or_reconcile_prevout_journal(cfg, issuer, prev_script_hex)
        maintain_prevout_journal(rpc, prevout_state)
        reject_conflicting_issuer_prevouts(
            prevout_state,
            prevout_owner_id,
            "mint",
            allocation_claim["consensus_allocation_id"],
            deposit_outpoint,
            utx,
        )
    except UnsignedCarrierAbandoned as e:
        emit_unsigned_carrier_abandoned(e)
    except Exception as e:
        refuse("issuer prevout journal: " + str(e)[:240])
    if retry_record is None:
        try:
            min_confs = cfg.get("min_prevout_confirmations", DEFAULT_MIN_PREVOUT_CONFIRMATIONS)
            if type(min_confs) is not int or not (1 <= min_confs <= 1_000_000):
                raise ValueError("min_prevout_confirmations must be an exact bounded JSON integer")
            total_in, resolved_inputs = resolve_mint_prevouts(utx, rpc, prev_script_hex, min_confs)
            fee = enforce_exact_mint_fee(total_in, total_out)
        except Exception as e:
            refuse("trusted prevout/fee verification: " + str(e)[:240])
    else:
        fee = EXPECTED_MINT_FEE_UNITS
        resolved_inputs = []
    try:
        reserve_issuer_prevouts(
            prevout_state,
            prevout_owner_id,
            "mint",
            allocation_claim["consensus_allocation_id"],
            deposit_outpoint,
            utx,
        )
    except UnsignedCarrierAbandoned as e:
        emit_unsigned_carrier_abandoned(e)
    except Exception as e:
        refuse("issuer prevout lease: " + str(e)[:240])

    # 3.5) INDEPENDENT solvency gate (F1): fail-closed on a stale/missing heartbeat
    #      or a mint that would exceed the watchtower-attested custody headroom.
    reserved_entry = _accounting_entry(state, request_id)
    capacity_reserved = retry_record is not None or reserved_entry is not None
    ignored_used, heartbeat = watchtower_gate(sats_tx, state, rpc=rpc, is_retry=capacity_reserved)
    if heartbeat is None:
        refuse("shared reservation witness is mandatory outside explicit unit helpers")

    try:
        if prune_finalized_signed_audits(state, keep_request_id=request_id):
            save_signer_state_durable(state)
    except Exception as e:
        refuse("finalized signer-journal pruning failed: " + str(e)[:200])

    # The independent witness is the fleet-wide allocator. It serializes every
    # signer replica against one durable ledger. Persist its signed receipt before
    # the randomized issuer signature can exist.
    if retry_record is None:
        try:
            receipt = reserve_witness_headroom(
                witness,
                issuer,
                request_id,
                request_id,
                utx,
                sats_tx,
                to_tx,
                heartbeat,
                allocation_claim,
            )
            record_mint_reservation(state, receipt)
            save_signer_state_durable(state)
        except Exception as e:
            refuse("mint reservation failed: " + str(e)[:240])

    # A receiver can publish a sticky HALT while this forced-command request is
    # already running.  Recheck at the final key/replay boundary so an old fresh
    # heartbeat cannot authorize one more signature after the emergency stop.
    try:
        if _trusted_marker_exists(HALTF, "HALT"):
            refuse(f"HALT present at signing boundary ({HALTF})")
    except Exception as e:
        refuse("HALT path policy at signing boundary: " + str(e)[:200])
    try:
        # Re-sample immediately before the randomized key operation or cached
        # byte replay. Reservations remain conservative if this late check
        # detects a competing mint/tip/cap change.
        validate_fresh_mint_boundary(
            rpc,
            issuer,
            sats_tx,
            deposit_outpoint,
            nullifier_proof_hex,
            retry_record.get("txid") if retry_record is not None else None,
            consensus_reservation_id,
            to_tx,
            allocation_claim["script_pubkey"],
            allocation_claim["commitment_blind"],
        )
    except Exception as e:
        refuse("fresh mint boundary changed before signing: " + str(e)[:200])

    def revalidate_mint_key_boundary():
        if _trusted_marker_exists(HALTF, "HALT"):
            raise ValueError("HALT present at mint key boundary")
        rpc.verify_chain_identity()
        validate_fresh_mint_boundary(
            rpc,
            issuer,
            sats_tx,
            deposit_outpoint,
            nullifier_proof_hex,
            None,
            consensus_reservation_id,
            to_tx,
            allocation_claim["script_pubkey"],
            allocation_claim["commitment_blind"],
        )
        resolve_mint_prevouts(utx, rpc, prev_script_hex, min_confs)
        watchtower_gate(sats_tx, state, rpc=rpc, is_retry=True)

    if retry_record is not None:
        # ML-DSA signing is randomized. Re-signing the same unsigned transaction
        # would create a second txid, so retries replay the byte-identical durable
        # transaction only after all fresh heartbeat/canonical checks above.
        signed = retry_record["signed_tx_hex"]
    else:
        try:
            signed = sign_or_recover_staged_carrier(
                prevout_state,
                prevout_owner_id,
                utx,
                prev_script_hex,
                "veld-keygen sign-tx",
                build_evidence=lambda: prepare_evidence(
                    KEYGEN,
                    rpc.call,
                    rpc.expected_chain,
                    utx,
                    prev_script_hex,
                    resolved_inputs,
                    issuer=issuer,
                    operation_type="BTCVELD_MINT",
                    recipient=to_tx,
                    amount=sats_tx,
                ),
                revalidate=revalidate_mint_key_boundary,
            )
            if len(signed) < 100:
                refuse("signer produced no valid signed tx")
        except Exception as e:
            refuse("veld-keygen sign-tx staging: " + str(e)[:240])

    # 5) Durably charge the signature BEFORE returning it. File fsync makes the
    # bytes durable; directory fsync makes the atomic rename durable. A persistence
    # failure refuses the request without writing the signed transaction to stdout.
    signed_txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed)).digest()).hexdigest()
    try:
        record_signed_mint(state, request_id, signed_txid, signed, sats_tx, to_tx)
        save_signer_state_durable(state)
    except Exception as e:
        refuse("signer state durability failure: " + str(e)[:200])

    # Bind the witness reservation to these exact signed bytes. The witness
    # reconstructs the unsigned serialization, re-hashes it, decodes the mint,
    # and refuses an unrelated/old txid. No bytes reach stdout until this durable
    # commit succeeds and its acknowledgement is fsynced locally.
    try:
        entry = _witness_entry(state, request_id)
        if not entry or not entry.get("witness_committed"):
            commit_witness_transaction(witness, state, request_id, signed_txid, signed)
            save_signer_state_durable(state)
    except Exception as e:
        refuse("witness transaction commit failed: " + str(e)[:240])

    try:
        mark_issuer_prevout_signature(prevout_state, prevout_owner_id, utx, signed_txid)
    except Exception as e:
        refuse("issuer prevout signature durability: " + str(e)[:240])

    try:
        if _trusted_marker_exists(HALTF, "HALT"):
            refuse(f"HALT present before signature release ({HALTF})")
    except Exception as e:
        refuse("HALT path policy before signature release: " + str(e)[:200])

    _log(
        f"{'REPLAYED' if retry_record is not None else 'SIGNED'} txid={signed_txid} "
        f"sats={sats_tx} to={to_tx} fee={fee} inputs={len(resolved_inputs)}"
    )
    sys.stdout.write(signed + "\n")
    # The forced-command process exits after one request, but main() is also
    # invoked in-process by qualification tests. Release the advisory lock on
    # the successful return path instead of depending on interpreter GC timing.
    lock.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--initialize-rtp1-state"]:
        try:
            from rtp1_service_runtime import initialize_issuer

            initialized = initialize_issuer(sys.modules[__name__])
        except Exception as exc:
            refuse("RTP1 initialization: " + str(exc)[:240])
        sys.stdout.write(json.dumps(initialized, sort_keys=True, separators=(",", ":")) + "\n")
    elif sys.argv[1:] == ["--initialize-authority-state"]:
        try:
            initialized = initialize_signer_authority_state()
        except Exception as exc:
            refuse("authority state initialization: " + str(exc)[:240])
        sys.stdout.write(
            json.dumps(initialized, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
        )
    elif (
        len(sys.argv) == 3
        and sys.argv[1] == "--capability"
        and sys.argv[2] in ("mint", "c1-reservation")
    ):
        main(sys.argv[2])
    else:
        refuse(
            "usage: veld_signerd.py --initialize-authority-state | --initialize-rtp1-state | "
            "--capability mint|c1-reservation"
        )
