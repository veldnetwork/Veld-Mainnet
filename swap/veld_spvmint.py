#!/usr/bin/env python3
"""Launch-live btcVELD SPV deposit and mint operator.

Two explicit one-shot modes are intentionally separate:

  deposit  Build, fund, sign, validate, and broadcast a Bitcoin mainnet
           transaction with exactly one descriptor-index-0 custody output and
           exactly one ``btcVELD:<VELD recipient>`` OP_RETURN.

  mint     Wait for the compiled Bitcoin burial depth, build and locally check
           the Merkle proof, strip any SegWit witnesses to the exact txid
           serialization, validate the deposit again, then fee-fund/sign/post a
           ``VELD_MSPV|`` transaction on Veld.

The existing /wrap + veld_mintd issuer route is deliberately untouched.  This
tool is the explicit permissionless-SPV front door.  It never holds a custody
signer key: Bitcoin deposits are paid *to* the 3-of-5 custody descriptor, while
the Veld key is a dedicated fees-only hot key constrained by
``veld-keygen sign-op``.

Every external observation is revalidated and identity-bound.  Ambiguity,
reorg, stale headers, cap exhaustion, malformed serialization, oversized proof,
or descriptor/manifest drift aborts before a fee is spent.
"""

import argparse
import decimal
import hashlib
import json
import os
import re
import stat
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

try:
    from .rpc_url_policy import (
        load_bounded_json_file,
        load_bounded_json_response,
        open_rpc_request,
        read_bounded_secret_file,
        run_bounded_subprocess,
        strict_json_loads,
        validate_loopback_http_rpc_url,
    )
except ImportError:  # direct-script execution
    from rpc_url_policy import (
        load_bounded_json_file,
        load_bounded_json_response,
        open_rpc_request,
        read_bounded_secret_file,
        run_bounded_subprocess,
        strict_json_loads,
        validate_loopback_http_rpc_url,
    )

try:
    import fcntl
except ImportError:  # production operator is POSIX; fail closed in main().
    fcntl = None

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_custody_binding as custody_binding  # noqa: E402


SATS = 100_000_000
STATE_SCHEMA = 1
OP_PREFIX = "VELD_MSPV|"
PROOF_MAGIC = b"MSP2"
NULLIFIER_PROOF_VERSION = "MNP1"
NULLIFIER_MIN_PROOF_BYTES = 32
NULLIFIER_MAX_PROOF_BYTES = 32 + 256 * 32
RECIPIENT_TAG = b"btcVELD:"
RAW_OP_MIN_CHARS = 12
# Exact C++ `btcnull::MAX_MSPV_OP_PAYLOAD_BYTES`: prefix + lowercase-hex of
# MSP2(max 32-hash branch, 12k stripped tx, max sparse witness).
RAW_OP_MAX_CHARS = 42_596
VELD_ADDRESS_RE = re.compile(r"^V[1-9A-HJ-NP-Za-km-z]{25,49}$")
TXID_RE = re.compile(r"^[0-9a-f]{64}$")
HEX_RE = re.compile(r"^[0-9a-f]+$")
MAX_WIRE_INT = (1 << 63) - 1
MAX_CONFIG_BYTES = 1024 * 1024
MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_STATE_RECORDS = 100_000
MAX_BITCOIN_TX_BYTES = 4 * 1024 * 1024
MAX_VELD_TX_BYTES = 4 * 1024 * 1024
MAX_BITCOIN_CLI_STDOUT = 32 * 1024 * 1024
MAX_SUBPROCESS_STDERR = 64 * 1024
MAX_KEYFILE_BYTES = 1024 * 1024
MAX_BLOCK_TXIDS = 100_000
MAX_VELD_FEE_INPUTS = 64
MAX_WAIT_SECONDS = 7 * 24 * 60 * 60
# preparerawop is compiled to spend exactly MIN_TX_FEE.  Refusing any other
# amount prevents a compromised/misconfigured local RPC from turning a proof
# submission into an unbounded native-VELD fee burn.
VELD_OP_FEE_UNITS = 100_000
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


class Pending(RuntimeError):
    """A safe, retryable not-ready condition (confirmations/header relay)."""


def dsha(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def _strict_int(value, label, minimum=0, maximum=MAX_WIRE_INT):
    if type(value) is not int or value < minimum or value > maximum:
        raise RuntimeError("%s must be a JSON integer in [%d,%d]" % (label, minimum, maximum))
    return value


def veld_p2pkh_from_address(address, label="VELD address"):
    """Validate one canonical Base58Check address and return its P2PKH SPK."""
    if not isinstance(address, str) or not VELD_ADDRESS_RE.fullmatch(address):
        raise RuntimeError("%s is not a canonical VELD address" % label)
    number = 0
    try:
        for char in address:
            number = number * 58 + BASE58_ALPHABET.index(char)
    except ValueError as exc:  # kept separate from the shape check for clarity
        raise RuntimeError("%s is not Base58" % label) from exc
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    decoded = b"\x00" * (len(address) - len(address.lstrip("1"))) + decoded
    if len(decoded) != 25:
        raise RuntimeError("%s has an invalid Base58Check payload length" % label)
    payload, checksum = decoded[:-4], decoded[-4:]
    if dsha(payload)[:4] != checksum or len(payload) != 21:
        raise RuntimeError("%s has an invalid Base58Check checksum" % label)
    return b"\x76\xa9\x14" + payload[1:] + b"\x88\xac"


def _validate_hex_bytes(value, label, maximum, minimum=1):
    if (
        not isinstance(value, str)
        or value != value.lower()
        or len(value) & 1
        or not HEX_RE.fullmatch(value)
    ):
        raise RuntimeError("%s must be canonical lowercase even-length hex" % label)
    size = len(value) // 2
    if size < minimum or size > maximum:
        raise RuntimeError("%s byte length is outside the safety bound" % label)
    return bytes.fromhex(value)


def be_to_le(display_hex):
    if not isinstance(display_hex, str) or not TXID_RE.fullmatch(display_hex):
        raise RuntimeError("hash must be canonical lowercase 64-hex")
    return bytes.fromhex(display_hex)[::-1]


def btc_to_sats(value):
    try:
        amount = decimal.Decimal(str(value))
    except (decimal.DecimalException, ValueError) as exc:
        raise RuntimeError("Bitcoin amount is not decimal") from exc
    sats = amount * SATS
    if not sats.is_finite() or sats != sats.to_integral_value():
        raise RuntimeError("Bitcoin amount is not an exact satoshi value")
    result = int(sats)
    if result < 0 or result > MAX_WIRE_INT:
        raise RuntimeError("Bitcoin amount is outside the bounded satoshi range")
    return result


def sats_json(sats):
    _strict_int(sats, "satoshi amount")
    return "%d.%08d" % (sats // SATS, sats % SATS)


def _compact_size(raw, off):
    if off >= len(raw):
        raise RuntimeError("truncated Bitcoin CompactSize")
    start = off
    first = raw[off]
    off += 1
    if first < 0xFD:
        return first, off, raw[start:off]
    width = 2 if first == 0xFD else 4 if first == 0xFE else 8
    if off + width > len(raw):
        raise RuntimeError("truncated Bitcoin CompactSize body")
    value = int.from_bytes(raw[off : off + width], "little")
    off += width
    if (
        (width == 2 and value < 0xFD)
        or (width == 4 and value <= 0xFFFF)
        or (width == 8 and value <= 0xFFFFFFFF)
    ):
        raise RuntimeError("non-canonical Bitcoin CompactSize")
    return value, off, raw[start:off]


def parse_and_strip_bitcoin_tx(raw):
    """Strictly parse a Bitcoin transaction and return its txid serialization.

    For a SegWit transaction this removes only marker/flag and each witness
    stack, preserving every byte of version, CompactSizes, inputs, outputs, and
    locktime.  For a legacy transaction it returns the original bytes exactly.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise RuntimeError("raw Bitcoin transaction must be bytes")
    raw = bytes(raw)
    if len(raw) < 10:
        raise RuntimeError("Bitcoin transaction is too short")
    if len(raw) > MAX_BITCOIN_TX_BYTES:
        raise RuntimeError("Bitcoin transaction exceeds the 4 MiB safety bound")

    off = 4
    segwit = False
    if raw[off] == 0:
        if off + 1 >= len(raw) or raw[off + 1] != 1:
            raise RuntimeError("unsupported/invalid Bitcoin witness marker or flag")
        segwit = True
        off += 2

    legacy = bytearray(raw[:4])
    vin_count, off, encoded = _compact_size(raw, off)
    if vin_count == 0 or vin_count > 100_000:
        raise RuntimeError("Bitcoin transaction input count is invalid")
    legacy.extend(encoded)
    inputs = []
    for _ in range(vin_count):
        start = off
        if off + 36 > len(raw):
            raise RuntimeError("truncated Bitcoin input prevout")
        prev_txid = raw[off : off + 32]
        prev_vout = int.from_bytes(raw[off + 32 : off + 36], "little")
        off += 36
        script_len, off, _ = _compact_size(raw, off)
        if script_len > 10_000 or off + script_len + 4 > len(raw):
            raise RuntimeError("truncated/oversized Bitcoin input script")
        off += script_len + 4
        legacy.extend(raw[start:off])
        inputs.append((prev_txid, prev_vout))

    vout_count, off, encoded = _compact_size(raw, off)
    if vout_count == 0 or vout_count > 100_000:
        raise RuntimeError("Bitcoin transaction output count is invalid")
    legacy.extend(encoded)
    outputs = []
    for index in range(vout_count):
        start = off
        if off + 8 > len(raw):
            raise RuntimeError("truncated Bitcoin output value")
        value = int.from_bytes(raw[off : off + 8], "little")
        off += 8
        script_len, off, _ = _compact_size(raw, off)
        if script_len > 10_000 or off + script_len > len(raw):
            raise RuntimeError("truncated/oversized Bitcoin output script")
        script = raw[off : off + script_len]
        off += script_len
        legacy.extend(raw[start:off])
        outputs.append({"vout": index, "value_sats": value, "script": script})

    if segwit:
        for _ in range(vin_count):
            item_count, off, _ = _compact_size(raw, off)
            if item_count > 100_000:
                raise RuntimeError("Bitcoin witness item count is invalid")
            for _ in range(item_count):
                item_len, off, _ = _compact_size(raw, off)
                if item_len > 4_000_000 or off + item_len > len(raw):
                    raise RuntimeError("truncated/oversized Bitcoin witness item")
                off += item_len

    if off + 4 != len(raw):
        raise RuntimeError("Bitcoin transaction has trailing or truncated locktime bytes")
    legacy.extend(raw[off : off + 4])
    return {
        "legacy": bytes(legacy),
        "segwit": segwit,
        "inputs": tuple(inputs),
        "outputs": tuple(outputs),
    }


def parse_veld_tx_hex(tx_hex, *, signed):
    """Parse the complete Veld transaction and reconstruct its unsigned bytes.

    Veld uses the legacy Bitcoin-style envelope.  ``sign-op`` may change only
    input scriptSigs; version, prevouts, sequences, outputs and locktime must be
    byte-identical to the RPC-prepared transaction.
    """
    raw = _validate_hex_bytes(tx_hex, "Veld transaction", MAX_VELD_TX_BYTES, minimum=10)
    off = 4
    input_count, off, encoded_count = _compact_size(raw, off)
    if not 1 <= input_count <= MAX_VELD_FEE_INPUTS:
        raise RuntimeError("Veld transaction input count exceeds the safety bound")
    unsigned = bytearray(raw[:4])
    unsigned.extend(encoded_count)
    inputs = []
    seen = set()
    for index in range(input_count):
        if off + 36 > len(raw):
            raise RuntimeError("truncated Veld transaction input")
        prev_txid = raw[off : off + 32].hex()
        prev_vout = int.from_bytes(raw[off + 32 : off + 36], "little")
        prevout = (prev_txid, prev_vout)
        if prevout in seen:
            raise RuntimeError("Veld transaction repeats a fee input")
        seen.add(prevout)
        unsigned.extend(raw[off : off + 36])
        off += 36
        script_len, off, _ = _compact_size(raw, off)
        if script_len > 32_768 or off + script_len + 4 > len(raw):
            raise RuntimeError("truncated/oversized Veld input script")
        if signed and script_len == 0:
            raise RuntimeError("signed Veld transaction has an empty input script")
        if not signed and script_len != 0:
            raise RuntimeError("unsigned Veld transaction has a non-empty input script")
        off += script_len
        unsigned.append(0)
        unsigned.extend(raw[off : off + 4])
        sequence = int.from_bytes(raw[off : off + 4], "little")
        off += 4
        inputs.append({"index": index, "txid": prev_txid, "vout": prev_vout, "sequence": sequence})

    outputs_start = off
    output_count, off, _ = _compact_size(raw, off)
    if not 1 <= output_count <= 2:
        raise RuntimeError("Veld relay transaction must have one or two outputs")
    outputs = []
    for index in range(output_count):
        if off + 8 > len(raw):
            raise RuntimeError("truncated Veld transaction output")
        value = int.from_bytes(raw[off : off + 8], "little")
        off += 8
        script_len, off, _ = _compact_size(raw, off)
        if script_len > 65_535 or off + script_len > len(raw):
            raise RuntimeError("truncated/oversized Veld output script")
        script = raw[off : off + script_len]
        off += script_len
        outputs.append({"index": index, "value_units": value, "script": script})
    if off + 4 != len(raw):
        raise RuntimeError("Veld transaction has trailing/truncated locktime bytes")
    unsigned.extend(raw[outputs_start:])
    return {
        "raw": raw,
        "unsigned_hex": bytes(unsigned).hex(),
        "inputs": tuple(inputs),
        "outputs": tuple(outputs),
    }


def _canonical_op_return(payload):
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= 65_535:
        raise RuntimeError("Veld OP_RETURN payload length is invalid")
    if len(payload) <= 75:
        push = bytes([len(payload)])
    elif len(payload) <= 255:
        push = b"\x4c" + bytes([len(payload)])
    else:
        push = b"\x4d" + struct.pack("<H", len(payload))
    return b"\x6a" + push + payload


def validate_op_tx_outputs(parsed, fund_addr, op_string, expected_change=None):
    if (
        not isinstance(op_string, str)
        or not op_string.startswith(OP_PREFIX)
        or not RAW_OP_MIN_CHARS <= len(op_string) <= RAW_OP_MAX_CHARS
        or not op_string.isascii()
    ):
        raise RuntimeError("MSPV op string is malformed")
    fund_spk = veld_p2pkh_from_address(fund_addr, "Veld fee-fund address")
    expected_op = _canonical_op_return(op_string.encode("ascii"))
    outputs = parsed["outputs"]
    if len(outputs) == 1 and outputs[0]["value_units"] == 0 and outputs[0]["script"] == expected_op:
        change = 0
    elif (
        len(outputs) == 2
        and outputs[0]["value_units"] > 0
        and outputs[0]["script"] == fund_spk
        and outputs[1]["value_units"] == 0
        and outputs[1]["script"] == expected_op
    ):
        change = outputs[0]["value_units"]
    else:
        raise RuntimeError("Veld relay transaction changed the exact MSPV outputs")
    if expected_change is not None and change != expected_change:
        raise RuntimeError("Veld relay transaction change differs from prepared metadata")
    return fund_spk, change


def validate_prepared_op(prepared, fund_addr, op_string):
    """Bind preparerawop metadata and exact unsigned output semantics."""
    if not isinstance(prepared, dict):
        raise RuntimeError("preparerawop returned a malformed result")
    unsigned = prepared.get("unsigned_tx_hex")
    parsed = parse_veld_tx_hex(unsigned, signed=False)
    fund_spk, _ = validate_op_tx_outputs(parsed, fund_addr, op_string)

    metadata = prepared.get("inputs")
    if not isinstance(metadata, list) or len(metadata) != len(parsed["inputs"]):
        raise RuntimeError("preparerawop fee-input metadata count is inconsistent")
    for index, item in enumerate(metadata):
        if not isinstance(item, dict) or set(("index", "sighash_hex", "prev_script_hex")) - set(
            item
        ):
            raise RuntimeError("preparerawop fee-input metadata is malformed")
        if (
            _strict_int(item["index"], "preparerawop input index", 0, MAX_VELD_FEE_INPUTS - 1)
            != index
        ):
            raise RuntimeError("preparerawop fee-input indexes are not contiguous")
        if not isinstance(item["sighash_hex"], str) or not TXID_RE.fullmatch(item["sighash_hex"]):
            raise RuntimeError("preparerawop input sighash is malformed")
        if item["prev_script_hex"] != fund_spk.hex():
            raise RuntimeError("preparerawop fee input is not owned by the fee-fund address")

    fee = _strict_int(prepared.get("fee"), "preparerawop fee", 1)
    total_input = _strict_int(prepared.get("total_input"), "preparerawop total_input", 1)
    change = _strict_int(prepared.get("change"), "preparerawop change")
    total_output = _strict_int(prepared.get("total_output"), "preparerawop total_output")
    if fee != VELD_OP_FEE_UNITS or total_output != 0 or total_input != change + fee:
        raise RuntimeError("preparerawop fee/change metadata violates the exact policy")

    validate_op_tx_outputs(parsed, fund_addr, op_string, expected_change=change)
    return parsed, fund_spk, fee, total_input


def extract_op_return(script):
    if not script or script[0] != 0x6A or len(script) < 2:
        return None
    off = 1
    opcode = script[off]
    off += 1
    if opcode <= 75:
        size = opcode
    elif opcode == 0x4C:
        if off >= len(script):
            raise RuntimeError("truncated OP_PUSHDATA1")
        size = script[off]
        off += 1
        if size <= 75:
            raise RuntimeError("non-canonical OP_PUSHDATA1")
    elif opcode == 0x4D:
        if off + 2 > len(script):
            raise RuntimeError("truncated OP_PUSHDATA2")
        size = int.from_bytes(script[off : off + 2], "little")
        off += 2
        if size <= 255:
            raise RuntimeError("non-canonical OP_PUSHDATA2")
    else:
        raise RuntimeError("unsupported OP_RETURN push opcode")
    if off + size != len(script):
        raise RuntimeError("OP_RETURN push length/trailing bytes mismatch")
    return script[off:]


def validate_spv_amount(peg, amount_sats):
    try:
        per_mint = _strict_int(peg["spv_max_per_mint_sats"], "SPV per-mint cap", 1)
        custody_cap = _strict_int(peg["spv_max_custody_sats"], "SPV custody cap", 1)
        supply = _strict_int(peg["supply_sats"], "btcVELD supply")
    except (KeyError, TypeError, ValueError, RuntimeError) as exc:
        raise RuntimeError("getpeginfo lacks exact SPV cap/supply fields") from exc
    if supply > custody_cap:
        raise RuntimeError("getpeginfo reports an invalid SPV cap/supply state")
    headroom = custody_cap - supply
    if amount_sats <= 0 or amount_sats > per_mint or amount_sats > headroom:
        raise RuntimeError("deposit amount exceeds current compiled SPV per-mint/custody headroom")
    return headroom


def validate_deposit_tx(
    legacy_tx, custody_spk_hex, peg, expected_recipient=None, expected_amount=None
):
    parsed = parse_and_strip_bitcoin_tx(legacy_tx)
    if parsed["segwit"] or parsed["legacy"] != legacy_tx:
        raise RuntimeError("deposit validator requires exact legacy/txid serialization")
    custody_spk = _validate_hex_bytes(
        custody_spk_hex, "compiled SPV custody script", 34, minimum=34
    )
    if not custody_spk.startswith(b"\x51\x20"):
        raise RuntimeError("compiled SPV custody script is not canonical P2TR")
    custody = [o for o in parsed["outputs"] if o["script"] == custody_spk]
    if len(custody) != 1:
        raise RuntimeError("deposit must contain exactly one index-0 custody output")

    op_returns = []
    for output in parsed["outputs"]:
        data = extract_op_return(output["script"])
        if data is not None:
            if output["value_sats"] != 0:
                raise RuntimeError("deposit OP_RETURN carries value")
            op_returns.append(data)
    if len(op_returns) != 1 or not op_returns[0].startswith(RECIPIENT_TAG):
        raise RuntimeError("deposit must contain exactly one btcVELD recipient OP_RETURN")
    try:
        recipient = op_returns[0][len(RECIPIENT_TAG) :].decode("ascii")
    except UnicodeDecodeError as exc:
        raise RuntimeError("deposit recipient marker is not canonical ASCII") from exc
    veld_p2pkh_from_address(recipient, "deposit recipient marker")
    if expected_recipient is not None and recipient != expected_recipient:
        raise RuntimeError("deposit recipient differs from the requested VELD address")

    amount = custody[0]["value_sats"]
    if expected_amount is not None and amount != expected_amount:
        raise RuntimeError("deposit custody amount differs from the requested satoshis")
    validate_spv_amount(peg, amount)
    return {
        "recipient": recipient,
        "amount_sats": amount,
        "vout": custody[0]["vout"],
    }


def build_merkle_branch(txids_internal, index):
    if not txids_internal or index < 0 or index >= len(txids_internal):
        raise RuntimeError("invalid Merkle leaf/index")
    if any(not isinstance(item, bytes) or len(item) != 32 for item in txids_internal):
        raise RuntimeError("Merkle leaves must be bytes32")
    level = list(txids_internal)
    branch = []
    dirs = 0
    depth = 0
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        sibling = index ^ 1
        branch.append(level[sibling])
        if sibling < index:
            dirs |= 1 << depth
        level = [dsha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        index >>= 1
        depth += 1
        if depth > 32:
            raise RuntimeError("Merkle branch exceeds consensus depth")
    return tuple(branch), dirs, level[0]


def fold_merkle(leaf, branch, dirs):
    value = leaf
    for depth, sibling in enumerate(branch):
        value = dsha(sibling + value) if ((dirs >> depth) & 1) else dsha(value + sibling)
    return value


def _rpc_arg(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, separators=(",", ":"))
    return str(value)


def _validate_argv(argv, label):
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 64
        or any(
            not isinstance(item, str)
            or not item
            or "\x00" in item
            or len(item.encode("utf-8")) > 4096
            for item in argv
        )
    ):
        raise RuntimeError("%s must be a bounded nonempty argv array" % label)
    if not os.path.isabs(argv[0]):
        raise RuntimeError("%s executable path must be absolute" % label)
    return list(argv)


def _validate_executable(path, label):
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        raise RuntimeError("%s path must be absolute" % label)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise RuntimeError("platform lacks O_NOFOLLOW required for %s" % label)
    try:
        fd = os.open(path, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise RuntimeError("cannot open trusted %s: %s" % (label, exc)) from exc
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or mode & 0o022
            or not mode & 0o111
        ):
            raise RuntimeError(
                "%s must be a root/service-owned, single-link, non-writable executable" % label
            )
    finally:
        os.close(fd)


def _subprocess_env():
    """Keep only the secret and locale needed by trusted operator binaries."""
    result = {"PATH": "/usr/bin:/bin"}
    for name in ("VELD_VAULT_PASSPHRASE", "LANG", "LC_ALL", "TZ"):
        value = os.environ.get(name)
        if value is not None:
            result[name] = value
    return result


class BitcoinCLI:
    def __init__(self, cli_base, wallet, timeout=60):
        cli_base = _validate_argv(cli_base, "bitcoin.cli_base")
        _validate_executable(cli_base[0], "bitcoin-cli")
        if any(x.startswith("-rpcwallet") for x in cli_base):
            raise RuntimeError("put bitcoin.wallet in config, not -rpcwallet in cli_base")
        if (
            not isinstance(wallet, str)
            or not wallet
            or "\x00" in wallet
            or len(wallet.encode("utf-8")) > 255
        ):
            raise RuntimeError("a configured Bitcoin Core mainnet wallet is required")
        self.node_base = list(cli_base)
        self.wallet_base = list(cli_base) + ["-rpcwallet=" + wallet]
        self.timeout = _strict_int(timeout, "bitcoin.rpc_timeout", 1, 600)

    def call(self, method, *args, wallet=False):
        base = self.wallet_base if wallet else self.node_base
        result = run_bounded_subprocess(
            base + [method] + [_rpc_arg(x) for x in args],
            timeout=self.timeout,
            stdout_max=MAX_BITCOIN_CLI_STDOUT,
            stderr_max=MAX_SUBPROCESS_STDERR,
            description="bitcoin-cli %s" % method,
        )
        if result.returncode != 0:
            raise RuntimeError("bitcoin-cli %s: %s" % (method, result.stderr.strip()[:400]))
        text = result.stdout.strip()
        try:
            return strict_json_loads(text, "bitcoin-cli %s response" % method)
        except (ValueError, TypeError) as exc:
            if text[:1] in ("{", "[", '"'):
                raise RuntimeError("bitcoin-cli %s returned malformed JSON" % method) from exc
            return text


class VeldRPC:
    def __init__(self, config):
        try:
            self.url = validate_loopback_http_rpc_url(config.get("url", ""), "veld_rpc.url")
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        token_cmd = config.get("token_cmd")
        token_file = config.get("token_file")
        self.token = ""
        if token_cmd and token_file:
            raise RuntimeError("configure only one of veld_rpc.token_cmd/token_file")
        if token_cmd:
            token_cmd = _validate_argv(token_cmd, "veld_rpc.token_cmd")
            _validate_executable(token_cmd[0], "Veld RPC token command")
            result = run_bounded_subprocess(
                token_cmd,
                timeout=30,
                stdout_max=4096,
                stderr_max=MAX_SUBPROCESS_STDERR,
                description="Veld RPC token command",
                env=_subprocess_env(),
            )
            if result.returncode != 0:
                raise RuntimeError("Veld RPC token command failed: " + result.stderr.strip()[:200])
            self.token = result.stdout.strip()
        elif token_file:
            try:
                self.token = (
                    read_bounded_secret_file(token_file, 4096, "Veld RPC token")
                    .decode("ascii")
                    .strip()
                )
            except UnicodeDecodeError as exc:
                raise RuntimeError("Veld RPC token is not ASCII") from exc
        if not TXID_RE.fullmatch(self.token):
            raise RuntimeError("Veld RPC bearer token must be one lowercase 64-hex token")

    def rpc(self, method, params=None):
        body = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []},
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=body,
            headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"},
        )
        with open_rpc_request(request, timeout=60) as rpc_response:
            response = load_bounded_json_response(
                rpc_response, 32 * 1024 * 1024, "Veld RPC response"
            )
        if not isinstance(response, dict):
            raise RuntimeError("%s: malformed JSON-RPC envelope" % method)
        if response.get("error") is not None:
            raise RuntimeError("%s: %s" % (method, response["error"]))
        if "result" not in response:
            raise RuntimeError("%s: JSON-RPC envelope omitted result" % method)
        return response.get("result")


class RelaySigner:
    def __init__(self, config, state_dir):
        self.keygen = config.get("keygen", "")
        self.keyfile = config.get("keyfile", "")
        self.state_dir = state_dir
        if not os.path.isabs(self.keygen) or not os.path.isabs(self.keyfile):
            raise RuntimeError("signer keygen/keyfile paths must be absolute")
        _validate_executable(self.keygen, "veld-keygen")
        if "passphrase" in config:
            raise RuntimeError("plaintext signer.passphrase is forbidden; use the environment")

    def sign(self, unsigned_tx_hex, prev_script_hex):
        parse_veld_tx_hex(unsigned_tx_hex, signed=False)
        _validate_hex_bytes(prev_script_hex, "signer prev_script_hex", 10_000)
        key_material = read_bounded_secret_file(
            self.keyfile, MAX_KEYFILE_BYTES, "Veld signer keyfile"
        )
        with tempfile.TemporaryDirectory(prefix="spvmint-sign.", dir=self.state_dir) as workdir:
            os.chmod(workdir, 0o700)
            prepared_path = os.path.join(workdir, "prepared.json")
            key_path = os.path.join(workdir, "relay-fee.key")
            for path, content in ((key_path, key_material),):
                fd = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0), 0o600
                )
                with os.fdopen(fd, "wb") as target:
                    target.write(content)
                    target.flush()
                    os.fsync(target.fileno())
            with open(prepared_path, "x", encoding="utf-8") as prepared:
                os.fchmod(prepared.fileno(), 0o600)
                json.dump(
                    {"unsigned_tx_hex": unsigned_tx_hex, "prev_script_hex": prev_script_hex},
                    prepared,
                    separators=(",", ":"),
                )
                prepared.flush()
                os.fsync(prepared.fileno())
            result = run_bounded_subprocess(
                [self.keygen, "sign-op", key_path, prepared_path],
                input_text="",
                timeout=120,
                stdout_max=2 * MAX_VELD_TX_BYTES + 2,
                stderr_max=MAX_SUBPROCESS_STDERR,
                description="veld-keygen sign-op",
                env=_subprocess_env(),
            )
            if result.returncode != 0:
                raise RuntimeError("veld-keygen sign-op failed: " + result.stderr.strip()[:400])
            signed = result.stdout.strip()
            _validate_hex_bytes(
                signed, "veld-keygen signed transaction", MAX_VELD_TX_BYTES, minimum=50
            )
            return signed


def _open_private_directory(path, label="state_dir"):
    if not isinstance(path, str) or not os.path.isabs(path) or "\x00" in path:
        raise RuntimeError(label + " must be an absolute path")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    odirectory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or odirectory is None:
        raise RuntimeError("platform lacks secure directory-open flags")
    fd = os.open(path, os.O_RDONLY | nofollow | odirectory | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()) or mode & 0o077:
            raise RuntimeError("%s must be a root/service-owned owner-only real directory" % label)
    except Exception:
        os.close(fd)
        raise
    return fd


def _validate_state_shape(value):
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value.get("schema") != STATE_SCHEMA
        or not isinstance(value.get("bitcoin_txs"), dict)
        or not isinstance(value.get("deposits"), dict)
    ):
        raise RuntimeError("SPV state schema is invalid")
    if len(value["bitcoin_txs"]) > MAX_STATE_RECORDS or len(value["deposits"]) > MAX_STATE_RECORDS:
        raise RuntimeError("SPV state record count exceeds the safety bound")
    if any(
        not isinstance(key, str) or not TXID_RE.fullmatch(key) or not isinstance(item, dict)
        for key, item in value["bitcoin_txs"].items()
    ):
        raise RuntimeError("SPV state contains a malformed Bitcoin transaction record")
    if any(
        not isinstance(key, str)
        or not re.fullmatch(r"[0-9a-f]{64}:(0|[1-9][0-9]{0,9})", key)
        or not isinstance(item, dict)
        for key, item in value["deposits"].items()
    ):
        raise RuntimeError("SPV state contains a malformed deposit record")
    return value


def load_state(path):
    directory = os.path.dirname(path)
    directory_fd = _open_private_directory(directory, "SPV state directory")
    os.close(directory_fd)
    try:
        value = load_bounded_json_file(path, MAX_STATE_BYTES, "SPV state", private=True)
    except FileNotFoundError:
        return {"schema": STATE_SCHEMA, "bitcoin_txs": {}, "deposits": {}}
    except OSError as exc:
        raise RuntimeError("cannot securely read linked/non-regular SPV state: %s" % exc) from exc
    return _validate_state_shape(value)


def save_state(path, value):
    _validate_state_shape(value)
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_STATE_BYTES:
        raise RuntimeError("SPV state exceeds the durable file safety bound")
    directory = os.path.dirname(path)
    basename = os.path.basename(path)
    if not basename or basename in (".", "..") or os.sep in basename:
        raise RuntimeError("SPV state path is malformed")
    directory_fd = _open_private_directory(directory, "SPV state directory")
    temporary = ".spvmint-state.%s.tmp" % os.urandom(16).hex()
    fd = -1
    try:
        try:
            existing = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (
            not stat.S_ISREG(existing.st_mode)
            or existing.st_nlink != 1
            or existing.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(existing.st_mode) & 0o077
        ):
            raise RuntimeError("existing SPV state is not a private single-link file")
        fd = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        with os.fdopen(fd, "wb") as target:
            fd = -1
            target.write(encoded)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, basename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        os.close(directory_fd)


def _open_lock(path):
    directory = os.path.dirname(path)
    basename = os.path.basename(path)
    directory_fd = _open_private_directory(directory, "SPV state directory")
    try:
        fd = os.open(
            basename,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise RuntimeError("SPV lock must be a private single-link regular file")
        os.fchmod(fd, 0o600)
        return os.fdopen(fd, "a+", encoding="ascii")
    except Exception:
        os.close(fd)
        raise


class SpvOperator:
    def __init__(self, config, btc=None, veld=None, signer=None):
        if not isinstance(config, dict):
            raise RuntimeError("SPV config root must be an object")
        self.config = config
        self.state_dir = config.get("state_dir", "")
        if (
            not isinstance(self.state_dir, str)
            or not os.path.isabs(self.state_dir)
            or "\x00" in self.state_dir
        ):
            raise RuntimeError("state_dir must be absolute")
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        state_dir_fd = _open_private_directory(self.state_dir)
        os.close(state_dir_fd)
        self.state_path = os.path.join(self.state_dir, "spvmint-state.json")
        bitcoin = config.get("bitcoin") or {}
        if not isinstance(bitcoin, dict):
            raise RuntimeError("bitcoin config must be an object")
        self.btc = btc or BitcoinCLI(
            bitcoin.get("cli_base"), bitcoin.get("wallet"), bitcoin.get("rpc_timeout", 60)
        )
        self.veld = veld or VeldRPC(config.get("veld_rpc") or {})
        self.fund_addr = config.get("veld_fee_fund_address", "")
        veld_p2pkh_from_address(self.fund_addr, "veld_fee_fund_address")
        self.signer = signer or RelaySigner(config.get("signer") or {}, self.state_dir)
        self.manifest_path = config.get("custody_manifest", "")
        self.binding = None
        self.identity_fingerprint = None
        self.custody_address = None

    def _btc(self, method, *args, wallet=False):
        return self.btc.call(method, *args, wallet=wallet)

    def _coherent_peg(self):
        """Bracket getpeginfo with the chain-coherent supply/tip snapshot."""
        before = self.veld.rpc("getbtcveldsupply")
        peg = self.veld.rpc("getpeginfo")
        after = self.veld.rpc("getbtcveldsupply")
        if not isinstance(before, dict) or before != after:
            raise Pending("Veld tip/supply changed during identity sampling; retry")
        try:
            supply = _strict_int(before["supply_sats"], "coherent btcVELD supply")
            tip = _strict_int(before["tip"], "coherent Veld tip")
            tip_hash = before["tip_hash"]
        except KeyError as exc:
            raise RuntimeError("getbtcveldsupply omitted coherent identity fields") from exc
        if not isinstance(tip_hash, str) or not TXID_RE.fullmatch(tip_hash):
            raise RuntimeError("getbtcveldsupply returned an invalid tip hash")
        if not isinstance(peg, dict) or peg.get("supply_sats") != supply or peg.get("tip") != tip:
            raise Pending("getpeginfo did not match the coherent Veld supply snapshot")
        peg = dict(peg)
        peg["_coherent_tip"] = tip
        peg["_coherent_tip_hash"] = tip_hash
        return peg

    def _identity(self, full_derivation=False):
        chain = self._btc("getblockchaininfo")
        if (
            not isinstance(chain, dict)
            or chain.get("chain") != "main"
            or chain.get("initialblockdownload") is not False
        ):
            raise RuntimeError("Bitcoin Core must be a synced mainnet node")
        headers = _strict_int(chain.get("headers"), "Bitcoin header height")
        blocks = _strict_int(chain.get("blocks"), "Bitcoin block height")
        if headers < blocks:
            raise RuntimeError("Bitcoin Core reports an invalid block/header state")

        peg = self._coherent_peg()
        if (
            peg.get("token_id") != "btcVELD"
            or peg.get("active") is not True
            or peg.get("spv_active") is not True
            or peg.get("peg_unlocked") is not True
            or peg.get("mint_live") is not True
        ):
            raise RuntimeError("getpeginfo is not the btcVELD launch peg")
        try:
            k_btc = _strict_int(peg["spv_k_btc"], "compiled spv_k_btc", 1, 32)
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            raise RuntimeError("getpeginfo lacks compiled spv_k_btc") from exc
        validate_spv_amount_fields = (
            _strict_int(peg.get("spv_max_per_mint_sats"), "SPV per-mint cap", 1),
            _strict_int(peg.get("spv_max_custody_sats"), "SPV custody cap", 1),
            _strict_int(peg.get("supply_sats"), "btcVELD supply"),
        )
        if validate_spv_amount_fields[2] > validate_spv_amount_fields[1]:
            raise RuntimeError("getpeginfo reports invalid SPV economics")

        binding = custody_binding.load_manifest(
            self.manifest_path,
            peg.get("custody_descriptor_sha256"),
            peg.get("custody_manifest_sha256"),
            peg.get("spv_custody_spk_hex"),
            require_absolute=True,
        )
        custody_binding.verify_peg_identity(peg, binding)
        fingerprint = (
            binding["descriptor_sha256"],
            binding["manifest_sha256"],
            binding["spv_custody_spk_hex"],
            k_btc,
            validate_spv_amount_fields[0],
            validate_spv_amount_fields[1],
        )
        if self.identity_fingerprint is not None and fingerprint != self.identity_fingerprint:
            raise RuntimeError("btcVELD compiled identity/economics drifted during operation")

        addresses = self._btc("deriveaddresses", binding["descriptor"], "[0,0]")
        if not isinstance(addresses, list) or len(addresses) != 1:
            raise RuntimeError("Bitcoin Core did not derive descriptor index 0 exactly")
        address = addresses[0]
        if custody_binding._bech32m_spk(address) != binding["spv_custody_spk_hex"]:
            raise RuntimeError("derived descriptor-index-0 address differs from compiled SPK")
        if full_derivation:
            custody_binding.verify_core_derivation(
                lambda method, *args: self._btc(method, *args), binding
            )

        self.binding = binding
        self.identity_fingerprint = fingerprint
        self.custody_address = address
        return peg, chain

    def _validate_final_deposit(self, raw_hex, peg, recipient, amount, change_pos):
        raw = _validate_hex_bytes(
            raw_hex, "finalized Bitcoin transaction", MAX_BITCOIN_TX_BYTES, minimum=10
        )
        parsed = parse_and_strip_bitcoin_tx(raw)
        result = validate_deposit_tx(
            parsed["legacy"],
            self.binding["spv_custody_spk_hex"],
            peg,
            expected_recipient=recipient,
            expected_amount=amount,
        )
        output_count = len(parsed["outputs"])
        expected_count = 3 if change_pos >= 0 else 2
        if output_count != expected_count:
            raise RuntimeError("funded deposit has an unexpected extra output")
        if change_pos >= 0:
            if change_pos >= output_count or change_pos in (result["vout"],):
                raise RuntimeError("wallet reported an invalid deposit change position")
            change = parsed["outputs"][change_pos]
            if (
                extract_op_return(change["script"]) is not None
                or change["script"].hex() == self.binding["spv_custody_spk_hex"]
            ):
                raise RuntimeError("deposit change collides with custody/OP_RETURN")
            decoded = self._btc("decodescript", change["script"].hex())
            address = decoded.get("address") if isinstance(decoded, dict) else None
            if not address:
                raise RuntimeError("deposit change output has no standard address")
            info = self._btc("getaddressinfo", address, wallet=True)
            if not isinstance(info, dict) or info.get("ismine") is not True:
                raise RuntimeError("deposit change is not owned by the configured wallet")
        local_txid = dsha(parsed["legacy"])[::-1].hex()
        return parsed, result, local_txid

    def _recover_broadcasting_deposit(self, recipient, amount_sats, peg):
        """Replay one durable pre-broadcast Bitcoin transaction byte-for-byte.

        A crash after the raw transaction WAL but before the final state update
        must not cause a second wallet-funded deposit on CLI retry.  Different
        deposit parameters are held until the existing WAL is resolved.
        """
        state = load_state(self.state_path)
        pending = [
            (txid, item)
            for txid, item in state["bitcoin_txs"].items()
            if isinstance(item, dict) and item.get("status") == "broadcasting"
        ]
        if not pending:
            return None
        if len(pending) != 1:
            raise RuntimeError("multiple unresolved broadcasting Bitcoin deposits require review")
        txid, record = pending[0]
        if (
            not TXID_RE.fullmatch(txid)
            or record.get("recipient") != recipient
            or record.get("amount_sats") != amount_sats
        ):
            raise RuntimeError(
                "an unresolved Bitcoin deposit must be retried with its original "
                "recipient and amount before creating another"
            )
        raw_hex = record.get("raw_hex")
        _validate_hex_bytes(
            raw_hex, "broadcasting Bitcoin deposit WAL", MAX_BITCOIN_TX_BYTES, minimum=10
        )

        change_pos = record.get("change_pos")
        if isinstance(change_pos, bool) or not isinstance(change_pos, int):
            # Upgrade recovery for the immediately preceding schema: infer the
            # sole non-custody/non-marker output, then authenticate its wallet
            # ownership through the normal final-deposit validator.
            preliminary = parse_and_strip_bitcoin_tx(bytes.fromhex(raw_hex))
            if len(preliminary["outputs"]) == 2:
                change_pos = -1
            elif len(preliminary["outputs"]) == 3:
                candidates = [
                    output["vout"]
                    for output in preliminary["outputs"]
                    if output["script"].hex() != self.binding["spv_custody_spk_hex"]
                    and extract_op_return(output["script"]) is None
                ]
                if len(candidates) != 1:
                    raise RuntimeError("cannot infer legacy deposit change output")
                change_pos = candidates[0]
            else:
                raise RuntimeError("broadcasting Bitcoin deposit has unexpected outputs")
        parsed, deposit, local_txid = self._validate_final_deposit(
            raw_hex, peg, recipient, amount_sats, change_pos
        )
        if (
            local_txid != txid
            or record.get("custody_vout") != deposit["vout"]
            or isinstance(record.get("fee_sats"), bool)
            or not isinstance(record.get("fee_sats"), int)
            or record["fee_sats"] <= 0
        ):
            raise RuntimeError("broadcasting Bitcoin deposit WAL identity is inconsistent")

        try:
            returned = str(self._btc("sendrawtransaction", raw_hex)).lower()
        except Exception:
            # Already-in-mempool/on-chain is a normal crash-recovery result.  Do
            # not suppress a real failure unless the exact tx is independently
            # retrievable by its locally derived txid.
            try:
                known = str(self._btc("getrawtransaction", local_txid, False)).lower()
                known_parsed = parse_and_strip_bitcoin_tx(
                    _validate_hex_bytes(
                        known, "known Bitcoin transaction", MAX_BITCOIN_TX_BYTES, minimum=10
                    )
                )
                if dsha(known_parsed["legacy"])[::-1].hex() != local_txid:
                    raise RuntimeError("known Bitcoin transaction has a mismatched txid")
            except Exception:
                raise
        else:
            if returned != local_txid:
                raise RuntimeError("Bitcoin rebroadcast txid differs from durable txid")
        fetched_hex = str(self._btc("getrawtransaction", local_txid, False)).lower()
        fetched = parse_and_strip_bitcoin_tx(
            _validate_hex_bytes(
                fetched_hex, "fetched Bitcoin transaction", MAX_BITCOIN_TX_BYTES, minimum=10
            )
        )
        if (
            dsha(fetched["legacy"])[::-1].hex() != local_txid
            or fetched["legacy"] != parsed["legacy"]
        ):
            raise RuntimeError("Bitcoin node returned bytes inconsistent with durable txid")

        outpoint = local_txid + ":" + str(deposit["vout"])
        state = load_state(self.state_path)
        current = state["bitcoin_txs"].get(local_txid)
        if not isinstance(current, dict) or current.get("raw_hex") != raw_hex:
            raise RuntimeError("Bitcoin deposit WAL changed during recovery")
        current["status"] = "broadcast"
        current["broadcast_at"] = int(time.time())
        current["change_pos"] = change_pos
        state["deposits"][outpoint] = {
            "status": "deposited",
            "btc_txid": local_txid,
            "vout": deposit["vout"],
            "recipient": recipient,
            "amount_sats": amount_sats,
            "btc_raw_hex": raw_hex,
        }
        save_state(self.state_path, state)
        return {
            "mode": "deposit",
            "btc_txid": local_txid,
            "outpoint": outpoint,
            "custody_address": self.custody_address,
            "custody_vout": deposit["vout"],
            "recipient": recipient,
            "amount_sats": amount_sats,
            "fee_sats": record["fee_sats"],
            "segwit_funded": bool(parsed["segwit"]),
            "required_confirmations": _strict_int(peg["spv_k_btc"], "compiled spv_k_btc", 1, 32)
            + 1,
            "recovered": True,
        }

    def deposit(self, recipient, amount_sats):
        veld_p2pkh_from_address(recipient, "recipient")
        if isinstance(amount_sats, bool) or not isinstance(amount_sats, int):
            raise RuntimeError("amount_sats must be an exact integer")
        peg, _ = self._identity(full_derivation=True)
        validate_spv_amount(peg, amount_sats)
        recovered = self._recover_broadcasting_deposit(recipient, amount_sats, peg)
        if recovered is not None:
            return recovered

        wallet_info = self._btc("getwalletinfo", wallet=True)
        if (
            not isinstance(wallet_info, dict)
            or wallet_info.get("private_keys_enabled") is not True
            or wallet_info.get("descriptors") is not True
        ):
            raise RuntimeError("configured Bitcoin wallet must be a private-key descriptor wallet")

        marker = RECIPIENT_TAG + recipient.encode("ascii")
        outputs_json = "[{%s:%s},{\"data\":%s}]" % (
            json.dumps(self.custody_address),
            sats_json(amount_sats),
            json.dumps(marker.hex()),
        )
        options = {
            "add_inputs": True,
            "includeWatching": False,
            "lockUnspents": False,
            "replaceable": False,
            "conf_target": _strict_int(
                (self.config.get("bitcoin") or {}).get("deposit_conf_target", 6),
                "bitcoin.deposit_conf_target",
                1,
                1008,
            ),
        }
        funded = self._btc(
            "walletcreatefundedpsbt", "[]", outputs_json, 0, options, True, wallet=True
        )
        if not isinstance(funded, dict) or not funded.get("psbt"):
            raise RuntimeError("walletcreatefundedpsbt returned no PSBT")
        change_pos = _strict_int(
            funded.get("changepos", -1), "wallet PSBT change position", -1, 100_000
        )
        fee_sats = btc_to_sats(funded.get("fee"))
        max_fee = _strict_int(
            (self.config.get("bitcoin") or {}).get("max_deposit_fee_sats", 100_000),
            "bitcoin.max_deposit_fee_sats",
            1,
        )
        if fee_sats <= 0 or fee_sats > max_fee:
            raise RuntimeError("Bitcoin deposit fee is zero or above configured ceiling")

        processed = self._btc("walletprocesspsbt", funded["psbt"], True, "ALL", True, wallet=True)
        if not isinstance(processed, dict) or not processed.get("psbt"):
            raise RuntimeError("walletprocesspsbt returned no signed PSBT")
        finalized = self._btc("finalizepsbt", processed["psbt"], True, wallet=True)
        if (
            not isinstance(finalized, dict)
            or finalized.get("complete") is not True
            or not finalized.get("hex")
        ):
            raise RuntimeError("Bitcoin deposit PSBT did not finalize completely")
        if not isinstance(finalized["hex"], str):
            raise RuntimeError("Bitcoin deposit PSBT returned non-text transaction hex")
        raw_hex = finalized["hex"].lower()
        parsed, deposit, local_txid = self._validate_final_deposit(
            raw_hex, peg, recipient, amount_sats, change_pos
        )

        # Re-sample compiled identity and aggregate headroom after funding and
        # signing, immediately before Bitcoin broadcast. A concurrent mint can
        # consume capacity while the wallet is constructing its PSBT.
        live_peg, _ = self._identity(full_derivation=False)
        validate_deposit_tx(
            parsed["legacy"],
            self.binding["spv_custody_spk_hex"],
            live_peg,
            expected_recipient=recipient,
            expected_amount=amount_sats,
        )

        acceptance = self._btc("testmempoolaccept", [raw_hex])
        if (
            not isinstance(acceptance, list)
            or len(acceptance) != 1
            or not isinstance(acceptance[0], dict)
            or acceptance[0].get("allowed") is not True
        ):
            reason = (
                acceptance[0].get("reject-reason")
                if acceptance and isinstance(acceptance[0], dict)
                else "no result"
            )
            raise RuntimeError("Bitcoin Core rejected deposit preflight: " + str(reason))
        wire_wtxid = dsha(bytes.fromhex(raw_hex))[::-1].hex()
        if acceptance[0].get("txid") != local_txid or acceptance[0].get("wtxid") != wire_wtxid:
            raise RuntimeError("Bitcoin mempool preflight changed transaction identity")
        fees = acceptance[0].get("fees")
        actual_fee = btc_to_sats(fees.get("base") if isinstance(fees, dict) else None)
        if actual_fee != fee_sats or actual_fee > max_fee:
            raise RuntimeError("Bitcoin deposit actual fee differs from the bounded PSBT fee")

        state = load_state(self.state_path)
        state["bitcoin_txs"][local_txid] = {
            "status": "broadcasting",
            "raw_hex": raw_hex,
            "recipient": recipient,
            "amount_sats": amount_sats,
            "custody_vout": deposit["vout"],
            "fee_sats": fee_sats,
            "change_pos": change_pos,
            "created_at": int(time.time()),
        }
        save_state(self.state_path, state)
        broadcast_txid = str(self._btc("sendrawtransaction", raw_hex)).lower()
        if broadcast_txid != local_txid:
            raise RuntimeError("Bitcoin broadcast txid differs from locally verified txid")
        fetched_hex = str(self._btc("getrawtransaction", local_txid, False)).lower()
        fetched = parse_and_strip_bitcoin_tx(
            _validate_hex_bytes(
                fetched_hex, "fetched Bitcoin transaction", MAX_BITCOIN_TX_BYTES, minimum=10
            )
        )
        if (
            dsha(fetched["legacy"])[::-1].hex() != local_txid
            or fetched["legacy"] != parsed["legacy"]
        ):
            raise RuntimeError("Bitcoin node returned bytes inconsistent with broadcast txid")

        outpoint = local_txid + ":" + str(deposit["vout"])
        state = load_state(self.state_path)
        current = state["bitcoin_txs"].get(local_txid)
        if (
            not isinstance(current, dict)
            or current.get("status") != "broadcasting"
            or current.get("raw_hex") != raw_hex
        ):
            raise RuntimeError("Bitcoin deposit WAL changed after broadcast")
        current["status"] = "broadcast"
        current["broadcast_at"] = int(time.time())
        state["deposits"][outpoint] = {
            "status": "deposited",
            "btc_txid": local_txid,
            "vout": deposit["vout"],
            "recipient": recipient,
            "amount_sats": amount_sats,
            "btc_raw_hex": raw_hex,
        }
        save_state(self.state_path, state)
        return {
            "mode": "deposit",
            "btc_txid": local_txid,
            "outpoint": outpoint,
            "custody_address": self.custody_address,
            "custody_vout": deposit["vout"],
            "recipient": recipient,
            "amount_sats": amount_sats,
            "fee_sats": fee_sats,
            "segwit_funded": bool(parsed["segwit"]),
            "required_confirmations": _strict_int(peg["spv_k_btc"], "compiled spv_k_btc", 1, 32)
            + 1,
        }

    def _find_confirmed_tx(self, txid):
        block_hash = None
        try:
            wallet_tx = self._btc("gettransaction", txid, wallet=True)
            if isinstance(wallet_tx, dict):
                block_hash = wallet_tx.get("blockhash")
        except Exception:
            pass
        if block_hash:
            verbose = self._btc("getrawtransaction", txid, True, block_hash)
        else:
            verbose = self._btc("getrawtransaction", txid, True)
            if isinstance(verbose, dict):
                block_hash = verbose.get("blockhash")
        if not isinstance(verbose, dict) or not block_hash:
            raise Pending("Bitcoin deposit is not yet in a canonical block")
        if (
            not isinstance(block_hash, str)
            or not TXID_RE.fullmatch(block_hash)
            or verbose.get("txid") not in (None, txid)
            or verbose.get("blockhash") not in (None, block_hash)
        ):
            raise RuntimeError("Bitcoin transaction lookup returned a mismatched identity")
        confirmations = _strict_int(
            verbose.get("confirmations", 0), "Bitcoin transaction confirmations", -1
        )
        if confirmations < 0:
            raise RuntimeError("Bitcoin deposit is conflicted/orphaned")
        return block_hash, confirmations

    def _assert_bitcoin_finality(self, block_hash, block_height, k_btc):
        mapped = self._btc("getblockhash", block_height)
        if not isinstance(mapped, str) or mapped.lower() != block_hash:
            raise RuntimeError("Bitcoin reorg changed the deposit height mapping")
        tip = _strict_int(self._btc("getblockcount"), "Bitcoin best height")
        header = self._btc("getblockheader", block_hash, True)
        if (
            not isinstance(header, dict)
            or header.get("hash") not in (None, block_hash)
            or _strict_int(header.get("height"), "Bitcoin deposit block height") != block_height
            or _strict_int(header.get("confirmations"), "Bitcoin deposit block confirmations", -1)
            < k_btc + 1
            or block_height + k_btc > tip
        ):
            raise Pending("Bitcoin deposit lost its required burial depth; retry")
        return tip

    def _assert_relay_finality(self, block_height, k_btc):
        relay = self.veld.rpc("getbtcheaderinfo")
        if (
            not isinstance(relay, dict)
            or relay.get("spv_active") is not True
            or _strict_int(relay.get("k_btc"), "relay k_btc", 1, 32) != k_btc
        ):
            raise RuntimeError("Veld BTC-header relay identity differs from getpeginfo")
        best = _strict_int(relay.get("best_height"), "relay best_height")
        if best < block_height + k_btc:
            raise Pending("Veld BTC-header relay has not reached deposit finality height")
        return best

    def _ready_proof(self, txid, peg):
        block_hash, confirmations = self._find_confirmed_tx(txid)
        header = self._btc("getblockheader", block_hash, True)
        if (
            not isinstance(header, dict)
            or _strict_int(header.get("confirmations", 0), "Bitcoin block confirmations", -1) <= 0
            or type(header.get("height")) is not int
        ):
            raise RuntimeError("deposit block is not on Bitcoin Core's best chain")
        block_height = _strict_int(header["height"], "Bitcoin deposit block height")
        k_btc = _strict_int(peg["spv_k_btc"], "compiled spv_k_btc", 1, 32)
        btc_tip = _strict_int(self._btc("getblockcount"), "Bitcoin best height")
        if block_height + k_btc > btc_tip or confirmations < k_btc + 1:
            raise Pending(
                "deposit needs %d confirmations (%d current)" % (k_btc + 1, confirmations)
            )

        self._assert_relay_finality(block_height, k_btc)

        block = self._btc("getblock", block_hash, 1)
        txids = block.get("tx") if isinstance(block, dict) else None
        if (
            not isinstance(txids, list)
            or not txids
            or len(txids) > MAX_BLOCK_TXIDS
            or any(not isinstance(item, str) or not TXID_RE.fullmatch(item) for item in txids)
            or txids.count(txid) != 1
        ):
            raise RuntimeError("deposit block has an invalid/ambiguous ordered txid list")
        if block.get("hash") not in (None, block_hash) or block.get("height") not in (
            None,
            block_height,
        ):
            raise RuntimeError("Bitcoin block response changed hash/height identity")
        index = txids.index(txid)
        branch, dirs, root = build_merkle_branch([be_to_le(item) for item in txids], index)
        merkle_root = block.get("merkleroot")
        if not isinstance(merkle_root, str) or not TXID_RE.fullmatch(merkle_root):
            raise RuntimeError("Bitcoin block returned an invalid Merkle root")
        if root != be_to_le(merkle_root) or fold_merkle(be_to_le(txid), branch, dirs) != root:
            raise RuntimeError("locally built Merkle branch does not match block root")

        raw_hex = str(self._btc("getrawtransaction", txid, False, block_hash)).lower()
        parsed = parse_and_strip_bitcoin_tx(
            _validate_hex_bytes(raw_hex, "Bitcoin raw deposit", MAX_BITCOIN_TX_BYTES, minimum=10)
        )
        legacy = parsed["legacy"]
        if dsha(legacy)[::-1].hex() != txid:
            raise RuntimeError("stripped Bitcoin transaction does not hash to deposit txid")
        deposit = validate_deposit_tx(legacy, self.binding["spv_custody_spk_hex"], peg)

        # Reorg/identity barrier immediately before proof material leaves this
        # function. A changed height mapping is never silently followed.
        self._assert_bitcoin_finality(block_hash, block_height, k_btc)
        self._assert_relay_finality(block_height, k_btc)
        current_peg, _ = self._identity(full_derivation=False)
        if current_peg["supply_sats"] != peg["supply_sats"]:
            # Supply races are safe in consensus, but fail here so the operator
            # consciously re-evaluates current headroom rather than wasting a fee.
            raise Pending("btcVELD supply changed while constructing proof; retry")

        outpoint = txid + ":" + str(deposit["vout"])
        nullifier = self._mint_status(outpoint)
        nullifier_bytes = bytes.fromhex(nullifier["proof_hex"])
        payload = (
            PROOF_MAGIC
            + be_to_le(block_hash)
            + struct.pack("<I", dirs)
            + bytes([len(branch)])
            + b"".join(branch)
            + struct.pack("<I", len(legacy))
            + legacy
            + nullifier_bytes
        )
        op_string = OP_PREFIX + payload.hex()
        if not (RAW_OP_MIN_CHARS <= len(op_string) <= RAW_OP_MAX_CHARS):
            raise RuntimeError("MSPV proof exceeds preparerawop 24,000-character policy cap")
        return {
            "block_hash": block_hash,
            "block_height": block_height,
            "confirmations": confirmations,
            "branch_len": len(branch),
            "op_string": op_string,
            "legacy_tx": legacy,
            "deposit": deposit,
            "segwit": parsed["segwit"],
            "k_btc": k_btc,
            "peg_supply_sats": peg["supply_sats"],
            "nullifier_root": nullifier["root"],
            "nullifier_count": nullifier["count"],
            "nullifier_proof_hex": nullifier["proof_hex"],
        }

    def _mint_status(self, outpoint):
        status = self.veld.rpc("getbtcveldmintstatus", [outpoint])
        if (
            not isinstance(status, dict)
            or status.get("outpoint") != outpoint
            or not isinstance(status.get("consumed"), bool)
            or status.get("proof_version") != NULLIFIER_PROOF_VERSION
            or not isinstance(status.get("proof_hex"), str)
            or not HEX_RE.fullmatch(status["proof_hex"])
            or not isinstance(status.get("root"), str)
            or not TXID_RE.fullmatch(status["root"])
            or not isinstance(status.get("tip_hash"), str)
            or not TXID_RE.fullmatch(status["tip_hash"])
        ):
            raise RuntimeError("getbtcveldmintstatus returned an invalid response")
        proof = bytes.fromhex(status["proof_hex"])
        if (
            not NULLIFIER_MIN_PROOF_BYTES <= len(proof) <= NULLIFIER_MAX_PROOF_BYTES
            or len(proof) != 32 + sum(byte.bit_count() for byte in proof[:32]) * 32
        ):
            raise RuntimeError("getbtcveldmintstatus returned a non-canonical proof shape")
        _strict_int(status.get("count"), "nullifier count", 0)
        _strict_int(status.get("tip"), "nullifier tip", 0)
        return status

    def _mint_consumed(self, outpoint):
        return self._mint_status(outpoint)["consumed"]

    def _validate_fee_prevouts(self, parsed, fund_spk, expected_total=None):
        total = 0
        for tx_input in parsed["inputs"]:
            prevout = self.veld.rpc("gettxout", [tx_input["txid"], str(tx_input["vout"])])
            if (
                not isinstance(prevout, dict)
                or prevout.get("txid") != tx_input["txid"]
                or prevout.get("vout") != tx_input["vout"]
                or prevout.get("script_pubkey_hex") != fund_spk.hex()
                or _strict_int(prevout.get("confirmations"), "Veld fee prevout confirmations", 1)
                < 1
            ):
                raise RuntimeError("Veld fee prevout is missing or changed identity")
            total += _strict_int(prevout.get("value_units"), "Veld fee prevout value", 1)
            if total > MAX_WIRE_INT:
                raise RuntimeError("Veld fee prevout total overflowed")
        output_total = sum(item["value_units"] for item in parsed["outputs"])
        if (
            expected_total is not None and total != expected_total
        ) or total - output_total != VELD_OP_FEE_UNITS:
            raise RuntimeError("Veld relay transaction does not preserve the exact fee")
        return total

    def _veld_tx_known(self, txid, signed):
        try:
            entry = self.veld.rpc("getmempoolentry", [txid])
        except Exception:
            entry = None
        else:
            if not isinstance(entry, dict):
                raise RuntimeError("getmempoolentry returned a malformed response")
            if not entry.get("error"):
                if entry.get("txid") != txid or entry.get("raw_hex") != signed:
                    raise RuntimeError("mempool returned a mismatched durable Veld transaction")
                return True
        try:
            known = self.veld.rpc("getrawtransaction", [txid])
        except Exception:
            return False
        if (
            not isinstance(known, dict)
            or known.get("txid") != txid
            or known.get("raw_hex") != signed
        ):
            raise RuntimeError("chain returned a mismatched durable Veld transaction")
        return True

    def _final_mint_barrier(self, proof, peg, outpoint):
        k_btc = _strict_int(proof.get("k_btc", peg.get("spv_k_btc")), "compiled spv_k_btc", 1, 32)
        self._assert_bitcoin_finality(proof["block_hash"], proof["block_height"], k_btc)
        self._assert_relay_finality(proof["block_height"], k_btc)
        live_peg, _ = self._identity(full_derivation=False)
        expected_supply = proof.get("peg_supply_sats", peg.get("supply_sats"))
        if live_peg["supply_sats"] != expected_supply:
            raise Pending("btcVELD supply changed before MSPV fee submission; retry")
        validate_deposit_tx(
            proof["legacy_tx"],
            self.binding["spv_custody_spk_hex"],
            live_peg,
            expected_recipient=proof["deposit"]["recipient"],
            expected_amount=proof["deposit"]["amount_sats"],
        )
        status = self._mint_status(outpoint)
        if status["consumed"]:
            return True
        if (
            status["root"] != proof.get("nullifier_root")
            or status["count"] != proof.get("nullifier_count")
            or status["proof_hex"] != proof.get("nullifier_proof_hex")
        ):
            raise Pending("btcVELD nullifier root changed; rebuild MSP2 proof")
        return False

    def mint(self, txid, expected_recipient=None, wait_seconds=0):
        txid = str(txid).lower()
        if not TXID_RE.fullmatch(txid):
            raise RuntimeError("txid must be canonical lowercase 64-hex")
        if expected_recipient is not None:
            veld_p2pkh_from_address(expected_recipient, "expected recipient")
        wait_seconds = _strict_int(wait_seconds, "wait_seconds", 0, MAX_WAIT_SECONDS)
        deadline = time.monotonic() + wait_seconds
        proof = peg = None
        while True:
            peg, _ = self._identity(full_derivation=self.binding is None)
            try:
                proof = self._ready_proof(txid, peg)
                break
            except Pending:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(min(30, max(1, int(deadline - time.monotonic()))))

        deposit = proof["deposit"]
        if expected_recipient is not None and deposit["recipient"] != expected_recipient:
            raise RuntimeError("proven recipient differs from --expected-recipient")
        outpoint = txid + ":" + str(deposit["vout"])
        state = load_state(self.state_path)
        existing = state["deposits"].get(outpoint)
        if existing:
            try:
                state_amount = _strict_int(existing.get("amount_sats"), "durable deposit amount", 1)
            except RuntimeError as exc:
                raise RuntimeError("durable state conflicts with proven deposit identity") from exc
            if (
                existing.get("recipient") != deposit["recipient"]
                or state_amount != deposit["amount_sats"]
            ):
                raise RuntimeError("durable state conflicts with proven deposit identity")

        if self._mint_consumed(outpoint):
            state["deposits"][outpoint] = {
                **(existing or {}),
                "status": "minted",
                "btc_txid": txid,
                "vout": deposit["vout"],
                "recipient": deposit["recipient"],
                "amount_sats": deposit["amount_sats"],
            }
            save_state(self.state_path, state)
            return {
                "mode": "mint",
                "outpoint": outpoint,
                "already_consumed": True,
                "broadcast": False,
            }

        if existing and existing.get("signed_veld_tx_hex"):
            signed = existing["signed_veld_tx_hex"]
            signed_parsed = parse_veld_tx_hex(signed, signed=True)
            local_txid = dsha(signed_parsed["raw"]).hex()
            if existing.get("nullifier_root") != proof.get("nullifier_root"):
                if self._veld_tx_known(local_txid, signed):
                    raise Pending(
                        "stale-root MSP2 transaction is still visible; wait for mempool revalidation"
                    )
                # The transaction was never accepted and no longer occupies a
                # fee input.  Keep the deposit identity, discard only the stale
                # signed carrier, and rebuild against the current root below.
                for field in (
                    "signed_veld_tx_hex",
                    "veld_txid",
                    "unsigned_veld_tx_hex",
                    "nullifier_root",
                    "nullifier_count",
                    "nullifier_proof_hex",
                    "btc_block_hash",
                ):
                    existing.pop(field, None)
                existing["status"] = "proof-stale"
                save_state(self.state_path, state)
            else:
                validate_op_tx_outputs(signed_parsed, self.fund_addr, proof["op_string"])
                if (
                    existing.get("veld_txid") != local_txid
                    or existing.get("btc_block_hash") != proof["block_hash"]
                    or existing.get("nullifier_count") != proof.get("nullifier_count")
                    or existing.get("nullifier_proof_hex") != proof.get("nullifier_proof_hex")
                    or (
                        existing.get("unsigned_veld_tx_hex") is not None
                        and existing.get("unsigned_veld_tx_hex") != signed_parsed["unsigned_hex"]
                    )
                ):
                    raise RuntimeError("durable signed Veld transaction identity mismatch")
                if not self._veld_tx_known(local_txid, signed):
                    if self._final_mint_barrier(proof, peg, outpoint):
                        return {
                            "mode": "mint",
                            "outpoint": outpoint,
                            "already_consumed": True,
                            "broadcast": False,
                        }
                    fund_spk, _ = validate_op_tx_outputs(
                        signed_parsed, self.fund_addr, proof["op_string"]
                    )
                    self._validate_fee_prevouts(signed_parsed, fund_spk)
                    try:
                        returned = self.veld.rpc("sendrawtransaction", [signed])
                        if returned != local_txid:
                            raise RuntimeError("rebroadcast returned a different Veld txid")
                    except Exception:
                        if not self._veld_tx_known(local_txid, signed):
                            raise
                existing["status"] = "submitted"
                existing["submitted_at"] = int(time.time())
                save_state(self.state_path, state)
                return {
                    "mode": "mint",
                    "outpoint": outpoint,
                    "veld_txid": local_txid,
                    "already_consumed": False,
                    "broadcast": True,
                    "rebroadcast": True,
                }

        # One final reorg/identity/outpoint barrier immediately before paying a
        # Veld fee. The proof is rebuilt on any retry, never patched in place.
        if self._final_mint_barrier(proof, peg, outpoint):
            return {
                "mode": "mint",
                "outpoint": outpoint,
                "already_consumed": True,
                "broadcast": False,
            }

        prepared = self.veld.rpc("preparerawop", [self.fund_addr, proof["op_string"]])
        prepared_tx, fund_spk, _fee, total_input = validate_prepared_op(
            prepared, self.fund_addr, proof["op_string"]
        )
        self._validate_fee_prevouts(prepared_tx, fund_spk, expected_total=total_input)
        unsigned = prepared_tx["raw"].hex()
        signed = self.signer.sign(unsigned, fund_spk.hex())
        signed_tx = parse_veld_tx_hex(signed, signed=True)
        if signed_tx["unsigned_hex"] != unsigned:
            raise RuntimeError("signer changed the prepared Veld transaction semantics")
        validate_op_tx_outputs(signed_tx, self.fund_addr, proof["op_string"])
        local_veld_txid = dsha(signed_tx["raw"]).hex()

        # Signing can be interactive and slow. Re-check every chain-derived
        # authorization and every fee prevout after that latency, before WAL and
        # broadcast make the fee spend externally visible.
        if self._final_mint_barrier(proof, peg, outpoint):
            return {
                "mode": "mint",
                "outpoint": outpoint,
                "already_consumed": True,
                "broadcast": False,
            }
        self._validate_fee_prevouts(signed_tx, fund_spk, expected_total=total_input)

        state = load_state(self.state_path)
        fresh = state["deposits"].get(outpoint)
        if fresh and (
            fresh.get("recipient") != deposit["recipient"]
            or fresh.get("amount_sats") != deposit["amount_sats"]
            or fresh.get("signed_veld_tx_hex")
        ):
            raise RuntimeError("durable deposit state changed while the Veld tx was signed")
        state["deposits"][outpoint] = {
            **(fresh or {}),
            "status": "broadcasting",
            "btc_txid": txid,
            "vout": deposit["vout"],
            "recipient": deposit["recipient"],
            "amount_sats": deposit["amount_sats"],
            "btc_block_hash": proof["block_hash"],
            "nullifier_root": proof["nullifier_root"],
            "nullifier_count": proof["nullifier_count"],
            "nullifier_proof_hex": proof["nullifier_proof_hex"],
            "signed_veld_tx_hex": signed,
            "veld_txid": local_veld_txid,
            "unsigned_veld_tx_hex": unsigned,
            "veld_fee_units": VELD_OP_FEE_UNITS,
            "proof_branch_len": proof["branch_len"],
            "proof_used_witness_stripping": proof["segwit"],
        }
        save_state(self.state_path, state)
        returned = self.veld.rpc("sendrawtransaction", [signed])
        if returned != local_veld_txid:
            raise RuntimeError("Veld broadcast txid differs from locally verified txid")
        state = load_state(self.state_path)
        current = state["deposits"].get(outpoint)
        if (
            not isinstance(current, dict)
            or current.get("signed_veld_tx_hex") != signed
            or current.get("veld_txid") != local_veld_txid
        ):
            raise RuntimeError("durable Veld broadcast WAL changed after submission")
        current["status"] = "submitted"
        current["submitted_at"] = int(time.time())
        save_state(self.state_path, state)
        return {
            "mode": "mint",
            "outpoint": outpoint,
            "veld_txid": local_veld_txid,
            "recipient": deposit["recipient"],
            "amount_sats": deposit["amount_sats"],
            "btc_block_hash": proof["block_hash"],
            "btc_confirmations": proof["confirmations"],
            "merkle_branch_len": proof["branch_len"],
            "witness_stripped": proof["segwit"],
            "already_consumed": False,
            "broadcast": True,
        }


def _read_config(path):
    value = load_bounded_json_file(
        os.path.abspath(path), MAX_CONFIG_BYTES, "SPV config", private=True
    )
    if not isinstance(value, dict):
        raise RuntimeError("SPV config root must be an object")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", help="absolute/relative operator JSON config")
    sub = parser.add_subparsers(dest="mode", required=True)
    deposit = sub.add_parser("deposit", help="create/fund/sign/broadcast BTC deposit")
    deposit.add_argument("--recipient", required=True)
    deposit.add_argument("--amount-sats", required=True, type=int)
    mint = sub.add_parser("mint", help="prove and submit a confirmed BTC deposit")
    mint.add_argument("--txid", required=True)
    mint.add_argument("--expected-recipient")
    mint.add_argument("--wait-seconds", type=int, default=0)
    args = parser.parse_args(argv)

    if fcntl is None:
        raise SystemExit("veld_spvmint: POSIX fcntl locking is required")
    config = _read_config(args.config)
    operator = SpvOperator(config)
    lock_path = os.path.join(operator.state_dir, "spvmint.lock")
    lock = _open_lock(lock_path)
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        raise SystemExit("veld_spvmint: another deposit/mint operation holds the lock")

    try:
        if args.mode == "deposit":
            result = operator.deposit(args.recipient, args.amount_sats)
        else:
            result = operator.mint(args.txid, args.expected_recipient, args.wait_seconds)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Pending as exc:
        sys.stderr.write("veld_spvmint: pending: %s\n" % exc)
        return 75
    except Exception as exc:
        sys.stderr.write("veld_spvmint: FATAL: %s: %s\n" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
