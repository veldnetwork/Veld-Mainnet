#!/usr/bin/env python3
"""Semantically verify the funded Bitcoin 3-of-5 custody boundary drills.

The parent release report already pins the six subreport byte streams.  This
validator goes beyond those hashes: it parses the raw Bitcoin transactions,
recomputes txids/wtxids, validates CMerkleBlock inclusion proofs, independently
derives each boundary output and five-key tapscript from the ceremony's exact
mainnet xpub descriptor, and verifies every BIP340 signature against the BIP341
script-path sighash.  Signer slots map positionally to the five ordered ceremony
operator identities.  A success report must contain exactly three valid
signatures and a high-work, hash-linked best-chain inclusion proof.  A rejection report must exercise
the other two signers before the successful transaction is broadcast and must
carry Bitcoin Core's exact negative ``testmempoolaccept`` JSON.

The retained Bitcoin Core snapshot is operator-produced evidence rather than a
remote attestation by the Bitcoin network.  The validator nevertheless derives
every confirmation count, header hash, chain link, compact target, proof of
work, Merkle inclusion, transaction identity and all 11,000 descriptor outputs
instead of trusting report assertions.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX = re.compile(r"^(?:[0-9a-f]{2})+$")
IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{2,127}$")
TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_TX_BYTES = 4_000_000
# Bitcoin mainnet's proof-of-work limit and a deliberately conservative floor
# for release evidence.  A short, self-contained header segment cannot prove
# ancestry all the way to the genesis block.  Requiring every retained header
# to carry at least one trillion difficulty, however, prevents a fixture-style
# easy-target chain from being presented as mainnet evidence while the exact
# transaction Merkle proofs bind the custody transactions into that segment.
BITCOIN_POW_LIMIT = int(
    "00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
MIN_MAINNET_EVIDENCE_DIFFICULTY = 1_000_000_000_000
MAX_MAINNET_EVIDENCE_TARGET = (
    BITCOIN_POW_LIMIT // MIN_MAINNET_EVIDENCE_DIFFICULTY)
NUMS_INTERNAL_KEY = bytes.fromhex(
    "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
XPUB_VERSION = bytes.fromhex("0488b21e")
DESCRIPTOR_INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")
DESCRIPTOR_CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
KEY_EXPRESSION = re.compile(
    r"^\[([0-9a-f]{8})/86h/0h/0h\]"
    r"(xpub[1-9A-HJ-NP-Za-km-z]{100,120})/0/\*$")

PARENT_FIELDS = {
    "schema", "statement", "result", "release_version", "source_commit",
    "source_tree", "completed_at_utc", "bitcoin_network",
    "descriptor_sha256", "manifest_sha256", "script_range",
    "consensus_manifest_sha256", "consensus_script_range",
    "bitcoin_core_chain_evidence_path",
    "bitcoin_core_chain_evidence_sha256",
    "threshold_spend_drills",
}
DRILL_FIELDS = {
    "descriptor_index", "funded_sats", "script_pubkey_hex",
    "three_of_five_signer_ids", "three_of_five_spend_txid",
    "three_of_five_success_report_path",
    "three_of_five_success_report_sha256", "two_of_five_signer_ids",
    "two_of_five_rejection_report_path",
    "two_of_five_rejection_report_sha256",
}
COMMON_FIELDS = {
    "schema", "statement", "result", "release_version", "source_commit",
    "source_tree", "completed_at_utc", "bitcoin_network",
    "descriptor_sha256", "manifest_sha256", "descriptor_index",
    "script_pubkey_hex", "funded_sats", "funding_txid", "funding_vout",
    "funding_raw_transaction_hex", "funding_txoutproof_hex",
    "funding_block_hash", "funding_confirmations", "spend_input_index",
    "signer_ids", "signer_slots", "signature_sha256",
    "tapleaf_script_hex", "control_block_hex",
}
SUCCESS_FIELDS = COMMON_FIELDS | {
    "spend_txid", "spend_raw_transaction_hex", "spend_txoutproof_hex",
    "spend_block_hash", "spend_confirmations",
    "testmempoolaccept_allowed", "testmempoolaccept_raw_json",
    "testmempoolaccept_checked_at_utc", "broadcast_txid",
    "broadcast_at_utc", "confirmed_at_utc",
}
REJECTION_FIELDS = COMMON_FIELDS | {
    "rejection_txid", "rejection_wtxid", "rejection_raw_transaction_hex",
    "finalizepsbt_complete", "testmempoolaccept_allowed",
    "testmempoolaccept_txid", "testmempoolaccept_wtxid", "reject_reason",
    "testmempoolaccept_raw_json", "finalizepsbt_checked_at_utc",
    "testmempoolaccept_checked_at_utc", "broadcast_attempted",
}
MANIFEST_FIELDS = {
    "version", "descriptor", "descriptor_sha256", "range", "script_pubkeys",
}
CHAIN_EVIDENCE_FIELDS = {
    "schema", "statement", "result", "bitcoin_network", "node_id",
    "node_version", "captured_at_utc", "collector_version",
    "bitcoin_cli_path", "bitcoin_cli_sha256", "bitcoind_path",
    "bitcoind_sha256", "bitcoind_pid", "bitcoind_start_time_ticks",
    "rpc_arguments_sha256", "getblockchaininfo", "headers", "txoutproofs",
}
CHAIN_INFO_FIELDS = {
    "chain", "blocks", "headers", "bestblockhash", "initialblockdownload",
}
CHAIN_HEADER_FIELDS = {
    "height", "requested_hash", "getblockheader_false_hex",
}
CHAIN_PROOF_FIELDS = {
    "txid", "block_hash", "gettxoutproof_hex",
}


class ValidationError(ValueError):
    pass


def fail(message: str) -> None:
    raise ValidationError(message)


def sha256(raw: bytes) -> bytes:
    return hashlib.sha256(raw).digest()


def hash256(raw: bytes) -> bytes:
    return sha256(sha256(raw))


def tagged_hash(tag: str, raw: bytes) -> bytes:
    tag_hash = sha256(tag.encode("ascii"))
    return sha256(tag_hash + tag_hash + raw)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file")
    raw = path.read_bytes()
    if not raw or len(raw) > MAX_JSON_BYTES:
        fail(f"{label} size is invalid")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=strict_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be a JSON object")
    return value, raw


def exact(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        fail(f"{label} fields are not exact")
    return value


def parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str) or TIME.fullmatch(value) is None:
        fail(f"{label} is not canonical UTC seconds")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc)
    except ValueError as exc:
        fail(f"{label} is invalid: {exc}")


def hex_bytes(value: object, label: str, maximum: int = MAX_TX_BYTES) -> bytes:
    if not isinstance(value, str) or HEX.fullmatch(value) is None:
        fail(f"{label} is not canonical lowercase even-length hex")
    raw = bytes.fromhex(value)
    if not raw or len(raw) > maximum:
        fail(f"{label} byte length is invalid")
    return raw


def compact_size(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


class Reader:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw
        self.offset = 0

    def take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.raw):
            fail("truncated Bitcoin serialization")
        result = self.raw[self.offset:self.offset + count]
        self.offset += count
        return result

    def varint(self) -> tuple[int, bytes]:
        first = self.take(1)[0]
        if first < 0xFD:
            return first, bytes([first])
        size = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
        encoded = self.take(size)
        value = int.from_bytes(encoded, "little")
        minimum = {0xFD: 0xFD, 0xFE: 0x10000, 0xFF: 0x100000000}[first]
        if value < minimum:
            fail("non-minimal Bitcoin CompactSize")
        return value, bytes([first]) + encoded

    def vector(self, maximum: int = MAX_TX_BYTES) -> tuple[bytes, bytes]:
        count, prefix = self.varint()
        if count > maximum:
            fail("Bitcoin vector is excessive")
        body = self.take(count)
        return body, prefix + body


@dataclass
class TxInput:
    txid: str
    vout: int
    script_sig: bytes
    sequence: int
    raw: bytes
    witness: list[bytes]


@dataclass
class TxOutput:
    value: int
    script_pubkey: bytes
    raw: bytes


@dataclass
class Transaction:
    raw: bytes
    version: int
    locktime: int
    inputs: list[TxInput]
    outputs: list[TxOutput]
    txid: str
    wtxid: str
    has_witness: bool


def parse_transaction(raw: bytes) -> Transaction:
    if not 10 <= len(raw) <= MAX_TX_BYTES:
        fail("raw transaction length is invalid")
    reader = Reader(raw)
    version_raw = reader.take(4)
    version = int.from_bytes(version_raw, "little", signed=True)
    has_witness = False
    if reader.offset + 2 <= len(raw) and raw[reader.offset] == 0:
        marker_flag = reader.take(2)
        if marker_flag != b"\x00\x01":
            fail("transaction has a non-canonical witness marker/flag")
        has_witness = True
    input_count, input_prefix = reader.varint()
    if not 1 <= input_count <= 100_000:
        fail("transaction input count is invalid")
    inputs: list[TxInput] = []
    input_bytes = bytearray(input_prefix)
    for _ in range(input_count):
        start = reader.offset
        prev_hash = reader.take(32)
        vout = int.from_bytes(reader.take(4), "little")
        script, _ = reader.vector(10_000)
        sequence = int.from_bytes(reader.take(4), "little")
        item_raw = raw[start:reader.offset]
        input_bytes.extend(item_raw)
        inputs.append(TxInput(
            prev_hash[::-1].hex(), vout, script, sequence, item_raw, []))
    output_count, output_prefix = reader.varint()
    if not 1 <= output_count <= 100_000:
        fail("transaction output count is invalid")
    outputs: list[TxOutput] = []
    output_bytes = bytearray(output_prefix)
    for _ in range(output_count):
        start = reader.offset
        value = int.from_bytes(reader.take(8), "little")
        if value > 21_000_000 * 100_000_000:
            fail("transaction output value exceeds Bitcoin supply")
        script, _ = reader.vector(10_000)
        item_raw = raw[start:reader.offset]
        output_bytes.extend(item_raw)
        outputs.append(TxOutput(value, script, item_raw))
    if has_witness:
        any_witness = False
        for item in inputs:
            count, _ = reader.varint()
            if count > 10_000:
                fail("witness item count is excessive")
            witness = []
            for _ in range(count):
                value, _ = reader.vector(MAX_TX_BYTES)
                witness.append(value)
                any_witness |= bool(value)
            item.witness = witness
        if not any_witness:
            fail("superfluous witness serialization")
    locktime_raw = reader.take(4)
    if reader.offset != len(raw):
        fail("transaction has trailing bytes")
    base = version_raw + bytes(input_bytes) + bytes(output_bytes) + locktime_raw
    return Transaction(
        raw=raw, version=version,
        locktime=int.from_bytes(locktime_raw, "little"), inputs=inputs,
        outputs=outputs, txid=hash256(base)[::-1].hex(),
        wtxid=hash256(raw)[::-1].hex(), has_witness=has_witness,
    )


def verify_partial_merkle_proof(raw: bytes, wanted_txid: str,
                                wanted_block_hash: str) -> None:
    reader = Reader(raw)
    header = reader.take(80)
    total = int.from_bytes(reader.take(4), "little")
    if not 1 <= total <= 10_000_000:
        fail("txoutproof total transaction count is invalid")
    hash_count, _ = reader.varint()
    if not 1 <= hash_count <= total:
        fail("txoutproof hash count is invalid")
    hashes = [reader.take(32) for _ in range(hash_count)]
    flag_count, _ = reader.varint()
    if not 1 <= flag_count <= (total * 2 + 7) // 8:
        fail("txoutproof flag count is invalid")
    flags = reader.take(flag_count)
    if reader.offset != len(raw):
        fail("txoutproof has trailing bytes")
    if hash256(header)[::-1].hex() != wanted_block_hash:
        fail("txoutproof block-header hash differs from report")

    height = 0
    while (total + (1 << height) - 1) >> height > 1:
        height += 1
    bit_index = 0
    hash_index = 0
    matches: list[bytes] = []

    def width(level: int) -> int:
        return (total + (1 << level) - 1) >> level

    def bit() -> int:
        nonlocal bit_index
        if bit_index >= len(flags) * 8:
            fail("txoutproof exhausted flag bits")
        result = (flags[bit_index >> 3] >> (bit_index & 7)) & 1
        bit_index += 1
        return result

    def walk(level: int, position: int) -> bytes:
        nonlocal hash_index
        parent = bit()
        if level == 0 or parent == 0:
            if hash_index >= len(hashes):
                fail("txoutproof exhausted hashes")
            value = hashes[hash_index]
            hash_index += 1
            if level == 0 and parent:
                matches.append(value)
            return value
        left = walk(level - 1, position * 2)
        right = walk(level - 1, position * 2 + 1) \
            if position * 2 + 1 < width(level - 1) else left
        if right == left and position * 2 + 1 < width(level - 1):
            fail("txoutproof contains a mutated merkle branch")
        return hash256(left + right)

    root = walk(height, 0)
    if hash_index != len(hashes) or (bit_index + 7) // 8 != len(flags):
        fail("txoutproof does not consume its exact hash/flag vectors")
    for index in range(bit_index, len(flags) * 8):
        if (flags[index >> 3] >> (index & 7)) & 1:
            fail("txoutproof has nonzero padding flag bits")
    if root != header[36:68]:
        fail("txoutproof merkle root differs from block header")
    if [value[::-1].hex() for value in matches] != [wanted_txid]:
        fail("txoutproof does not prove exactly the reported transaction")


Point = tuple[int, int] | None
JacobianPoint = tuple[int, int, int] | None


def point_add(left: Point, right: Point) -> Point:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def jacobian_double(point: JacobianPoint) -> JacobianPoint:
    if point is None or point[1] == 0:
        return None
    x, y, z = point
    yy = y * y % P
    s = 4 * x * yy % P
    m = 3 * x * x % P
    x3 = (m * m - 2 * s) % P
    y3 = (m * (s - x3) - 8 * yy * yy) % P
    z3 = 2 * y * z % P
    return x3, y3, z3


def jacobian_add_mixed(left: JacobianPoint, right: Point) -> JacobianPoint:
    """Add an affine point without performing a field inversion."""
    if left is None:
        return None if right is None else (right[0], right[1], 1)
    if right is None:
        return left
    x1, y1, z1 = left
    x2, y2 = right
    z1z1 = z1 * z1 % P
    u2 = x2 * z1z1 % P
    s2 = y2 * z1 * z1z1 % P
    h = (u2 - x1) % P
    r = (s2 - y1) % P
    if h == 0:
        return jacobian_double(left) if r == 0 else None
    hh = h * h % P
    hhh = h * hh % P
    v = x1 * hh % P
    x3 = (r * r - hhh - 2 * v) % P
    y3 = (r * (v - x3) - y1 * hhh) % P
    z3 = z1 * h % P
    return x3, y3, z3


def jacobian_add(left: JacobianPoint, right: JacobianPoint) -> JacobianPoint:
    if left is None:
        return right
    if right is None:
        return left
    x1, y1, z1 = left
    x2, y2, z2 = right
    z1z1 = z1 * z1 % P
    z2z2 = z2 * z2 % P
    u1 = x1 * z2z2 % P
    u2 = x2 * z1z1 % P
    s1 = y1 * z2 * z2z2 % P
    s2 = y2 * z1 * z1z1 % P
    if u1 == u2:
        return jacobian_double(left) if s1 == s2 else None
    h = (u2 - u1) % P
    i = (2 * h) ** 2 % P
    j = h * i % P
    r = 2 * (s2 - s1) % P
    v = u1 * i % P
    x3 = (r * r - j - 2 * v) % P
    y3 = (r * (v - x3) - 2 * s1 * j) % P
    z3 = ((z1 + z2) ** 2 - z1z1 - z2z2) * h % P
    return x3, y3, z3


def jacobian_to_affine(point: JacobianPoint) -> Point:
    if point is None:
        return None
    x, y, z = point
    inverse = pow(z, P - 2, P)
    inverse2 = inverse * inverse % P
    return x * inverse2 % P, y * inverse2 * inverse % P


def point_mul(scalar: int, point: Point = G) -> Point:
    if not 0 <= scalar < N:
        scalar %= N
    result: JacobianPoint = None
    addend: JacobianPoint = None if point is None else (point[0], point[1], 1)
    while scalar:
        if scalar & 1:
            result = jacobian_add(result, addend)
        addend = jacobian_double(addend)
        scalar >>= 1
    return jacobian_to_affine(result)


_GENERATOR_WINDOWS: list[list[Point]] | None = None
_MANIFEST_DERIVATION_CACHE: dict[
    str, tuple[list[str], dict[int, tuple[list[bytes], bytes, bytes, bytes]]]
] = {}


def generator_windows() -> list[list[Point]]:
    """Return 64 four-bit fixed-base tables for secp256k1's generator."""
    global _GENERATOR_WINDOWS
    if _GENERATOR_WINDOWS is not None:
        return _GENERATOR_WINDOWS
    tables: list[list[Point]] = []
    base: Point = G
    for _ in range(64):
        row: list[Point] = [None]
        running: JacobianPoint = None
        for _digit in range(1, 16):
            running = jacobian_add_mixed(running, base)
            row.append(jacobian_to_affine(running))
        tables.append(row)
        base_j = None if base is None else (base[0], base[1], 1)
        for _ in range(4):
            base_j = jacobian_double(base_j)
        base = jacobian_to_affine(base_j)
    _GENERATOR_WINDOWS = tables
    return tables


def point_plus_generator_mul(point: Point, scalar: int) -> Point:
    """Compute ``point + scalar*G`` with one field inversion."""
    if not 0 <= scalar < N:
        fail("secp256k1 generator scalar is out of range")
    result: JacobianPoint = None if point is None else (point[0], point[1], 1)
    for window, row in enumerate(generator_windows()):
        digit = (scalar >> (4 * window)) & 0xF
        if digit:
            result = jacobian_add_mixed(result, row[digit])
    return jacobian_to_affine(result)


def lift_x(raw: bytes) -> Point:
    if len(raw) != 32:
        return None
    x = int.from_bytes(raw, "big")
    if x >= P:
        return None
    y2 = (pow(x, 3, P) + 7) % P
    y = pow(y2, (P + 1) // 4, P)
    if pow(y, 2, P) != y2:
        return None
    if y & 1:
        y = P - y
    return x, y


def compressed_point(raw: bytes) -> Point:
    if len(raw) != 33 or raw[0] not in (2, 3):
        fail("custody xpub does not contain a compressed public key")
    point = lift_x(raw[1:])
    if point is None:
        fail("custody xpub public key is not on secp256k1")
    if point[1] & 1 != raw[0] & 1:
        point = (point[0], P - point[1])
    return point


def serialize_compressed(point: Point) -> bytes:
    if point is None:
        fail("BIP32 derivation produced the point at infinity")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def base58check_decode(value: str) -> bytes:
    number = 0
    for character in value:
        try:
            digit = BASE58_ALPHABET.index(character)
        except ValueError:
            fail("custody xpub contains a non-Base58 character")
        number = number * 58 + digit
    encoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading = len(value) - len(value.lstrip("1"))
    decoded = b"\x00" * leading + encoded
    if len(decoded) != 82 or hash256(decoded[:-4])[:4] != decoded[-4:]:
        fail("custody xpub Base58Check payload/checksum is invalid")
    return decoded[:-4]


def parse_xpub(value: str) -> tuple[Point, bytes]:
    payload = base58check_decode(value)
    if payload[:4] != XPUB_VERSION:
        fail("custody key is not a mainnet xpub")
    if payload[4] != 3 or int.from_bytes(payload[9:13], "big") != 0x80000000:
        fail("custody xpub is not the account-level m/86h/0h/0h key")
    chain_code = payload[13:45]
    point = compressed_point(payload[45:78])
    return point, chain_code


def ckd_pub(point: Point, chain_code: bytes, index: int) -> tuple[Point, bytes]:
    if point is None or len(chain_code) != 32 or not 0 <= index < 0x80000000:
        fail("custody BIP32 public derivation input is invalid")
    digest = hmac.new(
        chain_code, serialize_compressed(point) + index.to_bytes(4, "big"),
        hashlib.sha512).digest()
    tweak = int.from_bytes(digest[:32], "big")
    if tweak == 0 or tweak >= N:
        fail("custody BIP32 public derivation produced an invalid child")
    child = point_plus_generator_mul(point, tweak)
    if child is None:
        fail("custody BIP32 public derivation produced infinity")
    return child, digest[32:]


def descriptor_polymod(symbols: list[int]) -> int:
    checksum = 1
    generators = (
        0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D,
        0x3706B1677A, 0x644D626FFD,
    )
    for value in symbols:
        top = checksum >> 35
        checksum = ((checksum & 0x7FFFFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                checksum ^= generator
    return checksum


def descriptor_checksum(payload: str) -> str:
    symbols: list[int] = []
    groups: list[int] = []
    for character in payload:
        position = DESCRIPTOR_INPUT_CHARSET.find(character)
        if position < 0:
            fail("custody descriptor contains a character outside Core's checksum alphabet")
        symbols.append(position & 31)
        groups.append(position >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups.clear()
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    polymod = descriptor_polymod(symbols + [0] * 8) ^ 1
    return "".join(
        DESCRIPTOR_CHECKSUM_CHARSET[(polymod >> (5 * (7 - index))) & 31]
        for index in range(8))


def parse_custody_descriptor(descriptor: str) -> list[str]:
    if descriptor.count("#") != 1:
        fail("custody descriptor must contain one checksum")
    payload, checksum = descriptor.split("#", 1)
    if len(checksum) != 8 or checksum != descriptor_checksum(payload):
        fail("custody descriptor checksum is invalid")
    prefix = f"tr({NUMS_INTERNAL_KEY.hex()},multi_a(3,"
    if not payload.startswith(prefix) or not payload.endswith("))"):
        fail("custody descriptor is not exact tr(NUMS,multi_a(3,...))")
    expressions = payload[len(prefix):-2].split(",")
    if len(expressions) != 5:
        fail("custody descriptor does not contain exactly five key expressions")
    xpub_payloads = []
    for expression in expressions:
        match = KEY_EXPRESSION.fullmatch(expression)
        if match is None:
            fail("custody descriptor key expression is not exact [fp/86h/0h/0h]xpub/0/*")
        decoded = base58check_decode(match.group(2))
        xpub_payloads.append(decoded)
    if len(set(xpub_payloads)) != 5:
        fail("custody descriptor reuses an extended public key")
    return expressions


def derive_descriptor_key(expression: str, index: int) -> bytes:
    match = KEY_EXPRESSION.fullmatch(expression)
    if match is None:
        fail("custody descriptor key expression is malformed")
    point, chain_code = parse_xpub(match.group(2))
    point, chain_code = ckd_pub(point, chain_code, 0)
    point, _ = ckd_pub(point, chain_code, index)
    if point is None:
        fail("custody descriptor derived an invalid x-only key")
    return point[0].to_bytes(32, "big")


def prepare_descriptor_branches(expressions: list[str]) -> list[tuple[Point, bytes]]:
    branches = []
    for expression in expressions:
        match = KEY_EXPRESSION.fullmatch(expression)
        if match is None:
            fail("custody descriptor key expression is malformed")
        point, chain_code = parse_xpub(match.group(2))
        branches.append(ckd_pub(point, chain_code, 0))
    return branches


def descriptor_material_from_branches(
    branches: list[tuple[Point, bytes]], index: int,
) -> tuple[list[bytes], bytes, bytes, bytes]:
    keys = []
    for branch_point, branch_chain in branches:
        child, _ = ckd_pub(branch_point, branch_chain, index)
        if child is None:
            fail("custody descriptor derived an invalid x-only key")
        keys.append(child[0].to_bytes(32, "big"))
    if len(set(keys)) != 5:
        fail(f"custody descriptor derives duplicate keys at index {index}")
    script = b"".join(
        b"\x20" + key + bytes([0xAC if slot == 0 else 0xBA])
        for slot, key in enumerate(keys)) + b"\x53\x9c"
    internal = lift_x(NUMS_INTERNAL_KEY)
    if internal is None:
        fail("custody NUMS internal key is invalid")
    leaf = tagged_hash("TapLeaf", b"\xc0" + compact_size(len(script)) + script)
    tweak = int.from_bytes(tagged_hash("TapTweak", NUMS_INTERNAL_KEY + leaf), "big")
    if tweak >= N:
        fail("custody descriptor Taproot tweak is invalid")
    output = point_plus_generator_mul(internal, tweak)
    if output is None:
        fail("custody descriptor Taproot output is infinity")
    script_pubkey = b"\x51\x20" + output[0].to_bytes(32, "big")
    control = bytes([0xC0 | (output[1] & 1)]) + NUMS_INTERNAL_KEY
    return keys, script, control, script_pubkey


def descriptor_boundary_material(
    expressions: list[str], index: int,
) -> tuple[list[bytes], bytes, bytes, bytes]:
    return descriptor_material_from_branches(
        prepare_descriptor_branches(expressions), index)


def derive_operational_manifest(
    descriptor: str, expressions: list[str],
) -> tuple[list[str], dict[int, tuple[list[bytes], bytes, bytes, bytes]]]:
    cached = _MANIFEST_DERIVATION_CACHE.get(descriptor)
    if cached is not None:
        return cached
    branches = prepare_descriptor_branches(expressions)
    derived_scripts: list[str] = []
    boundary_material: dict[int, tuple[list[bytes], bytes, bytes, bytes]] = {}
    for index in range(11_000):
        material = descriptor_material_from_branches(branches, index)
        derived_scripts.append(material[3].hex())
        if index in (0, 1000, 10_999):
            boundary_material[index] = material
    result = derived_scripts, boundary_material
    _MANIFEST_DERIVATION_CACHE[descriptor] = result
    return result


def schnorr_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(public_key) != 32 or len(message) != 32 or len(signature) != 64:
        return False
    point = lift_x(public_key)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if point is None or r >= P or s >= N:
        return False
    challenge = int.from_bytes(tagged_hash(
        "BIP0340/challenge", signature[:32] + public_key + message), "big") % N
    negated = (point[0], (-point[1]) % P)
    result = point_add(point_mul(s), point_mul(challenge, negated))
    return result is not None and result[1] % 2 == 0 and result[0] == r


def parse_multi_a(script: bytes) -> list[bytes]:
    keys: list[bytes] = []
    offset = 0
    for index in range(5):
        if offset + 34 > len(script) or script[offset] != 32:
            fail("custody tapscript is not canonical five-key multi_a")
        key = script[offset + 1:offset + 33]
        opcode = script[offset + 33]
        if opcode != (0xAC if index == 0 else 0xBA):
            fail("custody tapscript has wrong CHECKSIG/CHECKSIGADD sequence")
        if lift_x(key) is None:
            fail("custody tapscript contains an invalid x-only public key")
        keys.append(key)
        offset += 34
    if script[offset:] != b"\x53\x9c":
        fail("custody tapscript threshold is not exactly 3-of-5 OP_NUMEQUAL")
    if len(set(keys)) != 5:
        fail("custody tapscript public keys are not distinct")
    return keys


def verify_taproot_commitment(script_pubkey: bytes, script: bytes,
                              control: bytes) -> bytes:
    if len(script_pubkey) != 34 or script_pubkey[:2] != b"\x51\x20":
        fail("custody manifest output is not canonical P2TR")
    if len(control) < 33 or (len(control) - 33) % 32 or len(control) > 33 + 128 * 32:
        fail("Taproot control block length is invalid")
    leaf_version = control[0] & 0xFE
    if leaf_version != 0xC0:
        fail("Taproot leaf version is not tapscript v0xc0")
    internal_key = control[1:33]
    point = lift_x(internal_key)
    if point is None:
        fail("Taproot control block internal key is invalid")
    leaf = tagged_hash("TapLeaf", bytes([leaf_version]) + compact_size(len(script)) + script)
    merkle = leaf
    for offset in range(33, len(control), 32):
        branch = control[offset:offset + 32]
        merkle = tagged_hash("TapBranch", min(merkle, branch) + max(merkle, branch))
    tweak = int.from_bytes(tagged_hash("TapTweak", internal_key + merkle), "big")
    if tweak >= N:
        fail("Taproot tweak is outside the group order")
    output = point_add(point, point_mul(tweak))
    if output is None or output[0].to_bytes(32, "big") != script_pubkey[2:] or \
            output[1] & 1 != control[0] & 1:
        fail("Taproot control block/script do not commit to manifest output")
    return leaf


def taproot_script_sighash(tx: Transaction, input_index: int, amount: int,
                           script_pubkey: bytes, tapleaf_hash: bytes) -> bytes:
    if len(tx.inputs) != 1 or input_index != 0:
        fail("custody drill transaction must have exactly one selected input")
    txin = tx.inputs[0]
    prevout = bytes.fromhex(txin.txid)[::-1] + txin.vout.to_bytes(4, "little")
    outputs = b"".join(item.raw for item in tx.outputs)
    sigmsg = (
        b"\x00" + tx.version.to_bytes(4, "little", signed=True) +
        tx.locktime.to_bytes(4, "little") + sha256(prevout) +
        sha256(amount.to_bytes(8, "little")) +
        sha256(compact_size(len(script_pubkey)) + script_pubkey) +
        sha256(txin.sequence.to_bytes(4, "little")) + sha256(outputs) +
        b"\x02" + input_index.to_bytes(4, "little") + tapleaf_hash +
        b"\x00" + b"\xff\xff\xff\xff"
    )
    return tagged_hash("TapSighash", b"\x00" + sigmsg)


def validate_witness(tx: Transaction, input_index: int, amount: int,
                     script_pubkey: bytes, report: dict[str, Any],
                     wanted_signatures: int, expected_keys: list[bytes],
                     expected_script: bytes, expected_control: bytes,
                     operator_ids: list[str]) -> list[int]:
    if not tx.has_witness or len(tx.inputs) != 1 or input_index != 0:
        fail("custody spend must be a one-input witness transaction")
    if tx.inputs[0].script_sig:
        fail("Taproot custody spend scriptSig must be empty")
    witness = tx.inputs[0].witness
    if len(witness) != 7:
        fail("custody multi_a witness must contain five slots, script, and control block")
    script = hex_bytes(report.get("tapleaf_script_hex"), "tapleaf_script_hex", 10_000)
    control = hex_bytes(report.get("control_block_hex"), "control_block_hex", 10_000)
    if witness[-2:] != [script, control]:
        fail("reported tapscript/control block differ from raw witness")
    keys = parse_multi_a(script)
    if keys != expected_keys or script != expected_script:
        fail("custody tapscript keys do not derive from the ceremony descriptor/index")
    if control != expected_control:
        fail("custody control block is not the descriptor's exact NUMS single-leaf path")
    leaf = verify_taproot_commitment(script_pubkey, script, control)
    message = taproot_script_sighash(tx, input_index, amount, script_pubkey, leaf)
    signed_slots: list[int] = []
    signature_hashes: list[str] = []
    for witness_index, signature in enumerate(witness[:5]):
        key_slot = 4 - witness_index
        if not signature:
            continue
        if len(signature) != 64:
            fail("custody drill requires canonical SIGHASH_DEFAULT Schnorr signatures")
        if not schnorr_verify(keys[key_slot], message, signature):
            fail(f"invalid custody Schnorr signature for key slot {key_slot}")
        signed_slots.append(key_slot)
        signature_hashes.append(hashlib.sha256(signature).hexdigest())
    ordered = sorted(zip(signed_slots, signature_hashes))
    if len(ordered) != wanted_signatures:
        fail(f"custody witness has {len(ordered)} signatures, expected {wanted_signatures}")
    slots = report.get("signer_slots")
    hashes = report.get("signature_sha256")
    if slots != [item[0] for item in ordered] or hashes != [item[1] for item in ordered]:
        fail("reported signer slots/signature hashes differ from raw valid witness")
    expected_ids = [operator_ids[item[0]] for item in ordered]
    if report.get("signer_ids") != expected_ids:
        fail("reported signer identities do not positionally map to valid key slots")
    return [item[0] for item in ordered]


def safe_subreport(root: Path, value: object, digest: object,
                   label: str) -> dict[str, Any]:
    if not isinstance(value, str) or "\\" in value:
        fail(f"{label} path is not canonical")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(
            part in ("", ".", "..") for part in pure.parts):
        fail(f"{label} path is unsafe")
    if not isinstance(digest, str) or HEX64.fullmatch(digest) is None:
        fail(f"{label} digest is not canonical")
    if root.is_symlink() or not root.is_dir():
        fail("evidence root must be a regular non-symlink directory")
    base = root.resolve()
    candidate = base
    for part in pure.parts:
        candidate = candidate / part
        try:
            if stat_is_symlink(candidate):
                fail(f"{label} path traverses a symlink")
        except OSError as exc:
            fail(f"cannot inspect {label} path: {exc}")
    path = candidate.resolve()
    try:
        path.relative_to(base)
    except ValueError:
        fail(f"{label} path escapes evidence root")
    document, raw = load_json(path, label)
    if hashlib.sha256(raw).hexdigest() != digest:
        fail(f"{label} differs from its pinned digest")
    return document


def stat_is_symlink(path: Path) -> bool:
    return os.path.islink(path)


def compact_target(bits: int, pow_limit: int = BITCOIN_POW_LIMIT) -> int:
    if type(bits) is not int or not 0 <= bits <= 0xFFFFFFFF:
        fail("Bitcoin header nBits is not uint32")
    size = bits >> 24
    word = bits & 0x007FFFFF
    if bits & 0x00800000 or word == 0:
        fail("Bitcoin header has a negative or zero compact target")
    target = word >> (8 * (3 - size)) if size <= 3 else word << (8 * (size - 3))
    if target <= 0 or target > pow_limit:
        fail("Bitcoin header compact target exceeds the mainnet proof-of-work limit")
    if target_to_compact(target) != bits:
        fail("Bitcoin header compact target is non-canonical")
    return target


def target_to_compact(target: int) -> int:
    if target <= 0:
        return 0
    size = (target.bit_length() + 7) // 8
    compact = target << (8 * (3 - size)) if size <= 3 else target >> (8 * (size - 3))
    compact &= 0xFFFFFF
    if compact & 0x00800000:
        compact >>= 8
        size += 1
    return compact | (size << 24)


def validate_chain_evidence(
    evidence: dict[str, Any], references: list[dict[str, Any]],
    parent_completed_at: dt.datetime,
    maximum_target: int = MAX_MAINNET_EVIDENCE_TARGET,
) -> None:
    exact(evidence, CHAIN_EVIDENCE_FIELDS, "Bitcoin Core chain evidence")
    if (evidence.get("schema") != 1 or evidence.get("statement") !=
            "veld-bitcoin-core-mainnet-custody-chain-evidence-v1" or
            evidence.get("result") != "PASS" or
            evidence.get("bitcoin_network") != "main"):
        fail("Bitcoin Core chain evidence schema/statement/result/network is invalid")
    if (not isinstance(evidence.get("node_id"), str) or
            IDENTITY.fullmatch(evidence["node_id"]) is None):
        fail("Bitcoin Core chain evidence node_id is invalid")
    if (not isinstance(evidence.get("node_version"), str) or
            not 3 <= len(evidence["node_version"]) <= 128 or
            re.search(r"(?:todo|tbd|placeholder|example)",
                      evidence["node_version"], re.I)):
        fail("Bitcoin Core chain evidence node_version is invalid")
    if evidence.get("collector_version") != \
            "collect-bitcoin-core-custody-evidence-v1":
        fail("Bitcoin Core chain evidence collector version is invalid")
    for field in ("bitcoin_cli_path", "bitcoind_path"):
        if (not isinstance(evidence.get(field), str) or
                not evidence[field].startswith("/") or
                len(evidence[field]) > 4096 or "\x00" in evidence[field]):
            fail(f"Bitcoin Core chain evidence {field} is invalid")
    for field in ("bitcoin_cli_sha256", "bitcoind_sha256", "rpc_arguments_sha256"):
        if not isinstance(evidence.get(field), str) or HEX64.fullmatch(
                evidence[field]) is None:
            fail(f"Bitcoin Core chain evidence {field} is invalid")
    if (type(evidence.get("bitcoind_pid")) is not int or
            evidence["bitcoind_pid"] <= 1 or
            type(evidence.get("bitcoind_start_time_ticks")) is not int or
            evidence["bitcoind_start_time_ticks"] <= 0):
        fail("Bitcoin Core chain evidence daemon process identity is invalid")
    captured_at = parse_time(
        evidence.get("captured_at_utc"), "Bitcoin Core chain evidence captured_at_utc")
    if captured_at > parent_completed_at:
        fail("Bitcoin Core chain evidence was captured after the parent report")

    info = exact(
        evidence.get("getblockchaininfo"), CHAIN_INFO_FIELDS,
        "Bitcoin Core getblockchaininfo result")
    if (info.get("chain") != "main" or
            info.get("initialblockdownload") is not False or
            type(info.get("blocks")) is not int or info["blocks"] < 0 or
            type(info.get("headers")) is not int or
            info["headers"] != info["blocks"] or
            not isinstance(info.get("bestblockhash"), str) or
            HEX64.fullmatch(info["bestblockhash"]) is None):
        fail("Bitcoin Core getblockchaininfo does not show a synced main chain")
    best_height = info["blocks"]

    records = evidence.get("headers")
    if not isinstance(records, list) or not 6 <= len(records) <= 1000:
        fail("Bitcoin Core evidence must retain a bounded contiguous header segment")
    by_hash: dict[str, tuple[int, bytes]] = {}
    previous_hash: str | None = None
    first_height: int | None = None
    for position, value in enumerate(records):
        record = exact(value, CHAIN_HEADER_FIELDS, f"Bitcoin Core header {position}")
        height = record.get("height")
        wanted_hash = record.get("requested_hash")
        raw_value = record.get("getblockheader_false_hex")
        if type(height) is not int or height < 0:
            fail(f"Bitcoin Core header {position} height is invalid")
        if first_height is None:
            first_height = height
        if height != first_height + position:
            fail("Bitcoin Core retained headers are not exact contiguous heights")
        if not isinstance(wanted_hash, str) or HEX64.fullmatch(wanted_hash) is None:
            fail(f"Bitcoin Core header {position} requested hash is invalid")
        if not isinstance(raw_value, str) or not re.fullmatch(
                r"[0-9a-f]{160}", raw_value):
            fail(f"Bitcoin Core header {position} is not exact lowercase 80-byte hex")
        raw = bytes.fromhex(raw_value)
        calculated_hash = hash256(raw)[::-1].hex()
        if calculated_hash != wanted_hash:
            fail(f"Bitcoin Core header {position} hash differs from raw header")
        if calculated_hash in by_hash:
            fail("Bitcoin Core header evidence duplicates a block hash")
        if previous_hash is not None and raw[4:36][::-1].hex() != previous_hash:
            fail("Bitcoin Core retained header segment is not hash-linked")
        bits = int.from_bytes(raw[72:76], "little")
        target = compact_target(bits, max(BITCOIN_POW_LIMIT, maximum_target))
        if target > maximum_target:
            fail("Bitcoin Core header proof of work is below the mainnet evidence floor")
        if int.from_bytes(hash256(raw), "little") > target:
            fail("Bitcoin Core retained header does not satisfy its proof-of-work target")
        header_time = dt.datetime.fromtimestamp(
            int.from_bytes(raw[68:72], "little"), tz=dt.timezone.utc)
        if header_time > captured_at + dt.timedelta(hours=2):
            fail("Bitcoin Core retained header timestamp is implausibly after capture")
        by_hash[calculated_hash] = (height, raw)
        previous_hash = calculated_hash
    if first_height is None or first_height + len(records) - 1 != best_height or \
            previous_hash != info["bestblockhash"]:
        fail("Bitcoin Core retained header segment does not end at the reported best block")

    proof_records = evidence.get("txoutproofs")
    if not isinstance(proof_records, list) or len(proof_records) != len(references):
        fail("Bitcoin Core evidence does not retain the exact referenced txoutproof set")
    proofs: dict[str, tuple[str, str]] = {}
    for position, value in enumerate(proof_records):
        record = exact(value, CHAIN_PROOF_FIELDS, f"Bitcoin Core txoutproof {position}")
        txid = record.get("txid")
        block_hash = record.get("block_hash")
        proof_hex = record.get("gettxoutproof_hex")
        if (not isinstance(txid, str) or HEX64.fullmatch(txid) is None or
                not isinstance(block_hash, str) or HEX64.fullmatch(block_hash) is None or
                not isinstance(proof_hex, str) or HEX.fullmatch(proof_hex) is None):
            fail(f"Bitcoin Core txoutproof {position} is not canonical")
        if txid in proofs:
            fail("Bitcoin Core evidence duplicates a transaction proof")
        proofs[txid] = (block_hash, proof_hex)

    wanted_txids: set[str] = set()
    minimum_height = best_height
    for reference in references:
        txid = str(reference["txid"])
        block_hash = str(reference["block_hash"])
        proof_hex = str(reference["proof_hex"])
        confirmations = reference["confirmations"]
        if txid in wanted_txids:
            fail("custody chain references reuse a confirmed transaction")
        wanted_txids.add(txid)
        if block_hash not in by_hash:
            fail("custody transaction block is absent from the retained best-chain segment")
        height, raw_header = by_hash[block_hash]
        minimum_height = min(minimum_height, height)
        derived_confirmations = best_height - height + 1
        if type(confirmations) is not int or confirmations != derived_confirmations or \
                confirmations < 6:
            fail("custody transaction confirmations differ from the retained best chain")
        if proofs.get(txid) != (block_hash, proof_hex):
            fail("custody transaction proof differs from the retained Bitcoin Core evidence")
        verify_partial_merkle_proof(bytes.fromhex(proof_hex), txid, block_hash)
        if bytes.fromhex(proof_hex)[:80] != raw_header:
            fail("custody txoutproof header differs from the retained best-chain header")
    if set(proofs) != wanted_txids:
        fail("Bitcoin Core evidence contains an unreferenced txoutproof")
    if first_height != minimum_height:
        fail("Bitcoin Core header evidence does not start at the earliest custody block")


def parse_mempool_response(
    raw_value: object, tx: Transaction, wanted_allowed: bool,
    reported_reason: object | None = None,
) -> dict[str, Any]:
    if not isinstance(raw_value, str) or not raw_value or len(raw_value) > 64 * 1024 or \
            "\r" in raw_value or not raw_value.endswith("\n"):
        fail("testmempoolaccept raw JSON is not canonical retained output")
    try:
        value = json.loads(raw_value, object_pairs_hook=strict_object)
    except (ValueError, json.JSONDecodeError) as exc:
        fail(f"testmempoolaccept raw JSON cannot be parsed: {exc}")
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    if raw_value != canonical:
        fail("testmempoolaccept raw JSON is not canonical sorted JSON")
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        fail("testmempoolaccept raw JSON must contain exactly one result")
    result = value[0]
    if result.get("txid") != tx.txid or result.get("wtxid") != tx.wtxid or \
            result.get("allowed") is not wanted_allowed:
        fail("testmempoolaccept raw result differs from the exact transaction/verdict")
    if wanted_allowed:
        if "reject-reason" in result:
            fail("allowed testmempoolaccept result unexpectedly contains reject-reason")
        return result
    reason = result.get("reject-reason")
    if reason != reported_reason or not isinstance(reason, str):
        fail("testmempoolaccept reject reason differs from retained raw result")
    lowered = reason.lower()
    spent_or_conflict = (
        "missingorspent", "missing input", "missing-input", "already spent",
        "mempool-conflict", "txn-mempool-conflict", "conflict",
    )
    threshold_failure = (
        "false/empty top stack", "finished with a false", "op_numequal",
    )
    if any(marker in lowered for marker in spent_or_conflict) or \
            not any(marker in lowered for marker in threshold_failure):
        fail("2-of-5 rejection is not specifically a threshold-script failure")
    return result


def common_report(report: dict[str, Any], parent: dict[str, Any],
                  drill: dict[str, Any], statement: str,
                  wanted_signatures: int) -> tuple[Transaction, int, bytes]:
    if report.get("schema") != 1 or report.get("statement") != statement or \
            report.get("result") != "PASS":
        fail("custody subreport schema/statement/result is invalid")
    for field in (
            "release_version", "source_commit", "source_tree",
            "bitcoin_network", "descriptor_sha256", "manifest_sha256"):
        if report.get(field) != parent.get(field):
            fail(f"custody subreport {field} differs from parent")
    for field in ("descriptor_index", "script_pubkey_hex", "funded_sats"):
        if report.get(field) != drill.get(field):
            fail(f"custody subreport {field} differs from boundary entry")
    if parse_time(report.get("completed_at_utc"), "subreport completed_at_utc") > \
            parse_time(parent.get("completed_at_utc"), "parent completed_at_utc"):
        fail("custody subreport completes after its parent")
    signer_ids = report.get("signer_ids")
    parent_ids = drill.get(
        "three_of_five_signer_ids" if wanted_signatures == 3 else
        "two_of_five_signer_ids")
    if (not isinstance(signer_ids, list) or len(signer_ids) != wanted_signatures or
            len(set(signer_ids)) != wanted_signatures or
            any(IDENTITY.fullmatch(str(item)) is None for item in signer_ids) or
            set(signer_ids) != set(parent_ids or [])):
        fail("custody subreport signer identities differ from parent")
    funding_raw = hex_bytes(
        report.get("funding_raw_transaction_hex"), "funding_raw_transaction_hex")
    funding = parse_transaction(funding_raw)
    if funding.txid != report.get("funding_txid"):
        fail("funding transaction txid differs from raw bytes")
    funding_vout = report.get("funding_vout")
    if type(funding_vout) is not int or not 0 <= funding_vout < len(funding.outputs):
        fail("funding_vout is invalid")
    output = funding.outputs[funding_vout]
    script_pubkey = hex_bytes(report.get("script_pubkey_hex"), "script_pubkey_hex", 10_000)
    if output.value != report.get("funded_sats") or output.script_pubkey != script_pubkey:
        fail("funding transaction output differs from reported amount/script")
    confirmations = report.get("funding_confirmations")
    if type(confirmations) is not int or confirmations < 6:
        fail("funding transaction has fewer than six confirmations")
    block_hash = report.get("funding_block_hash")
    if not isinstance(block_hash, str) or HEX64.fullmatch(block_hash) is None:
        fail("funding_block_hash is not canonical")
    verify_partial_merkle_proof(
        hex_bytes(report.get("funding_txoutproof_hex"), "funding_txoutproof_hex"),
        funding.txid, block_hash)
    return funding, funding_vout, script_pubkey


def validate_success(report: dict[str, Any], parent: dict[str, Any],
                     drill: dict[str, Any], expected_keys: list[bytes],
                     expected_script: bytes, expected_control: bytes,
                     operator_ids: list[str]) -> tuple[Transaction, list[int]]:
    exact(report, SUCCESS_FIELDS, "3-of-5 success report")
    funding, funding_vout, script_pubkey = common_report(
        report, parent, drill, "veld-mainnet-custody-3of5-success-v1", 3)
    spend = parse_transaction(hex_bytes(
        report.get("spend_raw_transaction_hex"), "spend_raw_transaction_hex"))
    if spend.txid != report.get("spend_txid") or \
            spend.txid != drill.get("three_of_five_spend_txid") or \
            report.get("broadcast_txid") != spend.txid:
        fail("3-of-5 spend txid differs across raw/report/parent/broadcast")
    index = report.get("spend_input_index")
    if index != 0 or spend.inputs[0].txid != funding.txid or \
            spend.inputs[0].vout != funding_vout:
        fail("3-of-5 spend does not consume the proved funding output")
    if sum(item.value for item in spend.outputs) >= report.get("funded_sats"):
        fail("3-of-5 spend does not pay a positive miner fee")
    signed_slots = validate_witness(
        spend, index, report["funded_sats"], script_pubkey, report, 3,
        expected_keys, expected_script, expected_control, operator_ids)
    if report.get("testmempoolaccept_allowed") is not True:
        fail("3-of-5 report does not record pre-broadcast mempool acceptance")
    parse_mempool_response(
        report.get("testmempoolaccept_raw_json"), spend, True)
    mempool_at = parse_time(
        report.get("testmempoolaccept_checked_at_utc"),
        "3-of-5 testmempoolaccept_checked_at_utc")
    broadcast_at = parse_time(report.get("broadcast_at_utc"), "3-of-5 broadcast_at_utc")
    confirmed_at = parse_time(report.get("confirmed_at_utc"), "3-of-5 confirmed_at_utc")
    completed_at = parse_time(report.get("completed_at_utc"), "3-of-5 completed_at_utc")
    if not mempool_at < broadcast_at <= confirmed_at <= completed_at:
        fail("3-of-5 mempool/broadcast/confirmation timestamps are out of order")
    confirmations = report.get("spend_confirmations")
    block_hash = report.get("spend_block_hash")
    if type(confirmations) is not int or confirmations < 6 or \
            not isinstance(block_hash, str) or HEX64.fullmatch(block_hash) is None:
        fail("3-of-5 spend has fewer than six confirmations or no canonical block")
    verify_partial_merkle_proof(
        hex_bytes(report.get("spend_txoutproof_hex"), "spend_txoutproof_hex"),
        spend.txid, block_hash)
    return spend, signed_slots


def validate_rejection(report: dict[str, Any], parent: dict[str, Any],
                       drill: dict[str, Any], success: Transaction,
                       expected_keys: list[bytes], expected_script: bytes,
                       expected_control: bytes,
                       operator_ids: list[str]) -> tuple[list[int], dt.datetime]:
    exact(report, REJECTION_FIELDS, "2-of-5 rejection report")
    funding, funding_vout, script_pubkey = common_report(
        report, parent, drill, "veld-mainnet-custody-2of5-rejection-v1", 2)
    rejected = parse_transaction(hex_bytes(
        report.get("rejection_raw_transaction_hex"),
        "rejection_raw_transaction_hex"))
    if rejected.txid != report.get("rejection_txid") or \
            rejected.wtxid != report.get("rejection_wtxid") or \
            rejected.txid != report.get("testmempoolaccept_txid") or \
            rejected.wtxid != report.get("testmempoolaccept_wtxid"):
        fail("2-of-5 txid/wtxid differs across raw/report/Core result")
    if rejected.txid == success.txid:
        fail("2-of-5 rejection reuses the successful transaction identity")
    index = report.get("spend_input_index")
    if index != 0 or rejected.inputs[0].txid != funding.txid or \
            rejected.inputs[0].vout != funding_vout:
        fail("2-of-5 attempt does not consume the proved funding output")
    if sum(item.value for item in rejected.outputs) >= report.get("funded_sats"):
        fail("2-of-5 attempt does not pay a positive miner fee")
    signed_slots = validate_witness(
        rejected, index, report["funded_sats"], script_pubkey, report, 2,
        expected_keys, expected_script, expected_control, operator_ids)
    reason = report.get("reject_reason")
    if not isinstance(reason, str) or not 3 <= len(reason) <= 512 or \
            re.search(r"(?:todo|tbd|replace|placeholder|example)", reason, re.I):
        fail("2-of-5 report has no canonical reject reason")
    if (report.get("finalizepsbt_complete") is not False or
            report.get("testmempoolaccept_allowed") is not False or
            report.get("broadcast_attempted") is not False):
        fail("2-of-5 report does not prove incomplete/rejected/non-broadcast state")
    parse_mempool_response(
        report.get("testmempoolaccept_raw_json"), rejected, False, reason)
    finalized_at = parse_time(
        report.get("finalizepsbt_checked_at_utc"),
        "2-of-5 finalizepsbt_checked_at_utc")
    tested_at = parse_time(
        report.get("testmempoolaccept_checked_at_utc"),
        "2-of-5 testmempoolaccept_checked_at_utc")
    completed_at = parse_time(report.get("completed_at_utc"), "2-of-5 completed_at_utc")
    if not finalized_at <= tested_at <= completed_at:
        fail("2-of-5 finalize/test/completion timestamps are out of order")
    return signed_slots, tested_at


def validate(parent_path: Path, manifest_path: Path, consensus_manifest_path: Path,
             evidence_root: Path, operator_ids: list[str],
             maximum_chain_target: int = MAX_MAINNET_EVIDENCE_TARGET) -> None:
    parent, _ = load_json(parent_path, "funded custody drill report")
    exact(parent, PARENT_FIELDS, "funded custody drill report")
    if (parent.get("schema") != 2 or parent.get("statement") !=
            "veld-mainnet-funded-custody-threshold-drill-v2" or
            parent.get("result") != "PASS" or parent.get("bitcoin_network") != "main"):
        fail("funded custody parent schema/statement/result/network is invalid")
    parse_time(parent.get("completed_at_utc"), "parent completed_at_utc")
    for field in ("descriptor_sha256", "manifest_sha256",
                  "consensus_manifest_sha256", "source_commit", "source_tree"):
        if not isinstance(parent.get(field), str) or HEX64.fullmatch(parent[field]) is None:
            fail(f"funded custody parent {field} is not canonical")
    if (len(operator_ids) != 5 or len(set(operator_ids)) != 5 or
            any(IDENTITY.fullmatch(item) is None for item in operator_ids)):
        fail("exactly five distinct ordered ceremony operator identities are required")

    manifest, manifest_raw = load_json(manifest_path, "operational custody manifest")
    exact(manifest, MANIFEST_FIELDS, "operational custody manifest")
    if hashlib.sha256(manifest_raw).hexdigest() != parent.get("manifest_sha256"):
        fail("operational custody manifest bytes differ from parent hash")
    if manifest.get("version") != 1 or manifest.get("range") != parent.get("script_range"):
        fail("operational custody manifest version/range differs from parent")
    descriptor = manifest.get("descriptor")
    if not isinstance(descriptor, str) or hashlib.sha256(
            descriptor.encode("utf-8")).hexdigest() != parent.get("descriptor_sha256") or \
            manifest.get("descriptor_sha256") != parent.get("descriptor_sha256"):
        fail("operational custody descriptor differs from parent")
    expressions = parse_custody_descriptor(descriptor)
    scripts = manifest.get("script_pubkeys")
    script_range = manifest.get("range")
    if (not isinstance(scripts, list) or not isinstance(script_range, list) or
            script_range != [0, len(scripts) - 1] or len(scripts) != 11_000 or
            len(set(map(str, scripts))) != len(scripts)):
        fail("operational custody manifest is not exact unique [0,10999]")
    derived_scripts, boundary_material = derive_operational_manifest(
        descriptor, expressions)
    for index, actual in enumerate(scripts):
        if not isinstance(actual, str) or re.fullmatch(r"5120[0-9a-f]{64}", actual) is None:
            fail(f"operational custody manifest script {index} is not canonical P2TR")
        if derived_scripts[index] != actual:
            fail(f"operational custody manifest script {index} does not derive from descriptor")

    consensus, consensus_raw = load_json(
        consensus_manifest_path, "consensus-prefix custody manifest")
    exact(consensus, MANIFEST_FIELDS, "consensus-prefix custody manifest")
    if hashlib.sha256(consensus_raw).hexdigest() != parent.get(
            "consensus_manifest_sha256"):
        fail("consensus-prefix custody manifest bytes differ from parent hash")
    if (consensus.get("version") != 1 or consensus.get("range") != [0, 999] or
            parent.get("consensus_script_range") != [0, 999] or
            consensus.get("descriptor") != descriptor or
            consensus.get("descriptor_sha256") != parent.get("descriptor_sha256") or
            consensus.get("script_pubkeys") != scripts[:1000]):
        fail("consensus custody manifest is not the exact derived [0,999] prefix")

    chain_evidence = safe_subreport(
        evidence_root, parent.get("bitcoin_core_chain_evidence_path"),
        parent.get("bitcoin_core_chain_evidence_sha256"),
        "Bitcoin Core chain evidence")

    drills = parent.get("threshold_spend_drills")
    if not isinstance(drills, list) or len(drills) != 3:
        fail("funded custody parent must contain exactly three drills")
    indices = []
    paths: set[str] = set()
    digests: set[str] = set()
    funding_outpoints: set[tuple[str, int]] = set()
    success_txids: set[str] = set()
    rejection_txids: set[str] = set()
    chain_references: list[dict[str, Any]] = []
    for position, drill_value in enumerate(drills, 1):
        drill = exact(drill_value, DRILL_FIELDS, f"boundary drill {position}")
        index = drill.get("descriptor_index")
        if type(index) is not int or not 0 <= index < len(scripts):
            fail(f"boundary drill {position} index is invalid")
        if index not in boundary_material:
            fail("custody boundary drills are not ordered exactly [0,1000,10999]")
        indices.append(index)
        if drill.get("script_pubkey_hex") != scripts[index]:
            fail(f"boundary drill {index} script differs from operational manifest")
        expected_keys, expected_script, expected_control, expected_spk = \
            boundary_material[index]
        if expected_spk.hex() != scripts[index]:
            fail(f"boundary drill {index} manifest script does not derive from descriptor")
        if type(drill.get("funded_sats")) is not int or drill["funded_sats"] <= 0:
            fail(f"boundary drill {index} funding is invalid")
        if not isinstance(drill.get("three_of_five_spend_txid"), str) or \
                HEX64.fullmatch(drill["three_of_five_spend_txid"]) is None:
            fail(f"boundary drill {index} success txid is invalid")
        success_path = drill.get("three_of_five_success_report_path")
        success_digest = drill.get("three_of_five_success_report_sha256")
        reject_path = drill.get("two_of_five_rejection_report_path")
        reject_digest = drill.get("two_of_five_rejection_report_sha256")
        for value in (success_path, reject_path):
            if str(value) in paths:
                fail("custody subreports reuse an evidence path")
            paths.add(str(value))
        for value in (success_digest, reject_digest):
            if str(value) in digests:
                fail("custody subreports reuse an evidence digest")
            digests.add(str(value))
        success_report = safe_subreport(
            evidence_root, success_path, success_digest,
            f"boundary {index} 3-of-5 success report")
        rejection_report = safe_subreport(
            evidence_root, reject_path, reject_digest,
            f"boundary {index} 2-of-5 rejection report")
        for field in (
                "funding_txid", "funding_vout", "funding_raw_transaction_hex",
                "funding_txoutproof_hex", "funding_block_hash",
                "funding_confirmations"):
            if rejection_report.get(field) != success_report.get(field):
                fail(f"boundary {index} success/rejection funding {field} differs")
        outpoint = (str(success_report.get("funding_txid")),
                    int(success_report.get("funding_vout", -1)))
        if outpoint in funding_outpoints:
            fail("custody boundary drills reuse a funding outpoint")
        funding_outpoints.add(outpoint)
        success_txid = str(success_report.get("spend_txid"))
        rejection_txid = str(rejection_report.get("rejection_txid"))
        if success_txid in success_txids or rejection_txid in rejection_txids:
            fail("custody boundary drills reuse a success/rejection transaction")
        success_txids.add(success_txid)
        rejection_txids.add(rejection_txid)
        success, success_slots = validate_success(
            success_report, parent, drill, expected_keys, expected_script,
            expected_control, operator_ids)
        rejection_slots, rejection_tested_at = validate_rejection(
            rejection_report, parent, drill, success, expected_keys,
            expected_script, expected_control, operator_ids)
        if drill.get("three_of_five_signer_ids") != [
                operator_ids[slot] for slot in success_slots]:
            fail(f"boundary drill {index} 3-of-5 signer IDs do not map to slots")
        if drill.get("two_of_five_signer_ids") != [
                operator_ids[slot] for slot in rejection_slots]:
            fail(f"boundary drill {index} 2-of-5 signer IDs do not map to slots")
        if set(success_slots) & set(rejection_slots) or \
                set(success_slots) | set(rejection_slots) != set(range(5)):
            fail(f"boundary drill {index} does not exercise all five disjoint signer slots")
        if rejection_tested_at >= parse_time(
                success_report.get("broadcast_at_utc"), "3-of-5 broadcast_at_utc"):
            fail(f"boundary drill {index} tested 2-of-5 only after success broadcast")
        chain_references.extend((
            {
                "txid": success_report["funding_txid"],
                "block_hash": success_report["funding_block_hash"],
                "proof_hex": success_report["funding_txoutproof_hex"],
                "confirmations": success_report["funding_confirmations"],
            },
            {
                "txid": success_report["spend_txid"],
                "block_hash": success_report["spend_block_hash"],
                "proof_hex": success_report["spend_txoutproof_hex"],
                "confirmations": success_report["spend_confirmations"],
            },
        ))
    if indices != [0, 1000, 10_999]:
        fail("custody boundary drills are not ordered exactly [0,1000,10999]")
    validate_chain_evidence(
        chain_evidence, chain_references,
        parse_time(parent.get("completed_at_utc"), "parent completed_at_utc"),
        maximum_chain_target)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--operational-manifest", required=True, type=Path)
    parser.add_argument("--consensus-manifest", required=True, type=Path)
    parser.add_argument("--evidence-root", type=Path)
    parser.add_argument(
        "--operator-id", action="append", required=True,
        help=("ceremony operator identity in exact descriptor key-slot order; "
              "repeat exactly five times"),
    )
    args = parser.parse_args()
    root = args.evidence_root or args.report.parent
    try:
        if not root.is_dir() or root.is_symlink():
            fail("evidence root must be a non-symlink directory")
        validate(
            args.report, args.operational_manifest, args.consensus_manifest,
            root, args.operator_id)
    except (OSError, ValidationError, UnicodeError) as exc:
        print(f"FUNDED-CUSTODY-SEMANTIC FAIL: {exc}", file=sys.stderr)
        return 1
    print("FUNDED-CUSTODY-SEMANTIC OK: all 11,000 descriptor outputs, exact consensus prefix, high-work linked Bitcoin Core chain evidence, 3-of-5 spends, and pre-broadcast 2-of-5 threshold rejections verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
