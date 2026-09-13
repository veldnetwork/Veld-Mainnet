#!/usr/bin/env python3
"""Canonical constant-space commitment for btcVELD REDEEM RPC rows.

The C++ token ledger extends the same SHA-256 accumulator in canonical index
order.  Consumers extend it while walking bounded RPC pages and reject the
snapshot unless both the final row count and root match the ledger authority.
"""

import hashlib
import re
import struct


DOMAIN = b"VELD_BTCVELD_REDEEM_COMMITMENT_v1|"
HASH256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_WIRE_INT = (1 << 63) - 1


def empty_root():
    return hashlib.sha256(DOMAIN).digest()


def _uint(value, field, maximum):
    if (type(value) is not int or value < 0 or value > maximum):
        raise RuntimeError("%s is not a bounded non-negative integer" % field)
    return value


def _text(value, field, maximum):
    if not isinstance(value, str):
        raise RuntimeError("%s is not a string" % field)
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise RuntimeError("%s is not valid UTF-8" % field) from exc
    if len(raw) > maximum:
        raise RuntimeError("%s exceeds its canonical bound" % field)
    return raw


def _lp(raw):
    if len(raw) > 0xffffffff:
        raise RuntimeError("redeem commitment field exceeds uint32 length")
    return struct.pack("<I", len(raw)) + raw


def parse_page_authority(page):
    """Return the exact (count, root_hex) authority advertised by one page."""
    if not isinstance(page, dict):
        raise RuntimeError("redeem commitment page is not an object")
    count = _uint(page.get("redeem_count"), "redeem_count", (1 << 64) - 1)
    root = page.get("redeem_root")
    if not isinstance(root, str) or not HASH256_RE.fullmatch(root):
        raise RuntimeError("redeem_root is not canonical lowercase hash256")
    return count, root


class RedeemCommitment:
    def __init__(self):
        self.count = 0
        self.root = empty_root()

    def add_rpc_row(self, row):
        """Extend with one exact getbtcveldredeems row in received order."""
        if not isinstance(row, dict):
            raise RuntimeError("redeem commitment row is not an object")
        txid = _text(row.get("txid"), "redeem txid", 64)
        block_hash_text = row.get("block_hash")
        if (txid.decode("ascii", "strict") != row.get("txid") or
                not HASH256_RE.fullmatch(row["txid"])):
            raise RuntimeError("redeem txid is not canonical lowercase hash256")
        if (not isinstance(block_hash_text, str) or
                not HASH256_RE.fullmatch(block_hash_text)):
            raise RuntimeError("redeem block_hash is not canonical lowercase hash256")
        block_hash = bytes.fromhex(block_hash_text)
        vout = _uint(row.get("vout"), "redeem vout", 0xffffffff)
        token = _text(row.get("token"), "redeem token", 32)
        source = _text(row.get("from"), "redeem source", 128)
        destination_account = _text(row.get("to"), "redeem to", 128)
        amount = _uint(row.get("amount_sats"), "redeem amount_sats", MAX_WIRE_INT)
        height = _uint(row.get("block"), "redeem block", MAX_WIRE_INT)
        memo = _text(row.get("memo"), "redeem memo", 512)
        for field, expected in (("is_mint", False), ("is_burn", False),
                                ("is_redeem", True)):
            if row.get(field) is not expected:
                raise RuntimeError("redeem commitment row has invalid %s" % field)
        if token != b"btcVELD" or destination_account or amount == 0:
            raise RuntimeError("redeem commitment row is not canonical btcVELD")

        body = bytearray()
        body.extend(self.root)
        body.extend(block_hash)
        body.extend(_lp(txid))
        body.extend(struct.pack("<I", vout))
        body.extend(_lp(token))
        body.extend(_lp(source))
        body.extend(_lp(destination_account))
        body.extend(struct.pack("<Q", amount))
        body.extend(struct.pack("<Q", height))
        body.extend(_lp(memo))
        body.extend(b"\x00\x00\x01")
        self.root = hashlib.sha256(DOMAIN + body).digest()
        self.count += 1
        if self.count > (1 << 64) - 1:
            raise RuntimeError("redeem commitment count overflow")

    def verify(self, advertised_count, advertised_root):
        if self.count != advertised_count or self.root.hex() != advertised_root:
            raise RuntimeError(
                "redeem index completeness commitment mismatch "
                "(walked %d/%s, ledger %d/%s)" %
                (self.count, self.root.hex(), advertised_count,
                 advertised_root))


def authority_for_rows(rows):
    """Build RPC authority fields for deterministic fixtures/tooling."""
    if not isinstance(rows, (list, tuple)):
        raise RuntimeError("redeem commitment rows are not a sequence")
    commitment = RedeemCommitment()
    for row in rows:
        commitment.add_rpc_row(row)
    return {"redeem_count": commitment.count,
            "redeem_root": commitment.root.hex()}
