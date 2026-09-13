#!/usr/bin/env python3
"""Wire-identical helpers for the consensus C1 allocation commitment."""

import hashlib
import re
import struct


COMMITMENT_DOMAIN = b"VELD_BTCVELD_C1_ALLOCATION_COMMITMENT_v2|"
REQUEST_RE = re.compile(r"0{16}[0-9a-f]{16}")
VELD_RE = re.compile(r"V[1-9A-HJ-NP-Za-km-z]{25,49}")
P2TR_RE = re.compile(r"5120[0-9a-f]{64}")
COMMITMENT_RE = re.compile(r"[0-9a-f]{64}")


def _length_prefixed(text):
    raw = text.encode("ascii", "strict")
    if len(raw) > 0xffffffff:
        raise ValueError("C1 commitment field is oversized")
    return struct.pack("<I", len(raw)) + raw


def allocation_commitment(request_id, recipient, amount_sats,
                          script_pubkey_hex, commitment_blind_hex):
    """Return the exact C++ c1reserve::AllocationCommitment hex value."""
    if (not isinstance(request_id, str) or
            not REQUEST_RE.fullmatch(request_id) or
            int(request_id, 16) == 0 or
            not isinstance(recipient, str) or
            not VELD_RE.fullmatch(recipient) or
            type(amount_sats) is not int or amount_sats <= 0 or
            amount_sats > (1 << 63) - 1 or
            not isinstance(script_pubkey_hex, str) or
            not P2TR_RE.fullmatch(script_pubkey_hex) or
            not isinstance(commitment_blind_hex, str) or
            not COMMITMENT_RE.fullmatch(commitment_blind_hex) or
            int(commitment_blind_hex, 16) == 0):
        raise ValueError("C1 allocation commitment identity is malformed")
    body = (_length_prefixed(request_id) + _length_prefixed(recipient) +
            struct.pack("<Q", amount_sats) +
            _length_prefixed(script_pubkey_hex) +
            _length_prefixed(commitment_blind_hex))
    return hashlib.sha256(COMMITMENT_DOMAIN + body).hexdigest()


def allocation_id(sequence):
    if type(sequence) is not int or not 1 <= sequence <= (1 << 64) - 1:
        raise ValueError("C1 allocation sequence is outside uint64")
    return "%032x" % sequence
