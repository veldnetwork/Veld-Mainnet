#!/usr/bin/env python3
"""
veld_peg_solvency.py - the single source of truth for the btcVELD peg-solvency
invariant, shared by the independent watchtower (veld_watchtowerd.py, runs on its
own box) and the issuer signer (veld_signerd.py, runs on the signer box).

Pure functions only: no I/O, no network, no fcntl - so it imports, runs, and
unit-tests identically on the signer box, the watchtower box, and a dev laptop.
That matters because this file encodes the load-bearing peg guard, and both sides
MUST agree on it byte-for-byte.

The invariant (design doc §7 / minter gate 8):

        backing_liability(btcVELD) + in_flight  <=  custody(BTC) - margin

``backing_liability`` is at least the live btcVELD supply and also includes
accepted REDEEM burns whose exact Bitcoin payout is not yet independently
confirmed.  A burn therefore cannot create mint headroom during the interval
between destroying btcVELD on Veld and spending BTC from custody.

All amounts are int64 sats; btcVELD is 1:1 wrapped BTC, so BTC sats == btcVELD
sats and the comparison is exact (no rounding, no float).

Trust split (why this makes F1's "no independent enforcement" go away):
  * The MINTER (custody box) checks the invariant too, but it is the box that a
    compromise would live on - so its check cannot be the only one.
  * The WATCHTOWER re-derives custody + supply from primary sources the minter
    cannot fake, and publishes a short-lived SOLVENT heartbeat carrying the
    remaining headroom.
  * The SIGNER (holds the only key that can mint) REQUIRES a fresh heartbeat and
    refuses to sign more than its headroom. So even a fully compromised custody
    box cannot mint unbacked btcVELD: the key never signs past what an
    independent observer just confirmed is backed by real BTC.

Beat authenticity: the transport (a locked-down SSH
forced-command) already stops a compromised custody box from delivering a beat,
but the payload is ALSO ML-DSA-signed by a dedicated watchtower key so the signer
trusts the beat's CONTENTS cryptographically, not merely the file's path. The bytes
that get signed/verified are canonical_beat_bytes() below - both boxes MUST derive
them identically, which is why it lives in this shared pure module.
"""

import json
import hashlib
import math
import re

SATS = 100_000_000

# Wire-format version of a heartbeat. The signer refuses a beat it doesn't
# understand (a format skew between the two boxes must fail closed, not guess).
HEARTBEAT_VERSION = 3
HASH256_RE = re.compile(r"^[0-9a-f]{64}$")

# Hard ceiling the receiver clamps every beat's lifetime to, no matter what the
# watchtower asks for. Bounds how long a single (last) beat can keep the signer
# live if the watchtower dies right after sending it.
MAX_TTL_SECS = 600
MAX_WIRE_INT = (1 << 63) - 1
RESERVATION_VERSION = 2
C1_RESERVATION_VERSION = 3
RESERVATION_KIND = "MINT_RESERVATION"
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
ALLOCATION_REQUEST_RE = re.compile(r"^[0-9a-f]{32}$")
BTC_OUTPOINT_RE = re.compile(r"^[0-9a-f]{64}:(0|[1-9][0-9]{0,9})$")
P2TR_ADDRESS_RE = re.compile(r"^bc1p[023456789ac-hj-np-z]{58}$")
P2TR_SCRIPT_RE = re.compile(r"^5120[0-9a-f]{64}$")


def _wire_uint(value, field, positive=False):
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 0
        or value > MAX_WIRE_INT
        or (positive and value == 0)
    ):
        raise ValueError(
            "%s must be a bounded %sinteger" % (field, "positive " if positive else "non-negative ")
        )
    return value


# --------------------------------------------------------------- the invariant
def solvency_headroom(custody_sats, backing_liability_sats, margin_sats):
    """Sats that may still be minted while keeping liabilities+margin <= custody.

    The second argument is the complete backing liability, not merely current
    supply.  In production it includes every accepted burn without an
    independently confirmed exact Bitcoin payout.  Negative means fail-closed
    insolvency.
    """
    return int(custody_sats) - int(backing_liability_sats) - int(margin_sats)


def is_solvent(custody_sats, supply_sats, margin_sats=0):
    return solvency_headroom(custody_sats, supply_sats, margin_sats) >= 0


# ------------------------------------------------- watchtower -> signer payload
def build_beat_payload(
    custody_sats,
    supply_sats,
    margin_sats,
    tip,
    tip_hash,
    seq,
    ttl_secs,
    backing_liability_sats=None,
):
    """Watchtower side: construct a SOLVENT beat payload. Only call when solvent;
    raises if headroom would be negative (never advertise phantom headroom)."""
    custody_sats = _wire_uint(custody_sats, "custody_sats")
    supply_sats = _wire_uint(supply_sats, "supply_sats")
    if backing_liability_sats is None:
        # Compatibility for pure/regtest callers. Production watchtower code
        # always passes the independently derived complete liability explicitly.
        backing_liability_sats = supply_sats
    backing_liability_sats = _wire_uint(backing_liability_sats, "backing_liability_sats")
    if backing_liability_sats < supply_sats:
        raise ValueError("backing_liability_sats cannot be below live supply")
    margin_sats = _wire_uint(margin_sats, "margin_sats")
    tip = _wire_uint(tip, "tip")
    seq = _wire_uint(seq, "seq", positive=True)
    ttl_secs = _wire_uint(ttl_secs, "ttl_secs", positive=True)
    if not isinstance(tip_hash, str) or not HASH256_RE.fullmatch(tip_hash):
        raise ValueError("tip_hash must be canonical lowercase hash256")
    headroom = solvency_headroom(custody_sats, backing_liability_sats, margin_sats)
    if headroom < 0:
        raise ValueError("refusing to build a SOLVENT beat while insolvent")
    return {
        "v": HEARTBEAT_VERSION,
        "kind": "SOLVENT",
        "custody_sats": custody_sats,
        "supply_sats": supply_sats,
        "backing_liability_sats": backing_liability_sats,
        "margin_sats": margin_sats,
        "headroom_sats": headroom,
        "tip": tip,
        "tip_hash": tip_hash,
        "seq": seq,
        "ttl_secs": ttl_secs,
    }


def build_halt_payload(reason):
    return {"v": HEARTBEAT_VERSION, "kind": "HALT", "reason": str(reason)[:200]}


def canonical_beat_bytes(payload):
    """The EXACT bytes the watchtower signs and the signer verifies. Both sides must
    produce byte-identical output, so serialize the payload's semantic fields
    deterministically (sorted keys, compact separators) and EXCLUDE the signature
    envelope itself (`sig`/`sig_alg`) so signing and verifying hash the same content.
    Only the watchtower's own fields are covered - the receiver-stamped issued/expiry
    are added AFTER verification and are not part of the signed message."""
    core = {k: payload[k] for k in payload if k not in ("sig", "sig_alg")}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reservation_id(
    issuer_id,
    request_id,
    unsigned_tx_sha256,
    sats,
    recipient,
    deposit_outpoint=None,
    allocation_request_id=None,
):
    """Stable identity for one mint authorization request.

    The witness keys idempotency by the complete immutable request, not by a
    caller-selected label.  Two active signer processes therefore race on the
    same reservation instead of independently consuming headroom.
    """
    core = {
        "issuer_id": issuer_id,
        "recipient": recipient,
        "request_id": request_id,
        "sats": sats,
        "unsigned_tx_sha256": unsigned_tx_sha256,
        "deposit_outpoint": deposit_outpoint,
        "allocation_request_id": allocation_request_id,
    }
    return hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def canonical_reservation_bytes(receipt):
    """Exact reservation-receipt bytes signed by the independent witness."""
    core = {k: receipt[k] for k in receipt if k not in ("sig", "sig_alg")}
    return json.dumps(core, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_reservation_receipt(receipt):
    if not isinstance(receipt, dict):
        return False, "reservation receipt is not an object"
    version = receipt.get("v")
    if version not in (RESERVATION_VERSION, C1_RESERVATION_VERSION):
        return False, "reservation receipt version is unsupported"
    if receipt.get("kind") != RESERVATION_KIND:
        return False, "reservation receipt kind is invalid"
    expected_fields = {
        "v",
        "kind",
        "issuer_id",
        "witness_id",
        "request_id",
        "unsigned_tx_sha256",
        "reservation_id",
        "sats",
        "recipient",
        "beat_seq",
        "tip",
        "tip_hash",
        "headroom_sats",
        "reserved_at",
        "allocation_verified",
        "allocation_request_id",
        "allocation_descriptor_index",
        "allocation_btc_address",
        "allocation_script_pubkey",
        "deposit_outpoint",
        "sig_alg",
        "sig",
    }
    c1_policy_fields = {
        "allocation_capacity_policy_sha256",
        "allocation_public_descriptor_range_start",
        "allocation_public_descriptor_range_end",
    }
    if version == C1_RESERVATION_VERSION:
        expected_fields |= c1_policy_fields
    if set(receipt) != expected_fields:
        return False, "reservation receipt has missing/unexpected fields"
    for field in ("issuer_id", "witness_id"):
        value = receipt.get(field)
        if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
            return False, "%s is invalid" % field
    for field in ("request_id", "unsigned_tx_sha256", "reservation_id", "tip_hash"):
        value = receipt.get(field)
        if not isinstance(value, str) or not HASH256_RE.fullmatch(value):
            return False, "%s is not canonical hash256" % field
    recipient = receipt.get("recipient")
    if not isinstance(recipient, str) or not (1 <= len(recipient) <= 128):
        return False, "recipient is invalid"
    allocation_verified = receipt.get("allocation_verified")
    if type(allocation_verified) is not bool:
        return False, "allocation_verified is not boolean"
    allocation_fields = (
        receipt.get("allocation_request_id"),
        receipt.get("allocation_descriptor_index"),
        receipt.get("allocation_btc_address"),
        receipt.get("allocation_script_pubkey"),
        receipt.get("deposit_outpoint"),
    )
    if allocation_verified:
        allocation_request_id, descriptor_index, address, script, outpoint = allocation_fields
        if version == RESERVATION_VERSION:
            descriptor_allowed = type(descriptor_index) is int and 1 <= descriptor_index <= 999
        else:
            policy_sha256 = receipt.get("allocation_capacity_policy_sha256")
            range_start = receipt.get("allocation_public_descriptor_range_start")
            range_end = receipt.get("allocation_public_descriptor_range_end")
            descriptor_allowed = (
                isinstance(policy_sha256, str)
                and HASH256_RE.fullmatch(policy_sha256) is not None
                and type(range_start) is int
                and range_start == 1000
                and type(range_end) is int
                and 10999 <= range_end <= 1_000_000
                and type(descriptor_index) is int
                and range_start <= descriptor_index <= range_end
            )
        if (
            not isinstance(allocation_request_id, str)
            or not ALLOCATION_REQUEST_RE.fullmatch(allocation_request_id)
            or not descriptor_allowed
            or not isinstance(address, str)
            or not P2TR_ADDRESS_RE.fullmatch(address)
            or not isinstance(script, str)
            or not P2TR_SCRIPT_RE.fullmatch(script)
            or not isinstance(outpoint, str)
            or not BTC_OUTPOINT_RE.fullmatch(outpoint)
            or int(outpoint.rsplit(":", 1)[1]) > 0xFFFFFFFF
        ):
            return False, "verified allocation binding is malformed"
    elif any(value is not None for value in allocation_fields):
        return False, "unverified reservation carries allocation fields"
    elif version == C1_RESERVATION_VERSION:
        return False, "C1 reservation must carry a verified allocation"
    try:
        _wire_uint(receipt.get("sats"), "sats", positive=True)
        _wire_uint(receipt.get("beat_seq"), "beat_seq", positive=True)
        _wire_uint(receipt.get("tip"), "tip")
        _wire_uint(receipt.get("headroom_sats"), "headroom_sats")
        _wire_uint(receipt.get("reserved_at"), "reserved_at", positive=True)
    except ValueError as e:
        return False, str(e)
    expected = reservation_id(
        receipt["issuer_id"],
        receipt["request_id"],
        receipt["unsigned_tx_sha256"],
        receipt["sats"],
        receipt["recipient"],
        receipt["deposit_outpoint"],
        receipt["allocation_request_id"],
    )
    if receipt["reservation_id"] != expected:
        return False, "reservation_id is inconsistent with immutable request"
    if receipt.get("sig_alg") != "mldsa65":
        return False, "reservation signature algorithm is invalid"
    sig = receipt.get("sig")
    if (
        not isinstance(sig, str)
        or not sig
        or len(sig) > 65536
        or len(sig) % 2
        or not re.fullmatch(r"[0-9a-f]+", sig)
    ):
        return False, "reservation signature is malformed"
    return True, "ok"


def _read_canonical_varint(raw, pos):
    if pos >= len(raw):
        raise ValueError("truncated transaction varint")
    first = raw[pos]
    pos += 1
    if first < 0xFD:
        return first, pos
    width = {0xFD: 2, 0xFE: 4, 0xFF: 8}[first]
    if pos + width > len(raw):
        raise ValueError("truncated transaction varint body")
    value = int.from_bytes(raw[pos : pos + width], "little")
    if (
        (first == 0xFD and value < 0xFD)
        or (first == 0xFE and value <= 0xFFFF)
        or (first == 0xFF and value <= 0xFFFFFFFF)
    ):
        raise ValueError("non-minimal transaction varint")
    return value, pos + width


def unsigned_template_from_signed_hex(signed_tx_hex):
    """Strip only input scriptSigs and return the exact unsigned serialization.

    Veld's signer mutates no other transaction field. Reconstructing this byte
    stream lets the independent witness prove a committed signed tx is the exact
    unsigned template whose SHA-256 was reserved.
    """
    if (
        not isinstance(signed_tx_hex, str)
        or not signed_tx_hex
        or len(signed_tx_hex) % 2
        or not re.fullmatch(r"[0-9a-fA-F]+", signed_tx_hex)
    ):
        raise ValueError("signed transaction is malformed hex")
    raw = bytes.fromhex(signed_tx_hex)
    if len(raw) < 10:
        raise ValueError("signed transaction is truncated")
    pos = 4
    in_count, after_count = _read_canonical_varint(raw, pos)
    if not (1 <= in_count <= 10_000):
        raise ValueError("signed transaction input count is invalid")
    unsigned = bytearray(raw[:after_count])
    pos = after_count
    for _ in range(in_count):
        if pos + 36 > len(raw):
            raise ValueError("signed transaction input is truncated")
        unsigned.extend(raw[pos : pos + 36])
        pos += 36
        script_len, after_len = _read_canonical_varint(raw, pos)
        if script_len == 0 or script_len > 32768 or after_len + script_len + 4 > len(raw):
            raise ValueError("signed transaction input script is empty/oversized/truncated")
        pos = after_len + script_len
        unsigned.append(0)
        unsigned.extend(raw[pos : pos + 4])
        pos += 4

    outputs_start = pos
    out_count, pos = _read_canonical_varint(raw, pos)
    if out_count > 100_000:
        raise ValueError("signed transaction output count is invalid")
    for _ in range(out_count):
        if pos + 8 > len(raw):
            raise ValueError("signed transaction output is truncated")
        pos += 8
        script_len, pos = _read_canonical_varint(raw, pos)
        if script_len > 4 * 1024 * 1024 or pos + script_len > len(raw):
            raise ValueError("signed transaction output script is truncated/oversized")
        pos += script_len
    if pos + 4 != len(raw):
        raise ValueError("signed transaction has trailing/truncated locktime bytes")
    unsigned.extend(raw[outputs_start:])
    return bytes(unsigned).hex()


def validate_unsigned_template_hex(unsigned_tx_hex):
    """Parse the complete Veld transaction envelope and require empty scriptSigs."""
    if (
        not isinstance(unsigned_tx_hex, str)
        or not unsigned_tx_hex
        or len(unsigned_tx_hex) % 2
        or not re.fullmatch(r"[0-9a-fA-F]+", unsigned_tx_hex)
    ):
        raise ValueError("unsigned transaction is malformed hex")
    raw = bytes.fromhex(unsigned_tx_hex)
    if len(raw) < 10:
        raise ValueError("unsigned transaction is truncated")
    pos = 4
    in_count, pos = _read_canonical_varint(raw, pos)
    if not (1 <= in_count <= 10_000):
        raise ValueError("unsigned transaction input count is invalid")
    for _ in range(in_count):
        if pos + 36 > len(raw):
            raise ValueError("unsigned transaction input is truncated")
        pos += 36
        script_len, pos = _read_canonical_varint(raw, pos)
        if script_len != 0:
            raise ValueError("unsigned transaction has a non-empty input script")
        if pos + 4 > len(raw):
            raise ValueError("unsigned transaction input sequence is truncated")
        pos += 4
    out_count, pos = _read_canonical_varint(raw, pos)
    if out_count > 100_000:
        raise ValueError("unsigned transaction output count is invalid")
    for _ in range(out_count):
        if pos + 8 > len(raw):
            raise ValueError("unsigned transaction output is truncated")
        pos += 8
        script_len, pos = _read_canonical_varint(raw, pos)
        if script_len > 4 * 1024 * 1024 or pos + script_len > len(raw):
            raise ValueError("unsigned transaction output script is truncated/oversized")
        pos += script_len
    if pos + 4 != len(raw):
        raise ValueError("unsigned transaction has trailing/truncated locktime bytes")
    return raw


def validate_beat_payload(p):
    """Receiver side (on the signer box): validate a payload that just arrived over
    the watchtower's SSH forced-command, BEFORE writing it to disk. Returns
    (ok, reason). Rejects anything malformed so a garbled beat can't become a
    live heartbeat."""
    if not isinstance(p, dict):
        return False, "payload not an object"
    if p.get("v") != HEARTBEAT_VERSION:
        return False, "version %r != %d" % (p.get("v"), HEARTBEAT_VERSION)
    kind = p.get("kind")
    if kind not in ("SOLVENT", "HALT"):
        return False, "bad kind %r" % (kind,)
    if kind == "HALT":
        return True, "ok"
    for k in (
        "custody_sats",
        "supply_sats",
        "backing_liability_sats",
        "margin_sats",
        "headroom_sats",
        "tip",
        "tip_hash",
        "seq",
        "ttl_secs",
    ):
        if k not in p:
            return False, "missing " + k
    try:
        for k in (
            "custody_sats",
            "supply_sats",
            "backing_liability_sats",
            "margin_sats",
            "headroom_sats",
            "tip",
        ):
            _wire_uint(p[k], k)
        _wire_uint(p["seq"], "seq", positive=True)
        _wire_uint(p["ttl_secs"], "ttl_secs", positive=True)
    except ValueError as e:
        return False, str(e)
    if not isinstance(p["tip_hash"], str) or not HASH256_RE.fullmatch(p["tip_hash"]):
        return False, "tip_hash is not canonical lowercase hash256"
    if not (0 < int(p["ttl_secs"]) <= MAX_TTL_SECS):
        return False, "ttl out of range"
    if int(p["backing_liability_sats"]) < int(p["supply_sats"]):
        return False, "backing liability is below live supply"
    # Headroom must be exactly consistent with the amounts - the receiver will not
    # take the watchtower's word for a headroom that doesn't match custody-supply.
    if int(p["headroom_sats"]) != solvency_headroom(
        p["custody_sats"], p["backing_liability_sats"], p["margin_sats"]
    ):
        return False, "headroom inconsistent with custody/liability/margin"
    return True, "ok"


def stamp_heartbeat(payload, recv_now, max_ttl_secs=MAX_TTL_SECS):
    """Receiver side: turn a validated SOLVENT payload into the on-disk heartbeat,
    stamping issued/expiry from the RECEIVER's own clock (same box as the signer,
    so no cross-box clock skew, and a replayed payload can't extend its own life)."""
    ttl = min(int(payload.get("ttl_secs", 0)), int(max_ttl_secs))
    hb = dict(payload)
    hb["issued_at"] = float(recv_now)
    hb["received_at"] = float(recv_now)
    hb["expires_at"] = float(recv_now) + float(ttl)
    return hb


# --------------------------------------------------- signer-side on-disk gate
def validate_heartbeat(hb):
    """Signer side: validate the on-disk heartbeat (a stamped SOLVENT beat)."""
    if not isinstance(hb, dict):
        return False, "heartbeat not an object"
    ok, why = validate_beat_payload(hb)
    if not ok:
        return False, why
    if hb.get("kind") != "SOLVENT":
        return False, "kind %r not SOLVENT" % (hb.get("kind"),)
    for k in ("expires_at", "issued_at"):
        if k not in hb:
            return False, "missing " + k
    try:
        for k in ("expires_at", "issued_at"):
            if isinstance(hb[k], bool) or not isinstance(hb[k], (int, float)):
                raise ValueError
            if not math.isfinite(float(hb[k])) or float(hb[k]) < 0:
                raise ValueError
    except (TypeError, ValueError):
        return False, "heartbeat timestamp types invalid"
    return True, "ok"


def heartbeat_gate(hb, now, outstanding_signed_sats, mint_sats):
    """The signer's FAIL-CLOSED decision for one mint of mint_sats.

      hb                : last heartbeat dict the signer holds (or None)
      now               : current unix time (float)
      outstanding_signed_sats: exact signed transactions not yet confirmed in
                               the heartbeat's canonical supply snapshot (so
                               backing cannot be reused across confirmation lag)
      mint_sats         : the mint being requested

    Returns (allow: bool, reason: str). Any doubt -> deny."""
    if hb is None:
        return False, "no watchtower heartbeat present (fail-closed)"
    ok, why = validate_heartbeat(hb)
    if not ok:
        return False, "invalid heartbeat: " + why
    if float(now) > float(hb["expires_at"]):
        age = int(float(now) - float(hb["expires_at"]))
        return False, "heartbeat expired %ds ago (watchtower stale/down; fail-closed)" % age
    if int(mint_sats) <= 0:
        return False, "mint amount non-positive"
    headroom = int(hb["headroom_sats"])
    used = int(outstanding_signed_sats)
    if used + int(mint_sats) > headroom:
        return False, (
            "would exceed watchtower headroom: outstanding_signed %d + mint %d > headroom %d"
            % (used, int(mint_sats), headroom)
        )
    return True, "ok"
