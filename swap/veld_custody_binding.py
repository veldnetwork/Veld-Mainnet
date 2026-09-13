#!/usr/bin/env python3
"""Shared fail-closed validation for the btcVELD 3-of-5 custody domain.

The descriptor is the public authority for the operational custody range. Veld
consensus intentionally keeps its launch identity at [0,999] and accepts SPV
deposits only to descriptor index 0. C1 may extend the same descriptor for
off-chain public allocations; that extended manifest is separately byte-pinned
and must never be confused with the compiled consensus manifest identity.
"""

import hashlib
import json
import os
import re

try:
    from .rpc_url_policy import read_bounded_regular_file, strict_json_loads
except ImportError:  # direct-script execution
    from rpc_url_policy import read_bounded_regular_file, strict_json_loads


HEX64_RE = re.compile(r"[0-9a-f]{64}")
P2TR_SPK_RE = re.compile(r"5120[0-9a-f]{64}")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MANIFEST_KEYS = {
    "version", "descriptor", "descriptor_sha256", "range", "script_pubkeys",
}
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _hex64(value, label):
    if not isinstance(value, str) or not HEX64_RE.fullmatch(value):
        raise RuntimeError("%s must be canonical lowercase 64-hex" % label)
    return value


def load_manifest(path, expected_descriptor_sha256,
                  expected_manifest_sha256, expected_spv_spk_hex=None,
                  require_absolute=True, expected_range_end=999,
                  expected_consensus_manifest_sha256=None):
    """Load one exact custody manifest and return its normalized binding.

    The SHA-256 is over the manifest's exact bytes.  This makes an operator's
    independently recorded ceremony digest meaningful and prevents a daemon
    from silently accepting a locally rewritten but semantically similar file.
    """
    if not isinstance(path, str) or not path:
        raise RuntimeError("custody SPK manifest path is required")
    if require_absolute and not os.path.isabs(path):
        raise RuntimeError("custody SPK manifest path must be absolute")
    descriptor_hash = _hex64(expected_descriptor_sha256,
                             "custody descriptor SHA-256")
    manifest_hash = _hex64(expected_manifest_sha256,
                           "custody manifest SHA-256")
    if (type(expected_range_end) is not int or
            not 999 <= expected_range_end <= 1_000_000):
        raise RuntimeError("custody manifest range end is outside [999,1000000]")
    consensus_manifest_hash = (
        manifest_hash if expected_consensus_manifest_sha256 is None else
        _hex64(expected_consensus_manifest_sha256,
               "consensus custody manifest SHA-256"))
    try:
        raw = read_bounded_regular_file(
            os.path.abspath(path), MAX_MANIFEST_BYTES,
            "custody SPK manifest")
    except OSError as exc:
        raise RuntimeError("cannot read custody SPK manifest: %s" % exc)
    if hashlib.sha256(raw).hexdigest() != manifest_hash:
        raise RuntimeError("custody SPK manifest bytes differ from the pinned SHA-256")
    try:
        document = strict_json_loads(raw, "custody SPK manifest")
    except (UnicodeError, ValueError, TypeError) as exc:
        raise RuntimeError("custody SPK manifest is not canonical UTF-8 JSON: %s" % exc)

    if not isinstance(document, dict) or set(document) != MANIFEST_KEYS:
        raise RuntimeError("custody SPK manifest schema is not exact")
    descriptor = document.get("descriptor")
    scripts = document.get("script_pubkeys")
    if (document.get("version") != 1 or
            not isinstance(descriptor, str) or
            not descriptor.startswith("tr(") or
            "multi_a(3," not in descriptor or
            re.search(r"(?:xprv|tprv|yprv|zprv|uprv|vprv)", descriptor, re.I) or
            hashlib.sha256(descriptor.encode("utf-8")).hexdigest() != descriptor_hash or
            document.get("descriptor_sha256") != descriptor_hash or
            document.get("range") != [0, expected_range_end] or
            not isinstance(scripts, list) or
            len(scripts) != expected_range_end + 1 or
            len(set(scripts)) != expected_range_end + 1 or
            any(not isinstance(item, str) or not P2TR_SPK_RE.fullmatch(item)
                for item in scripts)):
        raise RuntimeError("custody descriptor/SPK manifest is not exact/hash-bound")

    if expected_range_end == 999:
        if consensus_manifest_hash != manifest_hash:
            raise RuntimeError(
                "legacy operational and consensus manifest identities differ")
    else:
        prefix = dict(document)
        prefix["range"] = [0, 999]
        prefix["script_pubkeys"] = scripts[:1000]
        prefix_bytes = (json.dumps(
            prefix, sort_keys=True, separators=(",", ":")) + "\n").encode(
                "utf-8")
        if hashlib.sha256(prefix_bytes).hexdigest() != consensus_manifest_hash:
            raise RuntimeError(
                "C1 operational manifest prefix differs from compiled consensus manifest")

    spv_spk = scripts[0]
    if expected_spv_spk_hex is not None:
        if (not isinstance(expected_spv_spk_hex, str) or
                not P2TR_SPK_RE.fullmatch(expected_spv_spk_hex)):
            raise RuntimeError("expected SPV custody script must be canonical P2TR")
        if spv_spk != expected_spv_spk_hex:
            raise RuntimeError("manifest index 0 differs from the pinned SPV custody script")

    return {
        "descriptor": descriptor,
        "descriptor_sha256": descriptor_hash,
        "manifest_sha256": manifest_hash,
        "consensus_manifest_sha256": consensus_manifest_hash,
        "consensus_range": [0, 999],
        "range": [0, expected_range_end],
        "script_pubkeys": tuple(scripts),
        "script_pubkey_set": frozenset(scripts),
        "spv_custody_descriptor_index": 0,
        "spv_custody_spk_hex": spv_spk,
    }


def verify_peg_identity(peg, binding):
    """Require a getpeginfo response to match one locally pinned manifest."""
    if not isinstance(peg, dict) or peg.get("active") is not True:
        raise RuntimeError("getpeginfo does not report an active btcVELD peg")
    if peg.get("spv_active") is not True:
        raise RuntimeError("getpeginfo does not report launch-live SPV minting")
    if peg.get("custody_descriptor_sha256") != binding["descriptor_sha256"]:
        raise RuntimeError("compiled custody descriptor identity differs from the manifest")
    if (peg.get("custody_manifest_sha256") !=
            binding["consensus_manifest_sha256"]):
        raise RuntimeError("compiled custody manifest identity differs from the pinned file")
    if peg.get("custody_descriptor_range") != binding["consensus_range"]:
        raise RuntimeError("compiled custody descriptor range differs from the manifest")
    if peg.get("spv_custody_descriptor_index") != 0:
        raise RuntimeError("compiled SPV custody descriptor index is not zero")
    if peg.get("spv_custody_spk_hex") != binding["spv_custody_spk_hex"]:
        raise RuntimeError("compiled SPV custody script differs from manifest index 0")


def _bech32m_spk(address):
    if not isinstance(address, str) or address.lower() != address or \
            not address.startswith("bc1"):
        raise RuntimeError("derived custody address is not canonical mainnet bech32m")
    split = address.rfind("1")
    values = [BECH32_CHARSET.find(char) for char in address[split + 1:]]
    if len(values) < 7 or any(value < 0 for value in values):
        raise RuntimeError("derived custody address has invalid bech32m data")
    expanded = ([ord(char) >> 5 for char in address[:split]] + [0] +
                [ord(char) & 31 for char in address[:split]])
    check = 1
    generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                  0x3d4233dd, 0x2a1462b3)
    for value in expanded + values:
        top = check >> 25
        check = ((check & 0x1ffffff) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                check ^= generator
    if check != 0x2bc830a3:
        raise RuntimeError("derived custody address has invalid bech32m checksum")
    payload = values[:-6]
    if not payload or payload[0] != 1:
        raise RuntimeError("derived custody address is not witness version 1")
    acc = 0
    bits = 0
    program = bytearray()
    for value in payload[1:]:
        acc = (acc << 5) | value
        bits += 5
        while bits >= 8:
            bits -= 8
            program.append((acc >> bits) & 0xff)
    if bits and ((acc << (8 - bits)) & 0xff):
        raise RuntimeError("derived custody address has nonzero padding")
    if len(program) != 32:
        raise RuntimeError("derived custody address has a non-32-byte witness program")
    return "5120" + bytes(program).hex()


def verify_core_derivation(call, binding):
    """Re-derive every ranged script with Bitcoin Core and compare the manifest."""
    custody_range = binding.get("range") if isinstance(binding, dict) else None
    if (not isinstance(custody_range, list) or len(custody_range) != 2 or
            custody_range[0] != 0 or type(custody_range[1]) is not int or
            not 999 <= custody_range[1] <= 1_000_000):
        raise RuntimeError("custody derivation range is invalid")
    count = custody_range[1] + 1
    addresses = call(
        "deriveaddresses", binding["descriptor"],
        "[0,%d]" % custody_range[1])
    if not isinstance(addresses, list) or len(addresses) != count or \
            len(set(addresses)) != count:
        raise RuntimeError(
            "Bitcoin Core did not derive %d unique custody addresses" % count)
    scripts = tuple(_bech32m_spk(address) for address in addresses)
    if scripts != binding["script_pubkeys"]:
        raise RuntimeError("Bitcoin Core descriptor derivation differs from custody manifest")
