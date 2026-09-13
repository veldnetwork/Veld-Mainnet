"""Fresh, keyless RTP1 signing inspections from an independently pinned node.

This contract is not a witness reservation, an issuer signature, or permission to
activate issuance. Durable migration and signed-retry reconciliation remain
separate from a fresh inspection. No coordinator-supplied reserve context is used.
"""
import hashlib
import json
import re

from veld_chain_identity import parse_expected_chain, verify_expected_chain
from rpc_url_policy import run_bounded_subprocess, strict_json_loads


_HASH = re.compile(r"[0-9a-f]{64}")
_OUTPOINT = re.compile(r"[0-9a-f]{64}:(0|[1-9][0-9]{0,9})")
_FIELDS = frozenset({
    "version", "proof_version", "tip", "tip_hash", "candidate_height", "final_height",
    "genesis_hash", "unsigned_tx_sha256", "proof_sha256", "issuer", "recipient",
    "sats", "fee_units", "deposit_outpoint", "bitcoin_txid", "bitcoin_block",
    "reserve_prior_state_hex", "reserve_prior_supply_sats", "nullifier_root",
    "custody_descriptor_sha256", "custody_manifest_sha256",
})
_HASH_FIELDS = frozenset({
    "tip_hash", "genesis_hash", "unsigned_tx_sha256", "proof_sha256", "bitcoin_txid",
    "bitcoin_block", "nullifier_root", "custody_descriptor_sha256", "custody_manifest_sha256",
})


def _hash(value, description):
    if type(value) is not str or not _HASH.fullmatch(value) or value == "0" * 64:
        raise ValueError("%s must be a reviewed nonzero hash" % description)
    return value


def _template_bytes(unsigned_tx_hex):
    if (type(unsigned_tx_hex) is not str or not unsigned_tx_hex or
            len(unsigned_tx_hex) > 256 * 1024 or len(unsigned_tx_hex) % 2 or
            not re.fullmatch(r"[0-9a-f]+", unsigned_tx_hex)):
        raise ValueError("unsigned RTP1 mint template is not bounded canonical hex")
    return bytes.fromhex(unsigned_tx_hex)


def validate_inspection(value, unsigned_tx_hex, *, expected_chain, issuer,
                        recipient, sats, custody_descriptor_sha256,
                        custody_manifest_sha256):
    expected = parse_expected_chain(expected_chain)
    descriptor = _hash(custody_descriptor_sha256, "custody descriptor")
    manifest = _hash(custody_manifest_sha256, "custody manifest")
    raw = _template_bytes(unsigned_tx_hex)
    if type(value) is not dict or set(value) != _FIELDS:
        raise ValueError("RTP1 inspection schema is not version 1")
    if type(value["version"]) is not int or value["version"] != 1 or value["proof_version"] != "RTP1":
        raise ValueError("RTP1 inspection version is unsupported")
    for field in _HASH_FIELDS:
        _hash(value[field], field)
    for field in ("tip", "candidate_height", "final_height", "sats", "fee_units", "reserve_prior_supply_sats"):
        if type(value[field]) is not int or not 0 <= value[field] <= (1 << 63) - 1:
            raise ValueError("RTP1 inspection %s is not a bounded integer" % field)
    for field in ("issuer", "recipient"):
        if type(value[field]) is not str or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,49}", value[field]):
            raise ValueError("RTP1 inspection account is not canonical")
    if type(sats) is not int or sats <= 0:
        raise ValueError("RTP1 expected amount must be a positive integer")
    if (value["candidate_height"] != value["tip"] + 1 or
            not 0 < value["final_height"] <= value["tip"] or value["fee_units"] != 100000):
        raise ValueError("RTP1 inspection frame or fee is inconsistent")
    if (value["genesis_hash"] != expected["genesis_hash"] or value["issuer"] != issuer or
            value["recipient"] != recipient or value["sats"] != sats or
            value["custody_descriptor_sha256"] != descriptor or
            value["custody_manifest_sha256"] != manifest or
            value["unsigned_tx_sha256"] != hashlib.sha256(raw).hexdigest()):
        raise ValueError("RTP1 inspection differs from the exact mint and custody policy")
    outpoint = value["deposit_outpoint"]
    if (type(outpoint) is not str or not _OUTPOINT.fullmatch(outpoint) or
            int(outpoint.split(":")[1]) > 0xffffffff):
        raise ValueError("RTP1 inspection deposit identity is malformed")
    state = value["reserve_prior_state_hex"]
    if type(state) is not str or not 2 <= len(state) <= 4096 or len(state) % 2 or not re.fullmatch(r"[0-9a-f]+", state):
        raise ValueError("RTP1 inspection prior-state encoding is not bounded canonical hex")
    return dict(value)


def inspect_fresh_mint(call, unsigned_tx_hex, **policy):
    """Call only an independently configured/authenticated operator RPC.

    A new tip or unavailable chain observation refuses the inspection. This
    function neither falls back to a prior inspection nor reauthorizes a cached
    signed carrier. The caller must retain its own durable retry state.
    """
    _template_bytes(unsigned_tx_hex)
    _hash(policy["custody_descriptor_sha256"], "custody descriptor")
    _hash(policy["custody_manifest_sha256"], "custody manifest")
    verify_expected_chain(call, policy["expected_chain"])
    response = call("inspectrtp1mint", [unsigned_tx_hex])
    inspected = validate_inspection(response, unsigned_tx_hex, **policy)
    height = call("getblockcount", [])
    if type(height) is not int or height != inspected["tip"]:
        raise ValueError("native tip changed during RTP1 inspection; retry with fresh state")
    if call("getblockhash", [height]) != inspected["tip_hash"]:
        raise ValueError("native branch changed during RTP1 inspection; retry with fresh state")
    return inspected


def decode_inspected_mint(keygen, issuer_script, unsigned_tx_hex, inspection, **policy):
    """Check the exact inspected template with the native, keyless decoder.

    This also works for a retained reservation's immutable inspection, without
    representing that old observation as permission to issue a new signature.
    Fresh signing must repeat inspect_fresh_mint immediately before signing.
    """
    inspection = validate_inspection(inspection, unsigned_tx_hex, **policy)
    if (type(issuer_script) is not str or
            not re.fullmatch(r"76a914[0-9a-f]{40}88ac", issuer_script)):
        raise ValueError("RTP1 decoder requires the independently derived issuer script")
    payload = {"issuer_script_hex": issuer_script, "unsigned_tx_hex": unsigned_tx_hex,
        "reserve_prior_state_hex": inspection["reserve_prior_state_hex"],
        "reserve_prior_supply_sats": inspection["reserve_prior_supply_sats"]}
    result = run_bounded_subprocess([keygen, "decode-mint-stdin"],
        input_text=json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False), timeout=30,
        stdout_max=256 * 1024, stderr_max=64 * 1024, description="RTP1 mint decoder")
    if result.returncode != 0:
        raise ValueError("native RTP1 mint decoder refused the template")
    decoded = strict_json_loads(result.stdout, "RTP1 mint decoder response")
    if type(decoded) is not dict or set(decoded) != {
            "from", "to", "sats", "memo", "total_out_sats", "num_inputs"}:
        raise ValueError("RTP1 mint decoder response schema is invalid")
    for field in ("sats", "total_out_sats", "num_inputs"):
        if type(decoded[field]) is not int or not 0 <= decoded[field] <= (1 << 63) - 1:
            raise ValueError("RTP1 mint decoder integer is invalid")
    if (decoded["from"] != inspection["issuer"] or decoded["to"] != inspection["recipient"] or
            decoded["sats"] != inspection["sats"] or not 1 <= decoded["num_inputs"] <= 4096):
        raise ValueError("RTP1 mint decoder differs from the exact inspected intent")
    memo = decoded["memo"]
    if (type(memo) is not str or not memo.startswith("RTP1:") or
            not 2 <= len(memo) - 5 <= 256 * 1024 or (len(memo) - 5) % 2 or
            not re.fullmatch(r"[0-9a-f]+", memo[5:]) or
            hashlib.sha256(bytes.fromhex(memo[5:])).hexdigest() != inspection["proof_sha256"]):
        raise ValueError("RTP1 mint decoder proof differs from the inspected proof")
    return dict(decoded)
