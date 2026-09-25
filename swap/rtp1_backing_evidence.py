"""Independent Bitcoin backing checks for an already inspected RTP1 template.

The native decoder authenticates direct-parent and recipient bindings. A pinned
Bitcoin full node must independently observe the exact successor on its active
chain and unspent, including its mempool. Neither result grants signing authority.
"""

from decimal import Decimal, InvalidOperation
import hashlib
import json
import re

from rpc_url_policy import run_bounded_subprocess, strict_json_loads
from rtp1_mint_policy import inspect_fresh_mint, validate_inspection


_HASH = re.compile(r"[0-9a-f]{64}")
_OUTPOINT = re.compile(r"[0-9a-f]{64}:(0|[1-9][0-9]{0,9})")
_FACT_FIELDS = frozenset(
    {
        "version",
        "operation",
        "network_binding",
        "prior_commitment",
        "prior_transition_count",
        "bitcoin_txid",
        "bitcoin_block",
        "reserve_vout",
        "reserve_value_sats",
        "deposit_outpoint",
        "exact_commitment",
        "sats",
        "recipient",
        "issuer",
        "custody_script_hex",
        "direct_parent_txids",
    }
)
MAX_BTC_SATS = 21_000_000 * 100_000_000


def _hash(value, label):
    if type(value) is not str or not _HASH.fullmatch(value) or value == "0" * 64:
        raise ValueError(label + " is not a nonzero canonical hash")
    return value


def _uint(value, maximum, label, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(label + " is not a bounded integer")
    return value


def _script(value):
    if type(value) is not str or not re.fullmatch(r"5120[0-9a-f]{64}", value):
        raise ValueError("custody script is not the pinned P2TR output")
    return value


def _sats(value):
    if type(value) not in (int, float, Decimal):
        raise ValueError("Bitcoin value has an invalid type")
    try:
        amount = Decimal(str(value)) * 100_000_000
        if (
            not amount.is_finite()
            or amount != amount.to_integral_value()
            or not 0 <= amount <= MAX_BTC_SATS
        ):
            raise ValueError("Bitcoin value is not an exact bounded satoshi amount")
        return int(amount)
    except (InvalidOperation, OverflowError) as error:
        raise ValueError("Bitcoin value is invalid") from error


def validate_backing_facts(value):
    if type(value) is not dict or set(value) != _FACT_FIELDS:
        raise ValueError("native backing facts have an invalid schema")
    if type(value["version"]) is not int or value["version"] != 1:
        raise ValueError("native backing facts version is unsupported")
    if type(value["operation"]) is not str or value["operation"] not in {"OPEN", "DEPOSIT"}:
        raise ValueError("native backing operation is not a mint")
    for field in (
        "network_binding",
        "prior_commitment",
        "bitcoin_txid",
        "bitcoin_block",
        "exact_commitment",
    ):
        _hash(value[field], field)
    _uint(value["prior_transition_count"], (1 << 64) - 1, "transition count")
    _uint(value["reserve_vout"], 0xFFFFFFFE, "reserve output")
    _uint(value["reserve_value_sats"], MAX_BTC_SATS, "reserve value", 1)
    _uint(value["sats"], value["reserve_value_sats"], "mint amount", 1)
    _script(value["custody_script_hex"])
    for field in ("recipient", "issuer"):
        if type(value[field]) is not str or not re.fullmatch(
            r"V[1-9A-HJ-NP-Za-km-z]{25,49}", value[field]
        ):
            raise ValueError("native backing account is invalid")
    outpoint = value["deposit_outpoint"]
    if (
        type(outpoint) is not str
        or not _OUTPOINT.fullmatch(outpoint)
        or int(outpoint.split(":")[1]) > 0xFFFFFFFF
    ):
        raise ValueError("native backing deposit is invalid")
    parents = value["direct_parent_txids"]
    if type(parents) is not list or not 1 <= len(parents) <= 8:
        raise ValueError("native backing parent list is invalid")
    for parent in parents:
        _hash(parent, "direct parent")
    if value["operation"] == "OPEN":
        if outpoint != value["bitcoin_txid"] + ":" + str(value["reserve_vout"]):
            raise ValueError("OPEN does not identify the reserve deposit")
    elif len(parents) != 2 or outpoint.split(":")[0] not in parents:
        raise ValueError("DEPOSIT does not identify its exact pending parent")
    return dict(value, direct_parent_txids=list(parents))


def decode_backing_facts(keygen, issuer_script, unsigned_tx_hex, inspection, **policy):
    inspection = validate_inspection(inspection, unsigned_tx_hex, **policy)
    if type(issuer_script) is not str or not re.fullmatch(r"76a914[0-9a-f]{40}88ac", issuer_script):
        raise ValueError("independent issuer script is invalid")
    payload = {
        "issuer_script_hex": issuer_script,
        "unsigned_tx_hex": unsigned_tx_hex,
        "reserve_prior_state_hex": inspection["reserve_prior_state_hex"],
        "reserve_prior_supply_sats": inspection["reserve_prior_supply_sats"],
    }
    result = run_bounded_subprocess(
        [keygen, "inspect-rtp1-backing-stdin"],
        input_text=json.dumps(payload, separators=(",", ":"), allow_nan=False),
        timeout=30,
        stdout_max=64 * 1024,
        stderr_max=64 * 1024,
        description="native RTP1 backing decoder",
    )
    if result.returncode:
        raise ValueError("native RTP1 backing decoder refused the template")
    facts = validate_backing_facts(strict_json_loads(result.stdout, "native backing facts"))
    for field in ("issuer", "recipient", "sats", "deposit_outpoint"):
        if facts[field] != inspection[field]:
            raise ValueError("native backing differs from inspected " + field)
    for field in ("bitcoin_txid", "bitcoin_block"):
        if facts[field] != bytes.fromhex(inspection[field])[::-1].hex():
            raise ValueError("native backing differs from inspected Bitcoin identity")
    return facts


def _bitcoin_frame(call, network, genesis):
    if call("getblockhash", [0]) != genesis:
        raise ValueError("Bitcoin genesis differs from the independent pin")
    info = call("getblockchaininfo", [])
    if (
        type(info) is not dict
        or info.get("chain") != network
        or info.get("initialblockdownload") is not False
    ):
        raise ValueError("Bitcoin node is not ready on its intended network")
    height = _uint(info.get("blocks"), (1 << 31) - 1, "Bitcoin height")
    if type(info.get("headers")) is not int or info["headers"] != height:
        raise ValueError("Bitcoin full validation has not reached its headers")
    best = _hash(info.get("bestblockhash"), "Bitcoin tip")
    if call("getblockhash", [height]) != best:
        raise ValueError("Bitcoin tip changed while sampling its frame")
    return height, best


def verify_bitcoin_backing(
    call, facts, *, expected_network, expected_genesis, custody_script_hex, min_confirmations
):
    """Use only an independently configured, authenticated, bounded Core RPC.

    min_confirmations is an explicit deployment pin, not a coordinator field.
    The service's configuration contract must enforce its production floor.
    No original-deposit gettxout shortcut is used for a DEPOSIT rollover.
    """
    facts = validate_backing_facts(facts)
    if type(expected_network) is not str or expected_network not in {
        "main",
        "test",
        "testnet4",
        "signet",
        "regtest",
    }:
        raise ValueError("Bitcoin network must be explicitly pinned")
    _hash(expected_genesis, "Bitcoin genesis pin")
    _script(custody_script_hex)
    _uint(min_confirmations, 1_000_000, "Bitcoin confirmation policy", 1)
    if facts["custody_script_hex"] != custody_script_hex:
        raise ValueError("native custody script differs from the independent pin")
    height, best = _bitcoin_frame(call, expected_network, expected_genesis)
    header = call("getblockheader", [facts["bitcoin_block"], True])
    if type(header) is not dict or header.get("hash") != facts["bitcoin_block"]:
        raise ValueError("Bitcoin inclusion block is unavailable")
    included = _uint(header.get("height"), height, "Bitcoin inclusion height")
    confirmations = height - included + 1
    if (
        type(header.get("confirmations")) is not int
        or header["confirmations"] != confirmations
        or confirmations < min_confirmations
        or call("getblockhash", [included]) != facts["bitcoin_block"]
    ):
        raise ValueError("Bitcoin reserve inclusion is not sufficiently confirmed and canonical")
    transaction = call("getrawtransaction", [facts["bitcoin_txid"], True, facts["bitcoin_block"]])
    if (
        type(transaction) is not dict
        or transaction.get("txid") != facts["bitcoin_txid"]
        or transaction.get("blockhash") != facts["bitcoin_block"]
        or transaction.get("in_active_chain") is not True
    ):
        raise ValueError("Bitcoin reserve transaction is not in the exact active block")
    inputs = transaction.get("vin")
    if (
        type(inputs) is not list
        or len(inputs) != len(facts["direct_parent_txids"])
        or any(
            type(row) is not dict or row.get("txid") != parent or "coinbase" in row
            for row, parent in zip(inputs, facts["direct_parent_txids"])
        )
    ):
        raise ValueError("Bitcoin reserve inputs differ from the native direct parents")
    outputs = transaction.get("vout")
    vout = facts["reserve_vout"]
    if type(outputs) is not list or not vout < len(outputs) <= 10000:
        raise ValueError("Bitcoin reserve output is unavailable")
    output = outputs[vout]
    if (
        type(output) is not dict
        or type(output.get("n")) is not int
        or output["n"] != vout
        or type(output.get("scriptPubKey")) is not dict
        or output["scriptPubKey"].get("hex") != custody_script_hex
        or _sats(output.get("value")) != facts["reserve_value_sats"]
    ):
        raise ValueError("Bitcoin reserve output does not match native backing")
    unspent = call("gettxout", [facts["bitcoin_txid"], vout, True])
    if (
        type(unspent) is not dict
        or unspent.get("bestblock") != best
        or unspent.get("coinbase") is not False
        or type(unspent.get("confirmations")) is not int
        or unspent["confirmations"] != confirmations
        or type(unspent.get("scriptPubKey")) is not dict
        or unspent["scriptPubKey"].get("hex") != custody_script_hex
        or _sats(unspent.get("value")) != facts["reserve_value_sats"]
    ):
        raise ValueError("exact reserve successor is spent, unavailable or inconsistent")
    if _bitcoin_frame(call, expected_network, expected_genesis) != (height, best):
        raise ValueError("Bitcoin chain changed during independent backing inspection")
    return {
        "version": 1,
        "network": expected_network,
        "genesis_hash": expected_genesis,
        "height": height,
        "bestblock": best,
        "inclusion_height": included,
        "inclusion_block": facts["bitcoin_block"],
        "confirmations": confirmations,
        "reserve_outpoint": facts["bitcoin_txid"] + ":" + str(vout),
        "reserve_value_sats": facts["reserve_value_sats"],
        "custody_script_hex": custody_script_hex,
    }


def inspect_independent_backing(
    native_call,
    bitcoin_call,
    keygen,
    issuer_script,
    unsigned_tx_hex,
    *,
    mint_policy,
    bitcoin_policy,
):
    """Compose one fresh issuer/witness observation without storing liability.

    Both endpoints and policy objects belong to the operator, never a request.
    The complete descriptor, authority, durable reservation and restore gates
    remain the caller's responsibilities. This function does not sign or release
    a reservation, and refuses if the native frame changes during Bitcoin work.
    """
    native = inspect_fresh_mint(native_call, unsigned_tx_hex, **mint_policy)
    facts = decode_backing_facts(keygen, issuer_script, unsigned_tx_hex, native, **mint_policy)
    bitcoin = verify_bitcoin_backing(bitcoin_call, facts, **bitcoin_policy)
    fresh = inspect_fresh_mint(native_call, unsigned_tx_hex, **mint_policy)
    if fresh != native:
        raise ValueError(
            "native reserve or chain state changed during independent backing inspection"
        )
    body = {
        "version": 1,
        "kind": "rtp1-independent-backing",
        "native": native,
        "bitcoin": bitcoin,
        "transition": facts,
    }
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )
    return dict(
        body, evidence_sha256=hashlib.sha256(b"VELD/RTP1/BACKING/v1\x00" + encoded).hexdigest()
    )
