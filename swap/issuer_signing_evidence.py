"""Build native offline-signing evidence from the issuer's independent node.

Callers must first verify the operation against their issuer, witness and chain
policy. This module supplies authenticated input evidence; it grants no custody
authority and does not substitute for the caller's final signing gate.
"""

import hashlib
import json
import re

from rpc_url_policy import run_bounded_subprocess, strict_json_loads
from veld_chain_identity import parse_expected_chain, verify_expected_chain


MAX_EVIDENCE_BYTES = 32 * 1024 * 1024
_HASH = re.compile(r"[0-9a-f]{64}")
_ADDRESS = re.compile(r"V[1-9A-HJ-NP-Za-km-z]{25,49}")


def _canonical_hex(value, maximum, name):
    if (
        type(value) is not str
        or not 2 <= len(value) <= 2 * maximum
        or len(value) % 2
        or not re.fullmatch(r"[0-9a-f]+", value)
    ):
        raise ValueError(name + " is not bounded canonical hex")
    return bytes.fromhex(value)


def canonical_parent(call, row):
    txid, height = row.get("txid"), row.get("block_height")
    if (
        type(txid) is not str
        or not _HASH.fullmatch(txid)
        or type(height) is not int
        or not 0 <= height <= (1 << 63) - 1
    ):
        raise ValueError("resolved parent location is invalid")
    block = call("getblockhash", [height])
    if type(block) is not str or not _HASH.fullmatch(block):
        raise ValueError("resolved parent block is invalid")
    response = call("gettransaction", [txid, height])
    if (
        type(response) is not dict
        or response.get("txid") != txid
        or type(response.get("block_height")) is not int
        or response["block_height"] != height
        or response.get("block_hash") != block
    ):
        raise ValueError("independent node returned the wrong parent location")
    raw = _canonical_hex(response.get("raw_hex"), 4 * 1024 * 1024, "parent transaction")
    if hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest() != txid:
        raise ValueError("raw parent hash differs from the referenced transaction")
    if call("getblockhash", [height]) != block:
        raise ValueError("parent block changed while preparing signing evidence")
    return raw.hex()


def prepare_evidence(
    keygen,
    call,
    expected_chain,
    unsigned_tx_hex,
    issuer_script,
    resolved_inputs,
    *,
    issuer,
    operation_type,
    recipient,
    amount,
    reserve_context=None,
):
    expected = parse_expected_chain(expected_chain)
    _canonical_hex(unsigned_tx_hex, 128 * 1024, "unsigned transaction")
    if not re.fullmatch(r"76a914[0-9a-f]{40}88ac", str(issuer_script)):
        raise ValueError("issuer script is invalid")
    relay = (
        operation_type == "VELD_CST1|"
        and expected["disposable"] is True
        and expected["external_value"] is False
        and recipient == "-"
        and type(amount) is int
        and amount == 0
    )
    if (
        (
            not relay
            and operation_type
            not in {
                "BTCVELD_MINT",
                "BTCVELD_C1_RESERVE",
                "BTCVELD_C1_EXPOSE",
                "BTCVELD_C1_CANCEL",
                "BTCVELD_C1_FUND",
            }
        )
        or type(issuer) is not str
        or not _ADDRESS.fullmatch(issuer)
        or (not relay and (type(recipient) is not str or not _ADDRESS.fullmatch(recipient)))
        or type(amount) is not int
        or not 0 <= amount <= (1 << 63) - 1
        or type(resolved_inputs) is not list
        or not 1 <= len(resolved_inputs) <= 180
    ):
        raise ValueError("independently verified operation facts are invalid")
    verify_expected_chain(call, expected)
    parents, fetched, size = [], {}, len(unsigned_tx_hex)
    for row in resolved_inputs:
        if type(row) is not dict or not _HASH.fullmatch(str(row.get("txid"))):
            raise ValueError("resolved parent identity is invalid")
        txid = row["txid"]
        if txid not in fetched:
            fetched[txid] = canonical_parent(call, row)
        size += len(fetched[txid])
        if size > MAX_EVIDENCE_BYTES - 65536:
            raise ValueError("complete signing evidence exceeds its bound")
        parents.append(fetched[txid])
    payload = {
        "issuer_script_hex": issuer_script,
        "unsigned_tx_hex": unsigned_tx_hex,
        "parent_transactions": parents,
    }
    run = run_bounded_subprocess(
        [keygen, "prepare-signing-stdin"],
        input_text=json.dumps(payload, separators=(",", ":"), allow_nan=False),
        timeout=60,
        stdout_max=MAX_EVIDENCE_BYTES,
        stderr_max=64 * 1024,
        description="issuer evidence builder",
    )
    if run.returncode:
        raise ValueError("native signing evidence builder refused the transaction")
    answer = strict_json_loads(run.stdout, "native signing evidence")
    if (
        type(answer) is not dict
        or set(answer)
        != {"version", "genesis_hash", "signature_network", "operation_identity_digest", "prepared"}
        or type(answer["version"]) is not int
        or answer["version"] != 1
        or answer["genesis_hash"] != expected["genesis_hash"]
        or answer["signature_network"] not in {"mainnet", "testnet"}
        or not _HASH.fullmatch(str(answer["operation_identity_digest"]))
    ):
        raise ValueError("native signing evidence identity is invalid")
    prepared = answer["prepared"]
    if (
        type(prepared) is not dict
        or set(prepared)
        != {"unsigned_tx_hex", "inputs", "total_input", "total_output", "fee", "change"}
        or prepared["unsigned_tx_hex"] != unsigned_tx_hex
        or type(prepared["inputs"]) is not list
        or len(prepared["inputs"]) != len(resolved_inputs)
    ):
        raise ValueError("native signing evidence schema is invalid")
    for i, (meta, resolved, parent) in enumerate(zip(prepared["inputs"], resolved_inputs, parents)):
        if (
            type(meta) is not dict
            or set(meta) != {"index", "sighash_hex", "prev_script_hex", "value", "parent_tx_hex"}
            or type(meta["index"]) is not int
            or meta["index"] != i
            or type(meta["value"]) is not int
            or meta["value"] != resolved.get("value_units")
            or meta["prev_script_hex"] != issuer_script
            or resolved.get("script_pubkey_hex") != issuer_script
            or meta["parent_tx_hex"] != parent
            or not _HASH.fullmatch(str(meta["sighash_hex"]))
        ):
            raise ValueError("native signing evidence differs from independently resolved inputs")
    for field in ("total_input", "total_output", "fee", "change"):
        if type(prepared[field]) is not int or not 0 <= prepared[field] <= (1 << 63) - 1:
            raise ValueError("native signing evidence amount is invalid")
    if (
        prepared["fee"] != 100000
        or prepared["total_input"] != sum(row["value_units"] for row in resolved_inputs)
        or prepared["total_input"] != prepared["total_output"] + prepared["fee"]
        or prepared["change"] != prepared["total_output"]
    ):
        raise ValueError("native signing evidence fee differs from issuer policy")
    if reserve_context is not None:
        if type(reserve_context) is not dict or set(reserve_context) != {
            "reserve_prior_state_hex",
            "reserve_prior_supply_sats",
        }:
            raise ValueError("reserve context is incomplete")
        _canonical_hex(reserve_context["reserve_prior_state_hex"], 2048, "reserve prior state")
        supply = reserve_context["reserve_prior_supply_sats"]
        if type(supply) is not int or not 0 <= supply <= (1 << 63) - 1:
            raise ValueError("reserve prior supply is invalid")
        prepared.update(reserve_context)
    verify_expected_chain(call, expected)
    return {
        "version": 2,
        "prepared": prepared,
        "authorization": {
            "operation_type": operation_type,
            "recipient": recipient,
            "amount": amount,
            "change_destination": issuer,
            "operation_identity_digest": answer["operation_identity_digest"],
            "maximum_absolute_fee": 100000,
            "maximum_fee_rate": 19,
        },
    }
