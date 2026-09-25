"""Build native settlement evidence from independently pinned local chains.

This disposable-network entry point prepares a fee-only carrier. It neither
spends Bitcoin nor authorizes a refund by elapsed time alone.
"""

import hashlib
import re
import struct
import time

try:
    from . import native_custody_service as authority
    from .veld_spvmint import parse_and_strip_bitcoin_tx
    from .native_custody_wire import authorized_parents
except ImportError:
    import native_custody_service as authority
    from veld_spvmint import parse_and_strip_bitcoin_tx
    from native_custody_wire import authorized_parents


def digest(raw):
    return hashlib.sha256(hashlib.sha256(raw).digest()).digest()


def hash_bytes(value):
    if type(value) is not str or not authority.HASH.fullmatch(value):
        raise ValueError("settlement hash is not canonical")
    return bytes.fromhex(value)


def integer(value, maximum=(1 << 64) - 1):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError("settlement integer is invalid")
    return value


def blob(value, maximum):
    if (
        type(value) is not str
        or not 0 < len(value) <= 2 * maximum
        or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)
    ):
        raise ValueError("settlement bytes are invalid")
    return bytes.fromhex(value)


def vector(value):
    return struct.pack("<I", len(value)) + value


def reserve_network_binding(policy):
    # RTP1's established domain uses the pinned consensus literal. RPC genesis
    # uses canonical internal hash rendering and is verified independently.
    genesis = policy["domain_genesis_hash"]
    hash_bytes(genesis)
    profile = policy["expected_chain"]["profile_id"]
    return hashlib.sha256(
        b"VELD/BTCVELD/RESERVE_NETWORK/v1"
        + vector(genesis.encode())
        + vector(profile.encode())
        + vector(b"btcveld-reserve-outpoint-v1")
    ).digest()


def merkle_branch(txids, wanted, header):
    if (
        type(txids) is not list
        or not 1 <= len(txids) <= 100000
        or any(type(txid) is not str or not authority.HASH.fullmatch(txid) for txid in txids)
        or len(set(txids)) != len(txids)
        or txids.count(wanted) != 1
        or len(header) != 80
    ):
        raise ValueError("settlement Bitcoin block transaction set is invalid")
    rows = [hash_bytes(txid)[::-1] for txid in txids]
    index = txids.index(wanted)
    directions, branch = index, []
    while len(rows) > 1:
        if len(rows) % 2:
            rows.append(rows[-1])
        branch.append(rows[index ^ 1])
        rows = [digest(rows[i] + rows[i + 1]) for i in range(0, len(rows), 2)]
        index //= 2
    if rows[0] != header[36:68] or len(branch) > 32:
        raise ValueError("settlement Bitcoin Merkle root differs from its header")
    return directions, branch


def prepare(request, cfg, native, bitcoin):
    policy = authority.configuration(cfg)
    if (
        type(request) is not dict
        or set(request) != {"action", "authorization_hex", "raw_tx_hex", "fund_address"}
        or request["action"] != "native_settlement"
    ):
        raise ValueError("native settlement request schema is invalid")
    address = request["fund_address"]
    if type(address) is not str or not re.fullmatch(r"V[1-9A-HJ-NP-Za-km-z]{25,49}", address):
        raise ValueError("settlement fee address is invalid")
    raw = blob(request["raw_tx_hex"], authority.MAX_RAW_BYTES)
    wire = blob(request["authorization_hex"], authority.MAX_AUTH_BYTES)
    deadline = time.monotonic() + 180
    native_rpc = native

    def native(method, params):
        return native_rpc.call(method, params, deadline=deadline)

    def core(method, *params):
        return bitcoin.call(
            method,
            *(v if type(v) is str else authority.canonical(v) for v in params),
            deadline=deadline,
        )

    observed = authority.inspect(native, policy, wire.hex(), raw.hex())
    if len(wire) < 197 or wire[:4] != b"CIA1" or wire[101:133].hex() != observed["burn_id"]:
        raise ValueError("settlement authorization does not bind its burn")
    binding = authority.custody.load_manifest(
        policy["manifest_path"],
        policy["descriptor_hash"],
        policy["custody_manifest_sha256"],
        network="regtest",
    )
    authority.custody.verify_core_derivation(core, binding, expected_hrp="bcrt")
    peg = native("getpeginfo", [])
    authority.custody.verify_peg_identity(peg, binding, network="regtest")
    if (
        type(peg) is not dict
        or peg.get("reserve_accounting_holds") is not True
        or peg.get("reserve_status") != "ACTIVE"
        or peg.get("reserve_txid") != observed["reserve_txid"]
        or peg.get("reserve_vout") != observed["reserve_vout"]
    ):
        raise ValueError("native settlement no longer owns the current represented reserve")
    chain = core("getblockchaininfo")
    if (
        type(chain) is not dict
        or chain.get("chain") != "regtest"
        or chain.get("initialblockdownload") is not False
        or core("getblockhash", 0) != hash_bytes(policy["bitcoin_genesis_hash"])[::-1].hex()
    ):
        raise ValueError("settlement Bitcoin chain is not the independently pinned chain")
    txid = hash_bytes(observed["bitcoin_txid"])[::-1].hex()
    transaction = core("getrawtransaction", txid, True)
    if (
        type(transaction) is not dict
        or transaction.get("txid") != txid
        or integer(transaction.get("confirmations")) < policy["minimum_bitcoin_confirmations"]
    ):
        raise ValueError("settlement Bitcoin spend is not sufficiently confirmed")
    block_hash = transaction.get("blockhash")
    hash_bytes(block_hash)
    block = core("getblock", block_hash, 1)
    if (
        type(block) is not dict
        or block.get("hash") != block_hash
        or core("getblockhash", integer(block.get("height"))) != block_hash
        or integer(block.get("confirmations")) < policy["minimum_bitcoin_confirmations"]
    ):
        raise ValueError("settlement Bitcoin block is not sufficiently deep and canonical")
    header = blob(core("getblockheader", block_hash, False), 80)
    if digest(header)[::-1].hex() != block_hash:
        raise ValueError("settlement Bitcoin header identity differs")
    directions, branch = merkle_branch(block.get("tx"), txid, header)
    parsed = parse_and_strip_bitcoin_tx(blob(transaction.get("hex"), 4 * 1024 * 1024))
    stripped = parsed["legacy"]
    if stripped != raw or digest(stripped)[::-1].hex() != txid:
        raise ValueError("confirmed Bitcoin spend differs from the exact native authorization")
    if not 2 <= len(parsed["inputs"]) <= 8:
        raise ValueError("native settlement direct input count is invalid")
    parents = authorized_parents(wire, raw)
    if len(parents) != len(parsed["inputs"]):
        raise ValueError("settlement parent count differs from its native authorization")
    for authorized, (parent_hash, vout) in zip(parents, parsed["inputs"]):
        parent_raw = blob(
            core("getrawtransaction", parent_hash[::-1].hex(), False), 4 * 1024 * 1024
        )
        parent = parse_and_strip_bitcoin_tx(parent_raw)
        bound_parent = parse_and_strip_bitcoin_tx(authorized)
        if (
            digest(parent["legacy"]) != parent_hash
            or not vout < len(parent["outputs"])
            or bound_parent["legacy"] != parent["legacy"]
        ):
            raise ValueError("settlement parent does not match the exact consumed output")
    if (
        len(stripped) > 12000
        or sum(map(len, parents)) > 10000
        or any(len(p) > 12000 for p in parents)
    ):
        raise ValueError("settlement proof exceeds native transaction or direct parent bounds")
    custody_script = blob(binding["spv_custody_spk_hex"], 34)
    successors = [out for out in parsed["outputs"] if out["script"] == custody_script]
    prior_value = integer(peg.get("reserve_value_sats"))
    principal = integer(observed["principal_sats"])
    payout = observed["kind"] == "PAYOUT"
    new_value = prior_value - principal if payout else prior_value
    if (
        new_value < 0
        or (new_value and (len(successors) != 1 or successors[0]["value_sats"] != new_value))
        or (not new_value and successors)
    ):
        raise ValueError("settlement reserve successor violates exact principal accounting")
    new_vout = successors[0]["vout"] if successors else 0xFFFFFFFF
    network = reserve_network_binding(policy)
    proof = (
        b"RTP1"
        + bytes([4 if payout else 3])
        + network
        + hash_bytes(peg.get("reserve_transition_commitment"))
        + hash_bytes(peg["reserve_txid"])
        + struct.pack(
            "<IQQ",
            integer(peg["reserve_vout"], 0xFFFFFFFF),
            prior_value,
            integer(peg.get("reserve_transition_count")),
        )
        + (hash_bytes(observed["bitcoin_txid"]) if new_value else bytes(32))
        + struct.pack("<IQ", new_vout, new_value)
        + hash_bytes(observed["bitcoin_txid"])
        + hash_bytes(block_hash)[::-1]
        + struct.pack("<IB", directions, len(branch))
        + b"".join(branch)
        + (wire[133:165] if payout else bytes(32))
        + struct.pack("<Q", 0)
        + vector(stripped)
        + struct.pack("<H", len(parents))
        + b"".join(vector(p) for p in parents)
        + vector(b"")
    )
    settlement = b"CST1" + vector(wire) + vector(proof)
    if len(settlement) * 2 + len("VELD_CST1|") > 65000:
        raise ValueError("native settlement carrier exceeds its bound")
    if (
        authority.inspect(native, policy, wire.hex(), raw.hex()) != observed
        or native("getpeginfo", []) != peg
        or core("getblockhash", block["height"]) != block_hash
    ):
        raise ValueError(
            "settlement authority, reserve or Bitcoin inclusion changed during preparation"
        )
    prepared = native("preparerawop", [address, "VELD_CST1|" + settlement.hex()])
    if type(prepared) is not dict or type(prepared.get("unsigned_tx_hex")) is not str:
        raise ValueError("native node did not prepare a settlement carrier")
    return {
        "version": 1,
        "bitcoin_txid": txid,
        "bitcoin_block": block_hash,
        "burn_id": observed["burn_id"],
        "kind": observed["kind"],
        "settlement_hex": settlement.hex(),
        "proof_hex": proof.hex(),
        "prepared": prepared,
        "broadcast": False,
    }
