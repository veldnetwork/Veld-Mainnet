"""RTP1 adapters for the existing, locked issuer and witness entry points."""
import hashlib
import os
import time

import rtp1_service as lifecycle
import veld_peg_solvency as solvency
import veld_custody_binding as custody
from rtp1_backing_evidence import inspect_independent_backing
from rtp1_mint_policy import decode_inspected_mint
from rpc_url_policy import read_bounded_regular_file, strict_json_loads, run_bounded_subprocess
from swap_admission import verify_mldsa65_with_keygen
from veld_chain_identity import verify_expected_chain


def initialize_empty_migration(directory, role, config, legacy_paths, persist):
    """Offline, lock-held migration of proven empty versioned legacy journals.

    Funded, signed, archived, unversioned and partially initialized inventories
    are deliberately refused. Neither the originals nor their nullifiers change.
    """
    config = lifecycle.configuration(config)
    marker_path = os.path.join(directory, "rtp1-migration.json")
    journal_path = os.path.join(directory, "rtp1-" + role + ".json")
    if role not in {"issuer", "witness"} or any(os.path.lexists(p) for p in (marker_path, journal_path)):
        raise ValueError("RTP1 migration exists or is partial; never overwrite authority state")
    expected = {"mint", "c1", "leases"} if role == "issuer" else {"mint", "allocations", "terminal"}
    if set(legacy_paths) != expected:
        raise ValueError("complete legacy authority inventory is required")
    documents, hashes = {}, {}
    for label, path in legacy_paths.items():
        raw = read_bounded_regular_file(path, lifecycle.MAX_BYTES, "legacy " + label, private=True)
        documents[label] = strict_json_loads(raw, "legacy " + label)
        hashes[label] = hashlib.sha256(raw).hexdigest()
    if role == "issuer":
        empty_mints = ({"signed": []},
            {"signed": [], "mint_accounting": {"version": 2, "pending": [], "confirmed": []}})
        if lifecycle.canonical(documents["mint"]) not in {lifecycle.canonical(value) for value in empty_mints}:
            raise ValueError("existing mint liabilities require independent reconciliation")
        if documents["c1"] != {"version": 3, "records": {}, "terminal_observations": {}, "tombstones": {}, "compaction_cursor": None}:
            raise ValueError("existing C1 authority cannot be relabeled as RTP1")
        from veld_signerd import _empty_prevout_journal
        if documents["leases"] != _empty_prevout_journal():
            raise ValueError("existing issuer leases require independent reconciliation")
        # Leases evolve under the unchanged shared authority lock. Live loads
        # validate that journal through the existing versioned parser rather
        # than requiring it to remain empty.
        hashes.pop("leases")
    else:
        if documents["mint"] != {"version": 3, "terminal_count": 0, "terminal_head_sha256": lifecycle.ZERO, "reservations": []}:
            raise ValueError("existing witness liabilities require independent reconciliation")
        if documents["terminal"] != {"version": 1, "kind": "VELD_MINT_RESERVATION_TOMBSTONE_LOG"}:
            raise ValueError("witness terminal history cannot be discarded")
        allocation = documents["allocations"]
        fields = {"version", "initial_descriptor_index", "capacity_policy_sha256", "capacity_policy_sequence",
            "public_descriptor_range_end", "last_consensus_sequence", "allocations", "events"}
        if (type(allocation) is not dict or set(allocation) != fields or type(allocation["version"]) is not int or allocation["version"] != 5 or
                type(allocation["last_consensus_sequence"]) is not int or allocation["last_consensus_sequence"] != 0 or
                allocation["allocations"] != [] or allocation["events"] != []):
            raise ValueError("existing allocation authority requires independent reconciliation")
    marker = {"version": 1, "role": role, "policy_id": lifecycle.digest(config), "legacy_files": hashes}
    journal = lifecycle.empty_journal(role, config, lifecycle.digest(marker))
    persist(journal, journal_path)
    persist(marker, marker_path)
    return marker


def initialize_issuer(service):
    import fcntl
    service._secure_service_directory(service.HERE)
    cfg = service.load_signer_configuration()
    lifecycle.configuration(cfg.get("rtp1_service"))
    lock_path = os.path.join(service.HERE, ".signerd.lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "a+") as lock:
        service._secure_regular(lock_path, private=True)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        service.require_signer_authority_state_set(cfg)
        service.validate_mint_authority_config(cfg, service.issuer_addr())
        if os.path.lexists(service.SIGNING_STAGE_DIR) and os.listdir(service.SIGNING_STAGE_DIR):
            raise ValueError("existing issuer signing stages require reconciliation")
        return initialize_empty_migration(service.HERE, "issuer", cfg["rtp1_service"],
            {"mint": service.STATEF, "c1": service.C1_STATEF, "leases": service.PREVOUT_STATEF},
            lambda value, path: service.save_signer_state_durable(value, path, max_bytes=lifecycle.MAX_BYTES))


def initialize_witness(service):
    config_path = os.path.abspath(service.CONFIG)
    cfg = strict_json_loads(read_bounded_regular_file(config_path, 1024 * 1024,
        "witness configuration", private=True), "witness configuration")
    config = lifecycle.configuration(cfg.get("rtp1_service"))
    service._require_production_reservation_service(cfg)
    paths = service._paths(cfg)
    with service.exclusive_witness_state_lock(paths):
        service._require_restore_clear(paths)
        return initialize_empty_migration(cfg["state_dir"], "witness", config,
            {"mint": paths["ledger"], "allocations": paths["allocations"], "terminal": paths["terminal"]},
            lambda value, path: service.atomic_write(path, lifecycle.canonical(value).decode("utf-8") + "\n"))


def load_activated_state(directory, role, cfg, legacy_paths, persist, verify):
    config = lifecycle.configuration(cfg.get("rtp1_service"))
    if config["expected_chain"] != cfg.get("veld_rpc", {}).get("expected_chain"):
        raise ValueError("RTP1 service and operator chain pins differ")
    marker_path = os.path.join(directory, "rtp1-migration.json")
    marker = strict_json_loads(read_bounded_regular_file(marker_path, 16384,
        "RTP1 migration inventory", private=True), "RTP1 migration inventory")
    if (type(marker) is not dict or set(marker) != {"version", "role", "policy_id", "legacy_files"} or
            type(marker["version"]) is not int or marker["version"] != 1 or marker["role"] != role or
            marker["policy_id"] != lifecycle.digest(config) or type(marker["legacy_files"]) is not dict or
            set(marker["legacy_files"]) != set(legacy_paths)):
        raise ValueError("RTP1 migration does not bind the exact legacy authority inventory")
    for label, path in legacy_paths.items():
        raw = read_bounded_regular_file(path, lifecycle.MAX_BYTES, "legacy " + label, private=True)
        if hashlib.sha256(raw).hexdigest() != marker["legacy_files"][label]:
            raise ValueError("legacy authority changed after RTP1 migration; reconciliation required")
    path = os.path.join(directory, "rtp1-" + role + ".json")
    state = strict_json_loads(read_bounded_regular_file(path, lifecycle.MAX_BYTES,
        "RTP1 authority journal", private=True), "RTP1 authority journal")
    if type(state) is not dict or state.get("migration") != lifecycle.digest(marker):
        raise ValueError("RTP1 journal is not bound to its migration inventory")
    return lifecycle.Journal(state, config, role,
        lambda value: persist(value, path), verify)


def observation(config, rpc, btc, keygen, script, request):
    lifecycle.request_identity(request)
    policy = lifecycle.mint_policy(config, request)
    result = inspect_independent_backing(rpc.call, lambda method, params: btc.call(method, *params),
        keygen, script, request["unsigned_tx_hex"], mint_policy=policy, bitcoin_policy={
            "expected_network": config["bitcoin_network"], "expected_genesis": config["bitcoin_genesis"],
            "custody_script_hex": config["custody_script_hex"], "min_confirmations": config["minimum_confirmations"]})
    decode_inspected_mint(keygen, script, request["unsigned_tx_hex"], result["native"], **policy)
    return result


def confirmation(config, rpc, btc, row):
    """Absence, reorganization or uncertainty retains the entire liability."""
    try:
        verify_expected_chain(rpc.call, config["expected_chain"])
        before = rpc.call("getbtcveldsupply", [])
        if type(before) is not dict or set(before) != {"supply_sats", "tip", "tip_hash"}:
            return None
        if type(before["tip"]) is not int or type(before["supply_sats"]) is not int:
            return None
        peg = rpc.call("getpeginfo", [])
        if (type(peg) is not dict or type(peg.get("final_height")) is not int or
                not 0 < peg["final_height"] <= before["tip"]):
            return None
        request = row["request"]
        txid = lifecycle.signed_identity(row["signed_tx_hex"], request["unsigned_tx_hex"])
        outpoint = row["receipt"]["intent"]["native"]["deposit_outpoint"]
        status = rpc.call("getbtcveldmintstatus", [outpoint])
        if (type(status) is not dict or status.get("outpoint") != outpoint or
                status.get("minted") is not True or status.get("consumed") is not True or
                status.get("accepted_effect_kind") != "MINT" or status.get("accepted_txid") != txid or
                status.get("tip") != before["tip"] or status.get("tip_hash") != before["tip_hash"]):
            return None
        height, block = status.get("accepted_block_height"), status.get("accepted_block_hash")
        if type(height) is not int or not 0 < height <= peg["final_height"] or rpc.call("getblockhash", [height]) != block:
            return None
        raw = rpc.call("gettransaction", [txid, height])
        if (type(raw) is not dict or raw.get("txid") != txid or
                type(raw.get("block_height")) is not int or raw["block_height"] != height or
                raw.get("raw_hex") != row["signed_tx_hex"] or raw.get("block_hash") != block):
            return None
        facts = row["evidence"]["transition"]
        if btc.call("getblockhash", 0) != config["bitcoin_genesis"]:
            return None
        info = btc.call("getblockchaininfo")
        if (type(info) is not dict or info.get("chain") != config["bitcoin_network"] or
                info.get("initialblockdownload") is not False or type(info.get("blocks")) is not int or
                info.get("blocks") != info.get("headers")):
            return None
        header = btc.call("getblockheader", facts["bitcoin_block"], True)
        if (type(header) is not dict or type(header.get("height")) is not int or
                type(header.get("confirmations")) is not int or header["confirmations"] < config["minimum_confirmations"] or
                btc.call("getblockhash", header["height"]) != facts["bitcoin_block"]):
            return None
        if (btc.call("getblockchaininfo") != info or rpc.call("getbtcveldsupply", []) != before or
                rpc.call("getblockhash", [before["tip"]]) != before["tip_hash"]):
            return None
        return {"height": height, "hash": lifecycle.hash_value(block, "native mint block")}
    except (ValueError, RuntimeError, OSError, KeyError, TypeError):
        return None


def beat_gate(config, rpc, beat, outstanding, amount, verify):
    ok, why = solvency.validate_heartbeat(beat)
    if not ok:
        raise ValueError("RTP1 solvency heartbeat: " + why)
    signed_beat = {key: value for key, value in beat.items() if key not in {"issued_at", "received_at", "expires_at"}}
    if verify(solvency.canonical_beat_bytes(signed_beat), beat.get("sig")) is not True:
        raise ValueError("RTP1 solvency heartbeat signature is invalid")
    ok, why = solvency.heartbeat_gate(beat, time.time(), outstanding, amount)
    if not ok:
        raise ValueError("RTP1 solvency heartbeat: " + why)
    view = rpc.call("getbtcveldsupply", [])
    if (type(view) is not dict or view.get("supply_sats") != beat["supply_sats"] or
            view.get("tip") != beat["tip"] or view.get("tip_hash") != beat["tip_hash"] or
            rpc.call("getblockhash", [beat["tip"]]) != beat["tip_hash"]):
        raise ValueError("RTP1 solvency heartbeat is not the independent canonical supply")


def reserved_mint_gate(config, rpc, beat, journal, request, verify):
    lifecycle.request_identity(request)
    outstanding = sum(row["request"]["sats"] for row in journal.state["records"]
        if row["confirmation"] is None and row["request"] != request)
    beat_gate(config, rpc, beat, outstanding, request["sats"], verify)


def check_descriptor(config, cfg, rpc, btc):
    binding = custody.load_manifest(cfg.get("custody_spk_manifest_file"),
        config["custody_descriptor_sha256"], config["custody_manifest_sha256"],
        expected_spv_spk_hex=config["custody_script_hex"], network=config["bitcoin_network"])
    custody.verify_peg_identity(rpc.call("getpeginfo", []), binding, network=config["bitcoin_network"])
    descriptor = btc.call("getdescriptorinfo", binding["descriptor"])
    if (type(descriptor) is not dict or descriptor.get("descriptor") != binding["descriptor"] or
            descriptor.get("hasprivatekeys") is not False or descriptor.get("issolvable") is not True):
        raise ValueError("Bitcoin Core did not independently validate the full custody descriptor")
    custody.verify_core_derivation(btc.call, binding, expected_hrp="bcrt")


def verifier(keygen, public_key):
    pinned = read_bounded_regular_file(public_key, 4096, "independent witness public key").decode("ascii").strip()
    return lambda message, signature: verify_mldsa65_with_keygen(pinned, message, signature, keygen)


def verify_committed_carrier(keygen, script, config, request, retained, signed):
    decoded = decode_inspected_mint(keygen, script, request["unsigned_tx_hex"], retained["native"],
        **lifecycle.mint_policy(config, request))
    txid = lifecycle.signed_identity(signed, request["unsigned_tx_hex"])
    result = run_bounded_subprocess([keygen, "verify-signed-carrier-stdin"],
        input_text=lifecycle.canonical({"issuer_script_hex": script,
            "unsigned_tx_hex": request["unsigned_tx_hex"], "signed_tx_hex": signed}).decode("utf-8"),
        timeout=60, stdout_max=4096, stderr_max=65536, description="RTP1 committed carrier verifier")
    if result.returncode:
        raise ValueError("RTP1 committed carrier has invalid issuer signatures")
    answer = strict_json_loads(result.stdout, "RTP1 committed carrier verification")
    expected = {"version": 1, "genesis_hash": config["expected_chain"]["genesis_hash"],
        "unsigned_tx_sha256": lifecycle.request_identity(request), "txid": txid,
        "signed_tx_sha256": hashlib.sha256(bytes.fromhex(signed)).hexdigest(),
        "input_count": decoded["num_inputs"], "issuer_script_hex": script}
    if type(answer) is not dict or answer != expected or type(answer.get("version")) is not int or type(answer.get("input_count")) is not int:
        raise ValueError("RTP1 committed carrier verification differs from retained policy")
    return True


def issuer_request(service, request, cfg, issuer, script):
    from veld_wt_reserve import BitcoinCli
    config = lifecycle.configuration(cfg.get("rtp1_service"))
    if config["issuer"] != issuer:
        raise ValueError("RTP1 issuer identity differs from the active key")
    _, witness = service.validate_mint_authority_config(cfg, issuer)
    if witness["witness_id"] != config["witness_id"]:
        raise ValueError("RTP1 witness identity differs from the active authority")
    verify = verifier(service.KEYGEN, service.BEAT_PUBKEY)
    rpc, btc = service.TrustedVeldRpc(cfg["veld_rpc"]), BitcoinCli(cfg.get("btc"))
    verify_expected_chain(rpc.call, config["expected_chain"])
    check_descriptor(config, cfg, rpc, btc)
    journal = load_activated_state(service.HERE, "issuer", cfg,
        {"mint": service.STATEF, "c1": service.C1_STATEF},
        lambda value, path: service.save_signer_state_durable(value, path, max_bytes=lifecycle.MAX_BYTES), verify)
    journal.reconcile(lambda row: confirmation(config, rpc, btc, row))
    lease = service.load_prevout_journal()
    def halt():
        service.require_signer_authority_state_set(cfg)
        if service._trusted_marker_exists(service.HALTF, "HALT"):
            raise ValueError("HALT present at RTP1 authority boundary")
        service.validate_mint_authority_config(cfg, issuer)
    def gate(req, retained=None):
        halt()
        fresh = observation(config, rpc, btc, service.KEYGEN, script, req)
        if retained is not None and lifecycle.intent_from_evidence(config, req, fresh) != lifecycle.intent_from_evidence(config, req, retained):
            raise ValueError("RTP1 reserve context changed before signing")
        if not service._trusted_marker_exists(service.WT_REQUIRED, "watchtower-required"):
            raise ValueError("RTP1 requires the independent solvency watchtower")
        beat = strict_json_loads(read_bounded_regular_file(service.HEARTBEATF, 65536,
            "issuer solvency heartbeat", private=True), "issuer solvency heartbeat")
        reserved_mint_gate(config, rpc, beat, journal, req, verify)
        return fresh
    def call(action, req, **extra):
        return service._call_witness(witness["command"], {"action": action, "request": req, **extra})
    def sign(req, retained, revalidate):
        owner = service.direct_mint_prevout_owner_id(retained["native"]["deposit_outpoint"])
        service.reserve_issuer_prevouts(lease, owner, "mint-direct", None,
            retained["native"]["deposit_outpoint"], req["unsigned_tx_hex"])
        def evidence():
            total, inputs = service.resolve_mint_prevouts(req["unsigned_tx_hex"], rpc, script)
            return service.prepare_evidence(service.KEYGEN, rpc.call, rpc.expected_chain,
                req["unsigned_tx_hex"], script, inputs, issuer=issuer, operation_type="BTCVELD_MINT",
                recipient=req["recipient"], amount=req["sats"], reserve_context={
                    key: retained["native"][key] for key in ("reserve_prior_state_hex", "reserve_prior_supply_sats")})
        return service.sign_or_recover_staged_carrier(lease, owner, req["unsigned_tx_hex"], script,
            "RTP1 issuer signing", build_evidence=evidence, revalidate=revalidate)
    signed = lifecycle.issuer_mint(journal, request, inspect=gate,
        reserve=lambda req: call("rtp1_reserve", req), verify_fresh=gate, sign_or_recover=sign,
        commit=lambda req, signed: call("rtp1_commit", req, signed_tx_hex=signed), halt=halt,
        receipt_verify=verify, witness_snapshot=lambda req: call("rtp1_status", req),
        verify_carrier=lambda req, retained, signed: verify_committed_carrier(
            service.KEYGEN, script, config, req, retained, signed))
    row = journal.find(request)
    owner = service.direct_mint_prevout_owner_id(row["evidence"]["native"]["deposit_outpoint"])
    service.reserve_issuer_prevouts(lease, owner, "mint-direct", None,
        row["evidence"]["native"]["deposit_outpoint"], request["unsigned_tx_hex"])
    service.mark_issuer_prevout_signature(lease, owner, request["unsigned_tx_hex"],
        lifecycle.signed_identity(signed, request["unsigned_tx_hex"]))
    halt()
    return signed


def witness_request(service, envelope, cfg, paths, rpc):
    config = lifecycle.configuration(cfg.get("rtp1_service"))
    action = envelope.get("action")
    fields = {"action", "request"} | ({"signed_tx_hex"} if action == "rtp1_commit" else set())
    if type(envelope) is not dict or set(envelope) != fields or action not in {"rtp1_reserve", "rtp1_commit", "rtp1_status"}:
        raise ValueError("RTP1 witness request schema is invalid")
    request = envelope["request"]
    lifecycle.request_identity(request)
    keygen = cfg.get("keygen") or os.path.join(service.HERE, "veld-keygen")
    verify = verifier(keygen, cfg.get("rtp1_witness_public_key_file"))
    btc = service.BitcoinCli(cfg.get("btc"))
    verify_expected_chain(rpc.call, config["expected_chain"])
    check_descriptor(config, cfg, rpc, btc)
    journal = load_activated_state(cfg["state_dir"], "witness", cfg,
        {"mint": paths["ledger"], "allocations": paths["allocations"], "terminal": paths["terminal"]},
        lambda value, path: service.atomic_write(path, lifecycle.canonical(value).decode("utf-8") + "\n"), verify)
    journal.reconcile(lambda row: confirmation(config, rpc, btc, row))
    if action == "rtp1_status":
        return lifecycle.witness_status(journal, request)
    from veld_signerd import issuer_p2pkh_from_address
    script = issuer_p2pkh_from_address(config["issuer"])
    if action == "rtp1_commit":
        return lifecycle.witness_commit(journal, request, envelope["signed_tx_hex"],
            lambda req, retained, signed: verify_committed_carrier(keygen, script, config, req, retained, signed))
    def inspect(req):
        fresh = observation(config, rpc, btc, keygen, script, req)
        beat = service._load_beat(paths["beat"], time.time())
        reserved_mint_gate(config, rpc, beat, journal, req, verify)
        return fresh
    return lifecycle.witness_reserve(journal, request, inspect, lambda core: service._sign_receipt(core, cfg))
