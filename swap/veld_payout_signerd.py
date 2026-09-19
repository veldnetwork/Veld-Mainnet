#!/usr/bin/env python3
"""Independent btcVELD threshold-PSBT policy signer.

Run this as the forced command on each custody signer host.  Each host has:

* its own Veld full node and accepted-burn obligation database;
* its own Bitcoin node/wallet containing only one threshold key share;
* a pinned custody script allowlist and independent fee/confirmation policy.

`observe` requests are accepted only while the burn appears in this signer's own
consensus-derived feed, then fsynced locally.  A later `sign` request must match that
durable observation byte-for-byte and pass fresh Veld-canonical and Bitcoin-prevout
checks before walletprocesspsbt is allowed to use the key share.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_redeemd as rd
import veld_custody_binding as custody_binding
from rpc_url_policy import load_bounded_json_file, strict_json_loads

CONFIG = os.environ.get("VELD_PAYOUT_SIGNER_CONFIG",
                        os.path.join(HERE, "payout-signer-config.json"))
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_CONFIG_BYTES = 4 * 1024 * 1024


def _wire_uint(value, field, maximum=(1 << 63) - 1):
    if type(value) is not int or value < 0 or value > maximum:
        refuse("%s must be an exact bounded JSON integer" % field)
    return value


def refuse(msg):
    sys.stderr.write("veld_payout_signerd REFUSE: " + str(msg)[:300] + "\n")
    raise SystemExit(2)


def same_obligation(a, b):
    a = rd.normalize_redeem(a); b = rd.normalize_redeem(b)
    return all(a[k] == b[k] for k in (
        "burn_txid", "opreturn_vout", "redeemer", "amount_sats",
        "burn_height", "burn_block_hash", "dest_btc_addr"))


def _custody_policy(cfg):
    configured = cfg.get("custody_script_pubkeys", [])
    configured_range = cfg.get("custody_script_range")
    descriptor_hash = cfg.get("custody_descriptor_sha256")
    manifest_hash = cfg.get("custody_manifest_sha256")
    consensus_manifest_hash = cfg.get(
        "custody_consensus_manifest_sha256", manifest_hash)
    range_valid = (
        isinstance(configured_range, list) and len(configured_range) == 2 and
        configured_range[0] == 0 and type(configured_range[1]) is int and
        (configured_range[1] == 999 or
         10999 <= configured_range[1] <= 1_000_000))
    expected_count = (configured_range[1] + 1
                      if range_valid else -1)
    if (not isinstance(descriptor_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", descriptor_hash) or
            not isinstance(manifest_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", manifest_hash) or
            not isinstance(consensus_manifest_hash, str) or
            not re.fullmatch(r"[0-9a-f]{64}", consensus_manifest_hash) or
            not range_valid or
            not isinstance(configured, list) or len(configured) != expected_count or
            len(set(configured)) != expected_count or
            any(not isinstance(x, str) or
                not re.fullmatch(r"5120[0-9a-f]{64}", x) for x in configured)):
        refuse("custody scripts are not a unique manifest/hash-bound operational P2TR allowlist")
    return rd.partition_custody_policy({
        "descriptor": cfg.get("custody_descriptor"),
        "descriptor_sha256": descriptor_hash,
        "manifest_sha256": manifest_hash,
        "consensus_manifest_sha256": consensus_manifest_hash,
        "consensus_range": [0, 999],
        "range": list(configured_range),
        "script_pubkeys": tuple(configured),
        "script_pubkey_set": frozenset(configured),
        "spv_custody_descriptor_index": 0,
        "spv_custody_spk_hex": configured[0],
    })


def _verify_compiled_custody_identity(cfg, peg):
    policy = _custody_policy(cfg)
    try:
        custody_binding.verify_peg_identity(peg, policy)
    except RuntimeError as exc:
        refuse(str(exc))
    return policy


def _verify_operational_custody_derivation(cfg, btc):
    policy = _custody_policy(cfg)
    descriptor = policy.get("descriptor")
    if (not isinstance(descriptor, str) or not descriptor.startswith("tr(") or
            hashlib.sha256(descriptor.encode("utf-8")).hexdigest()
            != policy["descriptor_sha256"]):
        refuse("operational custody descriptor is absent or hash-mismatched")
    document = {
        "version": 1,
        "descriptor": descriptor,
        "descriptor_sha256": policy["descriptor_sha256"],
        "range": policy["range"],
        "script_pubkeys": list(policy["script_pubkeys"]),
    }
    operational_bytes = (json.dumps(
        document, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8")
    if hashlib.sha256(operational_bytes).hexdigest() != policy["manifest_sha256"]:
        refuse("operational custody allowlist differs from its exact manifest hash")
    consensus = dict(document)
    consensus["range"] = [0, 999]
    consensus["script_pubkeys"] = list(policy["script_pubkeys"][:1000])
    consensus_bytes = (json.dumps(
        consensus, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8")
    if (hashlib.sha256(consensus_bytes).hexdigest() !=
            policy["consensus_manifest_sha256"]):
        refuse("operational custody prefix differs from the consensus manifest hash")
    try:
        custody_binding.verify_core_derivation(btc.call, policy)
    except RuntimeError as exc:
        refuse(str(exc))
    listed = btc.call("listdescriptors", "false")
    entries = listed.get("descriptors") if isinstance(listed, dict) else None
    # Bitcoin Core may omit `internal` for an imported watch-only descriptor.
    # Absent means not-internal; an explicit true must still fail.
    matches = ([entry for entry in entries
                if isinstance(entry, dict) and
                entry.get("desc") == descriptor and
                entry.get("internal", False) is not True and
                entry.get("range") == policy["range"]]
               if isinstance(entries, list) else [])
    if len(matches) != 1:
        refuse("signer wallet lacks the exact full-range custody descriptor")
    return policy


def observe(req, cfg, store, veld):
    records = req.get("records")
    if not isinstance(records, list) or len(records) > 10_000:
        refuse("observe records must be a bounded list")
    # Snapshot this signer's independently queried accepted-burn view once.
    tip, fin, accepted = rd.fetch_from_node(veld)
    by_outpoint = {(x["burn_txid"], x["opreturn_vout"]): x for x in accepted}
    ack = []
    for source in records:
        r = rd.normalize_redeem(source); rid = rd.redeem_id(r)
        existing = store.get_record(rid)
        if existing and same_obligation(existing, r):
            ack.append(rid); continue
        independent = by_outpoint.get((r["burn_txid"], r["opreturn_vout"]))
        if not independent or not same_obligation(independent, r):
            refuse("new obligation is absent/mismatched in independent accepted feed")
        # Existing-but-moved is a pre-payout reorg of the same immutable burn
        # identity. ObligationStore updates the canonical height/hash; any prior
        # raw/input signing commitment remains immutable because partial custody
        # signatures can outlive the reorg. A paid record refuses this transition.
        changed = store.ingest([independent], tip, fin)
        if len(changed) != 1:
            refuse("obligation observation was not durably inserted")
        ack.append(rid)
    return {"signer_id": cfg["signer_id"], "observed": sorted(ack)}


def _resolved_inputs(btc, decoded, cfg, veld=None):
    policy = _custody_policy(cfg)
    allowed = policy["script_pubkey_set"]
    minconfs = cfg.get("btc_input_confirmations", 1)
    if type(minconfs) is not int or not (1 <= minconfs <= 1_000_000):
        refuse("btc_input_confirmations must be an exact bounded JSON integer")
    out = []
    seen = set()
    for vin in decoded.get("vin", []):
        if not isinstance(vin, dict):
            refuse("PSBT raw transaction input is malformed")
        txid_value = vin.get("txid", "")
        vout = vin.get("vout", -1)
        if not isinstance(txid_value, str) or type(vout) is not int:
            refuse("PSBT raw transaction input identity is malformed")
        txid = txid_value.lower()
        key = (txid, vout)
        if not rd.TXID_RE.fullmatch(txid) or not (0 <= vout <= 0xffffffff) or key in seen:
            refuse("PSBT raw transaction has malformed/duplicate inputs")
        seen.add(key)
        u = btc.call("gettxout", txid, vout, "true")
        if not isinstance(u, dict):
            refuse("custody prevout is missing or spent")
        script = str((u.get("scriptPubKey") or {}).get("hex", "")).lower()
        if script not in allowed:
            refuse("custody prevout script is not pinned")
        confs = u.get("confirmations", 0)
        if type(confs) is not int or confs < 0:
            refuse("custody prevout confirmations are malformed")
        if confs < minconfs:
            refuse("custody prevout is under-confirmed")
        out.append({"txid": txid, "vout": vout,
                    "value_sats": rd.btc_to_sats(u["value"]),
                    "script_pubkey_hex": script, "confirmations": confs})
    if not out:
        refuse("payout has no custody inputs")
    _validate_public_c1_inputs(veld, out, policy)
    return out


def _validate_public_c1_inputs(veld, resolved, policy):
    try:
        rd.validate_payout_custody_inputs(veld, resolved, policy)
    except Exception as exc:
        refuse(str(exc))


def _change_script_allowed(cfg, change_sats, change_spk):
    """Return whether nonzero change stays in operator indices 0--999."""
    if not change_sats:
        return True
    return change_spk in _custody_policy(cfg)["operator_script_pubkeys"]


def _validate_unsigned_psbt_policy(decoded_psbt, decoded_tx):
    """Refuse coordinator-selected weak sighashes or preloaded signatures.

    ``walletprocesspsbt`` uses its RPC sighash argument only for inputs whose
    PSBT_IN_SIGHASH_TYPE is absent.  Without this check an adversarial
    coordinator could request SINGLE/NONE/ANYONECANPAY and reuse a custody
    signer's otherwise policy-approved signature in a transaction with changed
    outputs or additional inputs.
    """
    inputs = decoded_psbt.get("inputs")
    tx_inputs = decoded_tx.get("vin")
    if (not isinstance(inputs, list) or not isinstance(tx_inputs, list) or
            len(inputs) != len(tx_inputs)):
        refuse("PSBT input map does not exactly match the reviewed transaction")
    signature_fields = (
        "partial_signatures", "taproot_key_path_sig",
        "taproot_script_path_sigs", "final_scriptSig", "final_scriptwitness",
    )
    for item in inputs:
        if not isinstance(item, dict):
            refuse("PSBT input map is malformed")
        sighash = item.get("sighash")
        if sighash not in (None, "ALL", "DEFAULT"):
            refuse("PSBT requests a non-committing or ANYONECANPAY sighash")
        if any(item.get(field) for field in signature_fields):
            refuse("PSBT supplied to an independent signer must be unsigned")


def backfill_legacy_input_commitments(store, btc):
    """Upgrade old per-burn locks into immutable global input commitments.

    Decoding is done independently from each already-committed raw transaction.
    If two legacy proposals conflict, the unique input commitment fails closed
    before this signer can touch its key share again.
    """
    for rid, raw in store.signing_proposals_pending_backfill():
        decoded = btc.call("decoderawtransaction", raw)
        if not isinstance(decoded, dict):
            refuse("cannot decode legacy payout commitment")
        inputs = []
        for vin in decoded.get("vin", []):
            if not isinstance(vin, dict):
                refuse("legacy payout commitment has malformed inputs")
            txid_value = vin.get("txid")
            vout = vin.get("vout")
            if not isinstance(txid_value, str) or type(vout) is not int:
                refuse("legacy payout commitment has malformed inputs")
            txid = txid_value.lower()
            inputs.append((txid, vout))
        try:
            store.commit_signing_proposal(rid, raw, inputs)
        except Exception as exc:
            refuse("legacy payout commitment cannot be input-locked: " + str(exc))


def _validate_fresh_burn_authority(veld, cfg, observed):
    """Take one coherent Veld tip/finality/burn snapshot for payout approval."""
    try:
        tip_before = _wire_uint(
            veld.call("getblockcount", []), "Veld tip height")
        tip_hash_before = veld.call("getblockhash", [tip_before])
        if not isinstance(tip_hash_before, str) or not rd.TXID_RE.fullmatch(
                tip_hash_before):
            refuse("Veld tip hash is malformed")
        rd.require_consensus_reorg_depth(veld)
        peg = veld.call("getpeginfo", [])
        rd.require_compatible_payout_authority(peg)
        _verify_compiled_custody_identity(cfg, peg)
        final_height = _wire_uint(
            peg.get("final_height") if isinstance(peg, dict) else None,
            "Veld final height")
        if final_height > tip_before:
            refuse("Veld final height is inconsistent with the sampled tip")
        canonical, why = rd.verify_burn_canonical(veld, observed)
        if not canonical:
            refuse(why)
        tip_after = _wire_uint(
            veld.call("getblockcount", []), "Veld tip height")
        tip_hash_after = veld.call("getblockhash", [tip_after])
    except SystemExit:
        raise
    except Exception as exc:
        refuse("fresh Veld burn authority is unavailable: " + str(exc))
    if tip_after != tip_before or tip_hash_after != tip_hash_before:
        refuse("Veld tip changed during burn finality checks")
    if (tip_before - observed["burn_height"] <= rd.K_VELD or
            observed["burn_height"] > final_height):
        refuse("burn has not cleared depth and finality")
    return tip_before, tip_hash_before, final_height


def sign(req, cfg, store, veld, btc):
    rid = str(req.get("redeem_id", ""))
    if not re.fullmatch(r"[0-9a-f]{64}", rid):
        refuse("redeem_id is malformed")
    observed = store.get_record(rid)
    if not observed:
        refuse("burn was never durably observed by this signer")
    proposed = rd.normalize_redeem({
        "burn_txid": req.get("burn_txid"),
        "opreturn_vout": req.get("opreturn_vout"),
        "redeemer": observed["redeemer"],
        "amount_sats": req.get("amount_sats"),
        "burn_height": req.get("burn_height"),
        "burn_block_hash": req.get("burn_block_hash"),
        "dest_btc_addr": req.get("dest_spk"),
    })
    if rd.redeem_id(proposed) != rid or not same_obligation(proposed, observed):
        refuse("proposal does not match durable accepted obligation")

    _validate_fresh_burn_authority(veld, cfg, observed)

    raw = req.get("raw_tx_hex"); psbt = req.get("psbt")
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]+", raw):
        refuse("raw payout transaction is missing/malformed")
    if not isinstance(psbt, str) or not psbt:
        refuse("PSBT is missing")
    decoded = btc.call("decoderawtransaction", raw)
    if not isinstance(decoded, dict):
        refuse("cannot decode payout transaction")
    p = btc.call("decodepsbt", psbt)
    if not isinstance(p, dict) or not isinstance(p.get("tx"), dict):
        refuse("cannot decode PSBT")
    if p["tx"].get("txid") != decoded.get("txid"):
        refuse("PSBT unsigned transaction differs from reviewed raw transaction")
    _validate_unsigned_psbt_policy(p, decoded)

    resolved = _resolved_inputs(btc, decoded, cfg, veld)
    supplied_inputs = req.get("inputs", [])
    if (not isinstance(supplied_inputs, list) or
            any(not isinstance(x, dict) or type(x.get("vout")) is not int
                for x in supplied_inputs)):
        refuse("proposal input list is malformed")
    proposal_inputs = [(x.get("txid"), x.get("vout")) for x in supplied_inputs]
    if proposal_inputs != [(x["txid"], x["vout"]) for x in resolved]:
        refuse("proposal input list differs from independently resolved transaction")
    fee = req.get("fee_sats", -1); change = req.get("change_sats", -1)
    max_fee = cfg.get("max_payout_fee_sats", 100_000)
    if type(max_fee) is not int or max_fee < 0 or max_fee > rd.SATS:
        refuse("max_payout_fee_sats must be an exact bounded JSON integer")
    if (type(fee) is not int or type(change) is not int or change < 0 or
            fee < 0 or fee > max_fee):
        refuse("payout fee violates signer policy")
    change_spk = str(req.get("change_spk", "")).lower()
    if not _change_script_allowed(cfg, change, change_spk):
        refuse("change does not return to pinned threshold custody")
    if req.get("marker_hex") != rd.payout_marker(observed).hex():
        refuse("payout marker does not bind the accepted burn outpoint")
    rd.validate_payout_tx(btc, raw, observed, resolved, fee, change, change_spk,
                          require_unsigned=True)

    # Bitcoin/PSBT inspection can take long enough for the Veld chain to move.
    # Re-take a coherent snapshot immediately before the irreversible signer
    # proposal/input commitment and key-share operation.
    _validate_fresh_burn_authority(veld, cfg, observed)
    # The first public-C1 check preceded PSBT/template validation. Re-sample it
    # here so a shallow reorg cannot race the irreversible input commitment and
    # key-share operation. This signer never trusts the coordinator's result.
    _validate_public_c1_inputs(veld, resolved, _custody_policy(cfg))

    # Commit before releasing a signature. This protects this signer's local
    # history; fixed 3-of-5 quorum overlap alone does not establish globally
    # unique payout intent when an overlapping member can equivocate.
    try:
        store.commit_signing_proposal(
            rid, raw, [(x["txid"], x["vout"]) for x in resolved])
    except Exception as e:
        refuse(str(e))
    answer = btc.call("walletprocesspsbt", psbt, "true", "ALL", "true")
    if not isinstance(answer, dict) or not answer.get("psbt"):
        refuse("signer wallet produced no partial PSBT")
    return {"signer_id": cfg["signer_id"], "psbt": answer["psbt"]}


def main():
    try:
        # This document contains public descriptor/policy data and command
        # paths, not a wallet secret.  Keep it root-owned and non-writable while
        # allowing the dedicated signer group to read it; the passphrase stays
        # in the separate owner-only secret file used by sign-wrapper.sh.
        cfg = load_bounded_json_file(
            os.path.abspath(CONFIG), MAX_CONFIG_BYTES,
            "payout signer configuration")
        if not isinstance(cfg, dict):
            refuse("configuration root must be an object")
        signer_id = cfg["signer_id"]
        if not isinstance(signer_id, str) or not signer_id:
            refuse("signer_id is required")
        if "native_custody" in cfg:
            import native_custody_service
            initialize = sys.argv[1:] == ["--initialize-native-authority-state"]
            if sys.argv[1:] and not initialize:
                refuse("unknown native custody command option")
            if initialize:
                req = None
            else:
                raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
                if len(raw) > MAX_REQUEST_BYTES:
                    refuse("request exceeds size limit")
                req = strict_json_loads(raw, "native custody request")
            result = native_custody_service.dispatch(req, cfg,
                rd.VeldRpc(cfg["veld_rpc"]), rd.Btc(cfg["cli_base"], cfg["wallet"]), initialize=initialize)
            sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
            return
        raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        if len(raw) > MAX_REQUEST_BYTES:
            refuse("request exceeds size limit")
        req = strict_json_loads(raw, "payout signer request")
        if not isinstance(req, dict):
            refuse("request root must be an object")
        veld = rd.VeldRpc(cfg["veld_rpc"])
        btc = rd.Btc(cfg["cli_base"], cfg["wallet"])
        store = rd.ObligationStore(cfg["authority_db"])
        backfill_legacy_input_commitments(store, btc)
        _verify_compiled_custody_identity(cfg, veld.call("getpeginfo", []))
        _verify_operational_custody_derivation(cfg, btc)
        if req.get("action") == "observe":
            result = observe(req, cfg, store, veld)
        elif req.get("action") == "sign":
            result = sign(req, cfg, store, veld, btc)
        else:
            refuse("unknown action")
        sys.stdout.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    except SystemExit:
        raise
    except Exception as e:
        refuse(type(e).__name__ + ": " + str(e))


if __name__ == "__main__":
    main()
