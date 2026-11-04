"""Actual issuer/witness cryptography and persistence with a simulated native view.

Called by the isolated Bitcoin backing fixture. This does not exercise native
mint admission, the full forced-command adapters or independent operators.
"""

import copy
import hashlib
import json
import os
import re
from unittest import mock

import rtp1_service as lifecycle
from rtp1_service_runtime import verify_committed_carrier
import veld_signerd as issuer_service
import veld_wt_reserve as witness_service
from swap_admission import verify_mldsa65_with_keygen


def exercise(
    root, run, keygen, fixture, issuer_key, issuer, prepared, facts, bitcoin, built, passphrase
):
    witness_key = root / "independent-witness.key"
    run([keygen, "new", "--out", witness_key])
    shown = run([keygen, "show", witness_key, "--full-pubkey-hex"])
    public = re.search(r"[0-9a-f]{3904}", shown).group(0)
    assert issuer not in shown
    password = root / "witness.pass"
    password.write_text(passphrase)
    password.chmod(0o600)
    config = {
        "version": 1,
        "expected_chain": {
            "profile_id": "simulated-native-view",
            "consensus_build_profile": "fixture",
            "disposable": True,
            "external_value": False,
            "fixed_difficulty_regtest": False,
            "genesis_hash": built["genesis_hash"],
            "launch_block_hash": "12" * 32,
        },
        "issuer": issuer,
        "witness_id": "disposable-independent-key",
        "custody_descriptor_sha256": "33" * 32,
        "custody_manifest_sha256": "44" * 32,
        "bitcoin_genesis": bitcoin["genesis_hash"],
        "bitcoin_network": "regtest",
        "custody_script_hex": facts["custody_script_hex"],
        "minimum_confirmations": 144,
    }
    request = {
        "action": "rtp1_mint",
        "unsigned_tx_hex": prepared["unsigned_tx_hex"],
        "recipient": facts["recipient"],
        "sats": facts["sats"],
    }
    decode_payload = {
        key: prepared[key]
        for key in ("unsigned_tx_hex", "reserve_prior_state_hex", "reserve_prior_supply_sats")
    }
    decode_payload["issuer_script_hex"] = prepared["inputs"][0]["prev_script_hex"]
    decoded = json.loads(run([keygen, "decode-mint-stdin"], json.dumps(decode_payload)))
    native = {
        "version": 1,
        "proof_version": "RTP1",
        "tip": 3000,
        "tip_hash": "55" * 32,
        "candidate_height": 3001,
        "final_height": 2980,
        "genesis_hash": built["genesis_hash"],
        "unsigned_tx_sha256": lifecycle.request_identity(request),
        "proof_sha256": hashlib.sha256(bytes.fromhex(decoded["memo"][5:])).hexdigest(),
        "issuer": issuer,
        "recipient": facts["recipient"],
        "sats": facts["sats"],
        "fee_units": 100000,
        "deposit_outpoint": facts["deposit_outpoint"],
        "bitcoin_txid": bytes.fromhex(facts["bitcoin_txid"])[::-1].hex(),
        "bitcoin_block": bytes.fromhex(facts["bitcoin_block"])[::-1].hex(),
        "reserve_prior_state_hex": prepared["reserve_prior_state_hex"],
        "reserve_prior_supply_sats": prepared["reserve_prior_supply_sats"],
        "nullifier_root": "66" * 32,
        "custody_descriptor_sha256": config["custody_descriptor_sha256"],
        "custody_manifest_sha256": config["custody_manifest_sha256"],
    }
    body = {
        "version": 1,
        "kind": "rtp1-independent-backing",
        "native": native,
        "bitcoin": bitcoin,
        "transition": facts,
    }
    evidence = dict(
        body,
        evidence_sha256=hashlib.sha256(
            b"VELD/RTP1/BACKING/v1\x00" + lifecycle.canonical(body)
        ).hexdigest(),
    )
    verify = lambda message, signature: verify_mldsa65_with_keygen(
        public, message, signature, str(keygen)
    )
    cfg = {
        "keygen": str(keygen),
        "signer": {"beat_keyfile": str(witness_key), "beat_passfile": str(password)},
    }

    def persist(role):
        return lambda state: issuer_service.save_signer_state_durable(
            state, str(root / (role + "-journal.json")), max_bytes=lifecycle.MAX_BYTES
        )

    journals = {
        role: lifecycle.Journal(
            lifecycle.empty_journal(role, config, "ab" * 32), config, role, persist(role), verify
        )
        for role in ("issuer", "witness")
    }
    reserve = lambda req: lifecycle.witness_reserve(
        journals["witness"],
        req,
        lambda req: evidence,
        lambda core: witness_service._sign_receipt(core, cfg),
    )

    def commit(req, signed):
        return lifecycle.witness_commit(
            journals["witness"],
            req,
            signed,
            lambda req, retained, signed: verify_committed_carrier(
                str(keygen), decode_payload["issuer_script_hex"], config, req, retained, signed
            ),
        )

    lease = issuer_service._empty_prevout_journal()
    owner = issuer_service.direct_mint_prevout_owner_id(facts["deposit_outpoint"])
    wrapper = {
        "version": 2,
        "prepared": prepared,
        "authorization": {
            "operation_type": "BTCVELD_MINT",
            "recipient": facts["recipient"],
            "amount": facts["sats"],
            "change_destination": issuer,
            "operation_identity_digest": built["operation_identity_digest"],
            "maximum_absolute_fee": 100000,
            "maximum_fee_rate": 19,
        },
    }
    counters = {"sign_attempts": 0, "fresh_gates": 0}

    def fresh(req, retained):
        assert lifecycle.intent_from_evidence(
            config, req, retained
        ) == lifecycle.intent_from_evidence(config, req, evidence)
        counters["fresh_gates"] += 1

    def sign(req, retained, gate):
        counters["sign_attempts"] += 1
        issuer_service.reserve_issuer_prevouts(
            lease, owner, "mint-direct", None, facts["deposit_outpoint"], req["unsigned_tx_hex"]
        )
        return issuer_service.sign_or_recover_staged_carrier(
            lease,
            owner,
            req["unsigned_tx_hex"],
            decode_payload["issuer_script_hex"],
            "RTP1 lifecycle fixture",
            build_evidence=lambda: wrapper,
            revalidate=gate,
        )

    def mint(commit_callback):
        return lifecycle.issuer_mint(
            journals["issuer"],
            request,
            inspect=lambda req: evidence,
            reserve=reserve,
            verify_fresh=fresh,
            sign_or_recover=sign,
            commit=commit_callback,
            halt=lambda: None,
            receipt_verify=verify,
            witness_snapshot=lambda req: lifecycle.witness_status(journals["witness"], req),
            verify_carrier=lambda req, retained, signed: verify_committed_carrier(
                str(keygen), decode_payload["issuer_script_hex"], config, req, retained, signed
            ),
        )

    with mock.patch.multiple(
        issuer_service,
        PREVOUT_STATEF=str(root / "issuer-lease.json"),
        SIGNING_STAGE_DIR=str(root / "issuer-staging"),
        KEYGEN=str(keygen),
        KEYFILE=str(issuer_key),
        PASSFILE=str(password),
    ):

        def lost(req, signed):
            commit(req, signed)
            raise ConnectionError("simulated acknowledgement loss")

        try:
            mint(lost)
        except ConnectionError:
            pass
        else:
            raise AssertionError("missing witness acknowledgement released bytes")
        for role in journals:
            state = json.loads((root / (role + "-journal.json")).read_text())
            journals[role] = lifecycle.Journal(state, config, role, persist(role), verify)
        signed = mint(commit)
        assert mint(commit) == signed and counters["sign_attempts"] == 1
        assert counters["fresh_gates"] >= 3
        path = root / "service-signed.hex"
        path.write_text(signed)
        prepared_path = root / "service-prepared.json"
        prepared_path.write_text(json.dumps(prepared))
        assert "PASS signed-inputs=" in run(
            [fixture, "--verify-signed", issuer, prepared_path, path]
        )
        for role in journals:
            assert journals[role].reconcile(lambda row: {"height": 3001, "hash": "ab" * 32}) == 0
            assert journals[role].reconcile(lambda row: None) == facts["sats"]
            assert journals[role].find(request)["signed_tx_hex"] == signed
    return {
        "actual_independent_mldsa_receipt": True,
        "actual_issuer_signature": True,
        "two_durable_journals": True,
        "lost_ack_restart_byte_exact": True,
        "one_randomized_issuer_attempt": counters["sign_attempts"] == 1,
        "retained_context_commit_after_retry": True,
        "reorg_liability_retained": True,
        "native_view_simulated": True,
        "full_service_entrypoints_tested": False,
    }
