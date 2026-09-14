import copy
import hashlib
import unittest
from unittest import mock

import rtp1_service as service
import test_rtp1_mint_policy as mint_fixture


def fixture():
    base = mint_fixture.Rtp1MintPolicyTests()
    base.setUp()
    unsigned = "01000000" + "01" + "66" * 32 + "00000000" + "00" + "ffffffff" + "01" + "0100000000000000" + "01" + "51" + "00000000"
    signed = unsigned[:82] + "0151" + unsigned[84:]
    config = {"version": 1, "expected_chain": base.chain, "issuer": base.account, "witness_id": "independent-witness",
        "custody_descriptor_sha256": "33" * 32, "custody_manifest_sha256": "44" * 32,
        "bitcoin_genesis": "77" * 32, "bitcoin_network": "regtest", "custody_script_hex": "5120" + "88" * 32,
        "minimum_confirmations": 144}
    request = {"action": "rtp1_mint", "unsigned_tx_hex": unsigned, "recipient": base.account, "sats": 20000}
    native = dict(base.response, unsigned_tx_sha256=hashlib.sha256(bytes.fromhex(unsigned)).hexdigest())
    facts = {"version": 1, "operation": "DEPOSIT", "network_binding": "11" * 32, "prior_commitment": "22" * 32,
        "prior_transition_count": 1, "bitcoin_txid": "55" * 32, "bitcoin_block": "55" * 32,
        "reserve_vout": 0, "reserve_value_sats": 120000, "deposit_outpoint": "66" * 32 + ":0",
        "exact_commitment": "55" * 32, "sats": 20000, "issuer": base.account, "recipient": base.account,
        "custody_script_hex": config["custody_script_hex"], "direct_parent_txids": ["aa" * 32, "66" * 32]}
    bitcoin = {"genesis_hash": config["bitcoin_genesis"], "network": "regtest", "confirmations": 144,
        "reserve_outpoint": "55" * 32 + ":0", "reserve_value_sats": 120000, "custody_script_hex": config["custody_script_hex"]}
    body = {"version": 1, "kind": "rtp1-independent-backing", "native": native, "bitcoin": bitcoin, "transition": facts}
    evidence = dict(body, evidence_sha256=hashlib.sha256(b"VELD/RTP1/BACKING/v1\x00" + service.canonical(body)).hexdigest())
    return config, request, evidence, signed


class Rtp1ServiceTests(unittest.TestCase):
    def setUp(self):
        self.config, self.request, self.evidence, self.signed = fixture()
        self.saved, self.events = {}, []
        self.verify = lambda message, sig: sig == "12" * 3309
        self.sign_receipt = lambda core: dict(core, sig_alg="mldsa65", sig="12" * 3309)
        self.issuer = self.journal("issuer")
        self.witness = self.journal("witness")
        self.sign_calls = 0

    def journal(self, role, state=None):
        def persist(value):
            self.saved[role] = copy.deepcopy(value)
            self.events.append(role + "-persist")
        return service.Journal(state or service.empty_journal(role, self.config, "bb" * 32), self.config, role, persist, self.verify)

    def reserve(self, request):
        return service.witness_reserve(self.witness, request, lambda req: self.evidence, self.sign_receipt)

    def commit(self, request, signed):
        return service.witness_commit(self.witness, request, signed, lambda req, retained, signed: (self.events.append("retained-decode") or True))

    def sign(self, request, evidence, gate):
        gate()
        self.sign_calls += 1
        self.events.append("sign")
        self.assertIsNotNone(self.saved["issuer"]["records"][0]["receipt"])
        self.assertIsNotNone(self.saved["witness"]["records"][0]["receipt"])
        return self.signed

    def mint(self, **overrides):
        kwargs = dict(inspect=lambda req: self.evidence, reserve=self.reserve,
            verify_fresh=lambda req, retained: None, sign_or_recover=self.sign, commit=self.commit,
            halt=lambda: None, receipt_verify=self.verify,
            witness_snapshot=lambda req: service.witness_status(self.witness, req),
            verify_carrier=lambda req, retained, signed: signed == self.signed)
        kwargs.update(overrides)
        return service.issuer_mint(self.issuer, self.request, **kwargs)

    def test_two_durable_exact_commitments_before_release(self):
        self.assertEqual(self.mint(), self.signed)
        self.assertEqual(self.sign_calls, 1)
        for role in ("issuer", "witness"):
            row = self.saved[role]["records"][0]
            self.assertTrue(row["committed"])
            self.assertEqual(row["signed_tx_hex"], self.signed)

    def test_disposable_label_cannot_enable_an_external_value_profile(self):
        config = copy.deepcopy(self.config)
        config["expected_chain"]["external_value"] = True
        with self.assertRaisesRegex(ValueError, "activation is closed"):
            service.configuration(config)

    def test_restart_replays_exact_bytes_without_fresh_issuance(self):
        self.mint()
        self.issuer = self.journal("issuer", self.saved["issuer"])
        self.witness = self.journal("witness", self.saved["witness"])
        fail = lambda *args: self.fail("retry attempted new issuance")
        self.assertEqual(self.mint(inspect=fail, verify_fresh=fail, sign_or_recover=fail), self.signed)

    def test_witness_commit_ack_loss_retains_bytes_and_recovers(self):
        def lost(req, signed):
            self.commit(req, signed)
            raise ConnectionError("ack lost")
        with self.assertRaises(ConnectionError): self.mint(commit=lost)
        self.assertFalse(self.saved["issuer"]["records"][0]["committed"])
        self.assertTrue(self.saved["witness"]["records"][0]["committed"])
        self.assertEqual(self.mint(), self.signed)
        self.assertEqual(self.sign_calls, 1)

    def test_signing_uncertainty_keeps_both_reservations(self):
        def uncertain(*args): raise RuntimeError("exact output missing")
        with self.assertRaises(RuntimeError): self.mint(sign_or_recover=uncertain)
        for role in ("issuer", "witness"):
            self.assertEqual(len(self.saved[role]["records"]), 1)
            self.assertIsNone(self.saved[role]["records"][0]["signed_tx_hex"])

    def test_witness_rollback_refuses_at_key_boundary(self):
        with self.assertRaises(ValueError): self.mint(witness_snapshot=lambda req: {})
        self.assertEqual(self.sign_calls, 0)

    def test_restored_issuer_recovers_committed_witness_bytes_without_signing(self):
        self.mint()
        restored = copy.deepcopy(self.saved["issuer"])
        restored["records"][0].update(signed_tx_hex=None, committed=False)
        self.issuer = self.journal("issuer", restored)
        fail = lambda *args: self.fail("witness already has exact signed bytes")
        self.assertEqual(self.mint(sign_or_recover=fail, verify_fresh=fail), self.signed)
        self.assertTrue(self.saved["issuer"]["records"][0]["committed"])

    def test_stale_or_different_context_prevents_signing(self):
        def stale(*args): raise ValueError("stale reserve")
        with self.assertRaises(ValueError): self.mint(verify_fresh=stale)
        self.assertEqual(self.sign_calls, 0)

    def test_issuer_checks_crypto_before_adopting_witness_recovery(self):
        self.mint()
        restored = copy.deepcopy(self.saved["issuer"])
        restored["records"][0].update(signed_tx_hex=None, committed=False)
        self.issuer = self.journal("issuer", restored)
        before = copy.deepcopy(self.issuer.state)
        with self.assertRaisesRegex(ValueError, "recovered RTP1 carrier"):
            self.mint(verify_carrier=lambda *args: False)
        self.assertEqual(self.issuer.state, before)
        self.assertEqual(self.sign_calls, 1)

    def test_issuer_refuses_invalid_new_and_retained_crypto(self):
        with self.assertRaisesRegex(ValueError, "new RTP1 carrier"):
            self.mint(verify_carrier=lambda *args: False)
        self.assertIsNone(self.issuer.find(self.request)["signed_tx_hex"])
        self.assertIsNone(self.witness.find(self.request)["signed_tx_hex"])
        self.mint()
        before = copy.deepcopy(self.issuer.state)
        with self.assertRaisesRegex(ValueError, "retained RTP1 carrier"):
            self.mint(verify_carrier=lambda *args: False)
        self.assertEqual(self.issuer.state, before)

    def test_halt_before_cached_release(self):
        self.mint()
        def halt(): raise ValueError("HALT")
        with self.assertRaises(ValueError): self.mint(halt=halt)

    def test_wrong_commit_ack_never_marks_issuer_committed(self):
        with self.assertRaises(ValueError): self.mint(commit=lambda req, signed: {"committed": True})
        self.assertFalse(self.saved["issuer"]["records"][0]["committed"])

    def test_different_signed_bytes_refused_after_commit(self):
        self.mint()
        changed = self.signed[:84] + "52" + self.signed[86:]
        self.assertEqual(service.unsigned_template_from_signed_hex(changed), self.request["unsigned_tx_hex"])
        with self.assertRaises(ValueError): self.commit(self.request, changed)

    def test_invalid_signature_receipt_refuses_before_key(self):
        with self.assertRaises(ValueError): self.mint(receipt_verify=lambda *args: False)
        self.assertEqual(self.sign_calls, 0)

    def test_invalid_carrier_signature_does_not_commit_the_reservation(self):
        self.reserve(self.request)
        before = copy.deepcopy(self.witness.state)
        with self.assertRaises(ValueError):
            service.witness_commit(self.witness, self.request, self.signed, lambda *args: False)
        self.assertEqual(self.witness.state, before)

    def test_immutable_receipt_verification_is_cached_only_within_this_journal(self):
        self.mint()
        checked = mock.Mock(return_value=True)
        state = copy.deepcopy(self.saved["issuer"])
        journal = service.Journal(state, self.config, "issuer", lambda value: None, checked)
        journal.validate()
        journal.validate()
        self.assertEqual(checked.call_count, 1)
        with self.assertRaises(ValueError): service.Journal(state, self.config, "issuer", lambda value: None, lambda *args: False)

    def test_mutated_claim_not_accepted_as_idempotent_retry(self):
        self.reserve(self.request)
        changed = dict(self.request, sats=20001)
        with self.assertRaises(ValueError): self.witness.find(changed)

    def test_missing_or_altered_journal_head_refuses(self):
        self.mint()
        altered = copy.deepcopy(self.saved["witness"])
        altered["records"] = []
        with self.assertRaises(ValueError): self.journal("witness", altered)

    def test_schema_and_integer_types_strict(self):
        for altered in (dict(self.request, extra=1), dict(self.request, sats=True), dict(self.request, unsigned_tx_hex="AA")):
            with self.subTest(altered=altered), self.assertRaises(ValueError): service.request_identity(altered)

    def test_production_and_wrong_policy_do_not_activate(self):
        for config in (dict(self.config, bitcoin_network="main"), dict(self.config, minimum_confirmations=143),
                dict(self.config, expected_chain=dict(self.config["expected_chain"], disposable=False))):
            with self.subTest(config=config), self.assertRaises(ValueError): service.configuration(config)

    def test_no_expiration_or_automatic_release_of_uncertain_liability(self):
        self.reserve(self.request)
        self.assertEqual(self.witness.reconcile(lambda row: None), 20000)
        self.assertEqual(len(self.witness.state["records"]), 1)
        self.assertIsNone(self.witness.state["records"][0]["confirmation"])

    def test_reorganization_reinstates_liability_without_forgetting_signature(self):
        self.mint()
        self.assertEqual(self.witness.reconcile(lambda row: {"height": 10, "hash": "ab" * 32}), 0)
        self.assertEqual(self.witness.reconcile(lambda row: None), 20000)
        self.assertEqual(self.witness.state["records"][0]["signed_tx_hex"], self.signed)

    def test_persistence_failure_returns_no_receipt_and_restores_memory(self):
        before = copy.deepcopy(self.witness.state)
        def fail(value): raise OSError("fsync failed")
        self.witness.persist = fail
        with self.assertRaises(OSError): self.reserve(self.request)
        self.assertEqual(self.witness.state, before)

    def test_conflicting_reserve_edge_never_has_two_receipts(self):
        self.mint()
        self.witness.reconcile(lambda row: {"height": 10, "hash": "ab" * 32})
        request = dict(self.request, unsigned_tx_hex=self.request["unsigned_tx_hex"][:-8] + "01000000")
        evidence = copy.deepcopy(self.evidence)
        evidence["native"]["unsigned_tx_sha256"] = service.request_identity(request)
        evidence["native"]["deposit_outpoint"] = "dd" * 32 + ":0"
        evidence["transition"]["deposit_outpoint"] = "dd" * 32 + ":0"
        body = {key: value for key, value in evidence.items() if key != "evidence_sha256"}
        evidence["evidence_sha256"] = hashlib.sha256(b"VELD/RTP1/BACKING/v1\x00" + service.canonical(body)).hexdigest()
        with self.assertRaises(ValueError):
            service.witness_reserve(self.witness, request, lambda req: evidence, self.sign_receipt)


if __name__ == "__main__":
    unittest.main()
