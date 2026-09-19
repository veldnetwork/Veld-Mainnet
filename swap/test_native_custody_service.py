import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from swap import native_custody_service as service


def fixture(directory):
    h = lambda n: format(n, "064x")
    pins = {"profile_id": "disposable-native-custody", "consensus_build_profile": "fixture",
        "disposable": True, "external_value": False, "fixed_difficulty_regtest": True,
        "genesis_hash": h(1), "launch_block_hash": h(2)}
    policy = {field: h(20 + i) for i, field in enumerate(service.HASH_FIELDS)}
    policy.update(version=1, expected_chain=pins, epoch=1, member_index=0, member_key=h(99),
        minimum_bitcoin_confirmations=144, max_fee_sats=1000,
        state_path=str(directory / "native.db"), manifest_path=str(directory / "manifest.json"), custody_manifest_sha256=h(98))
    cfg = {"native_custody": policy, "veld_rpc": {"expected_chain": pins}, "signer_id": "member-one"}
    raw = "010203"
    observed = {field: h(100 + i) for i, field in enumerate(service.INSPECTION_HASHES)}
    for field in service.HASH_FIELDS:
        observed["genesis_hash" if field == "domain_genesis_hash" else field] = policy[field]
    observed.update(version=1, native_authorized=True, kind="PAYOUT", epoch=1, fee_sats=1000,
        reserve_vout=0, principal_sats=100000, authorization_height=10, final_height=20, tip=22,
        destination_script_hex="0014" + "12" * 20, refund_address="V" + "1" * 33,
        unsigned_tx_sha256=hashlib.sha256(bytes.fromhex(raw)).hexdigest())
    def native(method, params):
        if method == "getnetworkinfo": return pins
        if method == "getcompiledgenesis": return pins["genesis_hash"]
        if method == "getblockcount": return observed["tip"]
        if method == "inspectcustodyintent": return copy.deepcopy(observed)
        if method == "getblockhash":
            return {0:pins["genesis_hash"], 1:pins["launch_block_hash"],
                observed["authorization_height"]:observed["authorization_block"],
                observed["final_height"]:observed["final_block"], observed["tip"]:observed["tip_hash"]}[params[0]]
        raise AssertionError(method)
    return cfg, observed, raw, native


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cfg, self.observed, self.raw, self.native = fixture(Path(self.directory.name))

    def test_exact_finalized_observation(self):
        self.assertEqual(service.inspect(self.native, self.cfg["native_custody"], "00", self.raw), self.observed)

    def test_tip_advance_preserves_unchanged_finalized_authority(self):
        old = copy.deepcopy(self.observed)
        self.observed["tip"] += 1
        self.observed["tip_hash"] = 'ab' * 32
        self.assertEqual(service.refresh_authority(self.native, self.cfg["native_custody"],
            "00", self.raw, old), self.observed)

    def test_finality_can_advance_only_above_the_same_canonical_prefix(self):
        old = copy.deepcopy(self.observed)
        self.observed.update(final_height=40, final_block='ab' * 32, finality_certificate='cd' * 32,
            tip=42, tip_hash='ef' * 32)
        def native(method, params):
            if method == 'getblockhash' and params == [old['final_height']]:
                return old['final_block']
            return self.native(method, params)
        self.assertEqual(service.refresh_authority(native, self.cfg['native_custody'],
            '00', self.raw, old), self.observed)
        def replaced(method, params):
            if method == 'getblockhash' and params == [old['final_height']]:
                return '01' * 32
            return self.native(method, params)
        with self.assertRaisesRegex(ValueError, 'finalized ancestry'):
            service.refresh_authority(replaced, self.cfg['native_custody'], '00', self.raw, old)

    def test_advancing_tip_never_allows_another_reserve_intent_or_refund(self):
        old = copy.deepcopy(self.observed)
        for field in ('reserve_txid', 'intent_commitment', 'burn_id', 'authorization_block'):
            self.observed[field] = 'ab' * 32
            self.observed['tip'] = old['tip'] + 1
            with self.subTest(field=field), self.assertRaises(ValueError):
                service.refresh_authority(self.native, self.cfg['native_custody'], '00', self.raw, old)
            self.observed.clear()
            self.observed.update(copy.deepcopy(old))

    def test_finality_rollback_refuses_even_with_an_unchanged_intent(self):
        old = copy.deepcopy(self.observed)
        self.observed['final_height'] -= 1
        with self.assertRaisesRegex(ValueError, 'finalized ancestry'):
            service.refresh_authority(self.native, self.cfg['native_custody'], '00', self.raw, old)

    def test_every_identity_is_bound(self):
        for field in service.HASH_FIELDS:
            with self.subTest(field=field):
                policy = copy.deepcopy(self.cfg["native_custody"])
                policy[field] = "ab" * 32
                with self.assertRaises(ValueError): service.inspect(self.native, policy, "00", self.raw)

    def test_public_activation_refused(self):
        for field, value in (("disposable", False), ("external_value", True)):
            with self.subTest(field=field):
                cfg = copy.deepcopy(self.cfg)
                cfg["native_custody"]["expected_chain"][field] = value
                with self.assertRaises(ValueError): service.configuration(cfg)

    def test_exact_numeric_types_and_bounds(self):
        for field in service.INSPECTION_NUMBERS:
            for value in (True, 1.0, "1", -1, 1 << 64):
                old = self.observed[field]
                with self.subTest(field=field, value=value):
                    self.observed[field] = value
                    with self.assertRaises(ValueError): service.inspect(self.native, self.cfg["native_custody"], "00", self.raw)
                self.observed[field] = old

    def test_changed_transaction_refused(self):
        with self.assertRaises(ValueError): service.inspect(self.native, self.cfg["native_custody"], "00", "010204")

    def test_schema_confusion_refused(self):
        for value in (None, [], True, dict(self.observed, extra=1)):
            def bad(method, params):
                return value if method == "inspectcustodyintent" else self.native(method, params)
            with self.assertRaises(ValueError): service.inspect(bad, self.cfg["native_custody"], "00", self.raw)

    def test_noncanonical_finality_refused(self):
        def wrong(method, params):
            if method == "getblockhash" and params == [20]: return "ff" * 32
            return self.native(method, params)
        with self.assertRaises(ValueError): service.inspect(wrong, self.cfg["native_custody"], "00", self.raw)

    def test_no_finality_no_authority(self):
        self.observed["final_height"] = 9
        with self.assertRaises(ValueError): service.inspect(self.native, self.cfg["native_custody"], "00", self.raw)


@unittest.skipUnless(os.name == "posix", "POSIX authority store; managed Windows integration remains separate")
class StoreTests(unittest.TestCase):
    setUp = PolicyTests.setUp
    def store(self, initialize=False):
        return service.CommitmentStore(self.cfg, initialize=initialize)

    def test_missing_history_never_initializes_implicitly(self):
        with self.assertRaises(OSError): self.store()

    def test_durable_commit_and_original_response(self):
        store = self.store(True)
        self.assertIsNone(store.commit(self.observed, self.raw, self.native))
        store.retain(self.observed, "original-response")
        store.close()
        store = self.store()
        try: self.assertEqual(store.commit(self.observed, self.raw, self.native), "original-response")
        finally: store.close()
        with self.assertRaises(FileExistsError): self.store(True)

    def test_conflicting_intent_and_reserve_burn_refused(self):
        store = self.store(True)
        try:
            store.commit(self.observed, self.raw, self.native)
            for field in ("intent_commitment", "burn_id"):
                altered = dict(self.observed, **{field:"ab" * 32})
                with self.assertRaises(ValueError): store.commit(altered, self.raw, self.native)
            self.assertEqual(store.db.execute("SELECT count(*) FROM commitments").fetchone()[0], 1)
        finally: store.close()

    def test_retirement_retains_original_and_disables_payout(self):
        store = self.store(True)
        try:
            store.commit(self.observed, self.raw, self.native)
            store.retain(self.observed, "original")
            retired = dict(self.observed, kind="RETIREMENT", intent_commitment="ab" * 32)
            store.commit(retired, "ff", self.native)
            with self.assertRaises(ValueError): store.commit(self.observed, self.raw, self.native)
            self.assertEqual(store.db.execute("SELECT psbt FROM commitments WHERE kind='PAYOUT'").fetchone()[0], "original")
        finally: store.close()

    def test_finalized_checkpoint_rollback_refused(self):
        store = self.store(True)
        try:
            store.commit(self.observed, self.raw, self.native)
            for altered, native in ((dict(self.observed, final_height=19), self.native), (self.observed, lambda *_: "ff" * 32)):
                with self.assertRaises(ValueError): store.commit(altered, self.raw, native)
            self.assertEqual(store.db.execute("SELECT final_height FROM identity").fetchone()[0], 20)
        finally: store.close()

    def test_partial_initialization_and_changed_identity_refused(self):
        store = self.store(True)
        store.close()
        self.cfg["signer_id"] = "changed"
        with self.assertRaises(ValueError): self.store()

    def test_retained_signature_cannot_be_replaced(self):
        store = self.store(True)
        try:
            store.commit(self.observed, self.raw, self.native)
            store.retain(self.observed, "original")
            with self.assertRaises(ValueError): store.retain(self.observed, "replacement")
        finally: store.close()


if __name__ == "__main__": unittest.main()
