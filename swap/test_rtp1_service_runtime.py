import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import rtp1_service as lifecycle
import rtp1_service_runtime as runtime
import veld_peg_solvency as solvency
from test_rtp1_service import fixture


class RuntimeBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.config, self.request, self.evidence, self.signed = fixture()

    def test_reserved_request_is_counted_exactly_once_before_and_after_reservation(self):
        amount = self.request["sats"]
        other = dict(self.request, recipient="V" + "2" * 30)
        rows = [{"request": other, "confirmation": None},
            {"request": dict(other, sats=amount + 1), "confirmation": {"height": 1}}]
        journal = mock.Mock(state={"records": rows})
        with mock.patch.object(runtime, "beat_gate") as gate:
            for reserved in (False, True):
                if reserved: rows.append({"request": self.request, "confirmation": None})
                runtime.reserved_mint_gate(self.config, "rpc", "beat", journal, self.request, "verify")
                gate.assert_called_with(self.config, "rpc", "beat", amount, amount, "verify")

    def test_reserved_request_cannot_reuse_backing_committed_elsewhere(self):
        amount = self.request["sats"]
        payload = solvency.build_beat_payload(amount, 0, 0, 100, "ab" * 32, 1, 600)
        payload.update(sig_alg="mldsa65", sig="12" * 3309)
        beat = solvency.stamp_heartbeat(payload, time.time())
        rpc = mock.Mock()
        rpc.call.side_effect = lambda method, params: {"supply_sats": 0, "tip": 100,
            "tip_hash": "ab" * 32} if method == "getbtcveldsupply" else "ab" * 32
        rows = [{"request": self.request, "confirmation": None}]
        journal = mock.Mock(state={"records": rows})
        runtime.reserved_mint_gate(self.config, rpc, beat, journal, self.request, lambda *args: True)
        rows.append({"request": dict(self.request, recipient="V" + "2" * 30), "confirmation": None})
        with self.assertRaisesRegex(ValueError, "exceed watchtower headroom"):
            runtime.reserved_mint_gate(self.config, rpc, beat, journal, self.request, lambda *args: True)

    def test_heartbeat_signature_excludes_only_receiver_timestamps(self):
        payload = solvency.build_beat_payload(100000, 0, 0, 100, "ab" * 32, 1, 600)
        payload.update(sig_alg="mldsa65", sig="12" * 3309)
        beat = solvency.stamp_heartbeat(payload, time.time())
        view = {"supply_sats": 0, "tip": 100, "tip_hash": "ab" * 32}
        rpc = mock.Mock()
        rpc.call.side_effect = lambda method, params: view if method == "getbtcveldsupply" else "ab" * 32
        verify = mock.Mock(return_value=True)
        runtime.beat_gate(self.config, rpc, beat, 20000, 20000, verify)
        verify.assert_called_once_with(solvency.canonical_beat_bytes(payload), payload["sig"])

    def test_invalid_expired_or_insufficient_heartbeat_refuses(self):
        payload = solvency.build_beat_payload(20000, 0, 0, 100, "ab" * 32, 1, 600)
        payload.update(sig_alg="mldsa65", sig="12" * 3309)
        beat = solvency.stamp_heartbeat(payload, time.time())
        rpc = mock.Mock()
        for candidate, verify, used in ((beat, lambda *args: False, 0),
                (dict(beat, expires_at=1), lambda *args: True, 0), (beat, lambda *args: True, 20000)):
            with self.subTest(used=used), self.assertRaises(ValueError):
                runtime.beat_gate(self.config, rpc, candidate, used, 20000, verify)
        rpc.call.assert_not_called()

    def test_bitcoin_argument_types_are_canonical_json(self):
        if os.name != "posix": self.skipTest("existing witness service is POSIX")
        import veld_wt_reserve as witness
        cfg = {"cli_base": ["/fixture/bitcoin-cli"], "wallet": "w", "confirmations": 144,
            "tip_age_alert_secs": 3600, "max_tip_age_secs": 7200}
        with mock.patch.object(witness, "run_bounded_subprocess", return_value=mock.Mock(returncode=0, stdout="{}")) as launch:
            witness.BitcoinCli(cfg).call("getrawtransaction", "12" * 32, True, None)
            self.assertEqual(launch.call_args.args[0][-2:], ["true", "null"])

    @unittest.skipUnless(os.name == "posix", "existing migration adapter is POSIX")
    def test_empty_migration_is_durable_and_originals_unchanged(self):
        import veld_signerd as issuer
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {label: str(root / (label + ".json")) for label in ("mint", "c1", "leases")}
            documents = {"mint": {"signed": [], "mint_accounting": {"version": 2, "pending": [], "confirmed": []}},
                "c1": issuer._empty_c1_signer_state(), "leases": issuer._empty_prevout_journal()}
            for label, path in paths.items(): issuer.save_signer_state_durable(documents[label], path)
            originals = {label: Path(path).read_bytes() for label, path in paths.items()}
            marker = runtime.initialize_empty_migration(str(root), "issuer", self.config, paths, issuer.save_signer_state_durable)
            cfg = {"rtp1_service": self.config, "veld_rpc": {"expected_chain": self.config["expected_chain"]}}
            loaded = runtime.load_activated_state(str(root), "issuer", cfg,
                {k: p for k, p in paths.items() if k != "leases"}, issuer.save_signer_state_durable, lambda *args: True)
            self.assertEqual(loaded.state["migration"], lifecycle.digest(marker))
            self.assertEqual(originals, {label: Path(path).read_bytes() for label, path in paths.items()})
            with self.assertRaises(ValueError): runtime.initialize_empty_migration(str(root), "issuer", self.config, paths, issuer.save_signer_state_durable)
            Path(paths["mint"]).write_bytes(originals["mint"] + b" ")
            with self.assertRaises(ValueError): runtime.load_activated_state(str(root), "issuer", cfg,
                {k: p for k, p in paths.items() if k != "leases"}, issuer.save_signer_state_durable, lambda *args: True)

    @unittest.skipUnless(os.name == "posix", "existing migration adapter is POSIX")
    def test_new_authority_initializer_mint_state_can_migrate_without_rewriting_it(self):
        import veld_signerd as issuer
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {label: str(root / (label + ".json")) for label in ("mint", "c1", "leases")}
            documents = {"mint": {"signed": []}, "c1": issuer._empty_c1_signer_state(),
                "leases": issuer._empty_prevout_journal()}
            for label, path in paths.items(): issuer.save_signer_state_durable(documents[label], path)
            original = Path(paths["mint"]).read_bytes()
            runtime.initialize_empty_migration(str(root), "issuer", self.config, paths, issuer.save_signer_state_durable)
            self.assertEqual(Path(paths["mint"]).read_bytes(), original)
            self.assertTrue((root / "rtp1-migration.json").is_file())

    @unittest.skipUnless(os.name == "posix", "existing migration adapter is POSIX")
    def test_existing_funded_or_signed_c1_state_cannot_migrate(self):
        import veld_signerd as issuer
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {label: str(root / (label + ".json")) for label in ("mint", "c1", "leases")}
            documents = {"mint": {"signed": [], "mint_accounting": {"version": 2, "pending": [], "confirmed": []}},
                "c1": dict(issuer._empty_c1_signer_state(), records={"funded": {"signed_tx_hex": self.signed}}),
                "leases": issuer._empty_prevout_journal()}
            for label, path in paths.items(): issuer.save_signer_state_durable(documents[label], path)
            with self.assertRaises(ValueError): runtime.initialize_empty_migration(str(root), "issuer", self.config, paths, issuer.save_signer_state_durable)
            self.assertFalse((root / "rtp1-migration.json").exists())
            self.assertFalse((root / "rtp1-issuer.json").exists())

    @unittest.skipUnless(os.name == "posix", "existing migration adapter is POSIX")
    def test_partial_migration_never_auto_adopts_or_overwrites(self):
        import veld_signerd as issuer
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            partial = root / "rtp1-issuer.json"
            partial.write_text("preserve")
            with self.assertRaises(ValueError): runtime.initialize_empty_migration(str(root), "issuer", self.config, {}, issuer.save_signer_state_durable)
            self.assertEqual(partial.read_text(), "preserve")

    def test_confirmation_requires_exact_native_effect_and_both_branches(self):
        row = {"request": self.request, "signed_tx_hex": self.signed,
            "receipt": {"intent": {"native": self.evidence["native"]}}, "evidence": self.evidence}
        view = {"supply_sats": 20000, "tip": 3000, "tip_hash": "ab" * 32}
        status = {"outpoint": self.evidence["native"]["deposit_outpoint"], "minted": True, "consumed": True,
            "accepted_effect_kind": "MINT", "accepted_txid": lifecycle.signed_identity(self.signed, self.request["unsigned_tx_hex"]),
            "tip": 3000, "tip_hash": "ab" * 32, "accepted_block_height": 2980, "accepted_block_hash": "cd" * 32}
        def native(method, params):
            if method == "getbtcveldsupply": return dict(view)
            if method == "getpeginfo": return {"final_height": 2980}
            if method == "getbtcveldmintstatus": return dict(status)
            if method == "getblockhash": return "ab" * 32 if params == [3000] else "cd" * 32
            if method == "gettransaction":
                self.assertEqual(params, [status["accepted_txid"], 2980])
                return {"txid": params[0], "block_height": 2980,
                    "raw_hex": self.signed, "block_hash": "cd" * 32}
            raise AssertionError(method)
        info = {"chain": "regtest", "initialblockdownload": False, "blocks": 500, "headers": 500}
        def bitcoin(method, *args):
            if method == "getblockhash": return self.config["bitcoin_genesis"] if args == (0,) else "55" * 32
            if method == "getblockchaininfo": return dict(info)
            if method == "getblockheader": return {"height": 100, "confirmations": 401}
            raise AssertionError(method)
        rpc, btc = mock.Mock(), mock.Mock()
        rpc.call.side_effect, btc.call.side_effect = native, bitcoin
        with mock.patch.object(runtime, "verify_expected_chain"):
            self.assertEqual(runtime.confirmation(self.config, rpc, btc, row), {"height": 2980, "hash": "cd" * 32})
            status["accepted_txid"] = "ef" * 32
            self.assertIsNone(runtime.confirmation(self.config, rpc, btc, row))
            status["accepted_txid"] = lifecycle.signed_identity(self.signed, self.request["unsigned_tx_hex"])
            info["initialblockdownload"] = True
            self.assertIsNone(runtime.confirmation(self.config, rpc, btc, row))

    @unittest.skipUnless(os.name == "posix", "existing witness entry point is POSIX")
    def test_status_and_commit_reconcile_before_releasing_cached_state(self):
        service, rpc, journal = mock.Mock(), mock.Mock(), mock.Mock()
        service.HERE = "/fixture"
        cfg = {"rtp1_service": self.config, "state_dir": "/fixture", "rtp1_witness_public_key_file": "/fixture/public"}
        paths = {key: "/fixture/" + key for key in ("ledger", "allocations", "terminal")}
        for action in ("rtp1_status", "rtp1_commit"):
            events = []
            envelope = {"action": action, "request": self.request}
            if action == "rtp1_commit": envelope["signed_tx_hex"] = self.signed
            journal.reconcile.side_effect = lambda callback: events.append(("reconcile", callback({})))
            with mock.patch.object(runtime, "verifier"), mock.patch.object(runtime, "verify_expected_chain"), \
                    mock.patch.object(runtime, "check_descriptor"), \
                    mock.patch.object(runtime, "load_activated_state", return_value=journal), \
                    mock.patch.object(runtime, "confirmation", return_value=None), \
                    mock.patch("veld_signerd.issuer_p2pkh_from_address", return_value="76a914" + "11" * 20 + "88ac"), \
                    mock.patch.object(lifecycle, "witness_status", side_effect=lambda *args: events.append(("status", None))), \
                    mock.patch.object(lifecycle, "witness_commit", side_effect=lambda *args: events.append(("commit", None))):
                runtime.witness_request(service, envelope, cfg, paths, rpc)
            self.assertEqual(events, [("reconcile", None), (action.removeprefix("rtp1_"), None)])


if __name__ == "__main__":
    unittest.main()
