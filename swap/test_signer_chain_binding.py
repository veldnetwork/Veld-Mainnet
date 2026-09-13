"""Issuer chain binding and durable-state lifecycle, without signing or networking."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import veld_signerd as signer
import test_chain_identity as chain_fixture

CHAIN = chain_fixture.CHAIN


class SignerChainBindingTests(unittest.TestCase):
    def test_rpc_constructor_checks_before_policy_calls(self):
        _, calls, call = chain_fixture.ChainIdentityTests().node()
        cfg = {"url": "http://127.0.0.1:38374",
               "token_file": "/disposable/test-token",
               "expected_chain": CHAIN}
        with mock.patch.object(signer, "read_bounded_secret_file",
                               return_value=b"disposable-test-token"), \
                mock.patch.object(signer.TrustedVeldRpc, "call", side_effect=call):
            rpc = signer.TrustedVeldRpc(cfg)
        self.assertEqual(rpc.expected_chain, CHAIN)
        self.assertEqual(len(calls), 4)

    def test_missing_pins_refused_before_token_access(self):
        with mock.patch.object(signer, "read_bounded_secret_file") as secret:
            with self.assertRaisesRegex(ValueError, "expected_chain"):
                signer.TrustedVeldRpc({"url": "http://127.0.0.1:38374",
                                       "token_file": "/disposable/test-token"})
        secret.assert_not_called()

    def test_policy_boundary_rechecks_after_rpc_was_created(self):
        answers, _, call = chain_fixture.ChainIdentityTests().node()
        rpc = object.__new__(signer.TrustedVeldRpc)
        rpc.expected_chain = copy.deepcopy(CHAIN)
        rpc.call = mock.Mock(side_effect=call)
        rpc.verify_chain_identity()
        answers[("getnetworkinfo", ())]["profile_id"] = "another-test-chain"
        with self.assertRaisesRegex(ValueError, "profile_id"):
            signer.validate_compiled_mint_policy(rpc, "disposable-issuer")
        self.assertNotIn(mock.call("getpeginfo", []), rpc.call.call_args_list)

    def test_c1_boundary_also_requires_chain_before_reservation_work(self):
        rpc = mock.Mock()
        rpc.verify_chain_identity.side_effect = ValueError("wrong intended chain")
        with self.assertRaisesRegex(ValueError, "intended chain"):
            signer.validate_c1_signing_boundary(rpc, "issuer", {}, "RESERVE")
        rpc.call.assert_not_called()

    def test_new_marker_binds_chain_and_restart_keeps_state(self):
        with tempfile.TemporaryDirectory(prefix="issuer-chain-binding-") as name:
            root = Path(name)
            cfg = {"authority_state_activation_marker": str(root / "signer-authority-state.json"),
                   "veld_rpc": {"expected_chain": copy.deepcopy(CHAIN)}}
            paths = {"HERE": name,
                     "STATEF": str(root / "signer-state.json"),
                     "C1_STATEF": str(root / "c1-reservation-signer-state.json"),
                     "PREVOUT_STATEF": str(root / "issuer-prevout-leases.json")}
            with mock.patch.multiple(signer, **paths), \
                    mock.patch.object(signer, "load_signer_configuration", return_value=cfg):
                created = signer.initialize_signer_authority_state()
                self.assertEqual(created["version"], 2)
                self.assertEqual(created["expected_chain"], CHAIN)
                before = {p: Path(p).read_bytes() for p in created["state_files"].values()}
                self.assertTrue(signer.require_signer_authority_state_set(cfg))
                with mock.patch.object(signer, "_validate_and_reconcile_signer_authority_members") as reconcile:
                    self.assertEqual(signer.initialize_signer_authority_state(), created)
                    reconcile.assert_called_once_with(cfg)
                self.assertEqual({p: Path(p).read_bytes() for p in before}, before)
                marker = Path(cfg["authority_state_activation_marker"])
                changed = copy.deepcopy(created)
                changed["expected_chain"]["disposable"] = 1
                marker.write_text(json.dumps(changed))
                marker.chmod(0o600)
                with self.assertRaisesRegex(ValueError, "exact boolean"):
                    signer.require_signer_authority_state_set(cfg)
                marker.write_text(json.dumps(created))
                cfg["veld_rpc"]["expected_chain"]["launch_block_hash"] = "ef" * 32
                with self.assertRaisesRegex(ValueError, "offline reconciliation"):
                    signer.require_signer_authority_state_set(cfg)
                self.assertEqual({p: Path(p).read_bytes() for p in before}, before)

    def test_legacy_marker_is_not_silently_rebound(self):
        with tempfile.TemporaryDirectory(prefix="issuer-chain-legacy-") as name:
            root = Path(name)
            marker = root / "signer-authority-state.json"
            cfg = {"authority_state_activation_marker": str(marker),
                   "veld_rpc": {"expected_chain": CHAIN}}
            with mock.patch.object(signer, "HERE", name):
                legacy = signer._authority_state_marker_document(cfg)
                legacy["version"] = 1
                del legacy["expected_chain"]
                marker.write_text(json.dumps(legacy))
                marker.chmod(0o600)
                before = marker.read_bytes()
                with self.assertRaisesRegex(ValueError, "offline reconciliation"):
                    signer.require_signer_authority_state_set(cfg)
                self.assertEqual(marker.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
