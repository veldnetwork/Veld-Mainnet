import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import veld_wt_reserve as witness


class WitnessReceiptSigningTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="witness-receipt-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = self.root / "fixture-key"
        self.key.write_bytes(b"disposable non-key fixture")
        self.key.chmod(0o600)
        self.password = self.root / "fixture-password"
        self.password.write_text("disposable fixture passphrase\n")
        self.password.chmod(0o600)
        self.cfg = {"keygen": "/fixture/keygen", "signer": {
            "beat_keyfile": str(self.key), "beat_passfile": str(self.password)}}

    def sign(self, signature_size=3309):
        def run(argv, **kwargs):
            self.assertEqual(kwargs["timeout"], 30)
            self.assertEqual(kwargs["stdout_max"], 65536)
            self.assertEqual(kwargs["stderr_max"], 65536)
            self.assertEqual(kwargs["env"]["VELD_VAULT_PASSPHRASE"],
                             "disposable fixture passphrase")
            Path(argv[-1]).write_bytes(b"s" * signature_size)
            return subprocess.CompletedProcess(argv, 0, "", "")
        with mock.patch.object(witness.sol, "canonical_reservation_bytes", return_value=b"{}"), \
                mock.patch.object(witness, "run_bounded_subprocess", side_effect=run):
            return witness._sign_receipt({}, self.cfg)

    def test_complete_receipt_and_original_environment(self):
        before = dict(os.environ)
        result = self.sign()
        self.assertEqual(result["sig_alg"], "mldsa65")
        self.assertEqual(len(bytes.fromhex(result["sig"])), 3309)
        self.assertEqual(dict(os.environ), before)

    def test_missing_signature_is_refused(self):
        with mock.patch.object(witness.sol, "canonical_reservation_bytes", return_value=b"{}"), \
                mock.patch.object(witness, "run_bounded_subprocess",
                    return_value=subprocess.CompletedProcess([], 0, "", "")), \
                self.assertRaises(FileNotFoundError):
            witness._sign_receipt({}, self.cfg)

    def test_incomplete_signature_is_refused(self):
        with self.assertRaises(SystemExit):
            self.sign(0)

    def test_unavailable_password_refuses_before_signing(self):
        self.password.unlink()
        with mock.patch.object(witness, "run_bounded_subprocess") as run, \
                self.assertRaises(SystemExit):
            witness._sign_receipt({}, self.cfg)
        run.assert_not_called()

    def test_empty_password_refuses_before_signing(self):
        self.password.write_text("\n")
        with mock.patch.object(witness, "run_bounded_subprocess") as run, \
                self.assertRaises(SystemExit):
            witness._sign_receipt({}, self.cfg)
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
