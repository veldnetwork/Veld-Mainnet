import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swap import veld_watchtowerd as wd


class TokenRotationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "rpc.token"
        self.replace(b"a" * 64)
        self.client = wd.Veld("http://127.0.0.1:8334", str(self.path))

    def replace(self, value, mode=0o600):
        replacement = self.path.with_suffix(".next")
        replacement.write_bytes(value)
        replacement.chmod(mode)
        replacement.replace(self.path)

    def request_token(self):
        with mock.patch.object(
            wd,
            "open_rpc_request",
            return_value=io.BytesIO(b'{"jsonrpc":"2.0","id":1,"result":7,"error":null}'),
        ) as transport:
            self.assertEqual(self.client.rpc("getbtcveldsupply"), 7)
            return transport.call_args.args[0].get_header("Authorization")

    def assert_no_request(self):
        with mock.patch.object(wd, "open_rpc_request") as transport:
            with self.assertRaises(RuntimeError):
                self.client.rpc("getbtcveldsupply")
            transport.assert_not_called()

    def test_rotation_without_restart(self):
        self.assertEqual(self.request_token(), "Bearer " + "a" * 64)
        self.replace(b"b" * 64 + b"\n")
        self.assertEqual(self.request_token(), "Bearer " + "b" * 64)

    def test_invalid_replacements_never_reuse_previous_token(self):
        for value in (b"", b"invalid", b"a" * 63, b"x" * 64, b"a" * 4097):
            with self.subTest(length=len(value)):
                self.replace(value)
                self.assert_no_request()
        self.replace(b"c" * 64)
        self.assertEqual(self.request_token(), "Bearer " + "c" * 64)

    def test_missing_replacement_never_reuses_previous_token(self):
        self.path.unlink()
        self.assert_no_request()

    def test_private_permissions_required_after_rotation(self):
        self.replace(b"b" * 64, 0o644)
        self.assert_no_request()

    def test_linked_replacement_refused(self):
        other = self.path.with_suffix(".target")
        self.path.replace(other)
        self.path.symlink_to(other)
        self.assert_no_request()
        self.path.unlink()
        os.link(other, self.path)
        self.assert_no_request()


if __name__ == "__main__":
    unittest.main()
