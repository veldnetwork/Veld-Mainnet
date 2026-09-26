"""Actual Windows handle/ACL checks using disposable, unprivileged fixtures."""

import os
from pathlib import Path
import tempfile
import unittest

from swap.fixtures.windows_file_acl import protect_fixture
from swap.rpc_url_policy import read_bounded_regular_file, read_bounded_secret_file


@unittest.skipUnless(os.name == "nt", "requires actual Windows file handles")
class WindowsProtectedFileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="veld-file-policy-")
        self.path = Path(self.temp.name) / "fixture.txt"
        self.path.write_bytes(b"disposable-fixture")
        protect_fixture(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def read(self, private=False, maximum=4096):
        return read_bounded_regular_file(str(self.path), maximum, private=private)

    def test_owner_file_and_exact_byte_limit(self):
        self.assertEqual(self.read(), b"disposable-fixture")
        self.assertEqual(self.read(private=True), b"disposable-fixture")
        self.assertEqual(self.read(maximum=18), b"disposable-fixture")
        with self.assertRaises(RuntimeError):
            self.read(maximum=17)

    def test_public_read_does_not_grant_private_access(self):
        protect_fixture(self.path, "Read")
        self.assertEqual(self.read(), b"disposable-fixture")
        with self.assertRaises(RuntimeError):
            self.read(private=True)

    def test_public_write_is_refused(self):
        protect_fixture(self.path, "Modify")
        with self.assertRaises(RuntimeError):
            self.read()

    def test_hard_link_and_directory_are_refused(self):
        link = Path(self.temp.name) / "linked.txt"
        os.link(self.path, link)
        try:
            with self.assertRaises(RuntimeError):
                self.read()
        finally:
            link.unlink()
        with self.assertRaises(RuntimeError):
            read_bounded_regular_file(self.temp.name, 4096)

    def test_rotation_reads_current_file_and_missing_replacement_fails(self):
        self.assertEqual(read_bounded_secret_file(str(self.path), 4096), b"disposable-fixture")
        replacement = Path(self.temp.name) / "replacement.txt"
        replacement.write_bytes(b"replacement-fixture")
        protect_fixture(replacement)
        os.replace(replacement, self.path)
        self.assertEqual(read_bounded_secret_file(str(self.path), 4096), b"replacement-fixture")
        self.path.unlink()
        with self.assertRaises(RuntimeError):
            self.read(private=True)

    def test_path_aliases_are_refused(self):
        for suffix in (".", " ", ":alternate"):
            with self.assertRaises(RuntimeError):
                read_bounded_regular_file(str(self.path) + suffix, 4096)


if __name__ == "__main__":
    unittest.main()
