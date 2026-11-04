import hashlib
import unittest

from issuer_signing_evidence import canonical_parent


class CanonicalParentTests(unittest.TestCase):
    def setUp(self):
        self.raw = "abcd"
        self.txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(self.raw)).digest()).hexdigest()
        self.row = {"txid": self.txid, "block_height": 100}
        self.block = "12" * 32
        self.answer = {
            "txid": self.txid,
            "block_height": 100,
            "block_hash": self.block,
            "raw_hex": self.raw,
        }
        self.calls = []

    def call(self, method, params):
        self.calls.append((method, params))
        if method == "getblockhash":
            return self.block
        if method == "gettransaction":
            return dict(self.answer)
        raise AssertionError("unbounded transaction search is forbidden")

    def test_exact_old_parent_is_fetched_without_recent_history_search(self):
        self.assertEqual(canonical_parent(self.call, self.row), self.raw)
        self.assertEqual(
            self.calls,
            [
                ("getblockhash", [100]),
                ("gettransaction", [self.txid, 100]),
                ("getblockhash", [100]),
            ],
        )

    def test_parent_location_and_raw_identity_are_independently_bound(self):
        for field, value in (
            ("txid", "ab" * 32),
            ("block_height", 101),
            ("block_height", True),
            ("block_hash", "34" * 32),
            ("raw_hex", "abcd00"),
        ):
            original = dict(self.answer)
            self.answer[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                canonical_parent(self.call, self.row)
            self.answer = original

    def test_reorganization_during_fetch_is_refused(self):
        def changed(method, params):
            result = self.call(method, params)
            if method == "gettransaction":
                self.block = "34" * 32
            return result

        with self.assertRaisesRegex(ValueError, "changed"):
            canonical_parent(changed, self.row)

    def test_invalid_location_never_issues_a_request(self):
        for height in (None, True, -1, "100", 1 << 63):
            with self.subTest(height=height), self.assertRaises(ValueError):
                canonical_parent(self.call, dict(self.row, block_height=height))
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
