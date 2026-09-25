import hashlib
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import native_custody_settlement as settlement


class SettlementProofTests(unittest.TestCase):
    def test_reserve_domain_is_distinct_from_rpc_hash_rendering(self):
        policy = {
            "domain_genesis_hash": "880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b",
            "expected_chain": {"profile_id": "veld-developer-v1", "genesis_hash": "ab" * 32},
        }
        before = settlement.reserve_network_binding(policy)
        policy["expected_chain"]["genesis_hash"] = 'cd' * 32
        self.assertEqual(before, settlement.reserve_network_binding(policy))
        policy["domain_genesis_hash"] = 'ab' * 32
        self.assertNotEqual(before, settlement.reserve_network_binding(policy))

    def test_odd_merkle_tree_binds_exact_transaction_and_header(self):
        leaves = [hashlib.sha256(bytes([i])).digest() for i in range(3)]
        parent = settlement.digest(leaves[0] + leaves[1])
        duplicated = settlement.digest(leaves[2] + leaves[2])
        root = settlement.digest(parent + duplicated)
        header = bytes(36) + root + bytes(12)
        txids = [value[::-1].hex() for value in leaves]
        directions, branch = settlement.merkle_branch(txids, txids[2], header)
        self.assertEqual(directions, 2)
        self.assertEqual(branch, [leaves[2], parent])
        with self.assertRaisesRegex(ValueError, "Merkle"):
            settlement.merkle_branch(txids, txids[2], bytes(80))

    def test_duplicate_unknown_malformed_and_unbounded_blocks_are_refused(self):
        value = 'ab' * 32
        header = bytes(36) + bytes.fromhex(value)[::-1] + bytes(12)
        for rows, wanted in (
            ([], value),
            ([value, value], value),
            ([value], '34' * 32),
            ([{}], value),
            ([None], value),
            ([value.upper()], value),
            ([value] * 100001, value),
        ):
            with self.subTest(rows_count=len(rows)), self.assertRaises(ValueError):
                settlement.merkle_branch(rows, wanted, header)

    def test_single_transaction_block_has_no_extra_branch(self):
        value = 'ab' * 32
        self.assertEqual(
            settlement.merkle_branch(
                [value], value, bytes(36) + bytes.fromhex(value)[::-1] + bytes(12)
            ),
            (0, []),
        )

    def test_numeric_and_wire_bounds_reject_coercion(self):
        for value in (True, -1, '1', 1.0, 1 << 64):
            with self.subTest(value=value), self.assertRaises(ValueError):
                settlement.integer(value)
        for value in (None, '', '0', 'AB', '0000', '0g'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                settlement.blob(value, 1)

    def test_malformed_request_has_no_rpc_or_key_side_effect(self):
        def forbidden(*args, **kwargs):
            self.fail('malformed request reached a backend')

        with patch.object(settlement.authority, 'configuration', return_value={}):
            for request in (
                None,
                [],
                {},
                {'action': 'native_settlement'},
                {
                    'action': 'native_settlement',
                    'authorization_hex': '00',
                    'raw_tx_hex': '00',
                    'fund_address': False,
                },
            ):
                with self.subTest(request=request), self.assertRaises(ValueError):
                    settlement.prepare(request, {}, forbidden, forbidden)


if __name__ == '__main__':
    unittest.main()
