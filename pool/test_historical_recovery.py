"""Focused synthetic long-downtime fixtures; genuine native aging is separate."""

import hashlib, pathlib, sys, tempfile, unittest
from unittest.mock import patch
import pool.test_payments as payment_fixtures
import pool.test_identity as identity_fixtures
from pool.payments import Payments
from pool.journal import Journal
from pool.protocol import Refused


class HistoricalRecoveryTests(unittest.TestCase):
    def test_signed_only_payment_restored_beyond_recent_window_uses_full_index(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            node, pool, journal, payment = payment_fixtures.PaymentTests().fixture(root)
            identity = payment.plan(now=100000)
            raw = b'synthetic aged payment fixture'
            txid = hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
            payment.record(
                'payment_signed',
                {'id': identity, 'txid': txid, 'signed_hex': raw.hex(), 'state': 'signed'},
            )
            journal.close()
            journal = Journal(root / 'payments', root / 'anchor/current.json')
            recovered = Payments(
                pool, journal, 'must-not-run', '', '', '11', '22', 'fees', 100000, 1000
            )
            calls = []

            def call(method, *args):
                calls.append(method)
                if method == 'getblockcount':
                    return 2200
                if method == 'getblockhash':
                    return 'd' * 64
                if method == 'gettransactionrecent':
                    raise Refused('outside recent canonical range')
                if method == 'getrawtransaction':
                    return dict(
                        txid=txid,
                        raw_hex=raw.hex(),
                        block_height=100,
                        block_hash='d' * 64,
                        confirmations=2101,
                        vout=[],
                    )
                if method == 'sendrawtransaction':
                    raise Refused('already mined')
                raise AssertionError(method)

            node.call = call
            try:
                with patch(
                    'pool.payments.subprocess.run',
                    side_effect=AssertionError('must never sign again'),
                ):
                    self.assertEqual(recovered.reconcile(identity), 'confirmed')
                    self.assertEqual(recovered.reconcile(identity), 'confirmed')
                self.assertEqual(calls.count('getrawtransaction'), 1)
                self.assertNotIn('sendrawtransaction', calls)
                self.assertEqual(len(recovered.intents), 1)
                self.assertEqual(recovered.intents[identity]['signed_hex'], raw.hex())
                self.assertEqual(
                    recovered.summary('a'), {'paid_units': '150000000', 'reserved_units': '0'}
                )
            finally:
                journal.close()

    def test_signed_only_operator_operations_use_full_index_before_retry_or_expiry(self):
        fixture = identity_fixtures.IdentityTests()
        fixture.setUp()
        try:
            fixture.state.update(height=6000, parent='b' * 64)
            for number, action in enumerate(('stake', 'consolidate', 'nms')):
                txid = f'{number + 1:064x}'
                identity = str(number)
                fixture.identity.record(
                    'identity_intent',
                    {
                        'id': identity,
                        'state': 'signed',
                        'txid': txid,
                        'signed_hex': 'ff',
                        'parent': '0' * 64,
                        'wire': {'action': action, 'height': '3201', 'inputs': fixture.funding},
                    },
                )
            calls = []

            def call(method, *args):
                calls.append(method)
                if method == 'gettransactionrecent':
                    raise Refused('outside recent canonical range')
                if method == 'getrawtransaction':
                    return dict(
                        txid=args[0], block_height=3201, block_hash='b' * 64, confirmations=2800
                    )
                if method == 'getblockhash':
                    return 'b' * 64
                if method == 'sendrawtransaction':
                    raise Refused('already mined')
                raise AssertionError(method)

            fixture.node.call = call
            fixture.identity.reconcile(fixture.state)
            self.assertTrue(
                all(i['state'] == 'confirmed' for i in fixture.identity.intents.values())
            )
            self.assertEqual(calls.count('getrawtransaction'), 3)
            self.assertNotIn('sendrawtransaction', calls)
            self.assertTrue(all(i['signed_hex'] == 'ff' for i in fixture.identity.intents.values()))
        finally:
            fixture.tearDown()


if __name__ == '__main__':
    unittest.main(defaultTest='HistoricalRecoveryTests', verbosity=2)
