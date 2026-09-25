"""Disposable journal fixtures; no miners, real signatures or network calls."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from pool.journal import Journal
from pool.payments import Payments
from pool import test_payments as payment_fixtures
from pool.protocol import Refused


class DestinationPaymentTests(unittest.TestCase):
    def fixture(self, root, credits):
        node, pool, journal, payment = payment_fixtures.PaymentTests().fixture(root)
        pool.accounts = {a: {'address': 'same-wallet'} for a in credits}
        pool.incomes['earned']['credits'] = {a: str(v) + '/1' for a, v in credits.items()}
        self.addCleanup(journal.close)
        return node, pool, journal, payment

    def test_pc_and_laptop_combined_balance_qualifies_one_wallet(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(
                Path(temp), {'pc': 81981122, 'laptop': 85117389}
            )
            identity = payment.plan(now=100000)
            self.assertIsNotNone(identity)
            intent = payment.intents[identity]
            self.assertEqual(
                intent['wire']['recipients'], [{'address': 'same-wallet', 'units': '167098511'}]
            )
            self.assertEqual(intent['deductions'], {'laptop': '85117389', 'pc': '81981122'})
            self.assertEqual(payment.summary('pc')['reserved_units'], '81981122')
            self.assertEqual(payment.history('pc')['payments'][0]['amount_units'], '81981122')
            self.assertNotIn('85117389', str(payment.history('pc')))

    def test_different_wallets_do_not_pool_their_threshold(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(Path(temp), {'a': 80000000, 'b': 90000000})
            pool.accounts['b']['address'] = 'different-wallet'
            self.assertIsNone(payment.plan(now=100000))
            self.assertEqual(payment.intents, {})

    def test_more_than_128_accounts_at_one_destination_still_make_one_output(self):
        with tempfile.TemporaryDirectory() as temp:
            credits = {f'worker{i:03}': 600000 for i in range(200)}
            node, pool, journal, payment = self.fixture(Path(temp), credits)
            identity = payment.plan(now=100000)
            self.assertIsNotNone(identity)
            self.assertEqual(
                payment.intents[identity]['wire']['recipients'],
                [{'address': 'same-wallet', 'units': '120000000'}],
            )
            self.assertEqual(payment.deductions(), credits)

    def test_partial_input_batch_keeps_individual_deductions_and_same_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            credits = {f'worker{i:03}': 100000000 for i in range(200)}
            node, pool, journal, payment = self.fixture(root, credits)
            node.coins['pool'] = [
                {'txid': f'{i:064x}', 'vout': 0, 'value_units': 100000000, 'confirmations': 120}
                for i in range(200)
            ]
            node.coins['fees'] = [
                {
                    'txid': f'{1000 + i:064x}',
                    'vout': 0,
                    'value_units': 1000000,
                    'confirmations': 120,
                }
                for i in range(10)
            ]
            pool.incomes = {
                str(i): {
                    'state': 'available',
                    'txid': coin['txid'],
                    'outputs': [{'vout': 0}],
                    'credits': {f'worker{i:03}': '100000000/1'},
                }
                for i, coin in enumerate(node.coins['pool'])
            }
            for _ in range(6):
                if payment.plan(now=100000) is None:
                    break
            self.assertEqual(len(payment.intents), 4)
            self.assertEqual(len(payment.batches), 1)
            self.assertEqual(payment.deductions(), credits)
            self.assertTrue(
                all(
                    len(i['wire']['inputs']) <= 64 and len(i['wire']['recipients']) == 1
                    for i in payment.intents.values()
                )
            )

    def test_restart_never_reissues_the_same_combined_entitlement(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            node, pool, journal, payment = self.fixture(root, {'a': 80000000, 'b': 90000000})
            identity = payment.plan(now=100000)
            self.assertIsNotNone(identity)
            raw = b'synthetic signed fixture'
            txid = hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
            payment.record(
                'payment_signed',
                {'id': identity, 'txid': txid, 'signed_hex': raw.hex(), 'state': 'signed'},
            )
            journal.close()
            reopened = Journal(root / 'payments', root / 'anchor/current.json')
            self.addCleanup(reopened.close)
            restored = Payments(
                pool, reopened, 'must-not-run', '', '', '11', '22', 'fees', 100000, 1000
            )
            self.assertIsNone(restored.plan(now=200000))
            self.assertEqual(restored.sign(identity), txid)
            self.assertEqual(restored.deductions(), {'a': 80000000, 'b': 90000000})
            self.assertEqual(len(restored.intents), 1)

    def test_relayable_change_adjusts_destination_and_preserves_each_remaining_balance(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(
                Path(temp), {'a': 99999999, 'b': 99999999, 'c': 99999999}
            )
            identity = payment.plan(now=100000)
            self.assertIsNotNone(identity)
            intent = payment.intents[identity]
            self.assertEqual(sum(int(v) for v in intent['deductions'].values()), 299999000)
            self.assertEqual(
                intent['wire']['recipients'], [{'address': 'same-wallet', 'units': '299999000'}]
            )
            self.assertEqual(sum(payment.available().values()), 997)

    def test_existing_daily_batch_and_interval_remain_frozen(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(Path(temp), {'a': 80000000, 'b': 90000000})
            payment.record(
                'payment_batch',
                {'id': 'old', 'created': 100000, 'quotas': {}, 'minimum_units': '100000000'},
            )
            self.assertIsNone(payment.plan(now=100001))
            self.assertIsNotNone(payment.plan(now=186400))

    def test_legacy_frozen_quotas_keep_the_old_account_minimum(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(Path(temp), {'a': 80000000, 'b': 90000000})
            payment.record(
                'payment_batch',
                {
                    'id': 'legacy',
                    'created': 100000,
                    'quotas': {'a': '80000000', 'b': '90000000'},
                    'minimum_units': '100000000',
                },
            )
            self.assertIsNone(payment.plan(now=100001))
            self.assertEqual(payment.intents, {})
            identity = payment.plan(now=186400)
            self.assertEqual(
                payment.intents[identity]['wire']['recipients'],
                [{'address': 'same-wallet', 'units': '170000000'}],
            )

    def test_frozen_destination_change_refuses_before_more_payment_authority(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(Path(temp), {'a': 80000000, 'b': 90000000})
            identity = payment.plan(now=100000)
            pool.accounts['a']['address'] = 'different-wallet'
            with self.assertRaisesRegex(Refused, 'frozen payout destination changed'):
                payment.plan(now=186400)
            self.assertEqual(list(payment.intents), [identity])

    def test_unknown_frozen_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            node, pool, journal, payment = self.fixture(Path(temp), {'a': 80000000, 'b': 90000000})
            payment.record(
                'payment_batch',
                {
                    'id': 'future',
                    'created': 100000,
                    'quotas': {},
                    'minimum_units': '100000000',
                    'threshold_scope': 'unknown',
                },
            )
            with self.assertRaisesRegex(Refused, 'unknown frozen payout threshold scope'):
                payment.plan(now=186400)
            self.assertEqual(payment.intents, {})


if __name__ == '__main__':
    unittest.main()
