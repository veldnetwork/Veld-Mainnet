"""Focused payment fault injection; these fixtures are not native E2E evidence."""

import hashlib
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool.journal import Journal
from pool.payments import Payments
from pool.protocol import Refused, Busy


class FixtureNode:
    genesis = 'a' * 64

    def __init__(self):
        self.broadcasts = []
        self.confirmed = False
        self.lose_response = False
        self.coins = {
            'pool': [{'txid': 'b' * 64, 'vout': 0, 'value_units': 300000000, 'confirmations': 120}],
            'fees': [{'txid': 'c' * 64, 'vout': 0, 'value_units': 1000000, 'confirmations': 120}],
        }

    def call(self, method, *args):
        if method == 'getblockcount':
            return 150 if self.confirmed else 149
        if method == 'listunspent':
            return self.coins[args[0]]
        if method in ('gettransaction', 'getrawtransaction'):
            if method == 'gettransaction' and len(args) != 2:
                raise Refused('block reference required')
            if not self.confirmed:
                raise Refused('not found')
            return {'confirmations': 1, 'block_height': 150, 'block_hash': 'd' * 64, 'vout': []}
        if method == 'getblockhash':
            return 'd' * 64
        if method == 'sendrawtransaction':
            self.broadcasts.append(args[0])
            if self.lose_response:
                raise OSError('response lost after admission')
            raw = bytes.fromhex(args[0])
            return hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
        raise AssertionError(method)


class PaymentTests(unittest.TestCase):
    def test_wide_payout_rechecks_activation_before_private_signer(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            for value in pool.accounts.values():
                value['address'] = 'x' * 73
            identity = payment.plan(now=100000)
            original = node.call
            response = [None]
            node.call = (
                lambda method, *args: response[0]
                if method == 'validateaddress'
                else original(method, *args)
            )
            with patch(
                'pool.payments.subprocess.run', side_effect=AssertionError('signer must not run')
            ):
                for value in [
                    None,
                    [],
                    {
                        'isvalid': True,
                        'destination_type': 'sha384-v1',
                        'active_for_next_block': False,
                    },
                ]:
                    response[0] = value
                    with self.assertRaisesRegex(Refused, 'not active'):
                        payment.sign(identity)
                    self.assertNotIn('signed_hex', payment.intents[identity])
            self.assertEqual(node.broadcasts, [])
            journal.close()

    def test_missing_payment_history_cannot_spend_other_miners_backing(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            # An old accounting snapshot still owes 3 VELD, but a spent receipt
            # leaves just 2 VELD. A partial retry must not pay the lost obligation.
            node.coins['pool'][0]['value_units'] = 200000000
            with self.assertRaisesRegex(Refused, 'backing deficit'):
                payment.plan(now=100000)
            self.assertEqual(payment.intents, {})
            self.assertEqual(node.broadcasts, [])
            journal.close()

    def test_incomplete_lookup_rebroadcasts_only_the_existing_signed_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            identity = payment.plan(now=100000)
            raw = b'focused lookup-failure fixture'
            txid = hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
            payment.record(
                'payment_signed',
                {'id': identity, 'txid': txid, 'signed_hex': raw.hex(), 'state': 'signed'},
            )
            original = node.call

            def call(method, *args):
                if method == 'getrawtransaction':
                    raise Busy('indexed lookup incomplete')
                return original(method, *args)

            node.call = call
            self.assertEqual(payment.reconcile(identity), 'broadcast')
            self.assertEqual(node.broadcasts, [raw.hex()])
            self.assertEqual(len(payment.intents), 1)
            journal.close()

    def test_fragmented_daily_batch_uses_bounded_transactions_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, pool, journal, payment = self.fixture(root)
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
                    'txid': c['txid'],
                    'outputs': [{'vout': 0}],
                    'credits': {'a': '50000000/1', 'b': '50000000/1'},
                }
                for i, c in enumerate(node.coins['pool'])
            }
            first = payment.plan(now=100000)
            self.assertIsNotNone(first)
            journal.close()
            journal = Journal(root / 'payments', root / 'anchor/current.json')
            payment = Payments(pool, journal, 'not-used', '', '', '11', '22', 'fees', 100000, 1000)
            for _ in range(10):
                if payment.plan(now=100000) is None:
                    break
            self.assertEqual(len(payment.intents), 4)
            self.assertEqual(len(payment.batches), 1)
            self.assertEqual(payment.deductions(), {'a': 10000000000, 'b': 10000000000})
            used = [
                (c['txid'], c['vout'])
                for i in payment.intents.values()
                for c in i['wire']['inputs']
            ]
            self.assertEqual(len(used), len(set(used)))
            self.assertTrue(all(len(i['wire']['inputs']) <= 64 for i in payment.intents.values()))
            self.assertIsNone(payment.plan(now=100001))
            journal.close()

    def test_same_second_payment_chunks_have_unique_history_cursors(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            for i in range(25):
                payment.record(
                    'payment_intent',
                    {
                        'id': str(i),
                        'created': 100000,
                        'deductions': {'a': str(100000000 + i)},
                        'state': 'reserved',
                        'wire': {'inputs': []},
                    },
                )
            first = payment.history('a')
            second = payment.history('a', first['next_before'])
            self.assertEqual(len(first['payments']), 20)
            self.assertEqual(len(second['payments']), 5)
            self.assertEqual(
                len({p['amount_units'] for p in first['payments'] + second['payments']}), 25
            )
            journal.close()

    def test_private_payment_history_is_bounded_and_contains_no_other_destinations_or_signatures(
        self,
    ):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            for n in range(25):
                payment.record(
                    'payment_intent',
                    {
                        'id': str(n),
                        'created': 100000 + n * 86400,
                        'deductions': {'a': '100000000', 'b': '200000000'},
                        'state': 'signed',
                        'signed_hex': 'secret-test-bytes',
                        'wire': {'inputs': ['operator-funding-test']},
                    },
                )
            first = payment.history('a')
            self.assertEqual(len(first['payments']), 20)
            second = payment.history('a', first['next_before'])
            self.assertEqual(len(second['payments']), 5)
            self.assertEqual(second['next_before'], 0)
            self.assertEqual(
                len({p['created'] for p in first['payments'] + second['payments']}), 25
            )
            self.assertNotIn('signed_hex', str(first))
            self.assertNotIn('200000000', str(first))
            self.assertEqual(payment.history('unknown'), {'payments': [], 'next_before': 0})
            journal.close()

    def fixture(self, root):
        node = FixtureNode()
        pool = SimpleNamespace(
            node=node,
            lock=threading.RLock(),
            pool_address='pool',
            accounts={'a': {'address': 'worker-a'}, 'b': {'address': 'worker-b'}},
            incomes={
                'earned': {
                    'state': 'available',
                    'txid': 'b' * 64,
                    'outputs': [{'vout': 0}],
                    'credits': {'a': '150000000/1', 'b': '150000000/1'},
                }
            },
        )
        journal = Journal(root / 'payments', root / 'anchor/current.json')
        payment = Payments(
            pool,
            journal,
            'native-not-used',
            'pool-key-not-used',
            'fees-key-not-used',
            '11',
            '22',
            'fees',
            100000,
            1000,
        )
        return node, pool, journal, payment

    def test_lost_response_restart_reuses_exact_signed_bytes_and_keeps_entitlements_reserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, pool, journal, payment = self.fixture(root)
            identity = payment.plan(now=100000)
            raw = b'focused fault fixture, not a Veld transaction'
            txid = hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
            response = SimpleNamespace(
                returncode=0, stdout=(txid + ' ' + raw.hex() + '\n').encode()
            )
            with patch('pool.payments.subprocess.run', return_value=response) as native:
                self.assertEqual(payment.sign(identity), txid)
                node.lose_response = True
                self.assertEqual(payment.reconcile(identity), 'unconfirmed')
                self.assertEqual(native.call_count, 1)
            journal.close()
            journal = Journal(root / 'payments', root / 'anchor/current.json')
            recovered = Payments(
                pool, journal, 'must-not-run', '', '', '11', '22', 'fees', 100000, 1000
            )
            self.assertEqual(recovered.sign(identity), txid)
            self.assertEqual(recovered.reconcile(identity), 'unconfirmed')
            self.assertEqual(node.broadcasts, [raw.hex(), raw.hex()])
            self.assertIsNone(recovered.plan(now=200000))
            node.confirmed = True
            self.assertEqual(recovered.reconcile(identity), 'confirmed')
            self.assertEqual(
                recovered.summary('a'), {'paid_units': '150000000', 'reserved_units': '0'}
            )
            node.confirmed = False
            self.assertEqual(recovered.reconcile(identity), 'unconfirmed')
            self.assertEqual(
                recovered.summary('a'), {'paid_units': '0', 'reserved_units': '150000000'}
            )
            self.assertEqual(len(recovered.intents), 1)
            journal.close()

    def test_fractional_earnings_leave_relayable_change_and_preserve_owed_units(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            pool.incomes['earned']['credits'] = {'a': '300000001/2', 'b': '299999999/2'}
            identity = payment.plan(now=100000)
            intent = payment.intents[identity]
            paid = sum(int(v) for v in intent['deductions'].values())
            self.assertEqual(300000000 - paid, 1000)
            self.assertEqual(sum(payment.available().values()), 999)
            self.assertEqual(sum(int(r['units']) for r in intent['wire']['recipients']), paid)
            journal.close()

    def test_operator_fee_shortfall_cannot_use_miner_balance(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            node.coins['fees'] = []
            with self.assertRaisesRegex(Refused, 'segregated'):
                payment.plan(now=100000)
            self.assertEqual(payment.intents, {})
            journal.close()

    def test_reorganized_income_freezes_new_payments_without_cancelling_signed_liabilities(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            identity = payment.plan(now=100000)
            pool.incomes['earned']['state'] = 'orphaned'
            with self.assertRaisesRegex(Refused, 'deficit'):
                payment.plan(now=200000)
            with self.assertRaisesRegex(Refused, 'deficit'):
                payment.sign(identity)
            self.assertEqual(len(payment.intents), 1)
            journal.close()

    def test_subthreshold_entitlements_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            node, pool, journal, payment = self.fixture(Path(directory))
            pool.incomes['earned']['credits'] = {'a': '999999999/10'}
            self.assertIsNone(payment.plan(now=100000))
            self.assertEqual(payment.available(), {'a': 99999999})
            self.assertEqual(pool.incomes['earned']['credits']['a'], '999999999/10')
            journal.close()


if __name__ == '__main__':
    unittest.main()
