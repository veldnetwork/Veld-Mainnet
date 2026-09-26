"""Account-admission regression fixtures; not native mining E2E evidence."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pool.coordinator import Coordinator
from pool.journal import Journal
from pool.protocol import Busy
from pool.records import Records


class AccountAdmissionTests(unittest.TestCase):
    def fixture(self, root):
        journal = Journal(root / 'events', root / 'anchor/current.json')
        calls = []

        def call(method, *args):
            calls.append((method, args))
            return {'isvalid': True}

        node = SimpleNamespace(check_chain=lambda: None, call=call, genesis='a' * 64)
        pool = Coordinator(node, journal, None, 'pool', 'f' * 64)
        return journal, pool, node, calls

    def test_historical_unworked_accounts_do_not_exhaust_future_registration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal, pool, node, calls = self.fixture(root)
            try:
                # Populate the projection through the same account-event replay
                # path used for old journals, without claiming this synthetic
                # history is native worker or chain coverage.
                for index in range(10000):
                    pool.apply(
                        'account',
                        {
                            'id': f'{index:032x}',
                            'address': 'x' * 30,
                            'worker_hash': 'a' * 64,
                            'view_hash': 'b' * 64,
                        },
                        index + 1,
                    )
                self.assertEqual(len(pool.accounts), 10000)
                self.assertIn(pool.register('y' * 30)['account'], pool.accounts)
                self.assertIsInstance(pool.accounts, Records)
                self.assertEqual(len(calls), 1)
            finally:
                journal.close()

    def test_global_budget_precedes_node_calls_and_persistence_and_refills(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch('pool.coordinator.time.monotonic', return_value=100) as clock,
        ):
            journal, pool, node, calls = self.fixture(Path(directory))
            try:
                for _ in range(16):
                    pool.register('x' * 30)
                sequence = journal.sequence
                for _ in range(100):
                    with self.assertRaises(Busy):
                        pool.register('x' * 30)
                self.assertEqual(journal.sequence, sequence)
                self.assertEqual(len(calls), 16)
                clock.return_value = 104.99
                with self.assertRaises(Busy):
                    pool.register('x' * 30)
                clock.return_value = 105
                self.assertIn(pool.register('x' * 30)['account'], pool.accounts)
                clock.return_value = 100
                with self.assertRaises(Busy):
                    pool.register('x' * 30)
                clock.return_value = 109.99
                with self.assertRaises(Busy):
                    pool.register('x' * 30)
                clock.return_value = 110
                pool.register('x' * 30)
                self.assertEqual(len(calls), 18)
            finally:
                journal.close()

    def test_concurrent_sources_share_one_budget(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            patch('pool.coordinator.time.monotonic', return_value=100),
        ):
            journal, pool, node, calls = self.fixture(Path(directory))
            try:

                def request(index):
                    try:
                        pool.register('x' * 29 + str(index % 10))
                        return True
                    except Busy:
                        return False

                with ThreadPoolExecutor(max_workers=32) as workers:
                    accepted = list(workers.map(request, range(64)))
                self.assertEqual(sum(accepted), 16)
                self.assertEqual(len(calls), 16)
                self.assertEqual(journal.sequence, 16)
            finally:
                journal.close()

    def test_old_credentials_and_liabilities_survive_projection_restore(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            journal, pool, node, calls = self.fixture(root)
            first = pool.register('x' * 30)
            # An old database is not authoritative; signed/current journal and
            # external rollback anchor remain intact throughout this test.
            journal.close()
            shutil.copyfile(root / 'events/index.sqlite', root / 'old.sqlite')
            journal = Journal(root / 'events', root / 'anchor/current.json')
            pool = Coordinator(node, journal, None, 'pool', 'f' * 64)
            second = pool.register('y' * 30)
            pool.record(
                'income',
                {
                    'id': 'receipt',
                    'category': 'mining',
                    'state': 'available',
                    'credits': {first['account']: '123456789/1', second['account']: '987654321/1'},
                },
            )
            journal.close()
            shutil.copyfile(root / 'old.sqlite', root / 'events/index.sqlite')
            journal = Journal(root / 'events', root / 'anchor/current.json')
            try:
                pool = Coordinator(node, journal, None, 'pool', 'f' * 64)
                for account, amount in ((first, '123456789'), (second, '987654321')):
                    self.assertEqual(
                        pool.authenticate(account['account'], account['worker_token'])['id'],
                        account['account'],
                    )
                    self.assertEqual(
                        pool.account(account['account'], account['view_token'])['available_units'],
                        amount,
                    )
                self.assertEqual(len(pool.accounts), 2)
            finally:
                journal.close()


if __name__ == '__main__':
    unittest.main()
