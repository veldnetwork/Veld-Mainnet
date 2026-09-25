"""Secondary indexing must not starve existing payments; canonical checks must."""

import threading
from types import SimpleNamespace
import unittest
import os
from unittest.mock import patch

if os.name != 'posix':
    raise unittest.SkipTest(
        'Linux coordinator service; required and executed in Linux qualification'
    )
from pool.service import maintain_once, main
from pool.protocol import Busy


class MaintenanceTests(unittest.TestCase):
    def exercise(self, failed):
        calls = []

        def action(name, result=None):
            def run(*_):
                calls.append(name)
                if name in failed:
                    raise Busy('injected temporary failure')
                return result

            return run

        pool = SimpleNamespace(
            lock=threading.RLock(),
            retry_deferred=action('work'),
            reconcile_solutions=action('solutions'),
            rewards=SimpleNamespace(reconcile=action('rewards')),
            reconcile_income=action('income'),
            identity=SimpleNamespace(maintain=action('identity')),
            payments=SimpleNamespace(
                intents={'old': {}},
                sign=action('sign'),
                reconcile=action('reconcile'),
                plan=action('plan', 'new'),
            ),
        )
        maintain_once(
            pool,
            SimpleNamespace(check_chain=action('chain'), require_transaction_index=action('index')),
            threading.Event(),
        )
        return calls, pool

    def test_rebuilding_reward_index_does_not_stop_safe_existing_payouts(self):
        calls, pool = self.exercise({'rewards'})
        self.assertEqual(calls.count('sign'), 2)
        self.assertIn('plan', calls)
        self.assertEqual(pool.deferred_phases, ['reward reconciliation'])

    def test_canonical_income_failure_stops_all_payment_signing(self):
        calls, _ = self.exercise({'income'})
        self.assertNotIn('sign', calls)
        self.assertNotIn('plan', calls)

    def test_wrong_or_unavailable_chain_prevents_all_subsequent_work(self):
        calls, _ = self.exercise({'chain'})
        self.assertEqual(calls, ['chain'])

    def test_index_loss_pauses_identity_and_payments_without_stopping_work(self):
        calls, pool = self.exercise({'index'})
        for name in ('work', 'solutions', 'rewards', 'income'):
            self.assertIn(name, calls)
        for name in ('identity', 'sign', 'plan', 'reconcile'):
            self.assertNotIn(name, calls)
        self.assertEqual(pool.deferred_phases, ['transaction index readiness'])
        calls, pool = self.exercise(set())
        for name in ('identity', 'sign', 'plan', 'reconcile'):
            self.assertIn(name, calls)
        self.assertEqual(pool.deferred_phases, [])

    def test_unavailable_index_refuses_startup_before_opening_economic_state(self):
        config = {
            name: 'fixture'
            for name in (
                'rpc_url',
                'rpc_token_file',
                'genesis',
                'state_directory',
                'rollback_anchor',
                'native_binary',
                'pool_address',
                'accounting_target',
                'socket',
            )
        }
        for enabled in ('identity', 'payments'):
            with (
                self.subTest(enabled=enabled),
                patch('sys.argv', ['service', '--config', 'unused']),
                patch('pool.service.read_private', return_value=b'{}'),
                patch('pool.service.decode', return_value=dict(config, **{enabled: {}})),
                patch('pool.service.Node') as node,
                patch('pool.service.Journal') as journal,
                patch('pool.service.prepare_socket') as socket,
            ):
                node.return_value.require_transaction_index.side_effect = Busy('index unavailable')
                with self.assertRaises(Busy):
                    main()
                node.return_value.check_chain.assert_called_once()
                node.return_value.require_transaction_index.assert_called_once()
                journal.assert_not_called()
                socket.assert_not_called()


if __name__ == '__main__':
    unittest.main()
