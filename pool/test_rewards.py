"""Focused chain/accounting fixtures; not native lottery qualification."""

import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from pool.coordinator import Coordinator
from pool.journal import Journal
from pool.rewards import Rewards
from pool.protocol import Refused


class RewardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.journal = Journal(root / 'events', root / 'anchor/current.json')
        self.hashes = {98: 'a' * 64, 100: 'b' * 64, 478: 'c' * 64, 480: 'd' * 64, 220: 'e' * 64}
        self.tip = 100
        self.rows = []
        self.outputs = []
        self.spendable = []
        self.calls = []
        self.node = SimpleNamespace(check_chain=lambda: None, call=self.call)
        self.pool = Coordinator(self.node, self.journal, None, 'pool', 'f' * 64)
        self.rewards = Rewards(self.pool, 100, 480)
        self.pool.rewards = self.rewards

    def tearDown(self):
        self.journal.close()
        self.tmp.cleanup()

    def call(self, method, *args):
        self.calls.append((method, args))
        if method == 'getblockcount':
            return self.tip
        if method == 'getblockhash':
            return self.hashes.get(int(args[0]), 'f' * 64)
        if method == 'getaddresshistory':
            return {'entries': self.rows, 'has_more': False, 'next_cursor': ''}
        if method == 'gettransaction':
            return {'block_hash': args[1], 'coinbase': False, 'vout': self.outputs}
        if method == 'listunspent':
            return self.spendable
        raise AssertionError(method)

    def receipt(self, name, height, status='verified'):
        seq = self.pool.record(
            'receipt', {'identity': name, 'account': name, 'height': height, 'target': 'f' * 64}
        )
        self.pool.record('verification', {'identity': name, 'status': status})
        return seq

    def reward(self, kind, height, amount=900):
        self.rows = [{'type': kind, 'block_height': height, 'txid': '1' * 64}]
        self.outputs = [
            {'n': 0, 'address': 'pool', 'value_units': str(amount)},
            {'n': 1, 'address': 'system', 'value_units': '999999'},
        ]
        self.spendable = [{'txid': '1' * 64, 'vout': 0, 'value_units': amount}]

    def test_seal_precedes_final_seed_and_freezes_beneficiaries(self):
        self.receipt('old', 1)
        self.receipt('a', 97)
        self.receipt('b', 98)
        self.rewards.seal(99, 'a' * 64)
        self.receipt('late', 98)
        self.receipt('final_seed', 99)
        self.receipt('draw', 100)
        self.reward('comine_payout', 100)
        self.rewards.reconcile()
        income = next(iter(self.pool.incomes.values()))
        self.assertEqual(
            {a: Fraction(v) for a, v in income['credits'].items()}, {'old': 300, 'a': 300, 'b': 300}
        )
        self.assertEqual(income['amount'], '900')
        self.rewards.reconcile()
        self.assertEqual(len(self.pool.incomes), 1)

    def test_ordinary_yield_is_shared_under_owner_override(self):
        self.receipt('a', 1)
        self.receipt('b', 478)
        self.rewards.seal(479, 'c' * 64)
        self.reward('staking_distribution', 480)
        self.rewards.reconcile()
        income = next(iter(self.pool.incomes.values()))
        self.assertEqual(income['operator_fee'], '0/1')
        self.assertEqual(set(income['credits']), {'a', 'b'})
        self.assertEqual(sum(Fraction(v) for v in income['credits'].values()), 900)

    def test_unresolved_early_work_delays_reward_without_changing_cutoff(self):
        self.receipt('a', 98, 'deferred')
        self.rewards.seal(99, 'a' * 64)
        self.receipt('late', 98)
        self.reward('comine_payout', 100)
        self.rewards.reconcile()
        self.assertEqual(self.pool.incomes, {})
        self.pool.record('verification', {'identity': 'a', 'status': 'verified'})
        self.rewards.reconcile()
        self.assertEqual(next(iter(self.pool.incomes.values()))['credits'], {'a': '900/1'})

    def test_missing_seal_or_wrong_branch_quarantines_and_never_credits(self):
        self.receipt('a', 98)
        self.reward('comine_payout', 100)
        self.rewards.reconcile()
        self.assertEqual(self.pool.incomes, {})
        self.rewards.seal(99, '9' * 64)
        self.rewards.reconcile()
        self.assertEqual(self.pool.incomes, {})
        self.assertEqual(len(self.rewards.quarantined), 1)

    def test_no_win_and_arbitrary_transfer_do_not_create_income(self):
        self.receipt('a', 98)
        self.rewards.seal(99, 'a' * 64)
        self.rewards.reconcile()
        self.assertEqual(self.pool.incomes, {})
        self.reward('received', 100)
        self.rewards.reconcile()
        self.assertEqual(self.pool.incomes, {})

    def test_restart_uses_same_seal_and_no_duplicate_allocation(self):
        self.receipt('a', 98)
        self.rewards.seal(99, 'a' * 64)
        self.reward('comine_payout', 100)
        self.rewards.reconcile()
        restored = Coordinator(self.node, self.journal, None, 'pool', 'f' * 64)
        recovered = Rewards(restored, 100, 480)
        recovered.reconcile()
        self.assertEqual(self.pool.incomes, restored.incomes)
        self.assertEqual(self.rewards.seals, recovered.seals)

    def test_maturity_actual_spendability_reorg_and_reconnection(self):
        self.receipt('a', 98)
        self.rewards.seal(99, 'a' * 64)
        self.reward('comine_payout', 100)
        self.rewards.reconcile()
        income = next(iter(self.pool.incomes.values()))
        self.tip = 218
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'pending')
        self.tip = 219
        self.spendable = []
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'pending')
        self.spendable = [{'txid': '1' * 64, 'vout': 0, 'value_units': 900}]
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'available')
        self.hashes[100] = '9' * 64
        self.hashes[219] = '8' * 64
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'orphaned')
        self.tip = 220
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'orphaned')
        self.hashes[100] = 'b' * 64
        self.hashes[220] = '7' * 64
        self.spendable = []
        self.pool.reconcile_income()
        self.assertEqual(self.pool.incomes[income['id']]['state'], 'available')


if __name__ == '__main__':
    unittest.main()
