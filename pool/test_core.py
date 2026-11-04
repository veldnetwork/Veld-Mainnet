"""Focused accounting/persistence tests. These are NOT native E2E evidence."""

import gc
import json
import os
from pathlib import Path
import random
import shutil
import tempfile
import unittest
from fractions import Fraction
from unittest.mock import patch

from pool.accounting import allocate, expected_work, pplns, window_weights, floor_total
from pool.journal import Journal
from pool.protocol import decode, nonce, units, Refused


class CoreTests(unittest.TestCase):
    def test_anchor_inside_backup_tree_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for anchor in (root / 'current.json', root / 'nested/witness/current.json'):
                with self.assertRaisesRegex(Refused, 'outside service backup'):
                    Journal(root, anchor)

    def test_restore_rejects_oversized_line_with_bounded_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            anchor = root / 'anchor/current.json'
            Journal(data, anchor).close()
            (data / 'events.jsonl').write_bytes(b'x' * 2048)
            with patch('pool.journal.MAX_EVENT', 1024):
                with self.assertRaisesRegex(Refused, 'damaged journal'):
                    Journal(data, anchor)

    def test_restore_rejects_bad_or_unbounded_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            anchor = root / 'anchor/current.json'
            Journal(data, anchor).close()
            for value in (
                {'seq': True, 'digest': '0' * 64},
                {'seq': 0, 'digest': 'bad'},
                {'seq': 0, 'digest': '0' * 64, 'extra': 0},
            ):
                anchor.write_text(json.dumps(value), encoding='utf8')
                with self.assertRaises(Refused):
                    Journal(data, anchor)
            anchor.write_bytes(b'x' * 257)
            with self.assertRaisesRegex(Refused, 'message limit'):
                Journal(data, anchor)

    def test_integer_balances_match_exact_reference_at_ambiguous_boundaries(self):
        self.assertEqual(floor_total([Fraction(1, 3), Fraction(2, 3)]), 1)
        self.assertEqual(floor_total([Fraction(1) - Fraction(1, 1 << 1024)]), 0)
        self.assertEqual(floor_total([Fraction(1) + Fraction(1, 1 << 1024)]), 1)
        rng = random.Random(943)
        for _ in range(1000):
            values = [
                Fraction(rng.randrange(1 << 60), rng.randrange(1, 1 << 80))
                for _ in range(rng.randrange(1, 100))
            ]
            expected = sum(values, Fraction())
            self.assertEqual(floor_total(values), expected.numerator // expected.denominator)

    def test_many_distinct_reward_denominators_do_not_require_decimal_common_denominator(self):
        values = [Fraction((1 << 255) + i, (1 << 257) + 2 * i + 1) for i in range(1000)]
        expected = sum(values, Fraction())
        self.assertGreater(expected.denominator.bit_length(), 14000)
        self.assertEqual(floor_total(values), expected.numerator // expected.denominator)

    def test_strict_wire(self):
        for raw in (b'[]', b'null', b'{"x":1,"x":2}', b'{"n":NaN}'):
            with self.assertRaises(Refused):
                decode(raw)
        for value in ('-1', '01', '1.0', 1, True, '18446744073709551616'):
            with self.assertRaises(Refused):
                units(value)
        self.assertEqual(nonce('ffffffffffffffff'), (1 << 64) - 1)
        for value in ('1', 'FFFFFFFFFFFFFFFF', '000000000000000g'):
            with self.assertRaises(Refused):
                nonce(value)

    def test_fractional_allocations_conserve_every_base_unit(self):
        rng = random.Random(7653)
        for _ in range(1000):
            amount = rng.randrange(1 << 53, 1 << 60)
            integer_weights = {
                str(i): rng.randrange(1, 1 << 128) for i in range(rng.randrange(1, 15))
            }
            weights = {k: Fraction(v, 7) for k, v in integer_weights.items()}
            fee = rng.randrange(1000001)
            amounts, operator = allocate(amount, weights, fee)
            self.assertEqual(sum(amounts.values()) + operator, amount)
            total = sum(integer_weights.values())
            # Independent cross-multiplied integer equation; no rounded oracle.
            for account, value in amounts.items():
                self.assertEqual(
                    value.numerator * 1000000 * total,
                    value.denominator * amount * (1000000 - fee) * integer_weights[account],
                )

    def test_account_splitting_does_not_increase_entitlement(self):
        whole, _ = allocate(7, {'a': Fraction(5), 'b': Fraction(2)})
        split, _ = allocate(7, {'a1': Fraction(1), 'a2': Fraction(4), 'b': Fraction(2)})
        self.assertEqual(whole['a'], split['a1'] + split['a2'])

    def test_pplns_winner_once_cutoff_difficulty_boundary(self):
        target = f'{1 << 248:064x}'
        easier = f'{1 << 249:064x}'
        rows = [
            {'seq': i, 'status': 'verified', 'target': t, 'account': a, 'height': 100 + i}
            for i, t, a in [
                (1, target, 'old'),
                (2, easier, 'b'),
                (3, target, 'winner'),
                (4, target, 'late'),
            ]
        ]
        result = pplns(rows, 3, target)
        self.assertEqual(
            result, {'winner': Fraction(256), 'b': Fraction(128), 'old': Fraction(128)}
        )
        amounts, _ = allocate(1000, result)
        self.assertEqual(amounts['winner'], 500)
        self.assertNotIn('late', result)
        rows[1]['status'] = 'invalid'
        self.assertEqual(pplns(rows, 3, target), {'winner': Fraction(256), 'old': Fraction(256)})

    def test_co_mining_window_is_separate_from_payment_membership(self):
        target = f'{1 << 248:064x}'
        rows = [
            {'seq': i, 'height': h, 'status': 'verified', 'target': target, 'account': a}
            for i, h, a in [
                (1, 99, 'earlier'),
                (2, 100, 'a'),
                (3, 199, 'b'),
                (4, 199, 'late'),
                (5, 200, 'next'),
            ]
        ]
        self.assertEqual(
            window_weights(rows, 100, 199, 3), {'a': Fraction(256), 'b': Fraction(256)}
        )

    def test_income_without_beneficiaries_is_not_assigned(self):
        with self.assertRaises(Refused):
            allocate(1, {})
        self.assertEqual(allocate(0, {}), ({}, 0))

    def test_journal_rebuilds_stale_database_without_reissuing_lease(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anchor = root / 'witness/current.json'
            data = root / 'data'
            journal = Journal(data, anchor)
            journal.append('lease', {'template': 'x', 'end': '100'})
            journal.close()
            shutil.copyfile(data / 'index.sqlite', root / 'backup.sqlite')
            journal = Journal(data, anchor)
            journal.append('lease', {'template': 'x', 'end': '200'})
            journal.close()
            shutil.copyfile(root / 'backup.sqlite', data / 'index.sqlite')
            journal = Journal(data, anchor)
            self.assertEqual([e['payload']['end'] for e in journal.events()], ['100', '200'])
            journal.close()

    def test_journal_rollback_is_refused_against_surviving_anchor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            anchor = root / 'witness/current.json'
            data = root / 'data'
            journal = Journal(data, anchor)
            journal.append('lease', {'end': '100'})
            journal.close()
            old = (data / 'events.jsonl').read_bytes()
            journal = Journal(data, anchor)
            journal.append('lease', {'end': '200'})
            journal.close()
            (data / 'events.jsonl').write_bytes(old)
            with self.assertRaisesRegex(Refused, 'rollback'):
                Journal(data, anchor)
            gc.collect()

    def test_database_crash_after_durable_event_replays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            anchor = root / 'witness/current.json'
            journal = Journal(data, anchor)
            original = journal._index

            def crash(*args):
                raise OSError('injected index crash')

            journal._index = crash
            with self.assertRaises(OSError):
                journal.append('intent', {'id': 'same-payment'})
            recovered = Journal(data, anchor)
            self.assertEqual([e['payload'] for e in recovered.events()], [{'id': 'same-payment'}])
            recovered.close()

    def test_partial_event_refuses_instead_of_recycling_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / 'data'
            anchor = root / 'witness/current.json'
            journal = Journal(data, anchor)
            journal.close()
            with (data / 'events.jsonl').open('ab') as file:
                file.write(b'{"seq":1')
            with self.assertRaisesRegex(Refused, 'damaged'):
                Journal(data, anchor)
            gc.collect()


if __name__ == '__main__':
    unittest.main()
