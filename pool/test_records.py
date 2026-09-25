import tempfile
import tracemalloc
import unittest
from pathlib import Path
from types import SimpleNamespace
from pool.journal import Journal
from pool.records import Records
from pool.coordinator import Coordinator, template_identity
from pool.accounting import pplns


class RecordTests(unittest.TestCase):
    def test_income_state_index_updates_each_eligible_receipt_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            j = Journal(root / 'data', root / 'anchor/current.json')
            records = Records(j, 'incomes')
            for i in range(200):
                records[str(i)] = {'id': str(i), 'height': i, 'state': 'pending'}
            seen = []
            for income in records.select(status='pending', last=99):
                seen.append(income['id'])
                income['state'] = 'available'
                records[income['id']] = income
            self.assertEqual(len(seen), 100)
            self.assertEqual(len(set(seen)), 100)
            self.assertEqual(len(list(records.select(status='available'))), 100)
            self.assertEqual(len(list(records.select(status='pending'))), 100)
            j.close()

    def test_large_projection_is_streamed_without_python_history_cache(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            j = Journal(root / 'data', root / 'anchor/current.json')
            records = Records(j, 'test')
            tracemalloc.start()
            for i in range(4000):
                records[str(i)] = {
                    'seq': i,
                    'height': i // 10,
                    'status': 'verified',
                    'extra': 'x' * 4096,
                }
            self.assertEqual(len(records), 4000)
            self.assertEqual(sum(1 for _ in records.values()), 4000)
            self.assertLess(tracemalloc.get_traced_memory()[1], 4 * 1024 * 1024)
            tracemalloc.stop()
            j.close()

    def test_indexed_pplns_matches_exact_reference_across_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            j = Journal(root / 'data', root / 'anchor/current.json')
            records = Records(j, 'receipts')
            values = []
            for i in range(1000):
                r = {
                    'seq': i,
                    'height': i // 10,
                    'status': 'invalid' if i % 7 == 0 else 'verified',
                    'account': str(i % 3),
                    'target': f'{1 << (247 + i % 3):064x}',
                }
                records[str(i)] = r
                values.append(r)
            for cutoff in (10, 153, 500, 999):
                expected = pplns(values, cutoff, f'{1 << 248:064x}')
                actual = pplns(
                    records.select(status='verified', cutoff=cutoff, reverse=True, sequence=True),
                    cutoff,
                    f'{1 << 248:064x}',
                    ordered=True,
                )
                self.assertEqual(actual, expected)
            j.close()

    def test_projection_tampering_is_replaced_from_authoritative_journal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            j = Journal(root / 'data', root / 'anchor/current.json')
            node = SimpleNamespace(check_chain=lambda: None)
            pool = Coordinator(node, j, None, 'pool', 'f' * 64)
            pool.record('job', {'id': 'one', 'template': 'template', 'height': 7, 'node': {}})
            pool.record(
                'lease',
                {
                    'id': 'lease',
                    'account': 'a',
                    'job': 'one',
                    'template': 'template',
                    'start': '0',
                    'end': '100',
                },
            )
            pool.highwater['template'] = {'end': '0'}
            pool.leases.clear()
            restored = Coordinator(node, j, None, 'pool', 'f' * 64)
            self.assertEqual(restored.highwater['template']['end'], '100')
            self.assertEqual(restored.leases['lease']['end'], '100')
            j.close()

    def test_aliases_and_restart_keep_nonce_ranges_nonoverlapping(self):
        class Node:
            genesis = 'a' * 64

            def check_chain(self):
                pass

            def call(self, *_):
                return {'isvalid': True}

            def template(self, _):
                return {
                    'block_hex': '00' * 92,
                    'height': 1,
                    'target': 'f' * 64,
                    'work_ttl_ms': 10000,
                }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            j = Journal(root / 'data', root / 'anchor/current.json')
            pool = Coordinator(Node(), j, None, 'pool', 'f' * 64)
            a = pool.register('x' * 30)
            first = pool.work(a['account'], a['worker_token'], 32)
            pool.active = None
            second = pool.work(a['account'], a['worker_token'], 32)
            restored = Coordinator(Node(), j, None, 'pool', 'f' * 64)
            third = restored.work(a['account'], a['worker_token'], 32)
            starts = [int(w['start'], 16) for w in (first, second, third)]
            self.assertEqual(starts[0], 0)
            self.assertTrue(all(a + 32 <= b for a, b in zip(starts, starts[1:])))
            j.close()


if __name__ == '__main__':
    unittest.main()
