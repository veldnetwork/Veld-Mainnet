from pathlib import Path
import importlib.util
import json
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('service', root / 'scripts/veld-public-stats.py')
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


class Backend:
    def __init__(self):
        self.blocks = {row['height']: dict(row, bits=0x1f00ffff, reward_veld=3.1403, winner='miner')
                       for row in map(json.loads, (root / 'tests/fixtures/explorer-block-page-summaries.jsonl').read_text().splitlines())}
        self.height = max(self.blocks)
        self.calls = []
        self.stats_calls = 0
        self.reorg = False
        self.error = None

    def read(self, path):
        self.calls.append(path)
        if path == '/api/stats':
            self.stats_calls += 1
            tip = self.blocks[self.height]['hash']
            if self.reorg and self.stats_calls > 1:
                tip = 'f' * 64
            return dict(height=self.height, best_block_hash=tip, block_time_target=180)
        if path.startswith('/api/v1/blocks/'):
            if self.error:
                raise self.error
            start, count = map(int, path.split('/')[-2:])
            blocks = [self.blocks[h] for h in range(start, start - count, -1)]
            if any(block['size'] > 1048576 for block in blocks):
                raise service.PublicBackendError(503, service.BLOCK_PAGE_BUDGET_ERROR)
            return dict(blocks=blocks)
        height = int(path.split('/')[-1])
        return dict(self.blocks[height], tx=['transaction-details-not-in-page'])


class BlockPages(unittest.TestCase):
    def test_many_readers_share_backend_work_without_stale_tip(self):
        backend = Backend()
        reader = service.SharedPublicReader(backend.read)
        cache = service.BlockPageCache(reader)
        first = cache.get('latest', 25)
        calls = len(backend.calls)
        for _ in range(100):
            self.assertEqual(cache.get('latest', 25), first)
        self.assertEqual(len(backend.calls), calls)
        backend.blocks[backend.height]['hash'] = 'f' * 64
        reader.expires = 0
        next_page = json.loads(cache.get('latest', 25))
        self.assertEqual(next_page['tip_hash'], 'f' * 64)
        self.assertEqual(next_page['blocks'][0]['hash'], 'f' * 64)

    def test_overlapping_pages_reuse_canonical_summaries(self):
        backend = Backend()
        reader = service.SharedPublicReader(backend.read)
        cache = service.BlockPageCache(reader)
        cache.get('latest', 25)
        calls = len(backend.calls)
        page = json.loads(cache.get('4607', 10))
        self.assertEqual(len(page['blocks']), 10)
        self.assertEqual(backend.calls[calls:], ['/api/stats'])

    def test_actual_large_block_history_preserves_every_summary(self):
        backend = Backend()
        cache = service.BlockPageCache(backend.read)
        result = json.loads(cache.get('4613', 25))
        self.assertEqual(result['end'], 4589)
        self.assertEqual(len(result['blocks']), 25)
        large = next(b for b in result['blocks'] if b['height'] == 4602)
        self.assertEqual(large['size'], 1105278)
        for block in result['blocks']:
            self.assertEqual(block, backend.blocks[block['height']])
        self.assertEqual(backend.calls.count('/api/v1/block/4602'), 1)

    def test_cache_coalesces_complete_page_reads(self):
        backend = Backend()
        cache = service.BlockPageCache(backend.read)
        first = cache.get('latest', 25)
        count = len(backend.calls)
        self.assertEqual(cache.get('latest', 25), first)
        self.assertEqual(backend.calls[count:], ['/api/stats'])

    def test_small_page_retains_one_bulk_read(self):
        backend = Backend()
        result = service.bounded_block_page(backend.read, 4613, 10)
        self.assertEqual(len(result), 10)
        self.assertEqual(backend.calls, ['/api/v1/blocks/4613/10'])

    def test_large_tip_stats_remain_available(self):
        backend = Backend()
        backend.height = 4602
        stats = service.StatsCollector(backend.read).collect()
        self.assertGreater(stats['hashrate'], 0)
        self.assertIn('/api/v1/block/4602', backend.calls)

    def test_reorganization_discards_assembled_page(self):
        backend = Backend()
        backend.reorg = True
        cache = service.BlockPageCache(backend.read)
        with self.assertRaises(service.PublicBackendError) as caught:
            cache.get('latest', 25)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(len(cache.pages), 0)

    def test_non_budget_error_is_not_retried_as_single_blocks(self):
        backend = Backend()
        backend.error = service.PublicBackendError(429, 'busy')
        with self.assertRaises(service.PublicBackendError):
            service.bounded_block_page(backend.read, 4613, 25)
        self.assertEqual(len(backend.calls), 1)

    def test_unknown_unavailability_is_not_hidden(self):
        backend = Backend()
        backend.error = service.PublicBackendError(503, 'disk unavailable')
        with self.assertRaises(service.PublicBackendError):
            service.bounded_block_page(backend.read, 4613, 25)
        self.assertEqual(len(backend.calls), 1)

    def test_broken_link_rejected(self):
        backend = Backend()
        backend.blocks[4610]['prev_hash'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'noncontiguous'):
            service.bounded_block_page(backend.read, 4613, 25)

    def test_page_bounds_and_future_height(self):
        backend = Backend()
        for start, count in [(-1, 10), (4613, 0), (4613, 51), (1, 25)]:
            with self.assertRaises(ValueError):
                service.bounded_block_page(backend.read, start, count)
        with self.assertRaises(service.PublicBackendError) as caught:
            service.BlockPageCache(backend.read).get('4614', 25)
        self.assertEqual(caught.exception.status, 409)

    def test_deadline_prevents_unbounded_reads(self):
        backend = Backend()
        times = iter([0, 0, 8])
        with self.assertRaisesRegex(ValueError, 'budget exceeded'):
            service.bounded_block_page(backend.read, 4613, 25, lambda: next(times))


if __name__ == '__main__':
    unittest.main(verbosity=2)
