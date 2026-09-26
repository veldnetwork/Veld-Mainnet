"""Display-only exact arithmetic and coherent legacy fallback regression checks."""

import importlib.util, math, pathlib, unittest
from fractions import Fraction

root = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('stats', root / 'scripts/veld-public-stats.py')
stats = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stats)


class HashrateTests(unittest.TestCase):
    def test_exact_variable_difficulty_and_elapsed_time(self):
        blocks = [
            dict(time=900, bits=0x1E00FFFF),
            dict(time=360, bits=0x1F00FFFF),
            dict(time=0, bits=0x1F00FFFF),
        ]
        work = ((1 << 256) // ((0xFFFF << (8 * 27)) + 1)) + (
            (1 << 256) // ((0xFFFF << (8 * 28)) + 1)
        )
        rate, count, seconds = stats.observed_hashrate(blocks)
        self.assertEqual((count, seconds), (2, 900))
        self.assertAlmostEqual(rate, float(Fraction(work, 900)))
        blocks[0]['time'] = 1800
        self.assertAlmostEqual(stats.observed_hashrate(blocks)[0], rate / 2)

    def test_time_range_handles_nonmonotonic_headers(self):
        blocks = [dict(time=t, bits=0x1F00FFFF) for t in (400, 500, 100)]
        self.assertEqual(stats.observed_hashrate(blocks)[2], 400)
        for b in blocks:
            b['time'] = 100
        self.assertIsNone(stats.observed_hashrate(blocks)[0])

    def test_invalid_bits_and_aliases(self):
        for bits in (True, 0, -1, 0x1F80FFFF, 0x23000001, 0x207FFFFF + 1, 0x02000100):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                stats.observed_hashrate([dict(time=180, bits=bits), dict(time=0, bits=0x1F00FFFF)])

    def test_native_estimate_is_preserved_without_body_reads(self):
        value = dict(
            height=8570,
            best_block_hash='a' * 64,
            hashrate_method='canonical_work_over_observed_time',
            hashrate_sample_height=8570,
            hashrate=1234.5,
            hashrate_window_blocks=144,
            hashrate_window_seconds=25920,
        )
        paths = []

        def read(path):
            paths.append(path)
            return value

        self.assertEqual(stats.StatsCollector(read).collect(), value)
        self.assertEqual(paths, ['/api/stats'])
        for field, bad in [
            ('hashrate', math.inf),
            ('hashrate_window_blocks', 145),
            ('hashrate_sample_height', 8569),
        ]:
            broken = dict(value)
            broken[field] = bad
            with self.assertRaises(ValueError):
                stats.StatsCollector(lambda _: broken).collect()


if __name__ == '__main__':
    unittest.main(verbosity=2)
