"""Deterministic timeout regression; not a native chain-validation test."""
import unittest
from pool.qualification.progress import ValidationProgress


class ValidationProgressTests(unittest.TestCase):
    def test_old_twenty_minute_deadline_does_not_reject_healthy_slow_progress(self):
        wait = ValidationProgress(3671, 5538, 0)
        self.assertGreater(wait.budget_seconds, (5538 - 3671) * 60 / 32)
        for second in range(10, 1801, 10):
            wait.observe(3671 + second // 10, second)

    def test_stalled_chain_fails_even_inside_overall_budget(self):
        wait = ValidationProgress(1, 10000, 0)
        wait.observe(2, 299)
        wait.observe(2, 598)
        with self.assertRaisesRegex(TimeoutError, 'no new height progress'):
            wait.observe(2, 599)

    def test_regressions_do_not_extend_the_stall_deadline(self):
        wait = ValidationProgress(100, 10000, 0)
        wait.observe(99, 299)
        with self.assertRaisesRegex(TimeoutError, 'no new height progress'):
            wait.observe(100, 300)

    def test_continuous_progress_cannot_extend_absolute_deadline(self):
        wait = ValidationProgress(0, 100000, 0)
        self.assertEqual(wait.budget_seconds, 21600)
        for second in range(100, 21600, 100):
            wait.observe(second, second)
        with self.assertRaisesRegex(TimeoutError, 'absolute time budget'):
            wait.observe(21600, 21600)

    def test_invalid_height_is_not_progress(self):
        for height in (-1, True, 1.5, '1', 2**63):
            with self.assertRaises(ValueError):
                ValidationProgress(height, 1, 0)
            with self.assertRaises(ValueError):
                ValidationProgress(0, 1, 0).observe(height, 1)


if __name__ == '__main__':
    unittest.main()
