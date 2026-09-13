#!/usr/bin/env python3
import unittest

from swap.veld_amount import VELD_UNITS, quote_base_units, quote_veld_str


class ExactVeldAmountTests(unittest.TestCase):
    def test_large_integer_rate_never_rounds_through_float(self):
        rate = 999_999_999_999
        amount = 10**18
        expected = rate * VELD_UNITS
        self.assertEqual(quote_base_units(amount, rate, 18), expected)
        # Historical float scaling was 7,936 base units low and crossed this
        # 0.01-VELD floor. The exact result must retain the final cent.
        self.assertTrue(quote_veld_str(amount, rate, 18).endswith('.00'))

    def test_decimal_string_and_price_feed_float_are_decimal_exact(self):
        self.assertEqual(quote_base_units(100_000_000, '0.12345678', 8),
                         12_000_000)
        self.assertEqual(quote_veld_str(100_000_000, 0.12, 8), '0.12')

    def test_floor_is_exactly_one_cent_and_never_rounds_up(self):
        self.assertEqual(quote_base_units(19_999_999, 1, 8), 19_000_000)
        self.assertEqual(quote_veld_str(19_999_999, 1, 8), '0.19')

    def test_rejects_ambiguous_or_overprecision_inputs(self):
        for rate in (True, 'nan', 'inf', 0, -1, '0.000000001'):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                quote_base_units(1, rate, 8)
        with self.assertRaises(ValueError):
            quote_base_units(True, 1, 8)
        with self.assertRaises(ValueError):
            quote_base_units(1, 1, 19)


if __name__ == '__main__':
    unittest.main(verbosity=2)
