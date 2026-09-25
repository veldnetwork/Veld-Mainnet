import struct
import unittest

from swap.native_custody_wire import authorized_parents


def vector(value):
    return struct.pack("<I", len(value)) + value


def fixture(*, parents=(b"first", b"second"), members=(0, 2, 4)):
    unsigned = b"unsigned"
    wire = (
        b"CIA1\x01"
        + bytes(6 * 32 + 2 * 8)
        + vector(b"destination")
        + vector(b"refund")
        + bytes(8)
        + vector(unsigned)
        + bytes([len(parents)])
        + b"".join(vector(p) for p in parents)
        + bytes([len(members)])
        + b"".join(bytes([m]) + bytes(3309) for m in members)
    )
    return wire, unsigned


class AuthorizationWireTests(unittest.TestCase):
    def test_preserves_exact_parent_bytes_and_order(self):
        wire, raw = fixture()
        self.assertEqual(authorized_parents(wire, raw), [b"first", b"second"])

    def test_transaction_identity_and_trailing_data_are_refused(self):
        wire, raw = fixture()
        for value, tx in ((wire, raw + b"x"), (wire + b"x", raw), (bytearray(wire), raw)):
            with self.subTest(tx=tx), self.assertRaises(ValueError):
                authorized_parents(value, tx)

    def test_every_truncation_is_refused(self):
        wire, raw = fixture()
        for length in range(len(wire)):
            with self.subTest(length=length), self.assertRaises(ValueError):
                authorized_parents(wire[:length], raw)

    def test_duplicate_out_of_order_and_below_threshold_approvals_refuse(self):
        for members in ((0, 0, 4), (2, 0, 4), (0, 2), (0, 2, 5)):
            wire, raw = fixture(members=members)
            with self.subTest(members=members), self.assertRaises(ValueError):
                authorized_parents(wire, raw)

    def test_parent_limits_and_empty_parent_refuse(self):
        for parents in ((b"one",), (b"x",) * 9, (b"", b"valid"), (b"x" * 10000, b"y")):
            wire, raw = fixture(parents=parents)
            with self.subTest(lengths=list(map(len, parents))), self.assertRaises(ValueError):
                authorized_parents(wire, raw)


if __name__ == "__main__":
    unittest.main()
