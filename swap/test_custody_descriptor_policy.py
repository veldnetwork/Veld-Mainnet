#!/usr/bin/env python3
"""Offline full-descriptor policy checks using disposable public test keys."""

import json
import unittest
from pathlib import Path
from unittest import mock

from swap import veld_custody_binding as binding


DESCRIPTOR = json.loads(
    (Path(__file__).parent / "fixtures" / "custody-policy-descriptor.json").read_text()
)["descriptor"]


class CustodyDescriptorPolicyTests(unittest.TestCase):
    def test_ceremony_descriptor_has_five_distinct_account_keys(self):
        keys = binding.validate_descriptor_policy(DESCRIPTOR)
        self.assertEqual(len(keys), 5)
        self.assertEqual(len(set(keys)), 5)

    def test_network_policy_is_explicit_and_never_accepts_mainnet_keys_as_testnet(self):
        for network in ("test", "regtest", "signet", "unknown"):
            with self.subTest(network=network), self.assertRaises(RuntimeError):
                binding.validate_descriptor_policy(DESCRIPTOR, network=network)
        call = mock.Mock()
        with self.assertRaises(RuntimeError):
            binding.verify_core_derivation(call, {"descriptor": DESCRIPTOR}, expected_hrp="unknown")
        call.assert_not_called()

    def test_policy_requires_bounded_string_and_checksum_field(self):
        for value in (
            None,
            {},
            [],
            3,
            "",
            "x" * 2049,
            DESCRIPTOR.split("#")[0],
            DESCRIPTOR + "#extra",
        ):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(RuntimeError):
                    binding.validate_descriptor_policy(value)

    def test_only_fixed_nums_key_and_three_of_five_tree_are_permitted(self):
        keys = binding.validate_descriptor_policy(DESCRIPTOR)
        for count in (4, 6):
            selected = list(keys[:count]) if count == 4 else list(keys) + [keys[0]]
            descriptor = (
                "tr("
                + binding.CUSTODY_NUMS_KEY
                + ",multi_a(3,"
                + ",".join(selected)
                + "))#sat2slz5"
            )
            with self.subTest(key_count=count):
                with self.assertRaisesRegex(RuntimeError, "exactly five"):
                    binding.validate_descriptor_policy(descriptor)
        for descriptor in (
            DESCRIPTOR.replace(binding.CUSTODY_NUMS_KEY, "11" * 32),
            DESCRIPTOR.replace("multi_a(3,", "multi_a(2,"),
            DESCRIPTOR.replace("multi_a(3,", "{multi_a(3,"),
        ):
            with self.assertRaises(RuntimeError):
                binding.validate_descriptor_policy(descriptor)

    def test_key_origin_and_derivation_are_exact(self):
        for old, new in (
            ("/86h/0h/0h]", "/86h/1h/0h]"),
            ("/86h/0h/0h]", "/84h/0h/0h]"),
            ("/0/*", "/1/*"),
            ("/0/*", "/0/0"),
        ):
            with self.subTest(replacement=new):
                with self.assertRaisesRegex(RuntimeError, "BIP86 public path"):
                    binding.validate_descriptor_policy(DESCRIPTOR.replace(old, new, 1))

    def test_repeated_account_key_is_not_a_new_member(self):
        keys = binding.validate_descriptor_policy(DESCRIPTOR)
        same_account = "[00000000" + keys[0][keys[0].index("/") :]
        descriptor = DESCRIPTOR.replace(keys[1], same_account)
        with self.assertRaisesRegex(RuntimeError, "repeats an underlying public key"):
            binding.validate_descriptor_policy(descriptor)

    def test_invalid_extended_key_checksum_is_rejected(self):
        keys = binding.validate_descriptor_policy(DESCRIPTOR)
        key = keys[0]
        last = key.index("/0/*") - 1
        changed = key[:last] + ("1" if key[last] != "1" else "2") + key[last + 1 :]
        with self.assertRaisesRegex(RuntimeError, "valid account xpub"):
            binding.validate_descriptor_policy(DESCRIPTOR.replace(key, changed))

    def test_invalid_policy_is_rejected_before_core_or_peg_checks(self):
        call = mock.Mock()
        with self.assertRaises(RuntimeError):
            binding.verify_core_derivation(call, {"descriptor": "invalid"})
        call.assert_not_called()
        with self.assertRaisesRegex(RuntimeError, "fixed NUMS"):
            binding.verify_peg_identity({}, {"descriptor": "invalid"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
