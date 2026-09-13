#!/usr/bin/env python3
"""Focused custody descriptor/manifest/compiled-identity regressions."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from swap import veld_custody_binding as binding


class CustodyBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="custody-binding-")
        self.path = Path(self.temp.name) / "custody-spks.json"
        self.descriptor = "tr(" + "11" * 32 + ",multi_a(3,xpub-fixture/0/*))#fixture"
        self.descriptor_hash = hashlib.sha256(self.descriptor.encode()).hexdigest()
        self.scripts = ["5120%064x" % n for n in range(1, 1001)]
        self.document = {
            "version": 1,
            "descriptor": self.descriptor,
            "descriptor_sha256": self.descriptor_hash,
            "range": [0, 999],
            "script_pubkeys": self.scripts,
        }
        self._write(self.document)

    def tearDown(self):
        self.temp.cleanup()

    def _write(self, document):
        self.path.write_text(json.dumps(document, sort_keys=True,
                                        separators=(",", ":")) + "\n")
        self.manifest_hash = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def _load(self, **kwargs):
        return binding.load_manifest(
            str(self.path), self.descriptor_hash,
            kwargs.get("manifest_hash", self.manifest_hash),
            kwargs.get("spv_spk", self.scripts[0]),
            expected_range_end=kwargs.get("range_end", 999),
            expected_consensus_manifest_sha256=kwargs.get("consensus_hash"),
        )

    def test_exact_manifest_binds_index_zero_and_full_range(self):
        found = self._load()
        self.assertEqual(found["spv_custody_spk_hex"], self.scripts[0])
        self.assertEqual(found["range"], [0, 999])
        self.assertEqual(len(found["script_pubkey_set"]), 1000)
        peg = {
            "active": True, "spv_active": True,
            "custody_descriptor_sha256": self.descriptor_hash,
            "custody_manifest_sha256": self.manifest_hash,
            "custody_descriptor_range": [0, 999],
            "spv_custody_descriptor_index": 0,
            "spv_custody_spk_hex": self.scripts[0],
        }
        binding.verify_peg_identity(peg, found)

    def test_byte_tamper_duplicate_and_wrong_index_zero_fail_closed(self):
        with self.assertRaisesRegex(RuntimeError, "bytes differ"):
            self._load(manifest_hash="00" * 32)

        duplicate = dict(self.document)
        duplicate["script_pubkeys"] = list(self.scripts)
        duplicate["script_pubkeys"][1] = duplicate["script_pubkeys"][0]
        self._write(duplicate)
        with self.assertRaisesRegex(RuntimeError, "exact/hash-bound"):
            self._load()

        self._write(self.document)
        with self.assertRaisesRegex(RuntimeError, "index 0"):
            self._load(spv_spk="5120" + "ff" * 32)

    def test_compiled_descriptor_or_spv_mismatch_fails_closed(self):
        found = self._load()
        base = {
            "active": True, "spv_active": True,
            "custody_descriptor_sha256": self.descriptor_hash,
            "custody_manifest_sha256": self.manifest_hash,
            "custody_descriptor_range": [0, 999],
            "spv_custody_descriptor_index": 0,
            "spv_custody_spk_hex": self.scripts[0],
        }
        bad_descriptor = dict(base)
        bad_descriptor["custody_descriptor_sha256"] = "ff" * 32
        with self.assertRaisesRegex(RuntimeError, "descriptor identity"):
            binding.verify_peg_identity(bad_descriptor, found)
        bad_spv = dict(base)
        bad_spv["spv_custody_spk_hex"] = "5120" + "ff" * 32
        with self.assertRaisesRegex(RuntimeError, "SPV custody script"):
            binding.verify_peg_identity(bad_spv, found)

    def test_c1_extended_manifest_preserves_compiled_prefix_identity(self):
        self.scripts = ["5120%064x" % n for n in range(1, 11001)]
        self.document = dict(self.document)
        self.document["range"] = [0, 10999]
        self.document["script_pubkeys"] = self.scripts
        self._write(self.document)
        prefix = dict(self.document)
        prefix["range"] = [0, 999]
        prefix["script_pubkeys"] = self.scripts[:1000]
        consensus_hash = hashlib.sha256((json.dumps(
            prefix, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        found = self._load(
            range_end=10999, consensus_hash=consensus_hash)
        self.assertEqual(found["range"], [0, 10999])
        self.assertEqual(found["consensus_range"], [0, 999])
        for index in (0, 999, 1000, 10999):
            self.assertEqual(found["script_pubkeys"][index],
                             self.scripts[index])

        peg = {
            "active": True, "spv_active": True,
            "custody_descriptor_sha256": self.descriptor_hash,
            "custody_manifest_sha256": consensus_hash,
            "custody_descriptor_range": [0, 999],
            "spv_custody_descriptor_index": 0,
            "spv_custody_spk_hex": self.scripts[0],
        }
        binding.verify_peg_identity(peg, found)

        calls = []
        def derive(method, descriptor, requested_range):
            calls.append((method, descriptor, requested_range))
            return ["address-%d" % index for index in range(11000)]
        with mock.patch.object(
                binding, "_bech32m_spk", side_effect=self.scripts):
            binding.verify_core_derivation(derive, found)
        self.assertEqual(calls, [
            ("deriveaddresses", self.descriptor, "[0,10999]")])

        with self.assertRaisesRegex(RuntimeError, "exact/hash-bound"):
            self._load(range_end=11000, consensus_hash=consensus_hash)
        with self.assertRaisesRegex(RuntimeError, "prefix differs"):
            self._load(range_end=10999, consensus_hash="ef" * 32)
        bad = dict(peg)
        bad["custody_descriptor_range"] = [0, 10999]
        with self.assertRaisesRegex(RuntimeError, "compiled custody descriptor range"):
            binding.verify_peg_identity(bad, found)


if __name__ == "__main__":
    unittest.main(verbosity=2)
