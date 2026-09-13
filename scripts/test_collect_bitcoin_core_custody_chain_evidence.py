#!/usr/bin/env python3
"""Adversarial unit tests for the Bitcoin Core custody collector."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name(
    "collect-bitcoin-core-custody-chain-evidence.py")
SPEC = importlib.util.spec_from_file_location("custody_chain_collector", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
C = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = C
SPEC.loader.exec_module(C)


class CollectorTests(unittest.TestCase):
    def test_rpc_is_loopback_and_secret_free(self) -> None:
        self.assertEqual(C.validate_rpc_args([
            "-datadir=/srv/bitcoin", "-rpcconnect=127.0.0.1",
            "-rpcport=8332",
        ]), ["-datadir=/srv/bitcoin", "-rpcconnect=127.0.0.1",
             "-rpcport=8332"])
        for value in ("-rpcconnect=198.51.100.7", "-rpcpassword=secret",
                      "-rpcport=abc", "-rpcport=8332\n-injected"):
            with self.subTest(value=value), self.assertRaises(C.CollectionError):
                C.validate_rpc_args([value])

    def test_chain_info_requires_synced_main(self) -> None:
        valid = {
            "chain": "main", "blocks": 900000, "headers": 900000,
            "bestblockhash": "1" * 64, "initialblockdownload": False,
            "extra_core_field": "retained only by Core, normalized by collector",
        }
        self.assertEqual(set(C.exact_chain_info(valid)), {
            "chain", "blocks", "headers", "bestblockhash",
            "initialblockdownload",
        })
        for mutation in (
                {"chain": "regtest"}, {"initialblockdownload": True},
                {"headers": 900001}):
            bad = dict(valid)
            bad.update(mutation)
            with self.assertRaises(C.CollectionError):
                C.exact_chain_info(bad)

    def test_known_bitcoin_header_hash_and_pow(self) -> None:
        genesis = (
            "01000000" + "00" * 32 +
            "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a" +
            "29ab5f49ffff001d1dac2b7c")
        original = C.MAX_EVIDENCE_TARGET
        try:
            C.MAX_EVIDENCE_TARGET = C.POW_LIMIT
            raw = C.verify_header(
                genesis,
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")
            self.assertEqual(len(raw), 80)
        finally:
            C.MAX_EVIDENCE_TARGET = original
        with self.assertRaisesRegex(C.CollectionError, "evidence floor"):
            C.verify_header(
                genesis,
                "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

    def test_output_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory(prefix="chain-collector-") as temp:
            path = Path(temp) / "receipt.json"
            C.exclusive_write(path.resolve(), b"{}\n")
            self.assertEqual(path.read_bytes(), b"{}\n")
            with self.assertRaises(C.CollectionError):
                C.exclusive_write(path.resolve(), b"changed\n")


if __name__ == "__main__":
    unittest.main()
