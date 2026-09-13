#!/usr/bin/env python3
"""BTC-header relay frontier-ordering regressions."""
import json
import os
import stat
import tempfile
import time
import unittest
from pathlib import Path

from swap import veld_btcrelayd as relayd


class FakeVeld:
    def __init__(self, best=0):
        self.best = best
        self.mempool = set()

    def rpc(self, method, params=None):
        if method == "getbtcheaderinfo":
            return {"spv_active": True, "best_height": self.best, "k_btc": 6}
        if method == "getmempoolentry":
            txid = params[0]
            if txid not in self.mempool:
                return {"error": "not in mempool", "txid": txid}
            return {"txid": txid, "fee_units": 100000}
        raise AssertionError(method)


class FakeBtc:
    def __init__(self, tip):
        self.tip = tip
        self.hashes = {}

    def call(self, method, *args):
        if method == "getblockcount":
            return self.tip
        raise AssertionError(method)

    def call_raw(self, method, *args):
        if method == "getblockhash":
            height = int(args[0])
            return self.hashes.get(height, f"{height:064x}")
        raise AssertionError(method)


class RelayFrontierTests(unittest.TestCase):
    def make_relay(self, td):
        r = object.__new__(relayd.Relay)
        r.veld = FakeVeld(0)
        r.btc = FakeBtc(250)
        r.checkpoint_height = 0
        r.max_per_op = 100
        r.max_ops_per_pass = 1
        r.resubmit_secs = 600
        r.state_path = str(Path(td) / "relay_state.json")
        r.state = {"submitted_tip": 0, "submitted_at": 0}
        r.raw_header = lambda height: bytes([height & 0xff]) * 80
        r.posts = []
        r.post_batch = lambda first, headers: (
            r.posts.append((first, len(headers))) or ("ab" * 32))
        return r

    def test_only_one_consensus_frontier_can_be_outstanding(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.run_once()
            self.assertEqual(r.posts, [(1, 100)])
            self.assertEqual(r.state["submitted_tip"], 100)

            # A second pass cannot treat local submission as accepted state.
            r.run_once()
            self.assertEqual(r.posts, [(1, 100)])

            # Only an independently observed consensus advance unlocks batch 2.
            r.veld.best = 100
            r.run_once()
            self.assertEqual(r.posts, [(1, 100), (101, 100)])

    def test_timed_out_frontier_reposts_from_consensus_best(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.state = {"submitted_tip": 100,
                       "submitted_at": time.time() - r.resubmit_secs - 1}
            r.run_once()
            self.assertEqual(r.posts, [(1, 100)])
            self.assertEqual(r.state["submitted_tip"], 100)

    def test_timed_out_identical_transaction_still_pending_is_not_duplicated(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            txid = "ab" * 32
            r.state = {"submitted_tip": 100,
                       "submitted_at": time.time() - r.resubmit_secs - 1,
                       "submitted_start": 1,
                       "submitted_txid": txid,
                       "submitted_tip_hash": f"{100:064x}"}
            r.veld.mempool.add(txid)
            r.run_once()
            self.assertEqual(r.posts, [])
            self.assertGreater(r.state["submitted_at"], time.time() - 5)

    def test_source_reorg_bypasses_pending_duplicate_suppression(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            txid = "ab" * 32
            r.state = {"submitted_tip": 100,
                       "submitted_at": time.time() - r.resubmit_secs - 1,
                       "submitted_start": 1,
                       "submitted_txid": txid,
                       "submitted_tip_hash": f"{100:064x}"}
            r.veld.mempool.add(txid)
            r.btc.hashes[100] = "ff" * 32
            r.run_once()
            self.assertEqual(r.posts, [(1, 100)])
            self.assertEqual(r.state["reorg_rewind"], relayd.REORG_REWIND_INIT)

    def test_evicted_timed_out_transaction_is_replaced(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.state = {"submitted_tip": 100,
                       "submitted_at": time.time() - r.resubmit_secs - 1,
                       "submitted_start": 1,
                       "submitted_txid": "ab" * 32,
                       "submitted_tip_hash": f"{100:064x}"}
            r.run_once()
            self.assertEqual(r.posts, [(1, 100)])

    def test_unadopted_frontier_rewinds_to_reanchor_source_reorg(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.veld.best = 200
            r.btc.tip = 500
            # A posted frontier consensus never adopted (best stayed at 200) whose
            # resubmit window has elapsed: treat it as a source reorg and rewind
            # below best+1 by REORG_REWIND_INIT rather than orphan-loop on best+1.
            r.state = {"submitted_tip": 299,
                       "submitted_at": time.time() - r.resubmit_secs - 1,
                       "reorg_rewind": 0}
            r.run_once()
            self.assertEqual(r.posts[-1], (200, 100))          # best+1-1
            self.assertEqual(r.state["reorg_rewind"], relayd.REORG_REWIND_INIT)

            # Still unadopted -> the re-anchor depth doubles.
            r.state["submitted_at"] = time.time() - r.resubmit_secs - 1
            r.run_once()
            self.assertEqual(r.posts[-1], (199, 100))          # best+1-2
            self.assertEqual(r.state["reorg_rewind"], 2)

            # Consensus finally adopts -> depth resets, normal extension resumes.
            r.veld.best = 400
            r.state["submitted_at"] = time.time() - r.resubmit_secs - 1
            r.run_once()
            self.assertEqual(r.posts[-1], (401, 100))          # best+1, no rewind
            self.assertEqual(r.state["reorg_rewind"], 0)

    def test_reorg_rewind_never_crosses_the_checkpoint_floor(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.veld.best = 5
            r.btc.tip = 500
            r.checkpoint_height = 5
            # A deep escalated rewind must never submit below checkpoint_height+1.
            r.state = {"submitted_tip": 105,
                       "submitted_at": time.time() - r.resubmit_secs - 1,
                       "reorg_rewind": 32}
            r.run_once()
            self.assertEqual(r.posts[-1][0], 6)                # checkpoint_height+1

    def test_future_checkpoint_is_a_fatal_config_error(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.checkpoint_height = 1
            with self.assertRaisesRegex(relayd.ConfigError, "exceeds.*consensus"):
                r.run_once()
            self.assertEqual(r.posts, [])

    def test_checkpoint_never_moves_authoritative_frontier(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.veld.best = 100
            r.checkpoint_height = 50
            r.run_once()
            self.assertEqual(r.posts, [(101, 100)])

    def test_batch_count_is_bounded_by_policy_and_one_byte_wire_count(self):
        with tempfile.TemporaryDirectory() as td:
            r = self.make_relay(td)
            r.max_per_op = relayd.MAX_HEADERS_PER_OP
            with self.assertRaisesRegex(RuntimeError, "oversized"):
                relayd.Relay.post_batch(
                    r, 1, [b"x" * 80] * (relayd.MAX_HEADERS_PER_OP + 1))
            with self.assertRaisesRegex(RuntimeError, "malformed"):
                relayd.Relay.post_batch(r, 1, [b"short"])


class RelayProductionConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.state = self.root / "state"
        self.state.mkdir(mode=0o700)
        self.bitcoin_dir = self.root / "bitcoin"
        self.bitcoin_dir.mkdir(mode=0o700)
        self.veld_dir = self.root / "veld"
        self.veld_dir.mkdir(mode=0o700)
        self.bitcoin = self._exe("bitcoin-cli")
        self.node = self._exe("veld-node")
        self.keygen = self._exe("veld-keygen")
        self.keyfile = self.state / "relay.key"
        self.keyfile.write_bytes(b"encrypted-test-key")
        os.chmod(self.keyfile, 0o600)

    def tearDown(self):
        self.temp.cleanup()

    def _exe(self, name):
        path = self.root / name
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        os.chmod(path, 0o755)
        return path

    def config(self):
        return {
            "production": True,
            "state_dir": str(self.state),
            "cli_base": [str(self.bitcoin),
                         "-datadir=" + str(self.bitcoin_dir)],
            "btc_rpc_timeout": 30,
            "veld_rpc": {
                "url": "http://127.0.0.1:8334",
                "token_cmd": [str(self.node),
                              "--datadir=" + str(self.veld_dir),
                              "--print-rpc-token"],
            },
            "fund_addr": "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg",
            "signer": {"keygen": str(self.keygen),
                       "keyfile": str(self.keyfile)},
            "checkpoint_height": 0,
            "max_headers_per_op": 100,
            "resubmit_timeout_secs": 600,
        }

    def test_exact_production_config_accepts_only_local_bounded_paths(self):
        self.assertIs(relayd.validate_config(self.config())["production"], True)
        for field, value in (("max_headers_per_op", 0),
                             ("max_headers_per_op", 101),
                             ("resubmit_timeout_secs", 29),
                             ("resubmit_timeout_secs", 86401),
                             ("checkpoint_height", -1)):
            cfg = self.config(); cfg[field] = value
            with self.assertRaises(RuntimeError, msg=(field, value)):
                relayd.validate_config(cfg)
        cfg = self.config(); cfg["veld_rpc"]["url"] = "http://localhost:8334"
        with self.assertRaisesRegex(RuntimeError, "exact http"):
            relayd.validate_config(cfg)
        cfg = self.config(); cfg["veld_rpc"]["token_file"] = str(self.keyfile)
        cfg["veld_rpc"].pop("token_cmd")
        with self.assertRaisesRegex(RuntimeError, "exact private runtime"):
            relayd.validate_config(cfg)

    def test_state_dir_and_state_file_fail_closed(self):
        relayd._secure_state_dir(str(self.state))
        os.chmod(self.state, 0o755)
        with self.assertRaisesRegex(RuntimeError, "mode-0700"):
            relayd._secure_state_dir(str(self.state))
        os.chmod(self.state, 0o700)
        state_path = self.state / "relay_state.json"
        relayd.save_json(str(state_path), {"submitted_tip": 5,
                                           "submitted_at": 1.0})
        self.assertEqual(relayd.load_relay_state(str(state_path))["submitted_tip"], 5)
        os.chmod(state_path, 0o644)
        with self.assertRaisesRegex(RuntimeError, "mode-0600"):
            relayd.load_relay_state(str(state_path))

    def test_loop_and_resubmit_bounds_are_explicit(self):
        for value in (relayd.MIN_LOOP_SECS, relayd.MAX_LOOP_SECS):
            self.assertEqual(relayd._strict_int(
                value, "--loop", relayd.MIN_LOOP_SECS,
                relayd.MAX_LOOP_SECS), value)
        for value in (relayd.MIN_LOOP_SECS - 1, relayd.MAX_LOOP_SECS + 1):
            with self.assertRaises(RuntimeError):
                relayd._strict_int(value, "--loop", relayd.MIN_LOOP_SECS,
                                   relayd.MAX_LOOP_SECS)

    def test_shipped_service_and_runbook_bind_the_relay(self):
        deploy = Path(__file__).parent / "deploy"
        unit = (deploy / "veld-btcrelayd.service").read_text(encoding="utf-8")
        example = json.loads((deploy / "btcrelayd.example.json").read_text(
            encoding="utf-8"))
        runbook = (deploy / "SPV-MINT-RUNBOOK.md").read_text(encoding="utf-8")
        self.assertIn("StateDirectory=veld-btcrelayd", unit)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("--loop 30", unit)
        self.assertTrue(example["production"])
        self.assertEqual(example["veld_rpc"]["url"], "http://127.0.0.1:8334")
        self.assertIn("scripts/run-hermetic-tests.sh", runbook)
        self.assertNotIn("intentionally not inserted into a shared runner", runbook)


if __name__ == "__main__":
    unittest.main(verbosity=2)
