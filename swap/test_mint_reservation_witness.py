#!/usr/bin/env python3
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import veld_peg_solvency as sol
import veld_signerd as signerd
import veld_wt_reserve as witness


ISSUER = "Vissuer"
RECIPIENT = "Vrecipient"
TIP_HASH = "11" * 32


def unsigned_tx(tag=1):
    return (
        b"\x01\x00\x00\x00"
        + b"\x01"
        + bytes([tag]) * 32
        + b"\x00\x00\x00\x00"
        + b"\x00"
        + b"\xff\xff\xff\xff"
        + b"\x01"
        + (1000).to_bytes(8, "little")
        + b"\x02\x6a\x00"
        + b"\x00\x00\x00\x00"
    ).hex()


def signed_tx(unsigned_hex):
    raw = bytearray.fromhex(unsigned_hex)
    # version(4)+count(1)+prevout(36) => input script length byte at 41.
    raw[41:42] = b"\x01\x01"
    return bytes(raw).hex()


class FakeRpc:
    def __init__(self):
        self.transactions = {}
        self.block_hashes = {100: TIP_HASH}

    def call(self, method, params=None):
        if method == "getblockhash":
            return self.block_hashes.get(params[0], "ff" * 32)
        if method == "getrawtransaction":
            txid = params[0]
            if txid not in self.transactions:
                raise RuntimeError("not canonical")
            return dict(self.transactions[txid])
        raise AssertionError(method)


def fake_receipt(core, cfg):
    result = dict(core)
    result["sig_alg"] = "mldsa65"
    result["sig"] = "00"
    return result


class ReservationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="witness-test-")
        self.state = Path(self.temp.name) / "state"
        self.state.mkdir(mode=0o700)
        self.paths = witness._paths({"state_dir": str(self.state)})
        witness.atomic_write(
            self.paths["ledger"],
            json.dumps(witness._empty_ledger(), sort_keys=True, separators=(",", ":")) + "\n",
        )
        witness.atomic_write(self.paths["terminal"], witness._empty_terminal_log_text())
        self.rpc = FakeRpc()
        self.beat = sol.stamp_heartbeat(
            sol.build_beat_payload(5, 0, 0, 100, TIP_HASH, 7, 120), int(time.time())
        )
        self.cfg = {
            "issuer_id": ISSUER,
            "witness_id": "witness-1",
            "issuer_p2pkh_hex": "76a914" + "22" * 20 + "88ac",
            "keygen": "/fake/keygen",
            "state_dir": str(self.state),
            "signer": {"beat_keyfile": "/fake/key"},
        }

    def tearDown(self):
        self.temp.cleanup()

    def request(self, tag=1, sats=1, recipient=RECIPIENT):
        raw = unsigned_tx(tag)
        digest = hashlib.sha256(bytes.fromhex(raw)).hexdigest()
        return {
            "action": "reserve",
            "issuer_id": ISSUER,
            "request_id": digest,
            "unsigned_tx_sha256": digest,
            "unsigned_tx_hex": raw,
            "sats": sats,
            "recipient": recipient,
            "beat_seq": 7,
            "tip": 100,
            "tip_hash": TIP_HASH,
        }

    def decoded(self, sats=1, recipient=RECIPIENT):
        return subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"from": ISSUER, "to": recipient, "sats": sats}), stderr=""
        )

    def reserve(self, ledger, request, decoded=None):
        with (
            mock.patch.object(witness, "_sign_receipt", side_effect=fake_receipt),
            mock.patch.object(witness.subprocess, "run", return_value=decoded or self.decoded()),
        ):
            return witness.handle_reserve(
                request, self.cfg, self.paths, ledger, self.beat, self.rpc
            )

    def test_exact_idempotency_mutation_and_durable_crash_charge(self):
        ledger = witness._load_ledger(self.paths["ledger"])
        first = self.reserve(ledger, self.request())
        self.assertFalse(first["idempotent"])
        restarted = witness._load_ledger(self.paths["ledger"])
        second = self.reserve(restarted, self.request())
        self.assertTrue(second["idempotent"])
        self.assertEqual(len(restarted["reservations"]), 1)
        shrunk = sol.stamp_heartbeat(
            sol.build_beat_payload(0, 0, 0, 100, TIP_HASH, 8, 120), int(time.time())
        )
        old_beat = self.beat
        self.beat = shrunk
        shrunk_request = self.request()
        shrunk_request["beat_seq"] = 8
        with self.assertRaises(SystemExit):
            self.reserve(restarted, shrunk_request)
        self.beat = old_beat

        mutated = self.request(recipient="Vother")
        # Reuse the original request id/hash while mutating the claimed recipient.
        mutated["request_id"] = self.request()["request_id"]
        mutated["unsigned_tx_sha256"] = self.request()["unsigned_tx_sha256"]
        with self.assertRaises(SystemExit):
            self.reserve(restarted, mutated, self.decoded(recipient="Vother"))

        # Model a tip change after the durable reserve but before response: the
        # request is refused by main, yet restart conservatively retains the charge.
        self.rpc.block_hashes[100] = "33" * 32
        self.assertFalse(witness._tip_matches(self.beat, self.rpc))
        charged = witness._load_ledger(self.paths["ledger"])
        self.assertEqual(witness._reconcile(charged, self.beat, self.rpc), 1)

    def test_reserve_independently_derives_amount_recipient_and_hash(self):
        ledger = witness._load_ledger(self.paths["ledger"])
        with self.assertRaises(SystemExit):
            self.reserve(ledger, self.request(sats=1), self.decoded(sats=5))
        with self.assertRaises(SystemExit):
            self.reserve(
                ledger, self.request(recipient=RECIPIENT), self.decoded(recipient="Vdifferent")
            )
        wrong_hash = self.request()
        wrong_hash["request_id"] = "aa" * 32
        with self.assertRaises(SystemExit):
            self.reserve(ledger, wrong_hash)
        self.assertEqual(witness._load_ledger(self.paths["ledger"])["reservations"], [])

    def test_commit_binds_signed_bytes_unsigned_template_and_mint_fields(self):
        ledger = witness._load_ledger(self.paths["ledger"])
        request = self.request()
        self.reserve(ledger, request)
        signed = signed_tx(request["unsigned_tx_hex"])
        txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed)).digest()).hexdigest()
        with mock.patch.object(witness.subprocess, "run", return_value=self.decoded()):
            answer = witness.handle_commit(
                {
                    "reservation_id": ledger["reservations"][0]["receipt"]["reservation_id"],
                    "txid": txid,
                    "signed_tx_hex": signed,
                },
                self.cfg,
                self.paths,
                ledger,
            )
        self.assertTrue(answer["committed"])

        restored = witness._load_ledger(self.paths["ledger"])
        unrelated = signed_tx(unsigned_tx(9))
        old_txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(unrelated)).digest()).hexdigest()
        with self.assertRaises(SystemExit):
            witness.handle_commit(
                {
                    "reservation_id": answer["reservation_id"],
                    "txid": old_txid,
                    "signed_tx_hex": unrelated,
                },
                self.cfg,
                self.paths,
                restored,
            )
        with mock.patch.object(witness.subprocess, "run", return_value=self.decoded(sats=999)):
            # A fresh ledger/receipt is needed because exact bytes already commit
            # idempotently; independently wrong decoded mint fields still refuse.
            other_ledger = witness._empty_ledger()
            other_req = self.request(tag=2)
            self.reserve(other_ledger, other_req)
            other_signed = signed_tx(other_req["unsigned_tx_hex"])
            other_txid = hashlib.sha256(
                hashlib.sha256(bytes.fromhex(other_signed)).digest()
            ).hexdigest()
            with self.assertRaises(SystemExit):
                witness.handle_commit(
                    {
                        "reservation_id": other_ledger["reservations"][0]["receipt"][
                            "reservation_id"
                        ],
                        "txid": other_txid,
                        "signed_tx_hex": other_signed,
                    },
                    self.cfg,
                    self.paths,
                    other_ledger,
                )

    def test_confirmation_requires_exact_block_hash_and_reorg_restores_charge(self):
        ledger = witness._load_ledger(self.paths["ledger"])
        request = self.request()
        self.reserve(ledger, request)
        signed = signed_tx(request["unsigned_tx_hex"])
        txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed)).digest()).hexdigest()
        ledger["reservations"][0]["txid"] = txid
        ledger["reservations"][0]["signed_tx_sha256"] = hashlib.sha256(
            bytes.fromhex(signed)
        ).hexdigest()
        self.rpc.transactions[txid] = {
            "txid": txid,
            "confirmations": 2,
            "block_height": 99,
            "block_hash": "22" * 32,
        }
        self.rpc.block_hashes[99] = "44" * 32
        self.assertEqual(witness._reconcile(ledger, self.beat, self.rpc), 1)
        self.rpc.block_hashes[99] = "22" * 32
        self.assertEqual(witness._reconcile(ledger, self.beat, self.rpc), 0)
        del self.rpc.transactions[txid]
        self.assertEqual(witness._reconcile(ledger, self.beat, self.rpc), 1)

    def test_confirmation_depth_is_derived_from_signed_beat_tip(self):
        ledger = witness._load_ledger(self.paths["ledger"])
        request = self.request()
        self.reserve(ledger, request)
        signed = signed_tx(request["unsigned_tx_hex"])
        txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed)).digest()).hexdigest()
        entry = ledger["reservations"][0]
        entry["txid"] = txid
        entry["signed_tx_sha256"] = hashlib.sha256(bytes.fromhex(signed)).hexdigest()
        self.rpc.transactions[txid] = {
            "txid": txid,
            # Live node raced far beyond the heartbeat tip.  This must not make
            # a two-deep mint final in the heartbeat's supply snapshot.
            "confirmations": 10_000,
            "block_height": 99,
            "block_hash": "22" * 32,
        }
        self.rpc.block_hashes[99] = "22" * 32
        self.assertEqual(witness._reconcile(ledger, self.beat, self.rpc), 0)
        self.assertEqual(entry["status"], "confirmed")
        info = signerd._canonical_mint_confirmation(self.rpc, {"txid": txid}, self.beat)
        self.assertEqual(info["confirmations"], 2)

        # A reported count lower than the heartbeat-derived count is internally
        # inconsistent and therefore remains charged fail-closed.
        self.rpc.transactions[txid]["confirmations"] = 1
        entry["status"] = "reserved"
        entry.pop("block_height", None)
        entry.pop("block_hash", None)
        self.assertEqual(witness._reconcile(ledger, self.beat, self.rpc), 1)
        self.assertIsNone(signerd._canonical_mint_confirmation(self.rpc, {"txid": txid}, self.beat))

    def test_concurrent_unique_requests_share_one_headroom_budget(self):
        winners = []
        barrier = threading.Barrier(12)

        def worker(tag):
            barrier.wait()
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(self.paths["lock"], flags, 0o600)
            try:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX)
                ledger = witness._load_ledger(self.paths["ledger"])
                try:
                    self.reserve(ledger, self.request(tag=tag))
                    winners.append(tag)
                except SystemExit:
                    pass
            finally:
                os.close(fd)

        threads = [threading.Thread(target=worker, args=(n + 1,)) for n in range(12)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(len(winners), 5)
        ledger = witness._load_ledger(self.paths["ledger"])
        self.assertEqual(len(ledger["reservations"]), 5)

    def test_stale_restore_symlink_oversize_and_witness_down_fail_closed(self):
        beat_path = Path(self.paths["beat"])
        beat_path.write_text(json.dumps(self.beat))
        beat_path.chmod(0o600)
        stale = dict(self.beat)
        stale["expires_at"] = time.time() - 1
        beat_path.write_text(json.dumps(stale))
        with self.assertRaises(SystemExit):
            witness._load_beat(str(beat_path), time.time())
        beat_path.unlink()
        beat_path.symlink_to("/etc/passwd")
        with self.assertRaises(SystemExit):
            witness._load_beat(str(beat_path), time.time())
        Path(self.paths["restore_halt"]).write_text("restore requires reconciliation\n")
        with self.assertRaises(SystemExit):
            witness._require_restore_clear(self.paths)
        oversized = subprocess.run(
            ["python3", str(Path(__file__).with_name("veld_wt_reserve.py"))],
            input="x" * (witness.MAX_STDIN + 1),
            text=True,
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(oversized.returncode, 2)
        with self.assertRaises(ValueError):
            signerd._call_witness(["/bin/false"], {"action": "reserve"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
