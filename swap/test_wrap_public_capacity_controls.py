#!/usr/bin/env python3
"""Adversarial capacity and restart tests for the btcVELD wrap front door."""

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

from swap import veld_wrapd as wrapd


class FakeDescriptorBackend:
    def __init__(self, binding):
        self.binding = binding
        self.next = 1
        self.labels = {}
        self.getnew_calls = 0

    def address(self, index):
        return "bc1p" + ("q" * 52) + ("%06d" % index)

    def json(self, method, *args):
        if method == "listdescriptors":
            return {
                "descriptors": [
                    {
                        "desc": self.binding["descriptor"],
                        "range": [0, 999],
                        "active": True,
                        "internal": False,
                        "next": self.next,
                    }
                ]
            }
        if method == "deriveaddresses":
            bounds = [int(value) for value in args[1].strip("[]").split(",")]
            return [self.address(index) for index in range(bounds[0], bounds[-1] + 1)]
        if method == "getaddressinfo":
            address = args[0]
            index = int(address[-6:])
            return {
                "scriptPubKey": self.binding["script_pubkeys"][index],
                "labels": ([{"name": self.labels[address]}] if address in self.labels else []),
            }
        raise AssertionError(method)

    def text(self, method, *args):
        if method != "getnewaddress":
            raise AssertionError(method)
        self.getnew_calls += 1
        address = self.address(self.next)
        self.labels[address] = args[0]
        self.next += 1
        return address


class WrapJournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "allocations.json")
        scripts = tuple("5120%064x" % (index + 1) for index in range(1000))
        self.binding = {
            "descriptor": "tr(test)#checksum",
            "range": [0, 999],
            "script_pubkeys": scripts,
        }
        self.backend = FakeDescriptorBackend(self.binding)
        self.witnessed = []
        self.patches = (
            mock.patch.object(wrapd, "_btc_json", side_effect=self.backend.json),
            mock.patch.object(wrapd, "_btc", side_effect=self.backend.text),
        )
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def journal(self, **kwargs):
        return wrapd.WrapAllocationJournal(
            self.path,
            self.binding,
            self.backend.next,
            max_bytes=1_048_576,
            reserve_indices=kwargs.get("reserve_indices", 100),
            per_principal=kwargs.get("per_principal", 4),
            per_destination=kwargs.get("per_destination", 4),
            register_allocation=lambda record, verify=False: self.witnessed.append(
                (record, verify)
            ),
            allow_initialize=not Path(self.path).exists(),
        )

    def test_missing_journal_requires_one_shot_initialization(self):
        args = dict(
            max_bytes=1_048_576,
            reserve_indices=100,
            per_principal=4,
            per_destination=4,
            register_allocation=lambda record, verify=False: self.witnessed.append(
                (record, verify)
            ),
        )
        with self.assertRaisesRegex(RuntimeError, "one-shot initialization"):
            wrapd.WrapAllocationJournal(
                self.path, self.binding, self.backend.next, allow_initialize=False, **args
            )
        created = wrapd.WrapAllocationJournal(
            self.path, self.binding, self.backend.next, allow_initialize=True, **args
        )
        self.assertTrue(created.initialized_now)
        with self.assertRaisesRegex(RuntimeError, "must be false"):
            wrapd.WrapAllocationJournal(
                self.path, self.binding, self.backend.next, allow_initialize=True, **args
            )

    def test_exact_retry_and_conflict_never_consume_another_index(self):
        journal = self.journal()
        request_id, principal = "11" * 16, "22" * 32
        veld = "V" + "1" * 25
        first = journal.allocate(request_id, principal, veld, 100)
        second = journal.allocate(request_id, principal, veld, 100)
        self.assertEqual(first, second)
        self.assertEqual(self.backend.getnew_calls, 1)
        with self.assertRaisesRegex(ValueError, "already bound"):
            journal.allocate(request_id, principal, veld, 101)
        self.assertEqual(self.backend.getnew_calls, 1)

    def test_crash_after_core_advance_recovers_reserved_intent_once(self):
        journal = self.journal()
        real_save = journal._save
        saves = [0]

        def fail_issued_once():
            saves[0] += 1
            if saves[0] == 2:
                raise OSError("simulated post-Core journal failure")
            return real_save()

        with mock.patch.object(journal, "_save", side_effect=fail_issued_once):
            with self.assertRaises(OSError):
                journal.allocate("33" * 16, "44" * 32, "V" + "2" * 25, 200)
        self.assertEqual(self.backend.getnew_calls, 1)
        disk = json.loads(Path(self.path).read_text())
        self.assertEqual(disk["records"][0]["state"], "reserved")

        restarted = self.journal()
        recovered = restarted.allocate("33" * 16, "44" * 32, "V" + "2" * 25, 200)
        self.assertEqual(recovered["state"], "issued")
        self.assertEqual(self.backend.getnew_calls, 1)

    def test_witness_outage_persists_allocated_boundary_and_never_returns_address(self):
        attempts = []

        def unavailable(record, verify=False):
            attempts.append(record)
            raise RuntimeError("independent allocation witness unavailable")

        journal = wrapd.WrapAllocationJournal(
            self.path,
            self.binding,
            self.backend.next,
            max_bytes=1_048_576,
            reserve_indices=100,
            per_principal=4,
            per_destination=4,
            register_allocation=unavailable,
            allow_initialize=True,
        )
        request_id, principal = "35" * 16, "46" * 32
        with self.assertRaisesRegex(RuntimeError, "witness unavailable"):
            journal.allocate(request_id, principal, "V" + "2" * 25, 202)
        self.assertEqual(self.backend.getnew_calls, 1)
        disk = json.loads(Path(self.path).read_text())
        self.assertEqual(disk["records"][0]["state"], "allocated")
        with self.assertRaisesRegex(RuntimeError, "prior custody allocation"):
            journal.allocate("36" * 16, "47" * 32, "V" + "3" * 25, 203)
        self.assertEqual(self.backend.getnew_calls, 1)

        witnessed = []
        restarted = wrapd.WrapAllocationJournal(
            self.path,
            self.binding,
            self.backend.next,
            max_bytes=1_048_576,
            reserve_indices=100,
            per_principal=4,
            per_destination=4,
            register_allocation=lambda record, verify=False: witnessed.append((record, verify)),
            allow_initialize=False,
        )
        issued = restarted.allocate(request_id, principal, "V" + "2" * 25, 202)
        self.assertEqual(issued["state"], "issued")
        self.assertEqual(self.backend.getnew_calls, 1)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(len(witnessed), 1)

    def test_post_replace_fsync_error_keeps_visible_reserved_intent(self):
        journal = self.journal()
        real_fsync = os.fsync

        def fail_directory_fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("simulated allocation directory fsync failure")
            return real_fsync(fd)

        request_id = "34" * 16
        with mock.patch.object(wrapd.os, "fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(OSError, "directory fsync"):
                journal.allocate(request_id, "45" * 32, "V" + "2" * 25, 201)
        self.assertTrue(journal.has_request(request_id))
        self.assertEqual(journal.records[request_id]["state"], "reserved")
        self.assertEqual(self.backend.getnew_calls, 0)
        disk = json.loads(Path(self.path).read_text())
        self.assertEqual(disk["records"][0]["state"], "reserved")

        issued = journal.allocate(request_id, "45" * 32, "V" + "2" * 25, 201)
        self.assertEqual(issued["state"], "issued")
        self.assertEqual(self.backend.getnew_calls, 1)
        disk = json.loads(Path(self.path).read_text())
        self.assertEqual(disk["records"][0]["state"], "issued")

    def test_concurrent_same_request_is_exactly_once(self):
        journal = self.journal()
        barrier = threading.Barrier(20)
        answers, errors = [], []

        def issue():
            try:
                barrier.wait()
                answers.append(journal.allocate("55" * 16, "66" * 32, "V" + "3" * 25, 300))
            except Exception as exc:  # pragma: no cover - diagnostic capture
                errors.append(exc)

        workers = [threading.Thread(target=issue) for _ in range(20)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(3)
        self.assertEqual(errors, [])
        self.assertEqual(len(answers), 20)
        self.assertEqual(self.backend.getnew_calls, 1)
        self.assertEqual({answer["btc_address"] for answer in answers}, {answers[0]["btc_address"]})

    def test_persistent_principal_destination_and_reserve_caps(self):
        journal = self.journal(per_principal=1, per_destination=1)
        journal.allocate("77" * 16, "88" * 32, "V" + "4" * 25, 1)
        with self.assertRaisesRegex(RuntimeError, "principal"):
            journal.allocate("78" * 16, "88" * 32, "V" + "5" * 25, 1)
        with self.assertRaisesRegex(RuntimeError, "destination"):
            journal.allocate("79" * 16, "89" * 32, "V" + "4" * 25, 1)

        self.backend.next = 900
        reserve = wrapd.WrapAllocationJournal(
            str(Path(self.temp.name) / "reserve-allocations.json"),
            self.binding,
            self.backend.next,
            max_bytes=1_048_576,
            reserve_indices=100,
            per_principal=4,
            per_destination=4,
            register_allocation=lambda record, verify=False: self.witnessed.append(
                (record, verify)
            ),
            allow_initialize=True,
        )
        with self.assertRaisesRegex(RuntimeError, "reserve threshold"):
            reserve.allocate("90" * 16, "91" * 32, "V" + "6" * 25, 1)

    def test_core_cursor_manual_advance_or_rollback_fails_closed(self):
        journal = self.journal()
        journal.allocate("a1" * 16, "b1" * 32, "V" + "7" * 25, 1)
        self.assertEqual(self.backend.next, 2)

        self.backend.next = 4
        with self.assertRaisesRegex(RuntimeError, "differs from durable"):
            journal.allocate("a2" * 16, "b2" * 32, "V" + "8" * 25, 1)
        with self.assertRaisesRegex(RuntimeError, "differs from durable"):
            self.journal()

        self.backend.next = 1
        with self.assertRaisesRegex(RuntimeError, "differs from durable"):
            self.journal()

    def test_noncontiguous_or_nonfinal_reserved_history_fails_startup(self):
        journal = self.journal()
        journal.allocate("c1" * 16, "d1" * 32, "V" + "9" * 25, 1)
        document = json.loads(Path(self.path).read_text())
        first = document["records"][0]
        second = dict(first)
        second.update(
            {
                "request_id": "c2" * 16,
                "descriptor_index": 3,
                "script_pubkey": self.binding["script_pubkeys"][3],
                "btc_address": self.backend.address(3),
                "state": "reserved",
            }
        )
        document["records"].append(second)
        Path(self.path).write_text(json.dumps(document) + "\n")
        with self.assertRaisesRegex(RuntimeError, "not contiguous"):
            self.journal()

    def test_persisted_address_must_rederive_to_exact_index(self):
        journal = self.journal()
        journal.allocate("e1" * 16, "f1" * 32, "V" + "A" * 25, 1)
        document = json.loads(Path(self.path).read_text())
        document["records"][0]["btc_address"] = self.backend.address(2)
        Path(self.path).write_text(json.dumps(document) + "\n")
        with self.assertRaisesRegex(RuntimeError, "differs from descriptor"):
            self.journal()


class AdmissionProofTests(unittest.TestCase):
    def test_wrap_proof_is_exact_bound_and_time_limited(self):
        request = {
            "request_id": "aa" * 16,
            "veld_address": "V" + "1" * 25,
            "amount_sats": 123,
            "admission_timestamp": 1_000_000,
        }
        with (
            mock.patch.object(wrapd, "ADMISSION_POW_BITS", 16),
            mock.patch.object(wrapd, "ADMISSION_POW_MAX_AGE_S", 300),
        ):
            for counter in range(1 << 20):
                nonce = "%016x" % counter
                message = "\x00".join(
                    (
                        "VELD-WRAP-ADMISSION-POW-v1",
                        request["request_id"],
                        request["veld_address"],
                        str(request["amount_sats"]),
                        str(request["admission_timestamp"]),
                        nonce,
                    )
                ).encode("ascii")
                if hashlib.sha256(message).digest()[:2] == b"\x00\x00":
                    request["admission_nonce"] = nonce
                    break
            else:  # pragma: no cover - overwhelmingly impossible
                self.fail("did not find a 16-bit proof")
            self.assertTrue(wrapd._verify_admission_pow(request, now=1_000_001))
            changed = dict(request, amount_sats=124)
            with self.assertRaisesRegex(ValueError, "difficulty"):
                wrapd._verify_admission_pow(changed, now=1_000_001)
            with self.assertRaisesRegex(ValueError, "stale"):
                wrapd._verify_admission_pow(request, now=1_000_301)


if __name__ == "__main__":
    unittest.main()
