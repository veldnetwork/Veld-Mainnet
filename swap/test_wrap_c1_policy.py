#!/usr/bin/env python3
"""Focused owner-C1 boundary and fail-closed acceptance tests."""
import copy
import json
import subprocess
import tempfile
from pathlib import Path
import unittest
from unittest import mock

from swap import swap_admission
from swap import veld_wrapd as wrapd
from swap import veld_wt_reserve as witness


def policy():
    value = dict(witness.C1_POLICY_EXACT)
    value.update({
        "record_sequence": 1,
        "previous_policy_sha256": "0" * 64,
        "public_descriptor_range": [1000, 10999],
        "archive_authority_id": "c4-test-authority",
    })
    return value


def row(at=0, amount=10_000, principal="p", destination="Vdest",
        *, funded=None, expires=604800):
    return {
        "admitted_at": at, "amount_sats": amount,
        "principal_hash": principal, "veld_address": destination,
        "deposit_observed_at": funded, "funded_reserved_at": funded,
        "expires_at": expires,
    }


class C1PolicyTests(unittest.TestCase):
    def test_signed_policy_is_exact_and_range_only_rises_by_linked_record(self):
        approved = policy()
        self.assertEqual(wrapd.validate_c1_policy(approved), approved)
        self.assertEqual(witness._validate_c1_policy(approved), approved)
        for name, value in (("pow_bits", 23),
                            ("minimum_allocation_sats", 9_999),
                            ("consensus_custody_ceiling_sats", 1_000_000)):
            changed = dict(approved, **{name: value})
            with self.subTest(name=name), self.assertRaises((RuntimeError, SystemExit)):
                wrapd.validate_c1_policy(changed)
        raised = dict(approved, record_sequence=2,
                      previous_policy_sha256="a" * 64,
                      public_descriptor_range=[1000, 11000])
        self.assertEqual(wrapd.validate_c1_policy(raised), raised)
        lowered = dict(raised, public_descriptor_range=[1000, 10998])
        with self.assertRaises(RuntimeError):
            wrapd.validate_c1_policy(lowered)

    def test_range_raise_is_parsed_but_both_services_refuse_activation_without_f4(self):
        old_hash = "a" * 64
        new_hash = "b" * 64
        raised = dict(
            policy(), record_sequence=2,
            previous_policy_sha256=old_hash,
            public_descriptor_range=[1000, 11000])
        cfg = {"wrap_allocation_authority": {
            "version": 2, "initial_descriptor_index": 1000,
            "allow_initial_ledger_creation": False,
            "checkpoint_command": ["/bin/checkpoint"],
        }}
        document = {
            "version": witness.ALLOCATION_LEDGER_VERSION,
            "initial_descriptor_index": 1000,
            "capacity_policy_sha256": old_hash,
            "capacity_policy_sequence": 1,
            "public_descriptor_range_end": 10999,
            "last_consensus_sequence": 0,
            "allocations": [], "events": [],
        }
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "allocations.json"
            path.write_text(json.dumps(document))
            path.chmod(0o600)
            with self.assertRaises(SystemExit):
                witness._load_allocation_ledger(
                    str(path), cfg,
                    {"range": [0, 11000],
                     "script_pubkeys": tuple("" for _ in range(11001))},
                    raised, new_hash)
            with self.assertRaisesRegex(RuntimeError,
                                        "C1_RANGE_ROTATION_REQUIRED"):
                wrapd.require_supported_allocation_range(raised)

    def test_public_index_boundaries_match_allocator_and_witness(self):
        approved = policy()
        for index, accepted in ((10998, True), (10999, True), (11000, False)):
            with self.subTest(index=index):
                self.assertIs(wrapd._c1_public_index_allowed(index, approved), accepted)
                self.assertIs(witness._c1_public_index_allowed(index, approved), accepted)

    def test_minimum_and_sat_ceiling_boundaries(self):
        approved = policy()
        candidate = row(amount=10_000, principal="candidate", destination="Vnew")
        ledger = {"allocations": []}
        below = dict(candidate, amount_sats=9_999)
        self.assertIn("minimum", witness._c1_capacity_reason(
            ledger, below, approved, 0))
        self.assertIsNone(witness._c1_capacity_reason(
            ledger, candidate, approved, 0))

        for total, rejected in ((999_999_999, False), (1_000_000_000, False),
                                (1_000_000_001, True)):
            prior = total - 10_000
            principal_ledger = {"allocations": [row(
                amount=prior, principal="candidate", destination="Vother")]}
            reason = witness._c1_capacity_reason(
                principal_ledger, candidate, approved, 0)
            self.assertEqual(reason is not None, rejected, (total, reason))
            destination_candidate = dict(candidate, principal_hash="different")
            destination_ledger = {"allocations": [row(
                amount=prior, principal="other", destination="Vnew")]}
            reason = witness._c1_capacity_reason(
                destination_ledger, destination_candidate, approved, 0)
            self.assertEqual(reason is not None, rejected, (total, reason))

    def test_fresh_headroom_charges_active_nonminted_allocations_once(self):
        approved = policy()
        first = dict(row(amount=62_500, principal="p1", destination="V1"),
                     minted_at=None)
        second = dict(row(amount=62_500, principal="p2", destination="V2"),
                      minted_at=None)
        self.assertIn("headroom", witness._c1_capacity_reason(
            {"allocations": [first]}, second, approved, 0,
            issuer_headroom_sats=100_000, issuer_reserved_sats=0))
        self.assertIn("headroom", witness._c1_capacity_reason(
            {"allocations": []}, second, approved, 0,
            issuer_headroom_sats=50_000, issuer_reserved_sats=0))

        # Canonical C1R1 liability is already subtracted from the RPC's net
        # headroom.  Matching issuer_reserved_sats must prevent double charge.
        self.assertIsNone(witness._c1_capacity_reason(
            {"allocations": [first]},
            dict(row(amount=10_000, principal="p3", destination="V3"),
                 minted_at=None), approved, 0,
            issuer_headroom_sats=37_500, issuer_reserved_sats=62_500))

        # Once the exact accepted transition is checkpointed, consensus
        # headroom already reflects it; do not charge that allocation twice.
        first["minted_at"] = 10
        residual = dict(row(amount=10_000, principal="p3", destination="V3"),
                        minted_at=None)
        self.assertIsNone(witness._c1_capacity_reason(
            {"allocations": [first]}, residual, approved, 0,
            issuer_headroom_sats=37_500, issuer_reserved_sats=0))

    def test_epoch_and_day_boundaries(self):
        approved = policy()
        candidate = row(at=60_000, principal="candidate", destination="Vnew",
                        expires=700_000)
        for total, rejected in ((4, False), (5, False), (6, True)):
            existing = total - 1
            ledger = {"allocations": [row(
                at=60_000, principal="p%d" % i, destination="V%d" % i,
                expires=700_000) for i in range(existing)]}
            reason = witness._c1_capacity_reason(
                ledger, candidate, approved, 60_000)
            self.assertEqual(reason is not None, rejected, (total, reason))

        for total, rejected in ((199, False), (200, False), (201, True)):
            existing = total - 1
            rows = [row(at=(i // 4) * 600, principal="p%d" % i,
                        destination="V%d" % i, expires=700_000)
                    for i in range(existing)]
            candidate_day = row(at=80_000, principal="candidate",
                                destination="Vnew", expires=700_000)
            reason = witness._c1_capacity_reason(
                {"allocations": rows}, candidate_day, approved, 80_000)
            self.assertEqual(reason is not None, rejected, (total, reason))

    def test_day_seven_releases_unfunded_quota_but_not_funded_quota(self):
        approved = policy()
        candidate = row(at=604_800, principal="same", destination="Vnew",
                        expires=1_209_600)
        expired = row(amount=1_000_000_000, principal="same", destination="Vold",
                      expires=604_800)
        self.assertIsNone(witness._c1_capacity_reason(
            {"allocations": [expired]}, candidate, approved, 604_800))
        funded = dict(expired, deposit_observed_at=604_799,
                      funded_reserved_at=604_799)
        self.assertIn("principal", witness._c1_capacity_reason(
            {"allocations": [funded]}, candidate, approved, 604_800))

    def test_storage_reserve_boundaries(self):
        approved = policy()
        max_rows = approved["journal_max_rows"]
        max_bytes = approved["journal_max_bytes"]
        self.assertTrue(witness._c1_storage_allows(
            89_999, max_bytes * 9 // 10 - 1, approved, new_admission=True))
        self.assertFalse(witness._c1_storage_allows(
            90_000, 1, approved, new_admission=True))
        self.assertTrue(witness._c1_storage_allows(
            95_000, max_bytes * 95 // 100, approved, new_admission=False))
        self.assertFalse(witness._c1_storage_allows(
            100_000, 1, approved, new_admission=False))

    def test_current_beacon_signature_tuple_and_rotation(self):
        authority = swap_admission.AdmissionBeacon(
            random_bytes=lambda count: b"r" * count)
        request = {
            "request_id": "aa" * 16,
            "veld_address": "V" + "1" * 33,
            "amount_sats": 10_000,
            "admission_nonce": "00" * 8,
            "admission_public_key": "00" * 1952,
            "admission_signature": "00" * 3309,
        }
        request["admission_beacon"] = authority.current(now=1)["beacon"]
        with mock.patch.object(wrapd, "PRODUCTION", True), \
             mock.patch.object(wrapd, "_C1_POLICY", policy()), \
             mock.patch.object(wrapd, "_C1_POLICY_SHA256", "a" * 64), \
             mock.patch.object(wrapd, "_ADMISSION_BEACON", authority), \
             mock.patch.object(wrapd, "has_leading_zero_bits", return_value=True):
            principal = wrapd._verify_admission_pow(
                request, now=1,
                signature_verifier=lambda key, message, signature: True)
            self.assertEqual(principal, __import__("hashlib").sha256(
                bytes.fromhex(request["admission_public_key"])).hexdigest())
            with self.assertRaisesRegex(ValueError, "not current"):
                wrapd._verify_admission_pow(
                    request, now=600,
                    signature_verifier=lambda key, message, signature: True)

    def test_c5_and_peg_unlock_phases_fail_closed(self):
        tip = "a" * 64
        def backend(method, *args):
            if method == "getblockchaininfo":
                return {"chain": "main", "initialblockdownload": False,
                        "blocks": 10, "headers": 10, "bestblockhash": tip}
            if method == "getblockheader":
                return {"hash": tip, "time": 1_000}
            raise AssertionError(method)
        with mock.patch.object(wrapd, "PRODUCTION", True), \
             mock.patch.object(wrapd, "_btc_json", side_effect=backend):
            observed = {}
            for age, expected in ((3_599, "FRESH"), (3_600, "ALERT"),
                                  (7_199, "ALERT"),
                                  (7_200, "RECOVERY_ONLY"),
                                  (7_201, "RECOVERY_ONLY")):
                with self.subTest(age=age):
                    observed[age] = wrapd._bitcoin_freshness(now=1_000 + age)
                    self.assertEqual(observed[age]["phase"], expected)
        self.assertEqual(wrapd._public_allocation_gate({}, {"phase": "FRESH"}),
                         "PEG_LOCKED")
        peg = {"peg_unlocked": True, "mint_live": True}
        for age in (3_599, 3_600, 7_199):
            self.assertEqual(
                wrapd._public_allocation_gate(peg, observed[age]), "OPEN")
        for age in (7_200, 7_201):
            self.assertEqual(
                wrapd._public_allocation_gate(peg, observed[age]),
                "RECOVERY_ONLY")

    def test_policy_hash_mismatch_and_worm_ack_fail_closed(self):
        record = {
            "request_id": "aa" * 16, "principal_hash": "bb" * 32,
            "veld_address": "V" + "1" * 33, "amount_sats": 100_000,
            "descriptor_index": 1000, "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "11" * 32,
            "admitted_at": 1, "expires_at": 604_801,
            "commitment_blind": "22" * 32,
            "consensus_allocation_id": "%032x" % 1,
        }
        wrong = {"version": 4, "action": "preflight_allocation",
                 "request_id": record["request_id"], "descriptor_index": 1000,
                 "authorized": True, "idempotent": False,
                 "commitment_blind": record["commitment_blind"],
                 "consensus_allocation_id":
                    record["consensus_allocation_id"],
                 "capacity_policy_sha256": "c" * 64}
        completed = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps(wrong), stderr="")
        with mock.patch.object(wrapd, "ALLOCATION_WITNESS_COMMAND", ("/bin/x",)), \
             mock.patch.object(wrapd, "_C1_POLICY_SHA256", "a" * 64), \
             mock.patch.object(wrapd, "run_bounded_subprocess", return_value=completed), \
             self.assertRaisesRegex(RuntimeError, "policy hash"):
            wrapd._call_allocation_witness("preflight_allocation", record)

        cfg = {"wrap_allocation_authority": {
            "version": 2, "initial_descriptor_index": 1000,
            "allow_initial_ledger_creation": False,
            "checkpoint_command": ["/bin/checkpoint"],
        }}
        ledger = {"last_consensus_sequence": 0,
                  "allocations": [], "events": []}
        bad_ack = subprocess.CompletedProcess(
            [], 0, stdout=json.dumps({"version": 1}), stderr="")
        with mock.patch.object(witness, "run_bounded_subprocess",
                               return_value=bad_ack), \
             self.assertRaises(SystemExit):
            witness._checkpoint_allocation_ledger(cfg, ledger, "a" * 64, "store")

    def test_real_allocator_uses_public_range_and_five_per_epoch(self):
        approved = policy()
        scripts = tuple("5120%064x" % (index + 1) for index in range(11000))
        binding = {"descriptor": "tr(c1)#test", "range": [0, 10999],
                   "script_pubkeys": scripts}
        labels = {}
        chain_sequence = [0]

        def address(index):
            return "bc1p" + ("q" * 50) + ("%08d" % index)

        def btc_json(method, *args):
            if method == "listdescriptors":
                return {"descriptors": [{"desc": binding["descriptor"],
                                          "range": binding["range"],
                                          "active": False,
                                          "internal": False}]}
            if method == "deriveaddresses":
                first, last = [int(value) for value in
                               args[1].strip("[]").split(",")]
                return [address(index) for index in range(first, last + 1)]
            if method == "getaddressinfo":
                index = int(args[0][-8:])
                return {"scriptPubKey": scripts[index],
                        "iswatchonly": True, "solvable": True,
                        "labels": ([{"name": labels[args[0]]}]
                                   if args[0] in labels else [])}
            raise AssertionError(method)

        def btc_text(method, *args):
            self.assertEqual(method, "setlabel")
            labels[args[0]] = args[1]
            return ""

        def checkpoint(*args, **kwargs):
            request = json.loads(kwargs["input_text"])
            answer = {"version": 2, "stored": True,
                      "action": request["action"],
                      "capacity_policy_sha256": "a" * 64,
                      "journal_sha256": request["journal_sha256"],
                      "last_consensus_sequence":
                          request["last_consensus_sequence"],
                      "monotonic_sequence": 1}
            return subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(answer), stderr="")

        lifecycle = {}

        def register(record, verify=False):
            state = lifecycle.get(record["request_id"], (None, None, None))
            return {"expires_at": record["expires_at"],
                    "deposit_observed_at": state[0],
                    "funded_reserved_at": state[1],
                    "minted_at": state[2]}

        def ensure(record):
            sequence = int(record["consensus_allocation_id"], 16)
            chain_sequence[0] = max(chain_sequence[0], sequence)
            return {
                "allocation_id": record["consensus_allocation_id"],
                "created_height": 10, "exposed_height": 111,
                "confirmations": 202, "tip": 312,
                "funded": False, "funding_outpoint": None,
                "send_starts_height": 212,
                "recommended_send_cutoff_height": 3_170,
                "funding_accepts_through_height": 3_271,
                "funding_expires_height": 3_371,
            }

        def sequence_status(allocation_id_value):
            return {"allocation_id": allocation_id_value,
                    "last_sequence": chain_sequence[0]}

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(wrapd, "_btc_json", side_effect=btc_json), \
             mock.patch.object(wrapd, "_btc", side_effect=btc_text), \
             mock.patch.object(wrapd, "ALLOCATION_CHECKPOINT_COMMAND",
                               ("/bin/checkpoint",)), \
             mock.patch.object(wrapd, "run_bounded_subprocess",
                               side_effect=checkpoint):
            journal = wrapd.WrapAllocationJournal(
                str(Path(directory) / "c1.json"), binding, None,
                max_bytes=64 * 1024 * 1024, policy=approved,
                policy_sha256="a" * 64,
                preflight_allocation=lambda record: True,
                register_allocation=register,
                ensure_consensus_reservation=ensure,
                sequence_status=sequence_status,
                allow_initialize=True, clock=lambda: 60_000)
            issued_indices = set()
            for index in range(5):
                result = journal.allocate(
                    "%032x" % (index + 1), "%064x" % (index + 1),
                    "V" + chr(ord("A") + index) * 25, 100_000)
                self.assertTrue(1000 <= result["descriptor_index"] <= 10999)
                self.assertNotIn(result["descriptor_index"], issued_indices)
                issued_indices.add(result["descriptor_index"])
                self.assertEqual(result["consensus_allocation_id"],
                                 "%032x" % (index + 1))
                self.assertIs(result["send_allowed"], True)
            with self.assertRaisesRegex(RuntimeError, "epoch"):
                journal.allocate("f" * 32, "e" * 64,
                                 "V" + "Z" * 25, 100_000)

            # The durable uint64 high-water is independent of terminal rows.
            # A WORM-authorized compaction may remove them, but sequence 1--5
            # can never become available again.
            store = Path(directory) / "c1.json"
            compacted = json.loads(store.read_text())
            compacted["records"] = []
            compacted["events"] = []
            store.write_text(json.dumps(compacted) + "\n")
            store.chmod(0o600)
            restarted = wrapd.WrapAllocationJournal(
                str(store), binding, None,
                max_bytes=64 * 1024 * 1024, policy=approved,
                policy_sha256="a" * 64,
                preflight_allocation=lambda record: True,
                register_allocation=register,
                ensure_consensus_reservation=ensure,
                sequence_status=sequence_status,
                allow_initialize=False, clock=lambda: 61_000)
            next_result = restarted.allocate(
                "6" * 32, "6" * 64, "V" + "Y" * 25, 10_000)
            self.assertEqual(next_result["consensus_allocation_id"],
                             "%032x" % 6)
            self.assertEqual(restarted.last_consensus_sequence, 6)


if __name__ == "__main__":
    unittest.main()
