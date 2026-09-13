"""Offline collector control-flow fixtures; no signing or Bitcoin execution."""
import base64
import copy
import json
import subprocess
import time
import unittest
from unittest import mock

from swap import veld_redeemd as rd


TXID = "a1" * 32
PSBT = lambda name: base64.b64encode(b"psbt\xff" + name.encode()).decode()
CONFIG = {"mode": "threshold_psbt", "threshold": 3,
          "signers": [{"id": f"s{i}", "command": [f"fixture-s{i}"]}
                      for i in range(1, 6)]}


def witness():
    script = b"".join(b"\x20" + bytes([i + 1]) * 32 +
                      bytes([0xac if i == 0 else 0xba]) for i in range(5)) + b"\x53\x9c"
    # Inert bytes: the fake Core below models its independent verification result.
    return ["01" * 64, "02" * 64, "03" * 64, "", "", script.hex(), "c0" + "00" * 32]


class CoreModel:
    def __init__(self, healthy=("s1", "s2", "s3"), inputs=2):
        self.healthy = set(healthy)
        self.inputs = inputs
        self.combinations = []
        self.deadlines = []
        self.last = ()
        self.accepted = True
        self.key_path = False

    def call(self, method, *args, deadline=None):
        self.deadlines.append(deadline)
        if method == "decoderawtransaction":
            vin = [{} for _ in range(self.inputs)]
            if args[0] != "00":
                for item in vin:
                    item["txinwitness"] = ["01" * 64] if self.key_path else witness()
            return {"txid": TXID, "vin": vin}
        if method == "converttopsbt":
            return PSBT("unsigned")
        if method == "walletprocesspsbt":
            return {"psbt": PSBT("unsigned")}
        if method == "decodepsbt":
            return {"tx": {"txid": TXID}, "inputs": [{} for _ in range(self.inputs)]}
        if method == "combinepsbt":
            self.last = tuple(base64.b64decode(p)[5:].decode() for p in json.loads(args[0]))
            self.combinations.append(self.last)
            return PSBT("combined")
        if method == "finalizepsbt":
            complete = len(set(self.last) & self.healthy) >= 3
            return {"complete": complete, "hex": "0100"} if complete else {"complete": False}
        if method == "testmempoolaccept":
            return [{"txid": TXID, "allowed": self.accepted}]
        raise AssertionError(method)


class PayoutCollectionTests(unittest.TestCase):
    def test_single_wallet_mode_cannot_bypass_fixed_threshold(self):
        core = CoreModel()
        with self.assertRaisesRegex(RuntimeError, "fixed 3-of-5"):
            rd.sign_payout(core, "00", {}, {
                "mode": "single_wallet_dev", "allow_unsafe_single_wallet": True})
        self.assertEqual(core.deadlines, [])

    def test_native_reserve_cannot_fall_through_to_legacy_payout(self):
        for peg in (None, [], {"reserve_semantics": None},
                    {"reserve_semantics": "rolling-outpoint-v1"},
                    {"reserve_semantics": "unknown-future-policy"}):
            with self.subTest(peg=peg), self.assertRaises(RuntimeError):
                rd.require_compatible_payout_authority(peg)

    def collect(self, core, responses=None, cfg=None):
        self.requests = []
        responses = responses or {}

        def transport(command, **kwargs):
            sid = command[0].removeprefix("fixture-")
            self.requests.append((sid, json.loads(kwargs["input_text"]), kwargs["timeout"]))
            response = responses.get(sid, {"signer_id": sid, "psbt": PSBT(sid)})
            return subprocess.CompletedProcess(command, 0, json.dumps(response), "")

        with mock.patch.object(rd, "run_bounded_subprocess", side_effect=transport):
            return rd.sign_payout(core, "00", {}, cfg or CONFIG)

    def test_normal_quorum_and_same_unsigned_proposal(self):
        core = CoreModel()
        raw, contributors = self.collect(core)
        self.assertEqual((raw, contributors), ("0100", ["s1", "s2", "s3"]))
        self.assertEqual({r[1]["psbt"] for r in self.requests}, {PSBT("unsigned")})
        self.assertTrue(all(isinstance(d, float) for d in core.deadlines))

    def test_unusable_early_partials_do_not_poison_healthy_subset(self):
        core = CoreModel(("s3", "s4", "s5"))
        self.assertEqual(self.collect(core)[1], ["s3", "s4", "s5"])
        self.assertEqual(len(self.requests), 5)
        self.assertLessEqual(len(core.combinations), 16)

    def test_response_schema_and_duplicate_partial_are_skipped(self):
        for first in (None, [], {"signer_id": "s1", "psbt": 1},
                      {"signer_id": "other", "psbt": PSBT("s1")}):
            with self.subTest(response=first):
                core = CoreModel(("s3", "s4", "s5"))
                self.assertEqual(self.collect(core, {"s1": first, "s2": first})[1],
                                 ["s3", "s4", "s5"])

    def test_insufficient_actual_signature_quorum_refused(self):
        core = CoreModel(("s1", "s2"))
        with self.assertRaisesRegex(RuntimeError, "No usable"):
            self.collect(core)
        self.assertEqual(len(self.requests), 5)

    def test_complete_flag_without_core_acceptance_is_refused(self):
        core = CoreModel()
        core.accepted = False
        with self.assertRaisesRegex(RuntimeError, "No usable"):
            self.collect(core)

    def test_key_path_witness_is_not_3_of_5(self):
        core = CoreModel()
        core.key_path = True
        with self.assertRaisesRegex(RuntimeError, "No usable"):
            self.collect(core)

    def test_all_input_witnesses_must_have_exact_threshold(self):
        tx = {"vin": [{"txinwitness": witness()}, {"txinwitness": witness()}]}
        self.assertTrue(rd._has_exact_custody_witness(tx))
        tx["vin"][1]["txinwitness"][0] = ""
        self.assertFalse(rd._has_exact_custody_witness(tx))

    def test_committing_sighash_variants(self):
        tx = {"vin": [{"txinwitness": witness()}]}
        tx["vin"][0]["txinwitness"][0] += "01"
        self.assertTrue(rd._has_exact_custody_witness(tx))

    def test_fixed_membership_and_threshold(self):
        cfg = copy.deepcopy(CONFIG)
        cfg["threshold"] = 2
        with self.assertRaisesRegex(RuntimeError, "exactly 3-of-5"):
            self.collect(CoreModel(), cfg=cfg)

    def test_command_deadline_stops_before_transport(self):
        core = rd.Btc(["fixture-bitcoin-cli"], None)
        with mock.patch.object(rd, "run_bounded_subprocess") as transport:
            with self.assertRaisesRegex(RuntimeError, "deadline"):
                core.call("decodepsbt", PSBT("unsigned"), deadline=time.monotonic() - 1)
            transport.assert_not_called()

    def test_unavailable_command_and_parser_failure_allow_remaining_quorum(self):
        for failure in (FileNotFoundError("fixture unavailable"), RecursionError("fixture parser")):
            contacted = []
            def transport(command, **kwargs):
                sid = command[0].removeprefix("fixture-")
                contacted.append(sid)
                if sid == "s1" and isinstance(failure, OSError):
                    raise failure
                return subprocess.CompletedProcess(command, 0, json.dumps(
                    {"signer_id": sid, "psbt": PSBT(sid)}), "")
            parse = rd.strict_json_loads
            def parser(value, *args):
                if json.loads(value)["signer_id"] == "s1" and isinstance(failure, RecursionError):
                    raise failure
                return parse(value, *args)
            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(rd, "run_bounded_subprocess", side_effect=transport), \
                    mock.patch.object(rd, "strict_json_loads", side_effect=parser):
                result = rd.sign_payout(CoreModel(("s2", "s3", "s4")), "00", {}, CONFIG)
                self.assertEqual(result[1], ["s2", "s3", "s4"])
                self.assertEqual(contacted, ["s1", "s2", "s3", "s4"])

    def test_observation_failures_allow_remaining_quorum(self):
        from swap.test_redemption_durability import BURN
        for failure in (FileNotFoundError("fixture unavailable"), RecursionError("fixture parser")):
            def transport(command, **kwargs):
                sid = command[0].removeprefix("fixture-")
                if sid == "s1" and isinstance(failure, OSError):
                    raise failure
                return subprocess.CompletedProcess(command, 0, json.dumps(
                    {"signer_id": sid, "observed": [rd.redeem_id(BURN)]}), "")
            parse = rd.strict_json_loads
            def parser(value, *args):
                if json.loads(value)["signer_id"] == "s1" and isinstance(failure, RecursionError):
                    raise failure
                return parse(value, *args)
            with self.subTest(failure=type(failure).__name__), \
                    mock.patch.object(rd, "run_bounded_subprocess", side_effect=transport), \
                    mock.patch.object(rd, "strict_json_loads", side_effect=parser):
                self.assertEqual(rd.replicate_observations(CONFIG, [BURN]), ["s2", "s3", "s4", "s5"])


if __name__ == "__main__":
    unittest.main()
