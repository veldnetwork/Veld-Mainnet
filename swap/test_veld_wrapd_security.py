#!/usr/bin/env python3
import http.client
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from swap import veld_wrapd as wrapd


class WrapConfigurationTests(unittest.TestCase):
    def test_configuration_is_absolute_owner_only_bounded_strict_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wrapd.json"
            path.write_text('{"production":false}', encoding="utf-8")
            path.chmod(0o600)
            self.assertEqual(wrapd.load_configuration(str(path)),
                             {"production": False})
            with self.assertRaisesRegex(RuntimeError, "absolute"):
                wrapd.load_configuration("wrapd.json")

            path.write_text('{"production":false,"production":true}',
                            encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "strict UTF-8 JSON"):
                wrapd.load_configuration(str(path))

            path.write_text('{"production":false}', encoding="utf-8")
            path.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "owner-only"):
                wrapd.load_configuration(str(path))

    def test_exact_scalars_loopback_command_and_production_cors(self):
        valid = {
            "production": True,
            "development_only_allow_unsafe_allocator": False,
            "cli_base": ["/usr/bin/bitcoin-cli"],
            "bind": "127.0.0.1",
            "port": 8097,
            "rl_per_ip_per_min": 6,
            "rl_global_per_min": 60,
            "cors_origin": "https://wallet.example",
            "public_capacity_policy_version": 2,
            "allocation_store": "/var/lib/veld-wrapd/allocations.json",
            "allow_initial_allocation_store_creation": False,
            "allocation_witness_command": ["/usr/bin/ssh", "wrap-witness"],
            "allocation_checkpoint_command": ["/usr/bin/checkpoint"],
            "consensus_reservation_command": ["/usr/bin/c1-reservationd"],
            "admission_verifier": "/usr/bin/veld-keygen",
            "public_capacity_config_file": "/etc/veld/c1.json",
            "public_capacity_config_signature_file": "/etc/veld/c1.sig",
            "public_capacity_config_public_key_file": "/etc/veld/c1.pub",
        }
        settings = wrapd.validate_configuration(valid)
        self.assertEqual(settings["cors_origin"], "https://wallet.example")
        for field, bad in (
                ("production", 1), ("port", "8097"),
                ("rl_per_ip_per_min", True),
                ("rl_global_per_min", 0),
                ("http_max_workers", 1.0),
                ("http_request_read_timeout_s", "15")):
            conf = dict(valid)
            conf[field] = bad
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                wrapd.validate_configuration(conf)
        for update in (
                {"bind": "0.0.0.0"},
                {"cli_base": ["bitcoin-cli"]},
                {"cors_origin": "*"},
                {"cors_origin": "http://wallet.example"},
                {"cors_origin": "https://wallet.example/path"},
                {"cors_origin": "https://user@wallet.example"},
        ):
            conf = dict(valid)
            conf.update(update)
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                wrapd.validate_configuration(conf)
        no_cors = dict(valid)
        no_cors["cors_origin"] = None
        self.assertIsNone(
            wrapd.validate_configuration(no_cors)["cors_origin"])

        missing_policy = dict(valid)
        del missing_policy["public_capacity_config_signature_file"]
        with self.assertRaisesRegex(RuntimeError, "policy is incomplete"):
            wrapd.validate_configuration(missing_policy)

        unsafe_production = dict(valid)
        unsafe_production["development_only_allow_unsafe_allocator"] = True
        with self.assertRaisesRegex(RuntimeError, "false in production"):
            wrapd.validate_configuration(unsafe_production)

    def test_development_allocator_needs_conspicuous_main_guard(self):
        with mock.patch.object(wrapd, "PRODUCTION", False), \
                mock.patch.object(
                    wrapd, "DEVELOPMENT_ONLY_ALLOW_UNSAFE_ALLOCATOR", False):
            with self.assertRaisesRegex(RuntimeError, "explicitly set"):
                wrapd.main()

    def test_allocation_witness_ack_is_exact_and_verify_is_nonmutating(self):
        record = {
            "request_id": "aa" * 16,
            "principal_hash": "bb" * 32,
            "veld_address": "V" + "1" * 33,
            "amount_sats": 100000,
            "descriptor_index": 1000,
            "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "11" * 32,
            "admitted_at": 1,
            "expires_at": 604801,
            "commitment_blind": "22" * 32,
            "consensus_allocation_id": "%032x" % 1,
            "state": "allocated",
        }

        def completed(action, idempotent):
            answer = {
                "version": 4, "action": action,
                "request_id": record["request_id"],
                "descriptor_index": 1000, "authorized": True,
                "capacity_policy_sha256": "cc" * 32,
                "commitment_blind": record["commitment_blind"],
                "consensus_allocation_id":
                    record["consensus_allocation_id"],
                "idempotent": idempotent,
            }
            if action in ("register_allocation", "verify_allocation"):
                answer.update({"expires_at": record["expires_at"],
                               "deposit_observed_at": None,
                               "funded_reserved_at": None,
                               "minted_at": None})
            return subprocess.CompletedProcess(
                [], 0, stdout=json.dumps(answer), stderr="")

        with mock.patch.object(
                wrapd, "ALLOCATION_WITNESS_COMMAND", ("/usr/bin/ssh", "w")), \
             mock.patch.object(wrapd, "_C1_POLICY_SHA256", "cc" * 32), \
             mock.patch.object(wrapd, "run_bounded_subprocess",
                               return_value=completed(
                                   "register_allocation", False)) as run:
            self.assertFalse(
                wrapd._register_allocation_with_witness(record)["idempotent"])
            payload = json.loads(run.call_args.kwargs["input_text"])
            self.assertEqual(payload["action"], "register_allocation")

        with mock.patch.object(
                wrapd, "ALLOCATION_WITNESS_COMMAND", ("/usr/bin/ssh", "w")), \
             mock.patch.object(wrapd, "_C1_POLICY_SHA256", "cc" * 32), \
             mock.patch.object(wrapd, "run_bounded_subprocess",
                               return_value=completed(
                                   "verify_allocation", True)):
            self.assertTrue(wrapd._register_allocation_with_witness(
                record, verify_only=True)["idempotent"])

        with mock.patch.object(
                wrapd, "ALLOCATION_WITNESS_COMMAND", ("/usr/bin/ssh", "w")), \
             mock.patch.object(wrapd, "_C1_POLICY_SHA256", "cc" * 32), \
             mock.patch.object(wrapd, "run_bounded_subprocess",
                               return_value=completed(
                                   "verify_allocation", False)):
            with self.assertRaisesRegex(RuntimeError, "acknowledgement"):
                wrapd._register_allocation_with_witness(
                    record, verify_only=True)


class AtomicDualWindowLimiterTests(unittest.TestCase):
    def test_limits_are_atomic_bounded_and_rejections_do_not_grow_state(self):
        now = [100.0]
        limiter = wrapd.AtomicDualWindowLimiter(
            2, 3, capacity=2, maintenance_budget=1,
            clock=lambda: now[0])
        self.assertTrue(limiter.allow("198.51.100.1"))
        self.assertTrue(limiter.allow("198.51.100.1"))
        for _ in range(20):
            self.assertFalse(limiter.allow("198.51.100.1"))
        self.assertTrue(limiter.allow("198.51.100.2"))
        for index in range(20):
            self.assertFalse(limiter.allow("203.0.113.%d" % index))
        self.assertEqual(limiter.source_count(), 2)
        self.assertEqual(limiter.stored_hits(), 6)

        now[0] = 161.0
        self.assertTrue(limiter.allow("203.0.113.9"))
        self.assertLessEqual(limiter.source_count(), 2)
        self.assertLessEqual(limiter.stored_hits(), 2 * 3)

    def test_concurrent_requests_share_one_global_window(self):
        limiter = wrapd.AtomicDualWindowLimiter(
            50, 20, clock=lambda: 10.0)
        barrier = threading.Barrier(50)
        answers = []
        answer_lock = threading.Lock()

        def hit(index):
            barrier.wait()
            answer = limiter.allow("198.51.100.%d" % index)
            with answer_lock:
                answers.append(answer)

        workers = [threading.Thread(target=hit, args=(index,))
                   for index in range(50)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        self.assertEqual(sum(answers), 20)
        self.assertEqual(limiter.source_count(), 20)


class CustodyAllocatorSeparationTests(unittest.TestCase):
    def setUp(self):
        self.script = "5120" + "11" * 32
        self.binding = {
            "descriptor": "tr(test)#checksum",
            "spv_custody_spk_hex": self.script,
        }
        self.entry = {
            "desc": self.binding["descriptor"],
            "active": True,
            "internal": False,
            "range": [0, 999],
            "next": 1,
        }

    def backend(self, labels):
        def call(method, *_args):
            if method == "deriveaddresses":
                return ["bc1p" + "q" * 58]
            if method == "getaddressinfo":
                return {"scriptPubKey": self.script, "labels": labels}
            raise AssertionError(method)
        return call

    def test_index_zero_is_reserved_and_unlabelled_for_issuer_allocation(self):
        with mock.patch.object(wrapd, "_btc_json",
                               side_effect=self.backend([])):
            wrapd._verify_descriptor_allocator_separation(
                self.entry, self.binding)
        with mock.patch.object(
                wrapd, "_btc_json",
                side_effect=self.backend([{"name": "SPV-RESERVED"}])):
            wrapd._verify_descriptor_allocator_separation(
                self.entry, self.binding)

    def test_zero_exhausted_or_recipient_labelled_allocator_fails_closed(self):
        for next_index in (0, 1000, True, "1"):
            entry = dict(self.entry, next=next_index)
            with self.subTest(next_index=next_index), \
                    mock.patch.object(wrapd, "_btc_json",
                                      side_effect=self.backend([])), \
                    self.assertRaisesRegex(
                        RuntimeError, r"(?:\[1,999\]|malformed)"):
                wrapd._verify_descriptor_allocator_separation(
                    entry, self.binding)

        veld = "V" + "1" * 25
        with mock.patch.object(
                wrapd, "_btc_json", side_effect=self.backend([veld])), \
                self.assertRaisesRegex(RuntimeError, "issuer-recipient"):
            wrapd._verify_descriptor_allocator_separation(
                self.entry, self.binding)

    def test_index_zero_script_and_label_metadata_are_exact(self):
        bad_backends = (
            lambda method, *_args: (["bc1p" + "q" * 58]
                                    if method == "deriveaddresses" else
                                    {"scriptPubKey": "5120" + "22" * 32,
                                     "labels": []}),
            self.backend(None),
            self.backend([{"not_name": "x"}]),
        )
        for backend in bad_backends:
            with self.subTest(backend=backend), \
                    mock.patch.object(wrapd, "_btc_json",
                                      side_effect=backend), \
                    self.assertRaises(RuntimeError):
                wrapd._verify_descriptor_allocator_separation(
                    self.entry, self.binding)


class BoundedCliTests(unittest.TestCase):
    def test_command_output_and_json_are_strictly_bounded(self):
        code, stdout, stderr = wrapd._run_bounded_command(
            [sys.executable, "-c", "print('ok')"], 32, 32, 5, "test")
        self.assertEqual(code, 0)
        self.assertEqual(stdout, b"ok\n")
        self.assertEqual(stderr, b"")

        with self.assertRaisesRegex(RuntimeError, "stdout exceeds"):
            wrapd._run_bounded_command(
                [sys.executable, "-c", "print('x'*10000)"],
                32, 32, 5, "test")
        with mock.patch.object(
                wrapd, "_btc_output", return_value=b'{"ok":1,"ok":2}'):
            with self.assertRaisesRegex(ValueError, "repeats field"):
                wrapd._btc_json("getblockchaininfo")


class WrapHttpBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = wrapd.BoundedThreadingTCPServer(
            ("127.0.0.1", 0), wrapd.Handler, max_workers=8,
            request_read_timeout_s=3)
        cls.thread = threading.Thread(target=cls.server.serve_forever,
                                      daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def setUp(self):
        self.patches = mock.patch.multiple(
            wrapd,
            PRODUCTION=False,
            CONF={"max_wrap_sats": 62_500},
            CORS_ORIGIN=None,
            _RATE_LIMITER=wrapd.AtomicDualWindowLimiter(100, 1000),
        )
        self.patches.start()

    def tearDown(self):
        self.patches.stop()

    def request(self, method, target, body=None, headers=None):
        connection = http.client.HTTPConnection(
            self.server.server_address[0], self.server.server_address[1],
            timeout=3)
        try:
            connection.request(method, target, body=body,
                               headers=headers or {})
            response = connection.getresponse()
            raw = response.read()
            payload = json.loads(raw) if raw else None
            return response.status, dict(response.getheaders()), payload
        finally:
            connection.close()

    def test_post_requires_exact_target_framing_content_type_and_json_schema(self):
        body = b'{"veld_address":"V1111111111111111111111111","amount_sats":1}'
        status, _, _ = self.request(
            "POST", "/wrap", body, {"Content-Type": "text/plain"})
        self.assertEqual(status, 415)

        duplicate = (b'{"veld_address":"V1111111111111111111111111",'
                     b'"amount_sats":1,"amount_sats":2}')
        status, _, _ = self.request(
            "POST", "/wrap", duplicate,
            {"Content-Type": "application/json"})
        self.assertEqual(status, 400)

        extra = (b'{"veld_address":"V1111111111111111111111111",'
                 b'"amount_sats":1,"extra":true}')
        status, _, _ = self.request(
            "POST", "/wrap", extra,
            {"Content-Type": "application/json"})
        self.assertEqual(status, 400)

        status, _, _ = self.request(
            "POST", "/wrap?ignored=1", body,
            {"Content-Type": "application/json"})
        self.assertEqual(status, 404)

    def test_development_only_one_sat_fixture_uses_bounded_backend_parsers(self):
        # This one-satoshi behavior exists only for the conspicuously unsafe,
        # non-production fixture.  The production handler boundaries are
        # exercised independently below and must never inherit this allowance.
        self.assertIs(wrapd.PRODUCTION, False)
        veld = "V" + "1" * 25
        btc = "bc1p" + "q" * 58

        def btc_json(method, *_args):
            if method == "getaddressinfo":
                return {"scriptPubKey": "5120" + "00" * 32}
            raise AssertionError(method)

        with mock.patch.object(wrapd, "_btc", return_value=btc) as btc_call, \
                mock.patch.object(wrapd, "_btc_json", side_effect=btc_json):
            status, headers, payload = self.request(
                "POST", "/wrap",
                json.dumps({"veld_address": veld,
                            "amount_sats": 1}).encode("utf-8"),
                {"Content-Type": "application/json",
                 "X-Real-IP": "198.51.100.9",
                 "X-Forwarded-For": "198.51.100.9"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["btc_address"], btc)
        self.assertEqual(payload["min_sats"], 1)
        self.assertEqual(payload["max_sats"], 1_000_000_000)
        self.assertIs(payload["consensus_capacity_reserved"], False)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers["Connection"], "close")
        btc_call.assert_called_once_with("getnewaddress", veld, "bech32m")

    def test_production_http_enforces_owner_wrap_range_and_reports_health(self):
        veld = "V" + "2" * 25
        peg = {
            "peg_unlocked": True,
            "mint_live": True,
            "issuer_max_per_mint_sats": 1_000_000_000,
            "issuer_static_custody_cap_sats": 1_000_000_000,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 0,
            "issuer_mint_headroom_sats": 62_500,
            "supply_sats": 37_500,
            "tip": 200,
            "spv_k_btc": 6,
        }
        tip_hash = "44" * 32

        def veld_rpc(method, params=None):
            if method == "getpeginfo":
                return dict(peg)
            if method == "getbtcveldsupply":
                return {"supply_sats": peg["supply_sats"], "tip": peg["tip"],
                        "tip_hash": "55" * 32}
            if method == "getblockhash":
                return "55" * 32
            if method == "validateaddress":
                address = params[0]
                return {"isvalid": True, "address": address,
                        "network": "mainnet"}
            raise AssertionError(method)

        def btc_rpc(method, *_args):
            if method == "getblockchaininfo":
                return {"chain": "main", "initialblockdownload": False,
                        "blocks": 100, "headers": 100,
                        "bestblockhash": tip_hash}
            if method == "getblockheader":
                return {"hash": tip_hash, "time": int(wrapd.time.time())}
            if method == "getwalletinfo":
                return {"walletname": "fixture"}
            raise AssertionError(method)

        allocator = mock.Mock()
        allocator.capacity.return_value = {
            "public_indices_remaining": 10_000,
            "new_admission_capacity": True,
        }
        allocator.has_request.return_value = False
        allocator.allocate.side_effect = lambda request_id, principal, address, amount: {
            "request_id": request_id,
            "principal_hash": principal,
            "veld_address": address,
            "amount_sats": amount,
            "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "11" * 32,
            "expires_at": 999_999_999,
            "deposit_observed_at": None,
            "funded_reserved_at": None,
            "minted_at": None,
            "lifecycle": "UNFUNDED",
            "send_allowed": True,
            "consensus_capacity_reserved": True,
            "consensus_reservation_created_height": 10,
            "consensus_reservation_exposed_height": 111,
            "send_starts_height": 211,
            "recommended_send_cutoff_height": 3_170,
            "funding_accepts_through_height": 3_271,
            "funding_expires_height": 3_371,
            "current_height": 211,
        }
        admission_beacon = mock.Mock()
        admission_beacon.current.return_value = {"beacon": "66" * 32}

        def production_body(amount):
            return {
                "veld_address": veld,
                "amount_sats": amount,
                "request_id": "%032x" % amount,
                "admission_beacon":
                    wrapd._ADMISSION_BEACON.current()["beacon"],
                "admission_nonce": "00" * 8,
                "admission_public_key": "00" * 1952,
                "admission_signature": "00" * 3309,
            }

        with mock.patch.multiple(
                wrapd,
                PRODUCTION=True,
                CONF={"admission_verifier": "/usr/bin/veld-keygen"},
                _custody={"fixture": True},
                _C1_POLICY={"pow_bits": 24},
                _C1_POLICY_SHA256="55" * 32,
                _ALLOCATOR=allocator,
                _ADMISSION_BEACON=admission_beacon,
                _RATE_LIMITER=wrapd.AtomicDualWindowLimiter(100, 1000)), \
             mock.patch.object(wrapd, "_veld", side_effect=veld_rpc), \
             mock.patch.object(wrapd, "_btc_json", side_effect=btc_rpc), \
             mock.patch.object(wrapd.custody_binding, "verify_peg_identity"), \
             mock.patch.object(wrapd, "has_leading_zero_bits",
                               return_value=True) as pow_check, \
             mock.patch.object(wrapd, "verify_mldsa65_with_keygen",
                               return_value=True) as signature_check:
            status, _, health = self.request("GET", "/health")
            self.assertEqual(status, 200)
            self.assertIs(health["ok"], True)
            self.assertEqual(health["min_wrap_sats"], 10_000)
            self.assertEqual(health["max_wrap_sats"], 62_500)
            self.assertEqual(
                health["consensus_capacity_reservation"],
                "C1R1_C1E1_C1C1_C1F1_MNP2")

            results = {}
            for amount in (9_999, 10_000, 62_500, 62_501):
                status, _, payload = self.request(
                    "POST", "/wrap",
                    json.dumps(production_body(amount)).encode("utf-8"),
                    {"Content-Type": "application/json"})
                results[amount] = (status, payload)

            # Close new admission and reduce current headroom below the
            # historical amount. A recorded exact retry must still reach its
            # authoritative FUNDED/EXPIRED lifecycle status.
            peg.update({"supply_sats": 100_000,
                        "issuer_mint_headroom_sats": 0})
            allocator.has_request.side_effect = lambda request_id: (
                request_id == "%032x" % 10_000)
            allocator.allocate.side_effect = lambda request_id, principal, address, amount: {
                "request_id": request_id, "principal_hash": principal,
                "veld_address": address, "amount_sats": amount,
                "expires_at": 999_999_999,
                "deposit_observed_at": 122,
                "funded_reserved_at": 123,
                "minted_at": None, "lifecycle": "FUNDED_RESERVED",
                "send_allowed": False, "consensus_capacity_reserved": True,
                "send_starts_height": 211,
                "recommended_send_cutoff_height": 3_170,
                "funding_accepts_through_height": 3_271,
                "funding_expires_height": 3_371,
                "current_height": 212,
            }
            funded_status, _, funded_payload = self.request(
                "POST", "/wrap",
                json.dumps(production_body(10_000)).encode("utf-8"),
                {"Content-Type": "application/json"})
            closed_status, _, closed_payload = self.request(
                "POST", "/wrap",
                json.dumps(production_body(10_001)).encode("utf-8"),
                {"Content-Type": "application/json"})
            allocator.allocate.side_effect = lambda request_id, principal, address, amount: {
                "request_id": request_id, "principal_hash": principal,
                "veld_address": address, "amount_sats": amount,
                "expires_at": 999_999_999,
                "deposit_observed_at": 122,
                "funded_reserved_at": 123,
                "minted_at": 456, "lifecycle": "MINTED",
                "send_allowed": False, "consensus_capacity_reserved": True,
                "send_starts_height": 211,
                "recommended_send_cutoff_height": 3_170,
                "funding_accepts_through_height": 3_271,
                "funding_expires_height": 3_371,
                "current_height": 213,
            }
            minted_status, _, minted_payload = self.request(
                "POST", "/wrap",
                json.dumps(production_body(10_000)).encode("utf-8"),
                {"Content-Type": "application/json"})
            allocator.allocate.side_effect = wrapd.ExpiredAllocation(777)
            expired_status, _, expired_payload = self.request(
                "POST", "/wrap",
                json.dumps(production_body(10_000)).encode("utf-8"),
                {"Content-Type": "application/json"})

        for amount in (9_999, 62_501):
            status, payload = results[amount]
            self.assertEqual(status, 400)
            self.assertEqual(payload["min_sats"], 10_000)
            self.assertEqual(payload["max_sats"], 62_500)
        for amount in (10_000, 62_500):
            status, payload = results[amount]
            self.assertEqual(status, 200)
            self.assertEqual(payload["amount_sats"], amount)
            self.assertEqual(payload["min_sats"], 10_000)
            self.assertEqual(payload["max_sats"], 62_500)
            self.assertEqual(payload["confirmations"], 6)
            self.assertEqual(payload["mint_path"], "issuer")
            self.assertIs(payload["send_allowed"], True)
            self.assertIs(payload["consensus_capacity_reserved"], True)
            self.assertIn("capacity remains held", payload["capacity_warning"])
            self.assertIn("btc_address", payload)

        self.assertEqual(funded_status, 200)
        self.assertEqual(funded_payload["lifecycle"], "FUNDED_RESERVED")
        self.assertIs(funded_payload["send_allowed"], False)
        self.assertIs(funded_payload["consensus_capacity_reserved"], True)
        self.assertNotIn("btc_address", funded_payload)
        self.assertNotIn("script_pubkey", funded_payload)
        self.assertEqual(closed_status, 503)
        self.assertEqual(closed_payload["status"], "AT_CAPACITY")
        self.assertIs(closed_payload["request_recorded"], False)
        self.assertEqual(minted_status, 200)
        self.assertEqual(minted_payload["lifecycle"], "MINTED")
        self.assertIs(minted_payload["send_allowed"], False)
        self.assertIs(minted_payload["consensus_capacity_reserved"], True)
        self.assertNotIn("btc_address", minted_payload)
        self.assertEqual(expired_status, 410)
        self.assertEqual(expired_payload["lifecycle"], "EXPIRED")
        self.assertIs(expired_payload["send_allowed"], False)
        self.assertIs(expired_payload["consensus_capacity_reserved"], False)
        self.assertNotIn("btc_address", expired_payload)

        self.assertEqual(
            [call.args[3] for call in allocator.allocate.call_args_list],
            [10_000, 62_500, 10_000, 10_000, 10_000])
        self.assertEqual(pow_check.call_count, 8)
        self.assertEqual(signature_check.call_count, 8)

    def test_open_to_stalled_allocation_never_reveals_btc_address(self):
        veld = "V" + "7" * 25
        open_peg = {
            "peg_unlocked": True, "mint_live": True,
            "issuer_max_per_mint_sats": 1_000_000_000,
            "issuer_static_custody_cap_sats": 1_000_000_000,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 0,
            "issuer_mint_headroom_sats": 100_000,
            "supply_sats": 0, "tip": 200, "spv_k_btc": 6,
        }
        stalled_peg = dict(open_peg, mint_live=False)
        allocator = mock.Mock()
        allocator.has_request.return_value = False
        allocator.allocate.side_effect = lambda request_id, principal, address, amount: {
            "request_id": request_id, "principal_hash": principal,
            "veld_address": address, "amount_sats": amount,
            "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "11" * 32,
            "expires_at": 999_999_999,
            "deposit_observed_at": None, "funded_reserved_at": None,
            "minted_at": None, "lifecycle": "UNFUNDED",
            "send_allowed": True, "consensus_capacity_reserved": True,
            "send_starts_height": 212,
            "recommended_send_cutoff_height": 3_170,
            "funding_accepts_through_height": 3_271,
            "funding_expires_height": 3_371,
            "current_height": 212,
        }

        def body(request_id):
            return {
                "veld_address": veld, "amount_sats": 10_000,
                "request_id": request_id,
                "admission_beacon": "66" * 32,
                "admission_nonce": "00" * 8,
                "admission_public_key": "00" * 1952,
                "admission_signature": "00" * 3309,
            }

        with mock.patch.multiple(
                wrapd, PRODUCTION=True, _ALLOCATOR=allocator,
                _RATE_LIMITER=wrapd.AtomicDualWindowLimiter(100, 1000)), \
             mock.patch.object(
                 wrapd, "_verify_production_identity",
                 side_effect=[open_peg, stalled_peg, open_peg, open_peg]), \
             mock.patch.object(
                 wrapd, "_bitcoin_freshness",
                 return_value={"phase": "FRESH", "tip_age_seconds": 0}), \
             mock.patch.object(wrapd, "_verify_admission_pow",
                               return_value="aa" * 32), \
             mock.patch.object(wrapd, "_validate_veld_destination",
                               return_value=True):
            stalled_status, _, stalled = self.request(
                "POST", "/wrap", json.dumps(body("11" * 16)).encode(),
                {"Content-Type": "application/json"})
            open_status, _, opened = self.request(
                "POST", "/wrap", json.dumps(body("22" * 16)).encode(),
                {"Content-Type": "application/json"})

        self.assertEqual(stalled_status, 200)
        self.assertIs(stalled["send_allowed"], False)
        self.assertEqual(stalled["lifecycle"], "RECOVERY_ONLY")
        self.assertNotIn("btc_address", stalled)
        self.assertNotIn("script_pubkey", stalled)
        self.assertEqual(open_status, 200)
        self.assertIs(opened["send_allowed"], True)
        self.assertIn("btc_address", opened)

    def test_proxy_attribution_and_query_shape_fail_closed(self):
        status, _, _ = self.request(
            "GET", "/health",
            headers={"X-Real-IP": "198.51.100.1",
                     "X-Forwarded-For": "198.51.100.2"})
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "GET", "/spk?address=a&address=b")
        self.assertEqual(status, 400)
        status, _, _ = self.request("GET", "/health?ignored=1")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
