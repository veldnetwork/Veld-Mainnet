#!/usr/bin/env python3
import copy
import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import veld_watchtowerd as wd
import test_chain_identity as chain_fixture


def p2tr_address(script):
    raw = bytes.fromhex(script[4:])
    charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    data = [1]; acc = 0; bits = 0
    for byte in raw:
        acc = (acc << 8) | byte; bits += 8
        while bits >= 5:
            bits -= 5; data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    def polymod(values):
        check = 1
        generators = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa,
                      0x3d4233dd, 0x2a1462b3)
        for value in values:
            top = check >> 25; check = ((check & 0x1ffffff) << 5) ^ value
            for index, generator in enumerate(generators):
                if (top >> index) & 1: check ^= generator
        return check
    expanded = [ord(c) >> 5 for c in "bc"] + [0] + [ord(c) & 31 for c in "bc"]
    mod = polymod(expanded + data + [0] * 6) ^ 0x2bc830a3
    checksum = [(mod >> (5 * (5 - index))) & 31 for index in range(6)]
    return "bc1" + "".join(charset[value] for value in data + checksum)


class FakeBtc:
    chain = "main"
    descriptor = ""
    wallet_descriptor = ""
    rows = []
    addresses = []
    ibd = False
    blocks = 900000
    headers = 900000
    header_time = 0

    def __init__(self, cli, wallet):
        self.wallet = wallet

    def call(self, method, *args):
        if method == "getblockchaininfo":
            return {"chain": self.chain, "blocks": self.blocks,
                    "headers": self.headers,
                    "bestblockhash": "77" * 32,
                    "initialblockdownload": self.ibd}
        if method == "getblockheader":
            return {"hash": "77" * 32, "time": self.header_time}
        if method == "getdescriptorinfo":
            return {"hasprivatekeys": False, "isrange": True}
        if method == "listdescriptors":
            return {"descriptors": [{"desc": self.wallet_descriptor,
                                      "internal": False, "active": False,
                                      "range": [0, 10999]}]}
        if method == "deriveaddresses": return list(self.addresses)
        if method == "listunspent": return copy.deepcopy(self.rows)
        if method == "listsinceblock":
            return {"transactions": [], "removed": []}
        raise AssertionError(method)


class FakeVeld:
    def __init__(self, binding, k_btc=6):
        self.binding = binding
        self.k_btc = k_btc

    def rpc(self, method, params=None):
        if method in ("getnetworkinfo", "getcompiledgenesis", "getblockhash"):
            return chain_fixture.ChainIdentityTests().node()[2](method, params or [])
        if method == "getpeginfo":
            return {
                "active": True, "spv_active": True, "token_id": "btcVELD",
                "spv_k_btc": self.k_btc,
                "custody_descriptor_sha256": self.binding["descriptor_sha256"],
                "custody_manifest_sha256":
                    self.binding["consensus_manifest_sha256"],
                "custody_descriptor_range": [0, 999],
                "spv_custody_descriptor_index": 0,
                "spv_custody_spk_hex": self.binding["spv_custody_spk_hex"],
            }
        if method == "getbtcveldredeems":
            cursor = params[0]
            return {"tip": 123, "tip_hash": "66" * 32,
                    "final_height": 123, "cursor": cursor,
                    "next_cursor": cursor, "has_more": False,
                    "page_limit": 512, "redeems": [],
                    **wd.redeem_liability.authority_for_rows([])}
        raise AssertionError(method)


class ProductionCustodyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wt-production-")
        root = Path(self.temp.name)
        self.state = root / "state"; self.state.mkdir(mode=0o700)
        self.rpc_token = root / "rpc-token"
        self.rpc_token.write_text("11" * 32)
        self.rpc_token.chmod(0o600)
        self.descriptor = json.loads((Path(__file__).parent / "fixtures" /
                                      "custody-policy-descriptor.json").read_text())["descriptor"]
        self.scripts = ["5120%064x" % i for i in range(1, 11001)]
        FakeBtc.addresses = [p2tr_address(script) for script in self.scripts]
        self.hash = hashlib.sha256(self.descriptor.encode()).hexdigest()
        self.manifest = root / "custody-spks.json"
        document = {
            "version": 1, "descriptor": self.descriptor,
            "descriptor_sha256": self.hash, "range": [0, 10999],
            "script_pubkeys": self.scripts,
        }
        self.manifest.write_text(json.dumps(document))
        self.manifest_hash = hashlib.sha256(self.manifest.read_bytes()).hexdigest()
        prefix = dict(document); prefix["range"] = [0, 999]
        prefix["script_pubkeys"] = self.scripts[:1000]
        self.consensus_manifest_hash = hashlib.sha256((json.dumps(
            prefix, sort_keys=True, separators=(",", ":")) + "\n").encode()
        ).hexdigest()
        FakeBtc.chain = "main"
        FakeBtc.descriptor = self.descriptor
        FakeBtc.wallet_descriptor = self.descriptor
        FakeBtc.rows = [{"scriptPubKey": self.scripts[0],
                         "confirmations": 6, "amount": "0.00000123"}]
        FakeBtc.ibd = False
        FakeBtc.blocks = 900000
        FakeBtc.headers = 900000
        FakeBtc.header_time = int(time.time())
        self.cfg = {
            "production": True,
            "veld_rpc": {"url": "http://127.0.0.1",
                         "expected_chain": dict(chain_fixture.CHAIN),
                         "token_file": str(self.rpc_token)},
            "btc": {"cli_base": ["bitcoin-cli"], "wallet": "custody-watch",
                    "confirmations": 6, "tip_age_alert_secs": 3600,
                    "max_tip_age_secs": 7200},
            "custody_addresses": [],
            "custody_spk_manifest_file": str(self.manifest),
            "custody_descriptor_sha256": self.hash,
            "custody_manifest_sha256": self.manifest_hash,
            "custody_consensus_manifest_sha256":
                self.consensus_manifest_hash,
            "public_descriptor_range_end": 10999,
            "signer": {"ssh_target": "signer", "beat_keyfile": ""},
            "state_dir": str(self.state), "margin_sats": 1, "ttl_secs": 120,
        }

    def tearDown(self): self.temp.cleanup()

    def make(self, cfg=None):
        with mock.patch.object(wd, "Btc", FakeBtc), \
             mock.patch.object(
                 wd.witness_reserve, "_load_signed_c1_policy",
                 return_value=({"public_descriptor_range": [1000, 10999]},
                               "77" * 32)):
            return wd.Watchtower(copy.deepcopy(cfg or self.cfg))

    def test_exact_local_descriptor_wallet_balance(self):
        watchtower = self.make()
        self.assertEqual(watchtower.production_capacity_policy_sha256,
                         "77" * 32)
        self.assertEqual(watchtower.read_custody(), 123)
        FakeBtc.rows.append({"scriptPubKey": "5120" + "ff" * 32,
                             "confirmations": 20, "amount": "99.0"})
        with self.assertRaisesRegex(RuntimeError, "unrelated custody script"):
            watchtower.read_custody()

    def test_missing_chain_pins_stop_before_token_access(self):
        cfg = copy.deepcopy(self.cfg)
        del cfg["veld_rpc"]["expected_chain"]
        with mock.patch.object(wd, "Veld") as client:
            with self.assertRaisesRegex(ValueError, "expected_chain"):
                self.make(cfg)
            client.assert_not_called()

    def test_chain_identity_rechecked_before_supply(self):
        watchtower = self.make()
        rpc = FakeVeld(watchtower.production_binding)
        watchtower.veld = rpc
        watchtower._verify_production_veld_identity()
        with mock.patch.object(rpc, "rpc", return_value=None) as call:
            with self.assertRaisesRegex(ValueError, "identity is unavailable"):
                watchtower.read_supply()
            call.assert_called_once_with("getnetworkinfo", [])

    def test_unavailable_chain_cannot_sign_or_publish_a_beat(self):
        watchtower = self.make()
        sequence = watchtower.seq
        with mock.patch.object(watchtower, "_verify_production_veld_identity",
                               side_effect=ValueError("intended chain unavailable")), \
                mock.patch.object(watchtower, "_sign_payload") as sign, \
                mock.patch.object(watchtower, "_push") as publish:
            with self.assertRaisesRegex(ValueError, "intended chain unavailable"):
                watchtower.push_beat(20000, 10000, 10000, 123, "66" * 32)
            self.assertEqual(watchtower.seq, sequence)
            sign.assert_not_called()
            publish.assert_not_called()

    def test_operational_range_must_match_signed_c1_policy(self):
        cfg = copy.deepcopy(self.cfg)
        cfg["public_descriptor_range_end"] = 11000
        with self.assertRaisesRegex(RuntimeError, "differs from signed C1 policy"):
            self.make(cfg)

    def test_production_rejects_api_duplicate_addresses_nonmain_and_unrelated_wallet(self):
        api = copy.deepcopy(self.cfg); api["btc"]["api"] = "mempool"
        with self.assertRaisesRegex(RuntimeError, "local Bitcoin Core"):
            self.make(api)
        duplicate = copy.deepcopy(self.cfg)
        duplicate["custody_addresses"] = ["bc1x", "bc1x"]
        with self.assertRaisesRegex(RuntimeError, "unique"):
            self.make(duplicate)
        FakeBtc.chain = "test"
        with self.assertRaisesRegex(RuntimeError, "not mainnet"):
            self.make()
        FakeBtc.chain = "main"; FakeBtc.wallet_descriptor = "wpkh(unrelated)#bad"
        with self.assertRaisesRegex(RuntimeError, "exactly the pinned"):
            self.make()

    def test_manifest_hash_and_duplicate_spks_fail_closed(self):
        bad = json.loads(self.manifest.read_text())
        bad["script_pubkeys"][1] = bad["script_pubkeys"][0]
        self.manifest.write_text(json.dumps(bad))
        with self.assertRaisesRegex(RuntimeError, "manifest"):
            self.make()

    def test_production_rejects_ibd_header_lag_and_enters_recovery_on_stale_tip(self):
        FakeBtc.ibd = True
        with self.assertRaisesRegex(RuntimeError, "IBD/header lag"):
            self.make()
        FakeBtc.ibd = False; FakeBtc.headers += 1
        with self.assertRaisesRegex(RuntimeError, "IBD/header lag"):
            self.make()
        FakeBtc.headers = FakeBtc.blocks
        FakeBtc.header_time = int(time.time()) - self.cfg["btc"]["max_tip_age_secs"] - 1
        self.assertEqual(self.make().last_c5_phase, "RECOVERY_ONLY")

    def test_c5_exact_config_and_five_point_watchtower_boundaries(self):
        for field, value in (("tip_age_alert_secs", 3599),
                             ("tip_age_alert_secs", 3601),
                             ("max_tip_age_secs", 7199),
                             ("max_tip_age_secs", 7201)):
            with self.subTest(config_field=field, value=value):
                cfg = copy.deepcopy(self.cfg); cfg["btc"][field] = value
                with self.assertRaisesRegex(RuntimeError, "configured"):
                    self.make(cfg)

        expected = {
            3_599: "FRESH", 3_600: "ALERT", 7_199: "ALERT",
            7_200: "RECOVERY_ONLY", 7_201: "RECOVERY_ONLY",
        }
        for age, phase in expected.items():
            with self.subTest(age=age):
                FakeBtc.header_time = 100_000 - age
                with mock.patch.object(wd.time, "time", return_value=100_000):
                    watchtower = self.make()
                    self.assertEqual(watchtower.last_c5_phase, phase)

        # A running process recovers admissions without restart or state loss.
        FakeBtc.header_time = 100_000
        with mock.patch.object(wd.time, "time", return_value=100_000):
            watchtower = self.make()
            FakeBtc.header_time = 100_000 - 7_200
            self.assertEqual(
                watchtower._production_bitcoin_chain_identity(),
                (FakeBtc.blocks, "77" * 32))
            self.assertEqual(watchtower.last_c5_phase, "RECOVERY_ONLY")
            FakeBtc.header_time = 100_000 - 3_599
            self.assertEqual(
                watchtower._production_bitcoin_chain_identity(),
                (FakeBtc.blocks, "77" * 32))
            self.assertEqual(watchtower.last_c5_phase, "FRESH")

    def test_full_snapshot_binds_compiled_k_and_rebuilds_liability(self):
        watchtower = self.make()
        watchtower.veld = FakeVeld(watchtower.production_binding, k_btc=6)
        watchtower._verify_production_veld_identity()
        custody, backing = watchtower.read_production_backing_snapshot(
            123, 123, "66" * 32)
        self.assertEqual((custody, backing), (123, 123))
        self.assertEqual(watchtower.last_liability_stats["canonical_redeems"], 0)
        self.assertEqual(watchtower.last_liability_stats["bitcoin_tip"], 900000)

        mismatched = copy.deepcopy(self.cfg)
        mismatched["btc"]["confirmations"] = 5
        watchtower = self.make(mismatched)
        watchtower.veld = FakeVeld(watchtower.production_binding, k_btc=6)
        with self.assertRaisesRegex(RuntimeError, "compiled spv_k_btc"):
            watchtower._verify_production_veld_identity()


if __name__ == "__main__":
    unittest.main(verbosity=2)
