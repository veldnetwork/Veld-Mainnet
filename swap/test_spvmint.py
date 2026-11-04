#!/usr/bin/env python3
"""Focused, network-free tests for the launch-live SPV operator."""

import os
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from swap import veld_spvmint as spv


RECIPIENT = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg"
FUND = "VUjD1JoewGkiGxRqJ52FkK1UiMotjsp9Tg"
CUSTODY_SPK = bytes.fromhex("5120" + "22" * 32)
CHANGE_SPK = bytes.fromhex("0014" + "33" * 20)


def compact(value):
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + struct.pack("<I", value)
    return b"\xff" + struct.pack("<Q", value)


def op_return(data):
    if len(data) <= 75:
        return b"\x6a" + bytes([len(data)]) + data
    if len(data) <= 255:
        return b"\x6a\x4c" + bytes([len(data)]) + data
    return b"\x6a\x4d" + struct.pack("<H", len(data)) + data


def output(value, script):
    return struct.pack("<Q", value) + compact(len(script)) + script


def veld_transaction(op_string, change=400_000):
    fund_spk = spv.veld_p2pkh_from_address(FUND)
    version = struct.pack("<I", 2)
    vin = (
        compact(1)
        + b"\x55" * 32
        + struct.pack("<I", 1)
        + compact(0)
        + struct.pack("<I", 0xFFFFFFFE)
    )
    outputs = []
    if change:
        outputs.append(output(change, fund_spk))
    outputs.append(output(0, spv._canonical_op_return(op_string.encode("ascii"))))
    return (version + vin + compact(len(outputs)) + b"".join(outputs) + struct.pack("<I", 0)).hex()


def sign_veld_transaction(unsigned_hex, script=b"\x51"):
    raw = bytes.fromhex(unsigned_hex)
    # The fixture has exactly one canonical input. Offset 41 is its zero-length
    # scriptSig CompactSize; signing replaces only that field and its bytes.
    return (raw[:41] + compact(len(script)) + script + raw[42:]).hex()


def transaction(outputs, segwit=False):
    version = struct.pack("<I", 2)
    vin = (
        compact(1)
        + b"\x11" * 32
        + struct.pack("<I", 1)
        + compact(0)
        + struct.pack("<I", 0xFFFFFFFE)
    )
    vout = compact(len(outputs)) + b"".join(outputs)
    locktime = struct.pack("<I", 7)
    legacy = version + vin + vout + locktime
    if not segwit:
        return legacy, legacy
    witness = compact(2) + compact(2) + b"\xaa\xbb" + compact(3) + b"\x01\x02\x03"
    wire = version + b"\x00\x01" + vin + vout + witness + locktime
    return wire, legacy


def valid_outputs(amount=50_000, duplicate_custody=False, duplicate_marker=False):
    marker = op_return(spv.RECIPIENT_TAG + RECIPIENT.encode("ascii"))
    outputs = [output(amount, CUSTODY_SPK), output(0, marker), output(10_000, CHANGE_SPK)]
    if duplicate_custody:
        outputs.append(output(1, CUSTODY_SPK))
    if duplicate_marker:
        outputs.append(output(0, marker))
    return outputs


def peg(supply=0):
    return {
        "active": True,
        "spv_active": True,
        "token_id": "btcVELD",
        "supply_sats": supply,
        "spv_max_per_mint_sats": 100_000,
        "spv_max_custody_sats": 200_000,
        "spv_k_btc": 6,
    }


class PureTests(unittest.TestCase):
    def test_operator_rpc_rejects_loopback_prefix_authority_bypass(self):
        with tempfile.TemporaryDirectory() as directory:
            token_file = os.path.join(directory, "token")
            with open(token_file, "w", encoding="ascii") as handle:
                handle.write("ab" * 32 + "\n")
            os.chmod(token_file, 0o600)
            for url in (
                "http://localhost:@evil.example/rpc",
                "http://127.0.0.1:8332@evil.example/rpc",
                "http://localhost.example:8332/rpc",
            ):
                with self.subTest(url=url):
                    with self.assertRaises(RuntimeError):
                        spv.VeldRPC({"url": url, "token_file": token_file})
            rpc = spv.VeldRPC(
                {
                    "url": "http://[::1]:8332/rpc",
                    "token_file": token_file,
                }
            )
            self.assertEqual(rpc.url, "http://[::1]:8332/rpc")
            self.assertEqual(rpc.token, "ab" * 32)

    def test_strips_witness_without_changing_txid_serialization(self):
        wire, legacy = transaction(valid_outputs(), segwit=True)
        parsed = spv.parse_and_strip_bitcoin_tx(wire)
        self.assertTrue(parsed["segwit"])
        self.assertEqual(parsed["legacy"], legacy)
        self.assertEqual(spv.dsha(parsed["legacy"]), spv.dsha(legacy))

    def test_legacy_transaction_is_byte_exact(self):
        wire, legacy = transaction(valid_outputs(), segwit=False)
        parsed = spv.parse_and_strip_bitcoin_tx(wire)
        self.assertFalse(parsed["segwit"])
        self.assertEqual(parsed["legacy"], legacy)

    def test_deposit_validation_derives_exact_vout_recipient_amount(self):
        _, legacy = transaction(valid_outputs())
        found = spv.validate_deposit_tx(legacy, CUSTODY_SPK.hex(), peg(), RECIPIENT, 50_000)
        self.assertEqual(found, {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0})

    def test_deposit_validation_rejects_ambiguous_outputs(self):
        _, duplicate_custody = transaction(valid_outputs(duplicate_custody=True))
        with self.assertRaisesRegex(RuntimeError, "exactly one index-0"):
            spv.validate_deposit_tx(duplicate_custody, CUSTODY_SPK.hex(), peg())
        _, duplicate_marker = transaction(valid_outputs(duplicate_marker=True))
        with self.assertRaisesRegex(RuntimeError, "exactly one btcVELD"):
            spv.validate_deposit_tx(duplicate_marker, CUSTODY_SPK.hex(), peg())

    def test_deposit_validation_rechecks_live_aggregate_headroom(self):
        _, legacy = transaction(valid_outputs(amount=50_000))
        with self.assertRaisesRegex(RuntimeError, "headroom"):
            spv.validate_deposit_tx(legacy, CUSTODY_SPK.hex(), peg(175_001))

    def test_merkle_branch_matches_odd_width_bitcoin_tree(self):
        leaves = [spv.dsha(bytes([n])) for n in range(5)]
        for index, leaf in enumerate(leaves):
            branch, dirs, root = spv.build_merkle_branch(leaves, index)
            self.assertEqual(spv.fold_merkle(leaf, branch, dirs), root)
            self.assertLessEqual(len(branch), 32)

    def test_strict_parser_rejects_unknown_witness_flag_and_trailing_bytes(self):
        wire, _ = transaction(valid_outputs(), segwit=True)
        with self.assertRaisesRegex(RuntimeError, "witness marker"):
            spv.parse_and_strip_bitcoin_tx(wire[:5] + b"\x02" + wire[6:])
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            spv.parse_and_strip_bitcoin_tx(wire + b"\x00")

    def test_recipient_requires_base58check_not_only_address_shape(self):
        malformed = RECIPIENT[:-1] + ("1" if RECIPIENT[-1] != "1" else "2")
        self.assertRegex(malformed, spv.VELD_ADDRESS_RE)
        with self.assertRaisesRegex(RuntimeError, "checksum"):
            spv.veld_p2pkh_from_address(malformed, "recipient")

    def test_prepared_and_signed_veld_transactions_are_byte_bound(self):
        op = spv.OP_PREFIX + (spv.PROOF_MAGIC + b"z" * 64).hex()
        unsigned = veld_transaction(op)
        prepared = {
            "unsigned_tx_hex": unsigned,
            "inputs": [
                {
                    "index": 0,
                    "sighash_hex": "66" * 32,
                    "prev_script_hex": spv.veld_p2pkh_from_address(FUND).hex(),
                }
            ],
            "total_input": 500_000,
            "total_output": 0,
            "fee": spv.VELD_OP_FEE_UNITS,
            "change": 400_000,
        }
        parsed, _spk, _fee, _total = spv.validate_prepared_op(prepared, FUND, op)
        signed = spv.parse_veld_tx_hex(sign_veld_transaction(unsigned), signed=True)
        self.assertEqual(signed["unsigned_hex"], parsed["raw"].hex())

        bad_spk = bytes.fromhex("76a914" + "77" * 20 + "88ac")
        altered = bytes.fromhex(unsigned).replace(spv.veld_p2pkh_from_address(FUND), bad_spk).hex()
        prepared["unsigned_tx_hex"] = altered
        with self.assertRaisesRegex(RuntimeError, "exact MSPV outputs"):
            spv.validate_prepared_op(prepared, FUND, op)

    def test_signed_veld_parser_rejects_trailing_and_oversized_work(self):
        op = spv.OP_PREFIX + (spv.PROOF_MAGIC + b"q" * 32).hex()
        signed = sign_veld_transaction(veld_transaction(op))
        with self.assertRaisesRegex(RuntimeError, "trailing"):
            spv.parse_veld_tx_hex(signed + "00", signed=True)
        with mock.patch.object(spv, "MAX_VELD_TX_BYTES", 16):
            with self.assertRaisesRegex(RuntimeError, "safety bound"):
                spv.parse_veld_tx_hex(signed, signed=True)

    def test_state_rejects_hardlinks_duplicate_json_and_oversize(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "spvmint-state.json")
            spv.save_state(path, {"schema": spv.STATE_SCHEMA, "bitcoin_txs": {}, "deposits": {}})
            linked = os.path.join(directory, "linked-state.json")
            os.link(path, linked)
            with self.assertRaisesRegex(RuntimeError, "non-linked"):
                spv.load_state(path)
            os.unlink(linked)

            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"schema":1,"schema":1,"bitcoin_txs":{},"deposits":{}}')
            os.chmod(path, 0o600)
            with self.assertRaisesRegex(RuntimeError, "repeats field"):
                spv.load_state(path)

            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{}" * 40)
            os.chmod(path, 0o600)
            with mock.patch.object(spv, "MAX_STATE_BYTES", 32):
                with self.assertRaisesRegex(RuntimeError, "exceeds"):
                    spv.load_state(path)

    def test_state_and_lock_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "target")
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("{}")
            os.chmod(target, 0o600)
            state = os.path.join(directory, "spvmint-state.json")
            os.symlink(target, state)
            with self.assertRaisesRegex(RuntimeError, "linked"):
                spv.load_state(state)
            lock = os.path.join(directory, "spvmint.lock")
            os.symlink(target, lock)
            with self.assertRaises(OSError):
                spv._open_lock(lock)

    def test_bitcoin_cli_rejects_duplicate_json_from_bounded_runner(self):
        completed = subprocess.CompletedProcess(
            ["bitcoin-cli"], 0, stdout='{"allowed":true,"allowed":false}\n', stderr=""
        )
        with (
            mock.patch.object(spv, "_validate_executable"),
            mock.patch.object(spv, "run_bounded_subprocess", return_value=completed),
        ):
            cli = spv.BitcoinCLI(["/trusted/bitcoin-cli"], "wallet", 10)
            with self.assertRaisesRegex(RuntimeError, "malformed JSON"):
                cli.call("getblockchaininfo")


class FakeBitcoin:
    def __init__(self, finalized_hex):
        self.finalized_hex = finalized_hex
        stripped = spv.parse_and_strip_bitcoin_tx(bytes.fromhex(finalized_hex))["legacy"]
        self.txid = spv.dsha(stripped)[::-1].hex()
        self.calls = []
        self.reorg = False

    def call(self, method, *args, wallet=False):
        self.calls.append((method, args, wallet))
        if method == "getwalletinfo":
            return {"private_keys_enabled": True, "descriptors": True}
        if method == "walletcreatefundedpsbt":
            return {"psbt": "funded", "changepos": 2, "fee": 0.00000100}
        if method == "walletprocesspsbt":
            return {"psbt": "signed"}
        if method == "finalizepsbt":
            return {"complete": True, "hex": self.finalized_hex}
        if method == "decodescript":
            return {"address": "bc1qchangefixture"}
        if method == "getaddressinfo":
            return {"ismine": True}
        if method == "testmempoolaccept":
            return [
                {
                    "allowed": True,
                    "txid": self.txid,
                    "wtxid": spv.dsha(bytes.fromhex(self.finalized_hex))[::-1].hex(),
                    "fees": {"base": 0.00000100},
                }
            ]
        if method == "sendrawtransaction":
            return self.txid
        if method == "getrawtransaction":
            return self.finalized_hex
        if method == "getblockhash":
            return ("bb" if self.reorg else "aa") * 32
        if method == "getblockcount":
            return 200
        if method == "getblockheader":
            return {"hash": "aa" * 32, "height": 100, "confirmations": 101}
        raise AssertionError("unexpected Bitcoin RPC %s %r" % (method, args))


class FakeVeld:
    def __init__(self):
        self.consumed = False
        self.nullifier_root = "11" * 32
        self.nullifier_count = 0
        self.nullifier_proof_hex = "00" * 32
        self.prepared = 0
        self.broadcast = 0
        self.signed = None
        self.veld_txid = None

    def rpc(self, method, params=None):
        if method == "getbtcveldmintstatus":
            return {
                "outpoint": params[0],
                "consumed": self.consumed,
                "proof_version": spv.NULLIFIER_PROOF_VERSION,
                "proof_hex": self.nullifier_proof_hex,
                "root": self.nullifier_root,
                "count": self.nullifier_count,
                "tip": 200,
                "tip_hash": "22" * 32,
            }
        if method == "preparerawop":
            self.prepared += 1
            self.last_op = params[1]
            return {
                "unsigned_tx_hex": veld_transaction(params[1]),
                "inputs": [
                    {
                        "index": 0,
                        "sighash_hex": "66" * 32,
                        "prev_script_hex": spv.veld_p2pkh_from_address(FUND).hex(),
                    }
                ],
                "total_input": 500_000,
                "total_output": 0,
                "fee": spv.VELD_OP_FEE_UNITS,
                "change": 400_000,
            }
        if method == "gettxout":
            return {
                "txid": params[0],
                "vout": int(params[1]),
                "value_units": 500_000,
                "script_pubkey_hex": spv.veld_p2pkh_from_address(FUND).hex(),
                "confirmations": 10,
            }
        if method == "getbtcheaderinfo":
            return {"spv_active": True, "k_btc": 6, "best_height": 200}
        if method == "sendrawtransaction":
            self.broadcast += 1
            self.signed = params[0]
            self.veld_txid = spv.dsha(bytes.fromhex(self.signed)).hex()
            return self.veld_txid
        if method in ("getmempoolentry", "getrawtransaction"):
            raise RuntimeError("not found")
        raise AssertionError("unexpected Veld RPC %s %r" % (method, params))


class FakeSigner:
    def __init__(self, signed=None):
        self.signed = signed
        self.calls = 0

    def sign(self, unsigned, prev_script):
        self.calls += 1
        self.signed = self.signed or sign_veld_transaction(unsigned)
        return self.signed


class MutatingSigner(FakeSigner):
    def sign(self, unsigned, prev_script):
        self.calls += 1
        raw = bytearray(bytes.fromhex(unsigned))
        raw[-1] ^= 1  # mutate locktime, then produce otherwise well-formed scripts
        self.signed = sign_veld_transaction(bytes(raw).hex())
        return self.signed


class ReorgSigner(FakeSigner):
    def __init__(self, btc):
        super().__init__()
        self.btc = btc

    def sign(self, unsigned, prev_script):
        result = super().sign(unsigned, prev_script)
        self.btc.reorg = True
        return result


class HarnessOperator(spv.SpvOperator):
    def __init__(self, config, btc, veld, signer, proof=None):
        super().__init__(config, btc=btc, veld=veld, signer=signer)
        self.fixture_peg = peg()
        self.fixture_proof = proof

    def _identity(self, full_derivation=False):
        self.binding = {
            "spv_custody_spk_hex": CUSTODY_SPK.hex(),
            "descriptor_sha256": "11" * 32,
            "manifest_sha256": "22" * 32,
        }
        self.custody_address = "bc1pfixtureindexzero"
        self.identity_fingerprint = ("fixture",)
        return dict(self.fixture_peg), {"chain": "main"}

    def _ready_proof(self, txid, peg_info):
        if self.fixture_proof is None:
            return super()._ready_proof(txid, peg_info)
        result = dict(self.fixture_proof)
        result.setdefault("nullifier_root", "11" * 32)
        result.setdefault("nullifier_count", 0)
        result.setdefault("nullifier_proof_hex", "00" * 32)
        return result


class OperatorTests(unittest.TestCase):
    def config(self, directory):
        return {
            "state_dir": directory,
            "bitcoin": {"max_deposit_fee_sats": 1_000},
            "veld_fee_fund_address": FUND,
            "custody_manifest": "/unused/fixture.json",
        }

    def test_mocked_deposit_builds_exact_template_and_persists_outpoint(self):
        wire, _ = transaction(valid_outputs(), segwit=True)
        btc = FakeBitcoin(wire.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner())
            result = operator.deposit(RECIPIENT, 50_000)
            self.assertEqual(result["outpoint"], btc.txid + ":0")
            self.assertTrue(result["segwit_funded"])
            funded_call = next(c for c in btc.calls if c[0] == "walletcreatefundedpsbt")
            self.assertIn(spv.RECIPIENT_TAG.hex(), funded_call[1][1])
            self.assertIn(RECIPIENT.encode("ascii").hex(), funded_call[1][1])
            state = spv.load_state(os.path.join(directory, "spvmint-state.json"))
            self.assertEqual(state["deposits"][result["outpoint"]]["status"], "deposited")

    def test_deposit_refuses_bad_recipient_checksum_before_wallet_spend(self):
        wire, _ = transaction(valid_outputs(), segwit=True)
        btc = FakeBitcoin(wire.hex())
        veld = FakeVeld()
        bad = RECIPIENT[:-1] + ("1" if RECIPIENT[-1] != "1" else "2")
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner())
            with self.assertRaisesRegex(RuntimeError, "checksum"):
                operator.deposit(bad, 50_000)
            self.assertNotIn("walletcreatefundedpsbt", [item[0] for item in btc.calls])

    def test_deposit_binds_actual_mempool_fee_not_only_psbt_metadata(self):
        wire, _ = transaction(valid_outputs(), segwit=True)

        class FeeMismatchBitcoin(FakeBitcoin):
            def call(self, method, *args, wallet=False):
                if method == "testmempoolaccept":
                    self.calls.append((method, args, wallet))
                    return [
                        {
                            "allowed": True,
                            "txid": self.txid,
                            "wtxid": spv.dsha(bytes.fromhex(self.finalized_hex))[::-1].hex(),
                            "fees": {"base": 0.00000200},
                        }
                    ]
                return super().call(method, *args, wallet=wallet)

        btc = FeeMismatchBitcoin(wire.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner())
            with self.assertRaisesRegex(RuntimeError, "actual fee"):
                operator.deposit(RECIPIENT, 50_000)
            self.assertNotIn("sendrawtransaction", [item[0] for item in btc.calls])

    def test_deposit_restart_replays_durable_raw_instead_of_funding_twice(self):
        wire, _ = transaction(valid_outputs(), segwit=True)
        btc = FakeBitcoin(wire.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner())
            operator._identity(full_derivation=True)
            state = spv.load_state(operator.state_path)
            state["bitcoin_txs"][btc.txid] = {
                "status": "broadcasting",
                "raw_hex": wire.hex(),
                "recipient": RECIPIENT,
                "amount_sats": 50_000,
                "custody_vout": 0,
                "fee_sats": 100,
                # Omit change_pos to exercise upgrade recovery inference.
                "created_at": 1,
            }
            spv.save_state(operator.state_path, state)

            result = operator.deposit(RECIPIENT, 50_000)
            self.assertTrue(result["recovered"])
            self.assertEqual(result["btc_txid"], btc.txid)
            self.assertNotIn("walletcreatefundedpsbt", [call[0] for call in btc.calls])
            restored = spv.load_state(operator.state_path)
            self.assertEqual(restored["bitcoin_txs"][btc.txid]["status"], "broadcast")
            self.assertEqual(restored["bitcoin_txs"][btc.txid]["change_pos"], 2)

    def test_new_deposit_is_held_behind_different_unresolved_wal(self):
        wire, _ = transaction(valid_outputs(), segwit=True)
        btc = FakeBitcoin(wire.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner())
            state = spv.load_state(operator.state_path)
            state["bitcoin_txs"][btc.txid] = {
                "status": "broadcasting",
                "raw_hex": wire.hex(),
                "recipient": RECIPIENT,
                "amount_sats": 50_000,
                "custody_vout": 0,
                "fee_sats": 100,
                "change_pos": 2,
                "created_at": 1,
            }
            spv.save_state(operator.state_path, state)
            with self.assertRaisesRegex(RuntimeError, "original recipient and amount"):
                operator.deposit(RECIPIENT, 49_999)
            self.assertNotIn("walletcreatefundedpsbt", [call[0] for call in btc.calls])

    def test_mocked_mint_posts_once_then_chain_replay_status_stops_fee(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 2,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"x" * 100).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()
        signer = FakeSigner()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, signer, proof=proof)
            first = operator.mint(btc_txid, RECIPIENT)
            self.assertTrue(first["broadcast"])
            self.assertEqual(first["outpoint"], btc_txid + ":0")
            self.assertEqual(veld.prepared, 1)
            self.assertEqual(signer.calls, 1)
            self.assertTrue(veld.last_op.startswith(spv.OP_PREFIX))

            veld.consumed = True
            second = operator.mint(btc_txid, RECIPIENT)
            self.assertTrue(second["already_consumed"])
            self.assertFalse(second["broadcast"])
            self.assertEqual(veld.prepared, 1)
            self.assertEqual(signer.calls, 1)

    def test_mint_rejects_signer_semantic_mutation_before_wal_or_broadcast(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"m" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(
                self.config(directory), btc, veld, MutatingSigner(), proof=proof
            )
            with self.assertRaisesRegex(RuntimeError, "signer changed"):
                operator.mint(btc_txid, RECIPIENT)
            self.assertEqual(veld.broadcast, 0)
            state = spv.load_state(operator.state_path)
            self.assertNotIn(btc_txid + ":0", state["deposits"])

    def test_mint_rechecks_bitcoin_reorg_after_signer_latency(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"r" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(
                self.config(directory), btc, veld, ReorgSigner(btc), proof=proof
            )
            with self.assertRaisesRegex(RuntimeError, "reorg"):
                operator.mint(btc_txid, RECIPIENT)
            self.assertEqual(veld.broadcast, 0)

    def test_mint_rechecks_nullifier_root_after_signer_latency(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"n" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()

        class RootRaceSigner(FakeSigner):
            def sign(self, unsigned, prev_script):
                signed = super().sign(unsigned, prev_script)
                veld.nullifier_root = "33" * 32
                veld.nullifier_count = 1
                return signed

        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(
                self.config(directory), btc, veld, RootRaceSigner(), proof=proof
            )
            with self.assertRaisesRegex(spv.Pending, "nullifier root changed"):
                operator.mint(btc_txid, RECIPIENT)
            self.assertEqual(veld.broadcast, 0)
            state = spv.load_state(operator.state_path)
            self.assertNotIn(btc_txid + ":0", state["deposits"])

    def test_stale_signed_carrier_rebuilds_only_after_it_is_absent(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"o" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()

        class RebuildingSigner(FakeSigner):
            def sign(self, unsigned, prev_script):
                self.calls += 1
                self.signed = sign_veld_transaction(unsigned)
                return self.signed

        signer = RebuildingSigner()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, signer, proof=proof)
            operator.mint(btc_txid, RECIPIENT)
            self.assertEqual(signer.calls, 1)

            # The old signed transaction is absent from both mempool and chain.
            # A new authenticated root may therefore discard only its carrier
            # fields and build a fresh transaction for the same deposit.
            veld.nullifier_root = "33" * 32
            veld.nullifier_count = 1
            proof["nullifier_root"] = veld.nullifier_root
            proof["nullifier_count"] = veld.nullifier_count
            proof["op_string"] = spv.OP_PREFIX + (spv.PROOF_MAGIC + b"q" * 80).hex()
            rebuilt = operator.mint(btc_txid, RECIPIENT)
            self.assertTrue(rebuilt["broadcast"])
            self.assertEqual(signer.calls, 2)
            durable = spv.load_state(operator.state_path)["deposits"][btc_txid + ":0"]
            self.assertEqual(durable["nullifier_root"], "33" * 32)

    def test_stale_signed_carrier_is_retained_while_visible(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"s" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }

        class VisibleVeld(FakeVeld):
            def rpc(self, method, params=None):
                if method == "getmempoolentry" and self.signed is not None:
                    return {"txid": self.veld_txid, "raw_hex": self.signed}
                return super().rpc(method, params)

        btc = FakeBitcoin(legacy.hex())
        veld = VisibleVeld()
        signer = FakeSigner()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, signer, proof=proof)
            operator.mint(btc_txid, RECIPIENT)
            original = spv.load_state(operator.state_path)["deposits"][btc_txid + ":0"]
            veld.nullifier_root = "44" * 32
            veld.nullifier_count = 1
            proof["nullifier_root"] = veld.nullifier_root
            proof["nullifier_count"] = veld.nullifier_count
            proof["op_string"] = spv.OP_PREFIX + (spv.PROOF_MAGIC + b"t" * 80).hex()
            with self.assertRaisesRegex(
                spv.Pending, "stale-root MSP2 transaction is still visible"
            ):
                operator.mint(btc_txid, RECIPIENT)
            current = spv.load_state(operator.state_path)["deposits"][btc_txid + ":0"]
            self.assertEqual(current["signed_veld_tx_hex"], original["signed_veld_tx_hex"])
            self.assertEqual(signer.calls, 1)

    def test_restart_refuses_signed_wal_if_current_proof_identity_changed(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"p" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }
        btc = FakeBitcoin(legacy.hex())
        veld = FakeVeld()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, FakeSigner(), proof=proof)
            operator.mint(btc_txid, RECIPIENT)
            proof["block_hash"] = "bb" * 32
            with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                operator.mint(btc_txid, RECIPIENT)
            self.assertEqual(veld.broadcast, 1)

    def test_mint_lost_broadcast_response_recovers_exact_mempool_wal(self):
        _, legacy = transaction(valid_outputs(), segwit=False)
        btc_txid = spv.dsha(legacy)[::-1].hex()
        proof = {
            "block_hash": "aa" * 32,
            "block_height": 100,
            "confirmations": 7,
            "branch_len": 1,
            "op_string": spv.OP_PREFIX + (spv.PROOF_MAGIC + b"w" * 80).hex(),
            "legacy_tx": legacy,
            "deposit": {"recipient": RECIPIENT, "amount_sats": 50_000, "vout": 0},
            "segwit": False,
        }

        class LostResponseVeld(FakeVeld):
            def rpc(self, method, params=None):
                if method == "sendrawtransaction":
                    self.broadcast += 1
                    self.signed = params[0]
                    self.veld_txid = spv.dsha(bytes.fromhex(self.signed)).hex()
                    raise RuntimeError("lost response after acceptance")
                if method == "getmempoolentry" and self.signed is not None:
                    return {"txid": self.veld_txid, "raw_hex": self.signed}
                return super().rpc(method, params)

        btc = FakeBitcoin(legacy.hex())
        veld = LostResponseVeld()
        signer = FakeSigner()
        with tempfile.TemporaryDirectory() as directory:
            operator = HarnessOperator(self.config(directory), btc, veld, signer, proof=proof)
            with self.assertRaisesRegex(RuntimeError, "lost response"):
                operator.mint(btc_txid, RECIPIENT)
            durable = spv.load_state(operator.state_path)["deposits"][btc_txid + ":0"]
            self.assertEqual(durable["status"], "broadcasting")
            recovered = operator.mint(btc_txid, RECIPIENT)
            self.assertTrue(recovered["rebroadcast"])
            self.assertEqual(veld.broadcast, 1)
            self.assertEqual(signer.calls, 1)


if __name__ == "__main__":
    unittest.main()
