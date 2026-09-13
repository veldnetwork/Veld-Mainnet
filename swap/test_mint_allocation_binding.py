import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from swap import veld_mintd as mintd


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def unsigned_proposal(txid, vout=0):
    raw = (1).to_bytes(4, "little") + b"\x01"
    raw += bytes.fromhex(txid) + int(vout).to_bytes(4, "little")
    raw += b"\x00" + b"\xff\xff\xff\xff"
    raw += b"\x01" + (0).to_bytes(8, "little") + b"\x01\x6a"
    raw += b"\x00" * 4
    return raw.hex()


def _bech32m_address(script_pubkey):
    """Encode one test-only v1 witness program as a mainnet address."""
    program = bytes.fromhex(script_pubkey[4:])
    data = [1]
    accumulator = 0
    bits = 0
    for byte in program:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            data.append((accumulator >> bits) & 31)
    if bits:
        data.append((accumulator << (5 - bits)) & 31)

    values = ([ord(char) >> 5 for char in "bc"] + [0] +
              [ord(char) & 31 for char in "bc"] + data + [0] * 6)
    check = 1
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA,
                  0x3D4233DD, 0x2A1462B3)
    for value in values:
        top = check >> 25
        check = ((check & 0x1FFFFFF) << 5) ^ value
        for index, generator in enumerate(generators):
            if (top >> index) & 1:
                check ^= generator
    checksum = check ^ 0x2BC830A3
    encoded_checksum = [(checksum >> (5 * (5 - index))) & 31
                        for index in range(6)]
    return "bc1" + "".join(BECH32_CHARSET[value]
                           for value in data + encoded_checksum)


class MintAllocationBindingTests(unittest.TestCase):
    def setUp(self):
        scripts = tuple("5120%064x" % index for index in range(1000))
        self.custody = {
            "range": [0, 999],
            "script_pubkeys": scripts,
            "script_pubkey_set": frozenset(scripts),
        }
        self.address1 = _bech32m_address(scripts[1])
        self.address2 = _bech32m_address(scripts[2])
        self.recipient = "V" + "3" * 33
        self.record = {
            "request_id": "ab" * 16,
            "principal_hash": "cd" * 32,
            "veld_address": self.recipient,
            "amount_sats": 62_500,
            "descriptor_index": 1,
            "btc_address": self.address1,
            "script_pubkey": scripts[1],
            "state": "issued",
        }

    def _document(self, records=None):
        return {
            "version": 2,
            "initial_next_index": 1,
            "records": copy.deepcopy(
                [self.record] if records is None else records),
        }

    @staticmethod
    def _write(path, document):
        path.write_text(json.dumps(document), encoding="utf-8")
        path.chmod(0o600)

    def _row(self, *, tx_byte="11", address=None, script=None,
             label=None, amount="0.00062500", vout=0):
        return {
            "txid": tx_byte * 32,
            "vout": vout,
            "address": self.address1 if address is None else address,
            "scriptPubKey": (self.custody["script_pubkeys"][1]
                             if script is None else script),
            "label": self.recipient if label is None else label,
            "amount": amount,
            "confirmations": 6,
        }

    def _discovery_daemon(self, path, rows):
        daemon = object.__new__(mintd.Minter)
        daemon.production = True
        daemon.K_BTC = 6
        daemon.custody = self.custody
        daemon.allocation_store = str(path)
        daemon.allocation_store_max_bytes = 65536
        daemon.allocation_policy_sha256 = None
        daemon.public_descriptor_range_end = None
        daemon.consensus_reservation_command = ("/usr/bin/false",)
        daemon._production_wallet_rows = mock.Mock(return_value=rows)
        return daemon

    def _process_daemon(self, root, allocation_path):
        daemon = object.__new__(mintd.Minter)
        daemon.production = True
        daemon.K_BTC = 6
        daemon.MAX_SINGLE_SATS = 100_000
        daemon.MAX_WINDOW_SATS = 1_000_000
        daemon.issuer_addr = "V" + "2" * 33
        daemon.custody = self.custody
        daemon.allocation_store = str(allocation_path)
        daemon.allocation_store_max_bytes = 65536
        daemon.allocation_policy_sha256 = None
        daemon.public_descriptor_range_end = None
        daemon.ledger = {}
        daemon.ledger_path = str(root / "minted_deposits.json")
        consensus_id = "0" * 31 + "1"
        blind = "55" * 32

        def current_allocation(deposit):
            if type(deposit.get("sats")) is not int:
                raise RuntimeError("production deposit allocation fields are malformed")
            issued = mintd.load_issued_wrap_allocations(
                str(allocation_path), 65536, self.custody)
            record = issued.get(deposit.get("deposit_address"))
            if record is None or record.get("request_id") != \
                    deposit.get("allocation_request_id"):
                raise RuntimeError("deposit allocation binding changed")
            return dict(record, commitment_blind=blind,
                        consensus_allocation_id=consensus_id)

        daemon._require_current_issued_allocation = current_allocation
        daemon._verify_production_identity = mock.Mock(return_value={
            "tip": 200, "supply_sats": 0,
            "issuer_static_custody_cap_sats": 1_000_000,
            "issuer_reserved_sats": 62_500,
            "issuer_mint_headroom_sats": 0,
        })
        daemon._require_canonical_c1_reservation = mock.Mock(return_value={
            "found": True, "active": True, "exposed": True,
            "funded": True, "funding_outpoint": "11" * 32 + ":0",
        })
        daemon.window_minted_sats = mock.Mock(return_value=0)
        daemon.reconcile_ok = mock.Mock(return_value=True)
        daemon.trip_halt = mock.Mock()
        daemon.signer = mock.Mock()
        daemon.signer.sign.return_value = "00" * 100
        daemon.veld = mock.Mock()

        def rpc(method, params=None):
            if method == "getbtcveldsupply":
                return {"supply_sats": 0, "tip": 200,
                        "tip_hash": "66" * 32}
            if method == "getbtcveldmintstatus":
                return {
                    "outpoint": "11" * 32 + ":0", "consumed": True,
                    "minted": False, "proof_version": "MNP1",
                    "proof_hex": "00" * 32, "root": "77" * 32,
                    "count": 1, "tip": 200, "tip_hash": "66" * 32,
                    "accepted_effect_kind": "C1_FUND",
                    "c1_allocation_id": consensus_id,
                    "accepted_txid": "88" * 32,
                    "accepted_block_height": 199,
                    "accepted_block_hash": "99" * 32,
                    "accepted_tx_index": 1, "accepted_marker_vout": 0,
                    "consumer_txid": "88" * 32,
                    "consumer_block_height": 199,
                    "consumer_block_hash": "99" * 32,
                    "consumer_tx_index": 1, "consumer_marker_vout": 0,
                    "credit_txid": None, "credit_block_height": None,
                    "credit_block_hash": None, "credit_tx_index": None,
                    "credit_marker_vout": None,
                }
            if method == "preparetokenmint":
                return {"unsigned_tx_hex": unsigned_proposal("aa" * 32),
                        "inputs": [],
                        "excluded_issuer_prevouts": [],
                        "c1_allocation_id": consensus_id,
                        "c1_script_pubkey_hex": self.record["script_pubkey"],
                        "c1_commitment_blind_hex": blind,
                        "recipient": self.recipient, "mint_sats": 62_500,
                        "deposit_outpoint": "11" * 32 + ":0"}
            if method == "sendrawtransaction":
                signed = bytes.fromhex(params[0])
                return hashlib.sha256(hashlib.sha256(signed).digest()).hexdigest()
            raise AssertionError("unexpected RPC %s" % method)

        daemon.veld.rpc.side_effect = rpc
        return daemon

    def test_production_requires_explicit_absolute_bounded_store_policy(self):
        with self.assertRaisesRegex(RuntimeError, "policy is incomplete"):
            mintd.production_allocation_settings({})
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "policy is incomplete"):
                mintd.Minter({"state_dir": directory, "production": True})
        with self.assertRaisesRegex(RuntimeError, "absolute path"):
            mintd.production_allocation_settings({
                "allocation_store": "allocations.json",
                "allocation_store_max_bytes": mintd.MAX_ALLOCATION_STORE_BYTES,
                "public_capacity_config_sha256": "a" * 64,
                "public_descriptor_range_end": 10999,
                "custody_consensus_manifest_sha256": "b" * 64,
                "consensus_reservation_command": ["/usr/bin/false"],
            })
        for invalid in (True, 65535, mintd.MAX_ALLOCATION_STORE_BYTES + 1):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(RuntimeError, "JSON integer"):
                    mintd.production_allocation_settings({
                        "allocation_store": "/var/lib/veld-wrapd/allocations.json",
                        "allocation_store_max_bytes": invalid,
                        "public_capacity_config_sha256": "a" * 64,
                        "public_descriptor_range_end": 10999,
                        "custody_consensus_manifest_sha256": "b" * 64,
                        "consensus_reservation_command": ["/usr/bin/false"],
                    })
        self.assertEqual(mintd.production_allocation_settings({
            "allocation_store": "/var/lib/veld-wrapd/allocations.json",
            "allocation_store_max_bytes": mintd.MAX_ALLOCATION_STORE_BYTES,
            "public_capacity_config_sha256": "a" * 64,
            "public_descriptor_range_end": 10999,
            "custody_consensus_manifest_sha256": "b" * 64,
            "consensus_reservation_command": ["/usr/bin/false"],
        }), ("/var/lib/veld-wrapd/allocations.json",
             mintd.MAX_ALLOCATION_STORE_BYTES, "a" * 64, 10999,
             "b" * 64, ("/usr/bin/false",)))

    def test_loader_accepts_only_exact_canonical_issued_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allocations.json"
            self._write(path, self._document())
            issued = mintd.load_issued_wrap_allocations(
                str(path), 65536, self.custody)
            self.assertEqual(issued[self.address1], self.record)

            reserved = copy.deepcopy(self.record)
            reserved["state"] = "reserved"
            self._write(path, self._document([reserved]))
            self.assertEqual(mintd.load_issued_wrap_allocations(
                str(path), 65536, self.custody), {})
            allocated = copy.deepcopy(self.record)
            allocated["state"] = "allocated"
            self._write(path, self._document([allocated]))
            self.assertEqual(mintd.load_issued_wrap_allocations(
                str(path), 65536, self.custody), {})

    def test_c1_index_1000_issued_record_is_mintable(self):
        scripts = tuple("5120%064x" % (index + 1)
                        for index in range(11000))
        address = _bech32m_address(scripts[1000])
        policy_hash = "a" * 64
        record = {
            "request_id": "aa" * 16,
            "principal_hash": "bb" * 32,
            "veld_address": self.recipient,
            "amount_sats": 100_000,
            "descriptor_index": 1000,
            "btc_address": address,
            "script_pubkey": scripts[1000],
            "state": "issued",
            "admitted_at": 1,
            "expires_at": 604_801,
            "capacity_policy_sha256": policy_hash,
            "commitment_blind": "cc" * 32,
            "consensus_allocation_id": "0" * 31 + "1",
        }
        events = []
        previous = "0" * 64
        for sequence, action in enumerate(
                ("reserved", "core_allocated", "witness_issued"), 1):
            event = {
                "sequence": sequence, "at": sequence,
                "action": action, "request_id": record["request_id"],
                "previous_event_sha256": previous,
            }
            event["event_sha256"] = hashlib.sha256(json.dumps(
                event, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            previous = event["event_sha256"]
            events.append(event)
        document = {
            "version": 6, "pool_range_start": 1000,
            "capacity_policy_sha256": policy_hash,
            "capacity_policy_sequence": 1,
            "public_descriptor_range_end": 10999,
            "last_consensus_sequence": 1,
            "records": [record], "events": events,
        }
        custody = {"range": [0, 10999], "script_pubkeys": scripts,
                   "script_pubkey_set": frozenset(scripts)}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allocations.json"
            self._write(path, document)
            issued = mintd.load_issued_wrap_allocations(
                str(path), 65536, custody, policy_hash)
        self.assertEqual(issued[address], record)

    def test_loader_rejects_amount_script_address_and_history_tampering(self):
        mutations = []

        bad_amount = copy.deepcopy(self.record)
        bad_amount["amount_sats"] = True
        mutations.append(("amount", self._document([bad_amount])))

        bad_script = copy.deepcopy(self.record)
        bad_script["script_pubkey"] = self.custody["script_pubkeys"][2]
        mutations.append(("script", self._document([bad_script])))

        bad_address = copy.deepcopy(self.record)
        bad_address["btc_address"] = self.address2
        mutations.append(("address", self._document([bad_address])))

        sparse = copy.deepcopy(self.record)
        sparse.update({
            "descriptor_index": 2,
            "btc_address": self.address2,
            "script_pubkey": self.custody["script_pubkeys"][2],
        })
        mutations.append(("sparse", self._document([sparse])))

        duplicate = copy.deepcopy(self.record)
        duplicate.update({
            "descriptor_index": 2,
            "btc_address": self.address2,
            "script_pubkey": self.custody["script_pubkeys"][2],
        })
        mutations.append(("duplicate-request",
                          self._document([self.record, duplicate])))

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allocations.json"
            for label, document in mutations:
                with self.subTest(label=label):
                    self._write(path, document)
                    with self.assertRaises(RuntimeError):
                        mintd.load_issued_wrap_allocations(
                            str(path), 65536, self.custody)

    def test_discovery_holds_every_nonexact_custody_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "allocations.json"
            self._write(path, self._document())
            rows = [
                self._row(tx_byte="11"),
                self._row(tx_byte="22", amount="0.00062501"),
                self._row(tx_byte="33", label="V" + "4" * 33),
                self._row(tx_byte="44", address=self.address2,
                          script=self.custody["script_pubkeys"][2]),
                self._row(tx_byte="55", script=self.custody["script_pubkeys"][2]),
            ]
            daemon = self._discovery_daemon(path, rows)
            deposits = daemon.eligible_deposits()
            self.assertEqual(len(deposits), 1)
            self.assertEqual(deposits[0], {
                "txid": "11" * 32,
                "vout": 0,
                "recipient": self.recipient,
                "sats": 62_500,
                "confs": 6,
                "allocation_request_id": self.record["request_id"],
                "deposit_address": self.address1,
                "script_pubkey": self.record["script_pubkey"],
            })

    def test_process_mints_exact_binding_and_rechecks_toctou_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "allocations.json"
            self._write(path, self._document())
            discovered = self._discovery_daemon(
                path, [self._row()]).eligible_deposits()[0]

            exact = self._process_daemon(root, path)
            exact.process_one(discovered)
            outpoint = "11" * 32 + ":0"
            self.assertEqual(exact.ledger[outpoint]["status"], "broadcast")
            exact.trip_halt.assert_not_called()
            exact.signer.sign.assert_called_once()
            self.assertTrue(exact._verify_production_identity.call_args_list)
            self.assertTrue(all(
                call.kwargs == {"completion": True}
                for call in exact._verify_production_identity.call_args_list))
            signer_claim = exact.signer.sign.call_args.args[4]
            self.assertEqual(signer_claim, {
                "request_id": self.record["request_id"],
                "btc_address": self.address1,
                "script_pubkey": self.record["script_pubkey"],
                "deposit_outpoint": outpoint,
                "descriptor_index": self.record["descriptor_index"],
                "capacity_policy_sha256": None,
                "commitment_blind": "55" * 32,
                "consensus_allocation_id": "0" * 31 + "1",
                "public_descriptor_range_start": 1000,
                "public_descriptor_range_end": None,
            })
            malformed = dict(discovered)
            malformed["sats"] = True
            with self.assertRaisesRegex(RuntimeError, "fields are malformed"):
                exact._require_current_issued_allocation(malformed)

            reserved = copy.deepcopy(self.record)
            reserved["state"] = "reserved"
            self._write(path, self._document([reserved]))
            changed = self._process_daemon(root, path)
            changed.process_one(discovered)
            self.assertEqual(changed.ledger, {})
            changed.signer.sign.assert_not_called()
            changed.trip_halt.assert_called_once()
            self.assertIn("allocation binding",
                          changed.trip_halt.call_args.args[0])

    def test_matching_mnp2_proceeds_with_zero_unreserved_headroom(self):
        allocation = dict(
            self.record, commitment_blind="77" * 32,
            consensus_allocation_id="0" * 31 + "1")
        daemon = object.__new__(mintd.Minter)
        daemon.veld = mock.Mock()
        daemon.veld.rpc.return_value = {
            "allocation_id": allocation["consensus_allocation_id"],
            "found": True, "active": True, "exposed": True,
            "exposure_canonical_depth_reached": True,
            "exposure_confirmations": 101,
            "recipient": allocation["veld_address"],
            "amount_sats": allocation["amount_sats"],
            "allocation_commitment": mintd.allocation_commitment(
                allocation["consensus_allocation_id"],
                allocation["veld_address"], allocation["amount_sats"],
                allocation["script_pubkey"], allocation["commitment_blind"]),
            "funded": False, "funding_outpoint": None,
            "tip": 200,
        }
        peg = {
            "tip": 200, "supply_sats": 37_500,
            "issuer_static_custody_cap_sats": 1_000_000,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 62_500,
            "issuer_mint_headroom_sats": 0,
        }
        status = daemon._require_canonical_c1_reservation(allocation, peg)
        self.assertIs(status["exposed"], True)
        daemon.veld.rpc.assert_called_once_with(
            "getbtcveldc1reservation",
            [allocation["consensus_allocation_id"]])


class MintEffectLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="mint-effect-state-")
        self.root = Path(self.temp.name)
        self.outpoint = "77" * 32 + ":0"
        self.signed = "03" * 100
        raw = bytes.fromhex(self.signed)
        self.txid = hashlib.sha256(hashlib.sha256(raw).digest()).hexdigest()
        self.rpc_calls = []
        self.effect = False
        self.mempool = True
        self.rebroadcast_error = None

        outer = self

        class Veld:
            def rpc(self, method, params=None):
                outer.rpc_calls.append((method, params))
                if method == "getbtcveldsupply":
                    return {"supply_sats": (10_000 if outer.effect else 0),
                            "tip": 200, "tip_hash": "11" * 32}
                if method == "getbtcveldmintstatus":
                    result = {
                        "outpoint": outer.outpoint,
                        "consumed": outer.effect,
                        "minted": outer.effect,
                        "proof_version": "MNP1", "tip": 200,
                        "tip_hash": "11" * 32,
                        "proof_hex": "00" * 32,
                        "root": "44" * 32, "count": 1,
                        "accepted_effect_kind": ("MINT" if outer.effect
                                                 else None),
                        "c1_allocation_id": None,
                        "accepted_txid": None,
                        "accepted_block_height": None,
                        "accepted_block_hash": None,
                        "accepted_tx_index": None,
                        "accepted_marker_vout": None,
                        "consumer_txid": None,
                        "consumer_block_height": None,
                        "consumer_block_hash": None,
                        "consumer_tx_index": None,
                        "consumer_marker_vout": None,
                        "credit_txid": None,
                        "credit_block_height": None,
                        "credit_block_hash": None,
                        "credit_tx_index": None,
                        "credit_marker_vout": None,
                    }
                    if outer.effect:
                        result.update({"accepted_txid": outer.txid,
                                       "accepted_block_height": 199,
                                       "accepted_block_hash": "22" * 32,
                                       "accepted_tx_index": 1,
                                       "accepted_marker_vout": 0,
                                       "credit_txid": outer.txid,
                                       "credit_block_height": 199,
                                       "credit_block_hash": "22" * 32,
                                       "credit_tx_index": 1,
                                       "credit_marker_vout": 0})
                    return result
                if method == "getmempoolentry":
                    if outer.mempool:
                        return {"txid": outer.txid}
                    raise RuntimeError("not in mempool")
                if method == "sendrawtransaction":
                    if outer.rebroadcast_error is not None:
                        raise RuntimeError(outer.rebroadcast_error)
                    return outer.txid
                if method == "getrawtransaction":
                    return {"txid": outer.txid, "confirmations": 1}
                raise AssertionError(method)

        self.daemon = object.__new__(mintd.Minter)
        self.daemon.production = True
        self.daemon.veld = Veld()
        self.daemon.ledger_path = str(self.root / "minted_deposits.json")
        self.daemon.trip_halt = mock.Mock()
        self.broadcast = {
            "status": "broadcast", "recipient": "V" + "3" * 33,
            "sats": 10_000, "at": 10, "signed_tx_hex": self.signed,
            "veld_txid": self.txid, "broadcast_at": 11,
        }
        self.daemon.ledger = {self.outpoint: copy.deepcopy(self.broadcast)}

    def tearDown(self):
        self.temp.cleanup()

    def test_confirmation_latency_and_paid_noop_stay_pending_without_halt(self):
        self.assertFalse(self.daemon._advance_unresolved(
            self.outpoint, self.daemon.ledger[self.outpoint]))
        self.assertEqual(self.daemon.ledger[self.outpoint]["status"], "broadcast")
        self.daemon.trip_halt.assert_not_called()
        self.assertFalse(any(method == "getrawtransaction"
                             for method, ignored in self.rpc_calls))

    def test_exact_accepted_effect_is_terminal_and_reorg_returns_to_pending(self):
        self.effect = True
        self.assertTrue(self.daemon._advance_unresolved(
            self.outpoint, self.daemon.ledger[self.outpoint]))
        self.assertEqual(self.daemon.ledger[self.outpoint]["status"],
                         "effect_confirmed")
        self.assertEqual(self.daemon.ledger[self.outpoint]["veld_txid"], self.txid)
        original_effect_at = self.daemon.ledger[self.outpoint]["effect_at"]

        with mock.patch.object(mintd.time, "time",
                               return_value=original_effect_at + 60):
            self.assertTrue(self.daemon._advance_unresolved(
                self.outpoint, self.daemon.ledger[self.outpoint]))
        self.assertEqual(self.daemon.ledger[self.outpoint]["effect_at"],
                         original_effect_at)

        self.effect = False
        self.mempool = False
        self.assertFalse(self.daemon._advance_unresolved(
            self.outpoint, self.daemon.ledger[self.outpoint]))
        self.assertEqual(self.daemon.ledger[self.outpoint]["status"], "broadcast")

    def test_purged_carrier_holds_exact_bytes_without_replacement(self):
        self.mempool = False
        self.rebroadcast_error = "policy purge"
        self.assertFalse(self.daemon._advance_unresolved(
            self.outpoint, self.daemon.ledger[self.outpoint]))
        row = self.daemon.ledger[self.outpoint]
        self.assertEqual(row["status"], "hold")
        self.assertEqual(row["signed_tx_hex"], self.signed)
        self.assertIn("unrebroadcastable", row["hold_reason"])

    def test_second_same_root_carrier_is_not_prepared(self):
        other = {"txid": "88" * 32, "vout": 0,
                 "recipient": "V" + "4" * 33, "sats": 10_000,
                 "confs": 6}
        self.daemon.veld = mock.Mock()
        self.daemon.process_one(other)
        self.daemon.veld.rpc.assert_not_called()
        self.assertNotIn("88" * 32 + ":0", self.daemon.ledger)

    def test_reorged_settled_effect_is_barrier_before_new_deposit_scan(self):
        self.daemon.ledger[self.outpoint] = {
            **copy.deepcopy(self.broadcast),
            "status": "effect_confirmed", "effect_at": 12,
            "accepted_block_height": 199,
            "accepted_block_hash": "22" * 32,
        }
        self.effect = False
        self.mempool = True
        self.daemon.halted = mock.Mock(return_value=False)
        self.daemon.eligible_deposits = mock.Mock()

        self.daemon.run_once()

        self.assertEqual(self.daemon.ledger[self.outpoint]["status"], "broadcast")
        self.daemon.eligible_deposits.assert_not_called()

    def test_production_preflight_rejects_same_height_mixed_supply_snapshot(self):
        issuer = "V" + "5" * 33
        peg = {
            "peg_unlocked": True, "mint_live": True,
            "issuer": issuer, "spv_k_btc": 6,
            "issuer_max_per_mint_sats": 100_000,
            "issuer_static_custody_cap_sats": 200_000,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 0,
            "issuer_mint_headroom_sats": 90_000,
            "supply_sats": 10_000, "tip": 200,
        }

        class MixedSnapshotVeld:
            def __init__(self):
                self.supply_reads = 0

            def rpc(self, method, params=None):
                if method == "getpeginfo":
                    return dict(peg)
                if method == "getbtcveldsupply":
                    self.supply_reads += 1
                    return {
                        "supply_sats": 10_000, "tip": 200,
                        "tip_hash": (("11" if self.supply_reads == 1 else "22")
                                     * 32),
                    }
                if method == "getblockhash":
                    return "11" * 32
                raise AssertionError(method)

        daemon = object.__new__(mintd.Minter)
        daemon.production = True
        daemon.veld = MixedSnapshotVeld()
        daemon.custody = {}
        daemon.issuer_addr = issuer
        daemon.K_BTC = 6
        daemon.MAX_SINGLE_SATS = 100_000
        daemon.MAX_WINDOW_SATS = 100_000
        with mock.patch.object(mintd.custody_binding,
                               "verify_peg_identity", return_value=None):
            with self.assertRaisesRegex(
                    RuntimeError, "capacity/supply tuple changed or is incoherent"):
                daemon._verify_production_identity()

    def test_production_c1_minter_accepts_only_completion_gate_during_stall(self):
        issuer = "V" + "5" * 33
        peg = {
            "active": True, "peg_unlocked": True,
            "mint_live": False, "completion_live": True,
            "issuer": issuer, "spv_k_btc": 6,
            "issuer_max_per_mint_sats": 100_000,
            "issuer_static_custody_cap_sats": 200_000,
            "issuer_effective_custody_cap_sats": 100_000,
            "issuer_reserved_sats": 0,
            "issuer_mint_headroom_sats": 90_000,
            "supply_sats": 10_000, "tip": 200,
        }

        class CoherentVeld:
            def rpc(self, method, params=None):
                if method == "getpeginfo":
                    return dict(peg)
                if method == "getbtcveldsupply":
                    return {"supply_sats": 10_000, "tip": 200,
                            "tip_hash": "11" * 32}
                if method == "getblockhash":
                    return "11" * 32
                raise AssertionError(method)

        daemon = object.__new__(mintd.Minter)
        daemon.production = True
        daemon.veld = CoherentVeld()
        daemon.custody = {}
        daemon.issuer_addr = issuer
        daemon.K_BTC = 6
        daemon.MAX_SINGLE_SATS = 100_000
        daemon.MAX_WINDOW_SATS = 100_000
        with mock.patch.object(mintd.custody_binding,
                               "verify_peg_identity", return_value=None):
            self.assertTrue(daemon._verify_production_identity(
                completion=True)["completion_live"])
            with self.assertRaisesRegex(RuntimeError, "minting is closed"):
                daemon._verify_production_identity()


if __name__ == "__main__":
    unittest.main()
