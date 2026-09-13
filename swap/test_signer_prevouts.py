#!/usr/bin/env python3
"""Focused N-01 regression tests for the isolated mint signer."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import veld_signerd as signer  # noqa: E402


ISSUER_SCRIPT = "76a914" + "11" * 20 + "88ac"
TXID_A = "aa" * 32
TXID_B = "bb" * 32


def vi(n):
    if n < 0xfd:
        return bytes([n])
    if n <= 0xffff:
        return b"\xfd" + n.to_bytes(2, "little")
    return b"\xfe" + n.to_bytes(4, "little")


def proposal(inputs, script_sig=b""):
    raw = (1).to_bytes(4, "little") + vi(len(inputs))
    for txid, vout in inputs:
        raw += bytes.fromhex(txid) + int(vout).to_bytes(4, "little")
        raw += vi(len(script_sig)) + script_sig + b"\xff\xff\xff\xff"
    # A minimal output section/locktime.  Canonical mint-output enforcement is
    # separately owned by decode-mint; this fixture targets exact input parsing.
    raw += b"\x01" + (0).to_bytes(8, "little") + b"\x01\x6a" + b"\x00" * 4
    return raw.hex()


class FakeRpc:
    def __init__(self, values):
        self.values = dict(values)
        self.calls = []

    def call(self, method, params=None):
        self.calls.append((method, list(params or [])))
        return self.values.get(tuple(params or []))


def utxo(txid, vout, value=1_100_000, script=ISSUER_SCRIPT, confs=12):
    return {"txid": txid, "vout": vout, "value_units": value,
            "script_pubkey_hex": script, "confirmations": confs,
            "block_height": 100}


class SignerPrevoutTests(unittest.TestCase):
    @staticmethod
    def boundary_rpc(headroom=62_500, proof="00" * 32,
                     consumed=False, accepted_txid=None):
        outpoint = TXID_A + ":0"

        class Rpc:
            def verify_chain_identity(self):
                return None

            def call(self, method, params=None):
                if method == "getpeginfo":
                    return {"active": True, "peg_unlocked": True,
                            "mint_live": True, "completion_live": True,
                            "issuer": "Vissuer",
                            "issuer_max_per_mint_sats": 1_000_000_000,
                            "issuer_static_custody_cap_sats": 1_000_000_000,
                            "issuer_effective_custody_cap_sats": 100_000,
                            "issuer_reserved_sats": 0,
                            "issuer_mint_headroom_sats": headroom,
                            "supply_sats": 100_000 - headroom, "tip": 20}
                if method == "getbtcveldsupply":
                    return {"supply_sats": 100_000 - headroom, "tip": 20,
                            "tip_hash": "22" * 32}
                if method == "getbtcveldmintstatus":
                    answer = {"outpoint": outpoint, "consumed": consumed,
                              "minted": consumed,
                              "proof_version": "MNP1", "proof_hex": proof,
                              "root": "11" * 32, "count": int(consumed),
                              "tip": 20, "tip_hash": "22" * 32,
                              "accepted_txid": accepted_txid,
                              "accepted_block_height": None,
                              "accepted_block_hash": None,
                              "accepted_tx_index": None,
                              "accepted_marker_vout": None,
                              "accepted_effect_kind":
                                  "MINT" if consumed else None,
                              "c1_allocation_id": None,
                              "consumer_txid": None,
                              "consumer_block_height": None,
                              "consumer_block_hash": None,
                              "consumer_tx_index": None,
                              "consumer_marker_vout": None,
                              "credit_txid": accepted_txid if consumed else None,
                              "credit_block_height": None,
                              "credit_block_hash": None,
                              "credit_tx_index": None,
                              "credit_marker_vout": None}
                    if consumed:
                        answer.update({"accepted_block_height": 19,
                                       "accepted_block_hash": "33" * 32,
                                       "accepted_tx_index": 1,
                                       "accepted_marker_vout": 0,
                                       "credit_block_height": 19,
                                       "credit_block_hash": "33" * 32,
                                       "credit_tx_index": 1,
                                       "credit_marker_vout": 0})
                    return answer
                raise AssertionError(method)
        return Rpc()

    def test_exact_inputs_resolved_and_caller_metadata_has_no_role(self):
        raw = proposal([(TXID_A, 3), (TXID_B, 7)])
        rpc = FakeRpc({(TXID_A, 3): utxo(TXID_A, 3, 400_000),
                       (TXID_B, 7): utxo(TXID_B, 7, 700_000)})
        total, got = signer.resolve_mint_prevouts(raw, rpc, ISSUER_SCRIPT, 6)
        self.assertEqual(total, 1_100_000)
        self.assertEqual([(x["txid"], x["vout"]) for x in got],
                         [(TXID_A, 3), (TXID_B, 7)])
        self.assertEqual(rpc.calls,
                         [("gettxout", [TXID_A, 3]), ("gettxout", [TXID_B, 7])])
        self.assertEqual(signer.enforce_exact_mint_fee(total, 1_000_000), 100_000)

    def test_real_prevout_value_exposes_inflated_fee(self):
        # The compromised preparer may claim this input is 1_100_000, but the
        # signer's node says 9_001_000_000.  Only that real value reaches policy.
        raw = proposal([(TXID_A, 0)])
        rpc = FakeRpc({(TXID_A, 0): utxo(TXID_A, 0, 9_001_000_000)})
        total, _ = signer.resolve_mint_prevouts(raw, rpc, ISSUER_SCRIPT, 1)
        with self.assertRaisesRegex(ValueError, "exact policy fee"):
            signer.enforce_exact_mint_fee(total, 1_000_000)

    def test_missing_or_spent_prevout_fails_closed(self):
        raw = proposal([(TXID_A, 0)])
        with self.assertRaisesRegex(ValueError, "missing or spent"):
            signer.resolve_mint_prevouts(raw, FakeRpc({}), ISSUER_SCRIPT, 1)

    def test_wrong_prevout_script_fails_closed(self):
        raw = proposal([(TXID_A, 0)])
        wrong = "76a914" + "22" * 20 + "88ac"
        rpc = FakeRpc({(TXID_A, 0): utxo(TXID_A, 0, script=wrong)})
        with self.assertRaisesRegex(ValueError, "not owned by the issuer"):
            signer.resolve_mint_prevouts(raw, rpc, ISSUER_SCRIPT, 1)

    def test_insufficient_confirmations_fails_closed(self):
        raw = proposal([(TXID_A, 0)])
        rpc = FakeRpc({(TXID_A, 0): utxo(TXID_A, 0, confs=5)})
        with self.assertRaisesRegex(ValueError, "need 6"):
            signer.resolve_mint_prevouts(raw, rpc, ISSUER_SCRIPT, 6)

    def test_rpc_identity_mismatch_fails_closed(self):
        raw = proposal([(TXID_A, 0)])
        rpc = FakeRpc({(TXID_A, 0): utxo(TXID_B, 0)})
        with self.assertRaisesRegex(ValueError, "wrong prevout identity"):
            signer.resolve_mint_prevouts(raw, rpc, ISSUER_SCRIPT, 1)

    def test_nonempty_scriptsig_is_not_an_unsigned_proposal(self):
        with self.assertRaisesRegex(ValueError, "non-empty scriptSig"):
            signer.parse_unsigned_tx_inputs(proposal([(TXID_A, 0)], b"x"))

    def test_fresh_headroom_and_exact_mnp1_proof_are_final_boundaries(self):
        outpoint = TXID_A + ":0"
        accepted = signer.validate_fresh_mint_boundary(
            self.boundary_rpc(headroom=50_000), "Vissuer", 50_000,
            outpoint, "00" * 32)
        self.assertFalse(accepted["effect_confirmed_retry"])
        with self.assertRaisesRegex(ValueError, "headroom"):
            signer.validate_fresh_mint_boundary(
                self.boundary_rpc(headroom=50_000), "Vissuer", 62_500,
                outpoint, "00" * 32)
        with self.assertRaisesRegex(ValueError, "proof differs"):
            signer.validate_fresh_mint_boundary(
                self.boundary_rpc(proof="11" * 32), "Vissuer", 10_000,
                outpoint, "00" * 32)

    def test_consumed_outpoint_replays_only_exact_accepted_txid(self):
        outpoint = TXID_A + ":0"
        exact = "44" * 32
        accepted = signer.validate_fresh_mint_boundary(
            self.boundary_rpc(consumed=True, accepted_txid=exact),
            "Vissuer", 62_500, outpoint, "00" * 32, retry_txid=exact)
        self.assertTrue(accepted["effect_confirmed_retry"])
        with self.assertRaisesRegex(ValueError, "another mint"):
            signer.validate_fresh_mint_boundary(
                self.boundary_rpc(consumed=True, accepted_txid=exact),
                "Vissuer", 62_500, outpoint, "00" * 32,
                retry_txid="55" * 32)

    def test_same_height_a_to_b_supply_mix_is_rejected(self):
        rpc = self.boundary_rpc()
        original = rpc.call
        calls = 0

        def mixed(method, params=None):
            nonlocal calls
            if method == "getbtcveldsupply":
                calls += 1
                if calls == 2:
                    return {"supply_sats": 37_500, "tip": 20,
                            "tip_hash": "99" * 32}
            return original(method, params)

        rpc.call = mixed
        with self.assertRaisesRegex(ValueError, "supply tuple"):
            signer.validate_fresh_mint_boundary(
                rpc, "Vissuer", 10_000, TXID_A + ":0", "00" * 32)

    def test_mnp2_reservation_tip_must_match_coherent_supply_tip(self):
        allocation_id = "0" * 31 + "1"
        recipient = "V" + "2" * 33
        script = "5120" + "33" * 32
        blind = "44" * 32
        rpc = self.boundary_rpc()
        original = rpc.call
        reservation_tip = 19

        def c1(method, params=None):
            if method == "getbtcveldmintstatus":
                status = original(method, params)
                status.update({
                    "consumed": True, "minted": False,
                    "accepted_effect_kind": "C1_FUND",
                    "c1_allocation_id": allocation_id,
                    "accepted_txid": "55" * 32,
                    "accepted_block_height": 19,
                    "accepted_block_hash": "66" * 32,
                    "accepted_tx_index": 1, "accepted_marker_vout": 0,
                    "consumer_txid": "55" * 32,
                    "consumer_block_height": 19,
                    "consumer_block_hash": "66" * 32,
                    "consumer_tx_index": 1, "consumer_marker_vout": 0,
                    "credit_txid": None, "credit_block_height": None,
                    "credit_block_hash": None, "credit_tx_index": None,
                    "credit_marker_vout": None,
                })
                return status
            if method == "getbtcveldc1reservation":
                return {
                    "allocation_id": allocation_id, "tip": reservation_tip,
                    "found": True, "active": True, "exposed": True,
                    "funded": True, "funding_outpoint": TXID_A + ":0",
                    "recipient": recipient, "amount_sats": 10_000,
                    "allocation_commitment": signer.allocation_commitment(
                        allocation_id, recipient, 10_000, script, blind),
                }
            return original(method, params)

        rpc.call = c1
        with self.assertRaisesRegex(ValueError, "funded C1"):
            signer.validate_fresh_mint_boundary(
                rpc, "Vissuer", 10_000, TXID_A + ":0", None,
                reservation_allocation_id=allocation_id,
                recipient=recipient, reservation_script_pubkey=script,
                reservation_commitment_blind=blind)
        reservation_tip = 20
        accepted = signer.validate_fresh_mint_boundary(
            rpc, "Vissuer", 10_000, TXID_A + ":0", None,
            reservation_allocation_id=allocation_id,
            recipient=recipient, reservation_script_pubkey=script,
            reservation_commitment_blind=blind)
        self.assertFalse(accepted["effect_confirmed_retry"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
