#!/usr/bin/env python3
"""Regressions for REDEEM-burn backing liability and exact payout release."""

import copy
import unittest

import veld_peg_solvency as sol
import veld_redeem_liability as liability


TIP = 700
TIP_HASH = "aa" * 32
K_BTC = 6
TOKEN = "btcVELD"


def btc_amount(sats):
    return "%d.%08d" % (sats // liability.SATS, sats % liability.SATS)


def redeem_row(number=1, amount=100, destination=None):
    return {
        "txid": "%064x" % number,
        "vout": number % 7,
        "token": TOKEN,
        "from": "V" + ("%033d" % number)[-33:],
        "to": "",
        "amount_sats": amount,
        "block": 100 + number,
        "time": 1_700_000_000 + number,
        "memo": destination or ("0014" + "%040x" % number),
        "is_mint": False,
        "is_burn": False,
        "is_redeem": True,
        "block_hash": "%064x" % (10_000 + number),
    }


def marker_script(row, txid=None, vout=None):
    burn_txid = txid if txid is not None else row["txid"]
    burn_vout = row["vout"] if vout is None else vout
    data = (
        liability.PAYOUT_MARKER_MAGIC + bytes.fromhex(burn_txid) + int(burn_vout).to_bytes(4, "big")
    )
    return (bytes([0x6A, len(data)]) + data).hex()


class VeldFeed:
    def __init__(
        self,
        rows,
        short_interior=False,
        duplicate_second=False,
        loop_cursor=False,
        fail_cursor=None,
        authority_rows=None,
    ):
        self.rows = list(rows)
        self.authority_rows = list(self.rows if authority_rows is None else authority_rows)
        self.short_interior = short_interior
        self.duplicate_second = duplicate_second
        self.loop_cursor = loop_cursor
        self.fail_cursor = fail_cursor
        self.calls = []

    def call(self, method, params=None):
        if method != "getbtcveldredeems":
            raise RuntimeError("unexpected Veld method")
        cursor, limit = params
        self.calls.append((cursor, limit))
        if cursor == self.fail_cursor:
            raise RuntimeError("simulated Veld read failure")
        start = 0 if cursor == "" else int(cursor.split("-")[-1])
        page = self.rows[start : start + liability.PAGE_LIMIT]
        has_more = start + len(page) < len(self.rows)
        if self.short_interior and cursor == "" and has_more:
            page = page[:-1]
        if self.duplicate_second and cursor != "" and page:
            page[0] = self.rows[0]
        next_cursor = cursor if self.loop_cursor and has_more else "page-%d" % (start + len(page))
        return {
            "tip": TIP,
            "tip_hash": TIP_HASH,
            "final_height": TIP,
            "cursor": cursor,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "page_limit": liability.PAGE_LIMIT,
            "redeems": copy.deepcopy(page),
            **liability.authority_for_rows(self.authority_rows),
        }


class BitcoinWallet:
    def __init__(self):
        self.transactions = {}
        self.chain = "main"
        self.height = 900_000
        self.best = "bb" * 32
        self.fail_method = None

    def add_payout(
        self,
        row,
        confirmations=K_BTC,
        amount=None,
        destination=None,
        marker=None,
        txid=None,
        outgoing=True,
        abandoned=False,
        conflicts=None,
    ):
        txid = txid or ("%064x" % (50_000 + len(self.transactions)))
        outputs = [
            {
                "value": btc_amount(row["amount_sats"] if amount is None else amount),
                "scriptPubKey": {"hex": destination or row["memo"]},
            },
            {
                "value": "0.00000000",
                "scriptPubKey": {"hex": marker or marker_script(row)},
            },
        ]
        self.transactions[txid] = {
            "info": {
                "txid": txid,
                "hex": "deadbeef%02x" % len(self.transactions),
                "confirmations": confirmations,
                "abandoned": abandoned,
                "walletconflicts": list(conflicts or []),
                "details": [{"category": "send" if outgoing else "receive"}],
            },
            "decoded": {"txid": txid, "vin": [], "vout": outputs},
        }
        return txid

    def call(self, method, *args):
        if method == self.fail_method:
            raise RuntimeError("simulated Bitcoin read failure")
        if method == "getblockchaininfo":
            return {
                "chain": self.chain,
                "blocks": self.height,
                "bestblockhash": self.best,
                "initialblockdownload": False,
            }
        if method == "listsinceblock":
            return {"transactions": [{"txid": txid} for txid in self.transactions], "removed": []}
        if method == "gettransaction":
            return copy.deepcopy(self.transactions[args[0]]["info"])
        if method == "decoderawtransaction":
            for transaction in self.transactions.values():
                if transaction["info"]["hex"] == args[0]:
                    return copy.deepcopy(transaction["decoded"])
            raise RuntimeError("unknown raw transaction")
        raise RuntimeError("unexpected Bitcoin method %s" % method)


def records(rows):
    return liability.read_canonical_redeems(VeldFeed(rows).call, TIP, TIP_HASH, TOKEN)


class RedeemLiabilityTests(unittest.TestCase):
    def test_redeem_commitment_cross_language_vector(self):
        row = {
            "txid": "01" * 32,
            "vout": 7,
            "token": "btcVELD",
            "from": "Vfixture",
            "to": "",
            "amount_sats": 123456789,
            "block": 42,
            "memo": "0014" + "22" * 20,
            "is_mint": False,
            "is_burn": False,
            "is_redeem": True,
            "block_hash": "ab" * 32,
        }
        commitment = liability.RedeemCommitment()
        self.assertEqual(
            commitment.root.hex(),
            "9adf6ee23748b10b2cff08f2ef81fe6fd56714ed4530771ed514e7b5759bf68f",
        )
        commitment.add_rpc_row(row)
        self.assertEqual(
            commitment.root.hex(),
            "e47891396250250e7966c446b9333a77da2002549886ac3d7a8757f16ced5863",
        )

    def test_burn_before_payout_does_not_free_mint_headroom(self):
        row = redeem_row(amount=100)
        current_supply = 900
        total, outstanding, count, released = liability.backing_liability(
            current_supply, records([row]), {}, K_BTC
        )
        self.assertEqual((total, outstanding, count, released), (1000, 100, 1, 0))
        self.assertEqual(sol.solvency_headroom(1000, total, 0), 0)

    def test_redeem_feed_matches_real_ledger_flags_and_normalizes_script_hex(self):
        row = redeem_row(destination=("0014" + "AB" * 20))
        normalized = records([row])
        self.assertFalse(row["is_burn"])
        self.assertTrue(row["is_redeem"])
        self.assertEqual(normalized[0]["dest_spk_hex"], "0014" + "ab" * 20)

    def test_exact_k_confirmed_payout_releases_only_its_liability(self):
        row = redeem_row(amount=100)
        wallet = BitcoinWallet()
        wallet.add_payout(row, confirmations=K_BTC)
        payouts = liability.scan_outgoing_payouts(wallet.call)
        self.assertEqual(
            liability.backing_liability(900, records([row]), payouts, K_BTC), (900, 0, 0, 1)
        )
        self.assertEqual(sol.solvency_headroom(900, 900, 0), 0)

    def test_unconfirmed_wrong_destination_amount_and_marker_fail_closed(self):
        row = redeem_row(amount=100)
        normalized = records([row])

        unconfirmed = BitcoinWallet()
        unconfirmed.add_payout(row, confirmations=K_BTC - 1)
        self.assertEqual(
            liability.backing_liability(
                900, normalized, liability.scan_outgoing_payouts(unconfirmed.call), K_BTC
            ),
            (1000, 100, 1, 0),
        )

        wrong_amount = BitcoinWallet()
        wrong_amount.add_payout(row, amount=99)
        with self.assertRaisesRegex(RuntimeError, "wrong destination or amount"):
            liability.backing_liability(
                900, normalized, liability.scan_outgoing_payouts(wrong_amount.call), K_BTC
            )

        wrong_destination = BitcoinWallet()
        wrong_destination.add_payout(row, destination="0014" + "ff" * 20)
        with self.assertRaisesRegex(RuntimeError, "wrong destination or amount"):
            liability.backing_liability(
                900, normalized, liability.scan_outgoing_payouts(wrong_destination.call), K_BTC
            )

        # A well-formed marker for a different burn cannot release this burn.
        wrong_marker = BitcoinWallet()
        wrong_marker.add_payout(row, marker=marker_script(row, txid="ff" * 32))
        self.assertEqual(
            liability.backing_liability(
                900, normalized, liability.scan_outgoing_payouts(wrong_marker.call), K_BTC
            ),
            (1000, 100, 1, 0),
        )

        partial = BitcoinWallet()
        partial.add_payout(row, marker=(b"\x6a\x05VLDR\x01").hex())
        with self.assertRaisesRegex(RuntimeError, "malformed payout marker"):
            liability.scan_outgoing_payouts(partial.call)

    def test_duplicate_payout_marker_is_ambiguous_and_rejected(self):
        row = redeem_row()
        wallet = BitcoinWallet()
        wallet.add_payout(row, txid="11" * 32)
        wallet.add_payout(row, txid="22" * 32)
        with self.assertRaisesRegex(RuntimeError, "multiple outgoing payouts"):
            liability.scan_outgoing_payouts(wallet.call)

    def test_bitcoin_reorg_restores_liability(self):
        row = redeem_row(amount=100)
        wallet = BitcoinWallet()
        txid = wallet.add_payout(row, confirmations=K_BTC)
        normalized = records([row])
        before = liability.backing_liability(
            900, normalized, liability.scan_outgoing_payouts(wallet.call), K_BTC
        )
        self.assertEqual(before[0], 900)
        wallet.transactions[txid]["info"]["confirmations"] = K_BTC - 1
        after = liability.backing_liability(
            900, normalized, liability.scan_outgoing_payouts(wallet.call), K_BTC
        )
        self.assertEqual(after, (1000, 100, 1, 0))

    def test_veld_reorg_disappearance_and_restart_recompute_from_authority(self):
        row = redeem_row(amount=100)
        wallet = BitcoinWallet()
        wallet.add_payout(row, confirmations=K_BTC)
        payouts = liability.scan_outgoing_payouts(wallet.call)
        first = liability.backing_liability(900, records([row]), payouts, K_BTC)
        # A fresh process has no cache/state yet derives the same result.
        restarted = liability.backing_liability(
            900, records([row]), liability.scan_outgoing_payouts(wallet.call), K_BTC
        )
        self.assertEqual(first, restarted)
        # If Veld reorgs the burn away, the stale Bitcoin marker is not authority;
        # restored live supply alone is the complete liability.
        self.assertEqual(
            liability.backing_liability(1000, records([]), payouts, K_BTC), (1000, 0, 0, 0)
        )

    def test_pagination_complete_and_gap_duplicate_loop_fail_closed(self):
        rows = [redeem_row(number=n, amount=1) for n in range(1, 514)]
        feed = VeldFeed(rows)
        walked = liability.read_canonical_redeems(feed.call, TIP, TIP_HASH, TOKEN)
        self.assertEqual(len(walked), 513)
        self.assertEqual(feed.calls, [("", "512"), ("page-512", "512")])

        with self.assertRaisesRegex(RuntimeError, "gap/short"):
            liability.read_canonical_redeems(
                VeldFeed(rows, short_interior=True).call, TIP, TIP_HASH, TOKEN
            )
        with self.assertRaisesRegex(RuntimeError, "repeated a burn outpoint"):
            liability.read_canonical_redeems(
                VeldFeed(rows, duplicate_second=True).call, TIP, TIP_HASH, TOKEN
            )
        with self.assertRaisesRegex(RuntimeError, "did not advance"):
            liability.read_canonical_redeems(
                VeldFeed(rows, loop_cursor=True).call, TIP, TIP_HASH, TOKEN
            )

    def test_deleted_index_row_cannot_match_ledger_commitment(self):
        first = redeem_row(number=1, amount=10)
        deleted = redeem_row(number=2, amount=20)
        feed = VeldFeed([first], authority_rows=[first, deleted])
        with self.assertRaisesRegex(RuntimeError, "completeness commitment mismatch"):
            liability.read_canonical_redeems(feed.call, TIP, TIP_HASH, TOKEN)

    def test_snapshot_mismatch_network_mismatch_and_read_failures(self):
        row = redeem_row()
        feed = VeldFeed([row])
        with self.assertRaisesRegex(RuntimeError, "supply snapshot tip"):
            liability.read_canonical_redeems(feed.call, TIP + 1, TIP_HASH, TOKEN)
        failing_feed = VeldFeed([row], fail_cursor="")
        with self.assertRaisesRegex(RuntimeError, "simulated Veld"):
            liability.read_canonical_redeems(failing_feed.call, TIP, TIP_HASH, TOKEN)

        wallet = BitcoinWallet()
        self.assertEqual(
            liability.bitcoin_chain_identity(wallet.call), (wallet.height, wallet.best)
        )
        wallet.chain = "test"
        with self.assertRaisesRegex(RuntimeError, "not mainnet"):
            liability.bitcoin_chain_identity(wallet.call)
        wallet.chain = "main"
        wallet.fail_method = "listsinceblock"
        with self.assertRaisesRegex(RuntimeError, "simulated Bitcoin"):
            liability.scan_outgoing_payouts(wallet.call)


if __name__ == "__main__":
    unittest.main(verbosity=2)
