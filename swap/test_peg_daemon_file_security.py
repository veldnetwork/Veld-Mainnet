import json
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import sys

from swap import rpc_url_policy as file_policy
from swap import veld_mintd as mintd
from swap import veld_redeemd as redeemd
from swap import veld_signerd as signerd
from swap import veld_watchtowerd as watchtowerd
from swap import veld_wt_recv as receiver


class OperatorFilePolicyTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_and_nonfinite_fields(self):
        with self.assertRaisesRegex(ValueError, "repeats field"):
            file_policy.strict_json_loads(b'{"a":1,"a":2}', "fixture")
        with self.assertRaisesRegex(ValueError, "non-finite"):
            file_policy.strict_json_loads(b'{"a":NaN}', "fixture")

    def test_regular_reader_rejects_symlink_hardlink_and_writable_file(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            original = root / "original"
            original.write_bytes(b"safe")
            original.chmod(0o600)
            self.assertEqual(
                file_policy.read_bounded_regular_file(
                    str(original.resolve()), 16, "fixture", private=True
                ),
                b"safe",
            )

            symlink = root / "symlink"
            symlink.symlink_to(original)
            with self.assertRaises(OSError):
                file_policy.read_bounded_regular_file(
                    str(symlink.absolute()), 16, "fixture", private=True
                )

            hardlink = root / "hardlink"
            os.link(original, hardlink)
            with self.assertRaisesRegex(RuntimeError, "non-linked"):
                file_policy.read_bounded_regular_file(
                    str(original.resolve()), 16, "fixture", private=True
                )
            hardlink.unlink()

            original.chmod(0o622)
            with self.assertRaisesRegex(RuntimeError, "private regular file"):
                file_policy.read_bounded_regular_file(
                    str(original.resolve()), 16, "fixture", private=True
                )

    def test_nonsecret_policy_may_be_group_readable_but_not_writable(self):
        with tempfile.TemporaryDirectory() as root:
            policy = Path(root) / "policy.json"
            policy.write_text('{"enabled":false}')
            policy.chmod(0o640)
            self.assertEqual(
                file_policy.load_bounded_json_file(str(policy.resolve()), 1024, "policy"),
                {"enabled": False},
            )
            policy.chmod(0o660)
            with self.assertRaisesRegex(RuntimeError, "writable"):
                file_policy.load_bounded_json_file(str(policy.resolve()), 1024, "policy")

    def test_subprocess_output_is_hard_bounded_before_parent_read(self):
        result = file_policy.run_bounded_subprocess(
            [sys.executable, "-c", "print('ok')"],
            timeout=5,
            stdout_max=64,
            stderr_max=64,
            description="fixture child",
        )
        self.assertEqual(result.stdout, "ok\n")
        with self.assertRaisesRegex(RuntimeError, "output exceeds"):
            file_policy.run_bounded_subprocess(
                [sys.executable, "-c", "print('x' * 1000000)"],
                timeout=5,
                stdout_max=1024,
                stderr_max=1024,
                description="oversized fixture child",
            )


class MintLedgerSecurityTests(unittest.TestCase):
    @staticmethod
    def _ledger():
        return {
            "11" * 32 + ":0": {
                "status": "minting",
                "recipient": "V" + "3" * 33,
                "sats": 1,
                "at": 1,
            }
        }

    def test_atomic_save_does_not_follow_legacy_predictable_tmp_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            ledger = root / "minted_deposits.json"
            victim = root / "victim"
            victim.write_text("do-not-touch")
            victim.chmod(0o600)
            (root / "minted_deposits.json.tmp").symlink_to(victim)

            mintd.save_json(str(ledger), self._ledger())

            self.assertEqual(victim.read_text(), "do-not-touch")
            self.assertEqual(mintd.load_ledger(str(ledger)), self._ledger())
            self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)

    def test_ledger_link_and_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            real = root / "real.json"
            real.write_text(json.dumps(self._ledger()))
            real.chmod(0o600)
            link = root / "ledger.json"
            link.symlink_to(real)
            with self.assertRaises(OSError):
                mintd.load_ledger(str(link))
            link.unlink()
            real.write_text('{"bad":"record"}')
            with self.assertRaisesRegex(RuntimeError, "malformed deposit outpoint"):
                mintd.load_ledger(str(real))

    def test_btc_amount_parser_rejects_sub_satoshi_and_nonfinite(self):
        for parser in (mintd.btc_to_sats, watchtowerd.btc_to_sats):
            self.assertEqual(parser("1.00000000"), 100_000_000)
            with self.assertRaises(ValueError):
                parser("0.000000001")
            with self.assertRaises(ValueError):
                parser("NaN")

    def test_remote_mint_signer_uses_only_the_pinned_host_key_file(self):
        completed = mock.Mock(returncode=0, stdout="ab" * 100, stderr="")
        signer = mintd.RemoteSigner(
            "veld-mint-signer", "/var/lib/veld-peg/.ssh/mint.key", "veld_signerd --capability mint"
        )
        with mock.patch.object(mintd, "run_bounded_subprocess", return_value=completed) as run:
            self.assertEqual(signer.sign("00" * 50, [], "V" + "3" * 33, 1), "ab" * 100)
        command = run.call_args.args[0]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("UserKnownHostsFile=/var/lib/veld-peg/.ssh/known_hosts", command)
        self.assertNotIn("StrictHostKeyChecking=no", command)

    def test_unfinished_intent_halts_before_discovering_or_minting_new_deposits(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            daemon = object.__new__(mintd.Minter)
            daemon.state = str(root)
            daemon.halt_path = str(root / "HALT")
            daemon._halted_memory = False
            daemon._halt_marker_durable = False
            daemon.production = False
            daemon.ledger = self._ledger()
            daemon.eligible_deposits = mock.Mock(
                side_effect=AssertionError("must not enumerate deposits")
            )
            daemon.run_once()
            daemon.eligible_deposits.assert_not_called()
            self.assertTrue(daemon.halted())

    def test_new_halt_stops_the_current_pass_immediately(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            daemon = object.__new__(mintd.Minter)
            daemon.state = str(root)
            daemon.halt_path = str(root / "HALT")
            daemon._halted_memory = False
            daemon._halt_marker_durable = False
            daemon.production = False
            daemon.issuer_addr = "V" + "2" * 33
            daemon.K_BTC = 6
            daemon.WINDOW_SECS = 3600
            daemon.ledger_path = str(root / "minted_deposits.json")
            daemon.ledger = {}
            deposits = [
                {"txid": "11" * 32, "vout": 0},
                {"txid": "22" * 32, "vout": 0},
            ]
            daemon.eligible_deposits = mock.Mock(return_value=deposits)
            calls = []

            def process(deposit):
                calls.append(deposit["txid"])
                daemon.trip_halt("fixture halt")

            daemon.process_one = process
            daemon.run_once()
            self.assertEqual(calls, ["11" * 32])
            self.assertTrue(daemon.halted())

    def test_old_mint_rows_prune_only_after_consensus_confirms_consumption(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            outpoint = "33" * 32 + ":0"
            daemon = object.__new__(mintd.Minter)
            daemon.WINDOW_SECS = 3600
            daemon.ledger_path = str(root / "minted_deposits.json")
            daemon.ledger = {
                outpoint: {
                    "status": "minted",
                    "recipient": "V" + "3" * 33,
                    "sats": 1,
                    "at": 0,
                    "veld_txid": "44" * 32,
                },
            }
            daemon.mint_outpoint_consumed = mock.Mock(return_value=True)
            self.assertEqual(daemon._prune_settled_ledger(), 1)
            self.assertEqual(daemon.ledger, {})
            self.assertEqual(mintd.load_ledger(daemon.ledger_path), {})


class DurableAuthoritySecurityTests(unittest.TestCase):
    def test_new_sqlite_authority_is_owner_only(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            path = root / "authority.sqlite3"
            store = redeemd.ObligationStore(str(path))
            store.close()
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_sqlite_authority_rejects_last_component_links(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            target = root / "target"
            target.write_bytes(b"")
            target.chmod(0o600)
            symlink = root / "authority.sqlite3"
            symlink.symlink_to(target)
            with self.assertRaises(OSError):
                redeemd.ObligationStore(str(symlink))
            symlink.unlink()
            hardlink = root / "authority.sqlite3"
            os.link(target, hardlink)
            with self.assertRaisesRegex(RuntimeError, "non-linked"):
                redeemd.ObligationStore(str(hardlink))

    def test_wallet_history_ambiguity_cannot_be_treated_as_unpaid(self):
        txid = "44" * 32
        redemption = {
            "burn_txid": "55" * 32,
            "opreturn_vout": 0,
            "redeemer": "V" + "4" * 33,
            "amount_sats": 1000,
            "burn_height": 1,
            "burn_block_hash": "66" * 32,
            "dest_btc_addr": "0014" + "77" * 20,
        }

        class MalformedWallet:
            def call(self, method, *args):
                if method == "listsinceblock":
                    return {"transactions": [{"txid": txid}], "removed": []}
                if method == "gettransaction":
                    return {"txid": txid}  # missing exact raw bytes
                raise AssertionError(method)

        with self.assertRaisesRegex(RuntimeError, "malformed wallet transaction"):
            redeemd.find_existing_payout(MalformedWallet(), redemption)

    def test_redeem_feed_cannot_silently_skip_a_malformed_row(self):
        class MalformedFeed:
            def call(self, method, params=None):
                cursor = (params or [""])[0]
                return {
                    "tip": 1,
                    "tip_hash": "11" * 32,
                    "final_height": 1,
                    "cursor": cursor,
                    "next_cursor": cursor,
                    "page_limit": 512,
                    "has_more": False,
                    "redeem_count": 0,
                    "redeem_root": redeemd.RedeemCommitment().root.hex(),
                    "redeems": [
                        {
                            "txid": "22" * 32,
                            "vout": 0,
                            "from": "V" + "4" * 33,
                            "amount_sats": 1,
                            "block": 1,
                            "block_hash": "11" * 32,
                            "memo": "0014" + "33" * 20,
                            # A load-bearing redeem feed must never treat this row
                            # as ignorable absence.
                            "token": "btcVELD",
                            "is_mint": False,
                            "is_burn": False,
                            "is_redeem": False,
                        }
                    ],
                }

        with self.assertRaisesRegex(RuntimeError, "non-canonical redeem row"):
            redeemd.fetch_from_node(MalformedFeed())


class WatchtowerAndSignerStateSecurityTests(unittest.TestCase):
    def test_watchtower_sequence_corruption_never_resets_to_zero(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            root.chmod(0o700)
            wt = object.__new__(watchtowerd.Watchtower)
            wt.state_dir = str(root)
            self.assertEqual(wt._load_seq(), 0)
            sequence = root / "watchtower-seq"
            sequence.write_text("not-a-sequence\n")
            sequence.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "corrupt"):
                wt._load_seq()

    def test_signer_marker_rejects_hardlink_and_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            marker = root / "marker"
            marker.write_text("")
            marker.chmod(0o600)
            self.assertTrue(signerd._trusted_marker_exists(str(marker), "marker"))
            alias = root / "alias"
            os.link(marker, alias)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                signerd._trusted_marker_exists(str(marker), "marker")
            alias.unlink()
            link = root / "link"
            link.symlink_to(marker)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                signerd._trusted_marker_exists(str(link), "marker")

    def test_receiver_rejects_linked_sequence_authority(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            sequence = root / "sequence"
            sequence.write_text("7\n")
            sequence.chmod(0o600)
            alias = root / "alias"
            os.link(sequence, alias)
            with mock.patch.multiple(
                receiver, LASTSEQF=str(sequence), HEARTBEATF=str(root / "missing-heartbeat")
            ):
                with self.assertRaisesRegex(RuntimeError, "non-linked"):
                    receiver._last_sequence()

    def test_unrelated_corrupt_signed_row_cannot_reduce_window_cap(self):
        signed = b"\x00"
        txid = hashlib.sha256(hashlib.sha256(signed).digest()).hexdigest()
        state = {
            "signed": [
                {
                    "request_id": "44" * 32,
                    "txid": txid,
                    "signed_tx_hex": signed.hex(),
                    "sats": -1,
                    "to": "V" + "5" * 33,
                    "at": 1,
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "positive integer"):
            signerd.window_signed_sats(state)

    def test_signer_journal_prunes_only_finalized_rows_outside_rate_window(self):
        signed = b"\x01"
        txid = hashlib.sha256(hashlib.sha256(signed).digest()).hexdigest()
        old = {
            "request_id": "55" * 32,
            "txid": txid,
            "signed_tx_hex": signed.hex(),
            "sats": 1,
            "to": "V" + "6" * 33,
            "at": 1,
        }
        state = {
            "signed": [old],
            "mint_accounting": {
                "version": signerd.MINT_ACCOUNTING_VERSION,
                "pending": [],
                "confirmed": [],
            },
        }
        self.assertEqual(
            signerd.prune_finalized_signed_audits(state, now=signerd.WINDOW_SECS + 2), 1
        )
        self.assertEqual(state["signed"], [])

        state["signed"] = [old]
        state["mint_accounting"]["pending"] = [
            {
                "request_id": old["request_id"],
                "txid": old["txid"],
                "sats": 1,
                "signed_at": 1,
            }
        ]
        self.assertEqual(
            signerd.prune_finalized_signed_audits(state, now=signerd.WINDOW_SECS + 2), 0
        )


if __name__ == "__main__":
    unittest.main()
