#!/usr/bin/env python3
"""Main-path regression: cached mint replay precedes spent-prevout lookup."""

import copy
from contextlib import ExitStack
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import subprocess

import veld_signerd as sd
import veld_peg_solvency as sol

REAL_TRUE = str(Path("/bin/true").resolve())


def unsigned_proposal(txid, vout=0):
    raw = (1).to_bytes(4, "little") + b"\x01"
    raw += bytes.fromhex(txid) + int(vout).to_bytes(4, "little")
    raw += b"\x00" + b"\xff\xff\xff\xff"
    raw += b"\x01" + (0).to_bytes(8, "little") + b"\x01\x6a"
    raw += b"\x00" * 4
    return raw.hex()


class SignerMainIdempotencyTests(unittest.TestCase):
    def test_active_authority_and_state_paths_reject_unsafe_files(self):
        issuer = "Vissuer"
        policy = {
            "mint_authority": {
                "topology": "single-active-shared-witness",
                "signer_id": "mint-primary",
                "active_signer_id": "mint-primary",
                "issuer_id": issuer,
                "wrap_allocation_witness_required": True,
                "witness": {"witness_id": "witness-1", "command": [REAL_TRUE]},
            }
        }
        with tempfile.TemporaryDirectory(prefix="signer-file-policy-") as td_name:
            td = Path(td_name)
            marker = td / "active-mint-signer"
            marker.write_text("mint-primary\n")
            marker.chmod(0o600)
            pubkey = td / "beat.pub"
            pubkey.write_text("public")
            state = td / "state.json"
            state.write_text('{"signed":[]}\n')
            state.chmod(0o600)
            with mock.patch.multiple(sd, ACTIVE_MINT_SIGNERF=str(marker), BEAT_PUBKEY=str(pubkey)):
                ignored, witness = sd.validate_mint_authority_config(policy, issuer)
                self.assertEqual(witness["witness_id"], "witness-1")
                self.assertEqual(sd.load_signer_state(str(state)), {"signed": []})

                marker.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "expected 0600"):
                    sd.validate_mint_authority_config(policy, issuer)
                marker.unlink()
                marker.symlink_to("/etc/passwd")
                with self.assertRaisesRegex(ValueError, "non-symlink"):
                    sd.validate_mint_authority_config(policy, issuer)

                marker.unlink()
                marker.write_text("mint-primary\n")
                marker.chmod(0o600)
                pubkey.unlink()
                pubkey.symlink_to("/etc/passwd")
                with self.assertRaisesRegex(ValueError, "non-symlink"):
                    sd.validate_mint_authority_config(policy, issuer)

                state.unlink()
                state.symlink_to("/etc/passwd")
                with self.assertRaisesRegex(ValueError, "non-symlink"):
                    sd.load_signer_state(str(state))

    def test_cached_request_replays_exact_bytes_without_spent_prevout_lookup(self):
        unsigned_hex = unsigned_proposal("10" * 32)
        signed_hex = "01" * 80
        request_id = hashlib.sha256(bytes.fromhex(unsigned_hex)).hexdigest()
        txid = hashlib.sha256(hashlib.sha256(bytes.fromhex(signed_hex)).digest()).hexdigest()
        recipient = "V" + "2" * 33
        issuer = "V" + "1" * 33
        sats = 12345
        deposit_outpoint = "aa" * 32 + ":0"
        allocation = {
            "request_id": "ab" * 16,
            "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "11" * 32,
            "deposit_outpoint": deposit_outpoint,
            "descriptor_index": 1000,
            "capacity_policy_sha256": "33" * 32,
            "commitment_blind": "55" * 32,
            "consensus_allocation_id": "0" * 31 + "1",
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
        }
        receipt_core = {
            "v": sol.C1_RESERVATION_VERSION,
            "kind": sol.RESERVATION_KIND,
            "issuer_id": issuer,
            "witness_id": "witness-1",
            "request_id": request_id,
            "unsigned_tx_sha256": request_id,
            "reservation_id": sol.reservation_id(
                issuer,
                request_id,
                request_id,
                sats,
                recipient,
                deposit_outpoint,
                allocation["consensus_allocation_id"],
            ),
            "sats": sats,
            "recipient": recipient,
            "beat_seq": 1,
            "tip": 10,
            "tip_hash": "11" * 32,
            "headroom_sats": sats,
            "allocation_verified": True,
            "allocation_request_id": allocation["consensus_allocation_id"],
            "allocation_descriptor_index": allocation["descriptor_index"],
            "allocation_btc_address": allocation["btc_address"],
            "allocation_script_pubkey": allocation["script_pubkey"],
            "allocation_capacity_policy_sha256": allocation["capacity_policy_sha256"],
            "allocation_public_descriptor_range_start": allocation["public_descriptor_range_start"],
            "allocation_public_descriptor_range_end": allocation["public_descriptor_range_end"],
            "deposit_outpoint": deposit_outpoint,
            "reserved_at": 1,
            "sig_alg": "mldsa65",
            "sig": "00",
        }
        state = {
            "signed": [
                {
                    "request_id": request_id,
                    "txid": txid,
                    "signed_tx_hex": signed_hex,
                    "sats": sats,
                    "to": recipient,
                    "at": 1,
                    "witness_receipt": receipt_core,
                    "witness_committed": True,
                }
            ],
            "mint_accounting": {
                "version": sd.MINT_ACCOUNTING_VERSION,
                "pending": [
                    {
                        "request_id": request_id,
                        "txid": txid,
                        "sats": sats,
                        "signed_at": 1,
                        "witness_receipt": receipt_core,
                        "witness_committed": True,
                    }
                ],
                "confirmed": [],
            },
        }

        with tempfile.TemporaryDirectory(prefix="signer-main-retry-") as td:
            td = Path(td)
            paths = {
                name: str(td / name)
                for name in (
                    "veld-keygen",
                    "issuer.key",
                    "passphrase.txt",
                    "issuer-address.txt",
                    "signer-state.json",
                    "HALT",
                    "signer.log",
                    "signer-heartbeat.json",
                    "watchtower-required",
                    "caps-only-ok",
                    "issuer-prevout-leases.json",
                )
            }
            for name in ("veld-keygen", "issuer.key", "passphrase.txt", "issuer-address.txt"):
                (td / name).write_text("fixture")
            (td / "veld-keygen").chmod(0o700)
            (td / "issuer.key").chmod(0o600)
            (td / "passphrase.txt").chmod(0o600)
            config = td / "signer-config.json"
            config.write_text("{}")
            config.chmod(0o600)

            fake_rpc = object()
            saved = []
            stdin = io.StringIO(
                json.dumps(
                    {
                        "unsigned_tx_hex": unsigned_hex,
                        "recipient": recipient,
                        "sats": sats,
                        "allocation": allocation,
                    }
                )
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            replacements = {
                "HERE": str(td),
                "KEYGEN": paths["veld-keygen"],
                "KEYFILE": paths["issuer.key"],
                "PASSFILE": paths["passphrase.txt"],
                "ADDRFILE": paths["issuer-address.txt"],
                "STATEF": paths["signer-state.json"],
                "HALTF": paths["HALT"],
                "LOGF": paths["signer.log"],
                "HEARTBEATF": paths["signer-heartbeat.json"],
                "WT_REQUIRED": paths["watchtower-required"],
                "CAPS_ONLY_OK": paths["caps-only-ok"],
                "SIGNER_CONFIG": str(config),
                "PREVOUT_STATEF": paths["issuer-prevout-leases.json"],
                "SIGNING_STAGE_DIR": str(td / ".staging"),
            }
            original_save = sd.save_signer_state_durable

            def save_state(value, path=None, max_bytes=sd.SIGNER_STATE_MAX_BYTES):
                if path == paths["issuer-prevout-leases.json"]:
                    return original_save(value, path, max_bytes)
                saved.append(copy.deepcopy(value))

            with (
                mock.patch.multiple(sd, **replacements),
                mock.patch.object(sd, "load_signer_configuration", return_value={}),
                mock.patch.object(sd, "require_signer_authority_state_set"),
                mock.patch.object(sd, "issuer_addr", return_value=issuer),
                mock.patch.object(sd, "issuer_p2pkh_from_address", return_value="00" * 25),
                mock.patch.object(
                    sd,
                    "mint_params_from_tx",
                    return_value=(
                        recipient,
                        sats,
                        99999,
                        deposit_outpoint,
                        None,
                        allocation["consensus_allocation_id"],
                        allocation["script_pubkey"],
                        allocation["commitment_blind"],
                    ),
                ),
                mock.patch.object(sd, "load_signer_state", return_value=copy.deepcopy(state)),
                mock.patch.object(
                    sd,
                    "load_or_reconcile_prevout_journal",
                    return_value=sd._empty_prevout_journal(),
                ),
                mock.patch.object(sd, "save_signer_state_durable", side_effect=save_state),
                mock.patch.object(sd, "TrustedVeldRpc", return_value=fake_rpc),
                mock.patch.object(
                    sd,
                    "validate_mint_authority_config",
                    return_value=({}, {"witness_id": "witness-1", "command": ["witness"]}),
                ),
                mock.patch.object(sd, "validate_fresh_mint_boundary", return_value={}),
                mock.patch.object(sd, "resolve_mint_prevouts") as resolve,
                mock.patch.object(sd, "watchtower_gate", return_value=(0, {"seq": 1})) as gate,
                mock.patch.object(sd.subprocess, "run") as signer_process,
                mock.patch.object(sd.sys, "stdin", stdin),
                mock.patch.object(sd.sys, "stdout", stdout),
                mock.patch.object(sd.sys, "stderr", stderr),
            ):
                sd.main()

            self.assertEqual(stdout.getvalue(), signed_hex + "\n")
            resolve.assert_not_called()
            signer_process.assert_not_called()
            self.assertTrue(gate.call_args.kwargs["is_retry"])
            self.assertIs(gate.call_args.kwargs["rpc"], fake_rpc)
            self.assertEqual(saved[0]["signed"][0]["signed_tx_hex"], signed_hex)

    def test_new_signature_is_reserved_and_fsynced_before_signing_and_commit(self):
        unsigned_hex = unsigned_proposal("20" * 32)
        signed_hex = "03" * 80
        request_id = hashlib.sha256(bytes.fromhex(unsigned_hex)).hexdigest()
        recipient = "V" + "4" * 33
        issuer = "V" + "3" * 33
        sats = 12345
        deposit_outpoint = "bb" * 32 + ":0"
        allocation = {
            "request_id": "cd" * 16,
            "btc_address": "bc1p" + "q" * 58,
            "script_pubkey": "5120" + "22" * 32,
            "deposit_outpoint": deposit_outpoint,
            "descriptor_index": 1000,
            "capacity_policy_sha256": "44" * 32,
            "commitment_blind": "66" * 32,
            "consensus_allocation_id": "0" * 31 + "2",
            "public_descriptor_range_start": 1000,
            "public_descriptor_range_end": 10999,
        }
        heartbeat = {
            "seq": 9,
            "tip": 20,
            "tip_hash": "22" * 32,
            "headroom_sats": sats,
            "expires_at": 9999999999,
        }
        receipt = {
            "v": sol.C1_RESERVATION_VERSION,
            "kind": sol.RESERVATION_KIND,
            "issuer_id": issuer,
            "witness_id": "witness-1",
            "request_id": request_id,
            "unsigned_tx_sha256": request_id,
            "reservation_id": sol.reservation_id(
                issuer,
                request_id,
                request_id,
                sats,
                recipient,
                deposit_outpoint,
                allocation["consensus_allocation_id"],
            ),
            "sats": sats,
            "recipient": recipient,
            "beat_seq": 9,
            "tip": 20,
            "tip_hash": "22" * 32,
            "headroom_sats": sats,
            "allocation_verified": True,
            "allocation_request_id": allocation["consensus_allocation_id"],
            "allocation_descriptor_index": allocation["descriptor_index"],
            "allocation_btc_address": allocation["btc_address"],
            "allocation_script_pubkey": allocation["script_pubkey"],
            "allocation_capacity_policy_sha256": allocation["capacity_policy_sha256"],
            "allocation_public_descriptor_range_start": allocation["public_descriptor_range_start"],
            "allocation_public_descriptor_range_end": allocation["public_descriptor_range_end"],
            "deposit_outpoint": deposit_outpoint,
            "reserved_at": 1,
            "sig_alg": "mldsa65",
            "sig": "00",
        }

        with tempfile.TemporaryDirectory(prefix="signer-main-order-") as td_name:
            td = Path(td_name)
            paths = {
                name: str(td / name)
                for name in (
                    "veld-keygen",
                    "issuer.key",
                    "passphrase.txt",
                    "issuer-address.txt",
                    "signer-state.json",
                    "HALT",
                    "signer.log",
                    "signer-heartbeat.json",
                    "watchtower-required",
                    "caps-only-ok",
                    "issuer-prevout-leases.json",
                )
            }
            for name in ("veld-keygen", "issuer.key", "passphrase.txt", "issuer-address.txt"):
                (td / name).write_text("fixture")
            (td / "veld-keygen").chmod(0o700)
            (td / "issuer.key").chmod(0o600)
            (td / "passphrase.txt").chmod(0o600)
            config = td / "signer-config.json"
            config.write_text("{}")
            config.chmod(0o600)
            (td / "signer-state.json").write_text('{"signed":[]}\n')
            (td / "signer-state.json").chmod(0o600)

            events = []
            original_save = sd.save_signer_state_durable

            def durable_save(value, path=None, max_bytes=sd.SIGNER_STATE_MAX_BYTES):
                if path == paths["issuer-prevout-leases.json"]:
                    active = next(iter(value["owners"].values()))["active"]
                    events.append(
                        "fsync-prevout-txid"
                        if active["txid"]
                        else (
                            "fsync-prevout-signing"
                            if active["signing_state"] == "SIGNING"
                            else "fsync-prevout-lease"
                        )
                    )
                    return original_save(value, path, max_bytes)
                if path is not None and path.endswith(".prepared.json"):
                    events.append("fsync-prepared")
                    return original_save(value, path, max_bytes)
                signed = value.get("signed", [])
                entry = sd._accounting_entry(value, request_id)
                if not signed:
                    events.append("fsync-reservation")
                elif entry and entry.get("witness_committed"):
                    events.append("fsync-commit")
                else:
                    events.append("fsync-signed-bytes")
                return original_save(value)

            def sign_process(argv, **ignored):
                events.append("sign")
                out_path = Path(argv[argv.index("--out") + 1])
                out_path.write_text(signed_hex)
                out_path.chmod(0o600)
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

            def reserve(*ignored_args, **ignored_kwargs):
                events.append("reserve")
                return copy.deepcopy(receipt)

            def commit(_witness, state, rid, txid, exact_signed):
                events.append("commit")
                self.assertEqual(rid, request_id)
                self.assertEqual(exact_signed, signed_hex)
                entry = sd._accounting_entry(state, request_id)
                entry["witness_committed"] = True
                for record in state["signed"]:
                    if record["request_id"] == request_id:
                        record["witness_committed"] = True
                return True

            class OrderedOutput(io.StringIO):
                def write(self, value):
                    events.append("stdout")
                    return super().write(value)

            stdin = io.StringIO(
                json.dumps(
                    {
                        "unsigned_tx_hex": unsigned_hex,
                        "recipient": recipient,
                        "sats": sats,
                        "allocation": allocation,
                    }
                )
            )
            stdout = OrderedOutput()
            stderr = io.StringIO()
            replacements = {
                "HERE": str(td),
                "KEYGEN": paths["veld-keygen"],
                "KEYFILE": paths["issuer.key"],
                "PASSFILE": paths["passphrase.txt"],
                "ADDRFILE": paths["issuer-address.txt"],
                "STATEF": paths["signer-state.json"],
                "HALTF": paths["HALT"],
                "LOGF": paths["signer.log"],
                "HEARTBEATF": paths["signer-heartbeat.json"],
                "WT_REQUIRED": paths["watchtower-required"],
                "CAPS_ONLY_OK": paths["caps-only-ok"],
                "SIGNER_CONFIG": str(config),
                "PREVOUT_STATEF": paths["issuer-prevout-leases.json"],
                "SIGNING_STAGE_DIR": str(td / ".staging"),
            }
            with ExitStack() as stack:
                stack.enter_context(mock.patch.multiple(sd, **replacements))
                stack.enter_context(
                    mock.patch.object(sd, "load_signer_configuration", return_value={})
                )
                stack.enter_context(mock.patch.object(sd, "require_signer_authority_state_set"))
                stack.enter_context(mock.patch.object(sd, "issuer_addr", return_value=issuer))
                stack.enter_context(
                    mock.patch.object(sd, "issuer_p2pkh_from_address", return_value="00" * 25)
                )
                stack.enter_context(
                    mock.patch.object(
                        sd,
                        "mint_params_from_tx",
                        return_value=(
                            recipient,
                            sats,
                            1000,
                            deposit_outpoint,
                            None,
                            allocation["consensus_allocation_id"],
                            allocation["script_pubkey"],
                            allocation["commitment_blind"],
                        ),
                    )
                )
                stack.enter_context(mock.patch.object(sd, "TrustedVeldRpc", return_value=object()))
                stack.enter_context(
                    mock.patch.object(
                        sd,
                        "load_or_reconcile_prevout_journal",
                        return_value=sd._empty_prevout_journal(),
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        sd,
                        "validate_mint_authority_config",
                        return_value=({}, {"witness_id": "witness-1", "command": ["witness"]}),
                    )
                )
                stack.enter_context(
                    mock.patch.object(sd, "validate_fresh_mint_boundary", return_value={})
                )
                stack.enter_context(
                    mock.patch.object(
                        sd, "resolve_mint_prevouts", return_value=(101000, [{"txid": "x"}])
                    )
                )
                stack.enter_context(
                    mock.patch.object(sd, "watchtower_gate", return_value=(0, heartbeat))
                )
                stack.enter_context(
                    mock.patch.object(sd, "reserve_witness_headroom", side_effect=reserve)
                )
                stack.enter_context(
                    mock.patch.object(sd, "commit_witness_transaction", side_effect=commit)
                )
                stack.enter_context(
                    mock.patch.object(
                        sd.sol, "unsigned_template_from_signed_hex", return_value=unsigned_hex
                    )
                )
                stack.enter_context(
                    mock.patch.object(sd, "save_signer_state_durable", side_effect=durable_save)
                )
                stack.enter_context(
                    mock.patch.object(sd.subprocess, "run", side_effect=sign_process)
                )
                stack.enter_context(mock.patch.object(sd.sys, "stdin", stdin))
                stack.enter_context(mock.patch.object(sd.sys, "stdout", stdout))
                stack.enter_context(mock.patch.object(sd.sys, "stderr", stderr))
                sd.main()

            self.assertEqual(stdout.getvalue(), signed_hex + "\n")
            self.assertEqual(
                events,
                [
                    "fsync-prevout-lease",
                    "reserve",
                    "fsync-reservation",
                    "fsync-prepared",
                    "fsync-prevout-signing",
                    "sign",
                    "fsync-signed-bytes",
                    "commit",
                    "fsync-commit",
                    "fsync-prevout-txid",
                    "stdout",
                ],
            )
            durable = json.loads(Path(paths["signer-state.json"]).read_text())
            self.assertTrue(durable["signed"][0]["witness_committed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
