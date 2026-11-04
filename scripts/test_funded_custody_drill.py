#!/usr/bin/env python3
"""Positive and adversarial fixtures for funded-custody semantic evidence."""

from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/validate-funded-custody-drill.py"
SPEC = importlib.util.spec_from_file_location("custody_validator", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
V = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = V
SPEC.loader.exec_module(V)


def write_json(path: Path, value: object) -> str:
    raw = json.dumps(value, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()


def point_for_secret(secret: int) -> tuple[int, int]:
    point = V.point_mul(secret)
    assert point is not None
    return point


def bip340_sign(secret: int, message: bytes) -> bytes:
    point = point_for_secret(secret)
    normalized = secret if point[1] % 2 == 0 else V.N - secret
    public_key = point[0].to_bytes(32, "big")
    nonce = (
        int.from_bytes(
            V.tagged_hash("BIP0340/nonce", normalized.to_bytes(32, "big") + public_key + message),
            "big",
        )
        % V.N
    )
    assert nonce
    nonce_point = point_for_secret(nonce)
    if nonce_point[1] & 1:
        nonce = V.N - nonce
        nonce_point = point_for_secret(nonce)
    r = nonce_point[0].to_bytes(32, "big")
    challenge = (
        int.from_bytes(V.tagged_hash("BIP0340/challenge", r + public_key + message), "big") % V.N
    )
    signature = r + ((nonce + challenge * normalized) % V.N).to_bytes(32, "big")
    assert V.schnorr_verify(public_key, message, signature)
    return signature


def base58check(payload: bytes) -> str:
    raw = payload + V.hash256(payload)[:4]
    number = int.from_bytes(raw, "big")
    encoded = ""
    while number:
        number, digit = divmod(number, 58)
        encoded = V.BASE58_ALPHABET[digit] + encoded
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded


def account_fixture(slot: int) -> tuple[int, bytes, str]:
    secret = 10_000 + slot
    chain = hashlib.sha256(f"chain-{slot}".encode()).digest()
    point = point_for_secret(secret)
    compressed = bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")
    fingerprint = hashlib.sha256(f"master-{slot}".encode()).digest()[:4]
    payload = (
        V.XPUB_VERSION
        + b"\x03"
        + hashlib.sha256(f"parent-{slot}".encode()).digest()[:4]
        + (0x80000000).to_bytes(4, "big")
        + chain
        + compressed
    )
    expression = f"[{fingerprint.hex()}/86h/0h/0h]{base58check(payload)}/0/*"
    return secret, chain, expression


def ckd_private(secret: int, chain: bytes, index: int) -> tuple[int, bytes]:
    point = point_for_secret(secret)
    compressed = bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")
    derived = hmac.new(chain, compressed + index.to_bytes(4, "big"), hashlib.sha512).digest()
    tweak = int.from_bytes(derived[:32], "big")
    assert 0 < tweak < V.N
    return (secret + tweak) % V.N, derived[32:]


def boundary_fixture(
    accounts: list[tuple[int, bytes, str]],
    expressions: list[str],
    index: int,
) -> tuple[list[int], bytes, bytes, bytes]:
    secrets = []
    for secret, chain, _ in accounts:
        secret, chain = ckd_private(secret, chain, 0)
        secret, _ = ckd_private(secret, chain, index)
        secrets.append(secret)
    keys, script, control, script_pubkey = V.descriptor_boundary_material(expressions, index)
    self_keys = [point_for_secret(secret)[0].to_bytes(32, "big") for secret in secrets]
    assert keys == self_keys
    return secrets, script, control, script_pubkey


def funding_tx(script_pubkey: bytes, amount: int, tag: int) -> bytes:
    return (
        (2).to_bytes(4, "little")
        + b"\x01"
        + bytes([tag]) * 32
        + (0).to_bytes(4, "little")
        + b"\x01\x00"
        + (0xFFFFFFFE).to_bytes(4, "little")
        + b"\x01"
        + amount.to_bytes(8, "little")
        + V.compact_size(len(script_pubkey))
        + script_pubkey
        + (tag).to_bytes(4, "little")
    )


def spend_tx(
    prev_txid: str, prev_vout: int, amount_out: int, locktime: int, witness: list[bytes]
) -> bytes:
    txin = (
        bytes.fromhex(prev_txid)[::-1]
        + prev_vout.to_bytes(4, "little")
        + b"\x00"
        + (0xFFFFFFFD).to_bytes(4, "little")
    )
    txout = amount_out.to_bytes(8, "little") + b"\x01\x51"
    witness_raw = V.compact_size(len(witness)) + b"".join(
        V.compact_size(len(item)) + item for item in witness
    )
    return (
        (2).to_bytes(4, "little")
        + b"\x00\x01\x01"
        + txin
        + b"\x01"
        + txout
        + witness_raw
        + locktime.to_bytes(4, "little")
    )


def merkle_proof(txid: str, header: bytes) -> tuple[str, str]:
    internal = bytes.fromhex(txid)[::-1]
    proof = header + (1).to_bytes(4, "little") + b"\x01" + internal + b"\x01\x01"
    return proof.hex(), V.hash256(header)[::-1].hex()


TEST_BITS = 0x207FFFFF
TEST_TARGET = 0x7FFFFF << (8 * (0x20 - 3))


def mine_header(previous_hash: str, merkle_internal: bytes, height: int) -> bytes:
    prefix = (
        (4).to_bytes(4, "little")
        + bytes.fromhex(previous_hash)[::-1]
        + merkle_internal
        + (1_788_112_800 + height).to_bytes(4, "little")
        + TEST_BITS.to_bytes(4, "little")
    )
    for nonce in range(0x100000000):
        header = prefix + nonce.to_bytes(4, "little")
        if int.from_bytes(V.hash256(header), "little") <= TEST_TARGET:
            return header
    raise AssertionError("easy test header could not be mined")


def signed_spend(
    funding: V.Transaction,
    amount: int,
    secrets: list[int],
    script: bytes,
    control: bytes,
    script_pubkey: bytes,
    selected_slots: list[int],
    locktime: int,
) -> bytes:
    blank_witness = [b""] * 5 + [script, control]
    provisional = V.parse_transaction(
        spend_tx(funding.txid, 0, amount - 1_000 - locktime, locktime, blank_witness)
    )
    leaf = V.verify_taproot_commitment(script_pubkey, script, control)
    message = V.taproot_script_sighash(provisional, 0, amount, script_pubkey, leaf)
    witness = [b""] * 5
    for slot in selected_slots:
        witness[4 - slot] = bip340_sign(secrets[slot], message)
    return spend_tx(
        funding.txid, 0, amount - 1_000 - locktime, locktime, witness + [script, control]
    )


def report_signatures(tx: V.Transaction) -> tuple[list[int], list[str]]:
    values = []
    for witness_index, signature in enumerate(tx.inputs[0].witness[:5]):
        if signature:
            values.append((4 - witness_index, hashlib.sha256(signature).hexdigest()))
    values.sort()
    return [item[0] for item in values], [item[1] for item in values]


def build_fixture(root: Path) -> tuple[Path, Path]:
    accounts = [account_fixture(slot) for slot in range(5)]
    expressions = [account[2] for account in accounts]
    payload = f"tr({V.NUMS_INTERNAL_KEY.hex()},multi_a(3," + ",".join(expressions) + "))"
    descriptor = payload + "#" + V.descriptor_checksum(payload)
    scripts, _ = V.derive_operational_manifest(descriptor, expressions)
    scripts = list(scripts)
    source_commit = "1" * 64
    source_tree = "2" * 64
    manifest: dict[str, object] = {
        "version": 1,
        "descriptor": descriptor,
        "descriptor_sha256": hashlib.sha256(descriptor.encode()).hexdigest(),
        "range": [0, 10_999],
        "script_pubkeys": scripts,
    }
    drill_material = []
    for position, index in enumerate((0, 1000, 10_999), 1):
        secrets, script, control, script_pubkey = boundary_fixture(accounts, expressions, index)
        assert scripts[index] == script_pubkey.hex()
        amount = 100_000 + position * 10_000
        funding_raw = funding_tx(script_pubkey, amount, position)
        funding = V.parse_transaction(funding_raw)
        success_raw = signed_spend(
            funding, amount, secrets, script, control, script_pubkey, [0, 1, 2], 10 + position
        )
        success = V.parse_transaction(success_raw)
        success_slots, success_hashes = report_signatures(success)
        reject_raw = signed_spend(
            funding, amount, secrets, script, control, script_pubkey, [3, 4], 20 + position
        )
        reject = V.parse_transaction(reject_raw)
        reject_slots, reject_hashes = report_signatures(reject)
        common = {
            "schema": 1,
            "result": "PASS",
            "release_version": "2.8.0",
            "source_commit": source_commit,
            "source_tree": source_tree,
            "completed_at_utc": "2026-08-30T18:00:21Z",
            "bitcoin_network": "main",
            "descriptor_sha256": manifest["descriptor_sha256"],
            "descriptor_index": index,
            "script_pubkey_hex": script_pubkey.hex(),
            "funded_sats": amount,
            "funding_txid": funding.txid,
            "funding_vout": 0,
            "funding_raw_transaction_hex": funding_raw.hex(),
            "funding_txoutproof_hex": "00",
            "funding_block_hash": "0" * 64,
            "funding_confirmations": 0,
            "spend_input_index": 0,
            "tapleaf_script_hex": script.hex(),
            "control_block_hex": control.hex(),
        }
        success_report = {
            **common,
            "statement": "veld-mainnet-custody-3of5-success-v1",
            "signer_ids": [f"signer-{slot + 1}" for slot in success_slots],
            "signer_slots": success_slots,
            "signature_sha256": success_hashes,
            "spend_txid": success.txid,
            "spend_raw_transaction_hex": success_raw.hex(),
            "spend_txoutproof_hex": "00",
            "spend_block_hash": "0" * 64,
            "spend_confirmations": 0,
            "testmempoolaccept_allowed": True,
            "testmempoolaccept_raw_json": json.dumps(
                [
                    {
                        "allowed": True,
                        "txid": success.txid,
                        "wtxid": success.wtxid,
                    }
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            "testmempoolaccept_checked_at_utc": "2026-08-30T18:00:05Z",
            "broadcast_txid": success.txid,
            "broadcast_at_utc": "2026-08-30T18:00:06Z",
            "confirmed_at_utc": "2026-08-30T18:00:20Z",
        }
        reject_report = {
            **common,
            "statement": "veld-mainnet-custody-2of5-rejection-v1",
            "signer_ids": [f"signer-{slot + 1}" for slot in reject_slots],
            "signer_slots": reject_slots,
            "signature_sha256": reject_hashes,
            "rejection_txid": reject.txid,
            "rejection_wtxid": reject.wtxid,
            "rejection_raw_transaction_hex": reject_raw.hex(),
            "finalizepsbt_complete": False,
            "testmempoolaccept_allowed": False,
            "testmempoolaccept_txid": reject.txid,
            "testmempoolaccept_wtxid": reject.wtxid,
            "reject_reason": (
                "mandatory-script-verify-flag-failed (Script evaluated without "
                "error but finished with a false/empty top stack element)"
            ),
            "testmempoolaccept_raw_json": "",
            "finalizepsbt_checked_at_utc": "2026-08-30T18:00:02Z",
            "testmempoolaccept_checked_at_utc": "2026-08-30T18:00:03Z",
            "broadcast_attempted": False,
        }
        reject_report["completed_at_utc"] = "2026-08-30T18:00:04Z"
        reject_report["testmempoolaccept_raw_json"] = (
            json.dumps(
                [
                    {
                        "allowed": False,
                        "reject-reason": reject_report["reject_reason"],
                        "txid": reject.txid,
                        "wtxid": reject.wtxid,
                    }
                ],
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        drill_material.append(
            (index, amount, funding, success, success_report, reject, reject_report)
        )

    # Retain an exact, contiguous Bitcoin Core-style header snapshot.  The unit
    # fixture uses an easy target through validate()'s explicit test-only
    # maximum; the command-line release path has no such override and enforces
    # the fixed mainnet difficulty floor.
    reference_transactions = [item[2] for item in drill_material] + [
        item[3] for item in drill_material
    ]
    headers = []
    proofs: dict[str, tuple[str, str, int]] = {}
    previous_hash = "0" * 64
    first_height = 100
    for offset in range(11):
        transaction = reference_transactions[offset] if offset < 6 else None
        merkle_internal = (
            bytes.fromhex(transaction.txid)[::-1]
            if transaction is not None
            else hashlib.sha256(f"empty-{offset}".encode()).digest()
        )
        header = mine_header(previous_hash, merkle_internal, first_height + offset)
        block_hash = V.hash256(header)[::-1].hex()
        headers.append(
            {
                "height": first_height + offset,
                "requested_hash": block_hash,
                "getblockheader_false_hex": header.hex(),
            }
        )
        if transaction is not None:
            proof_hex, proof_block = merkle_proof(transaction.txid, header)
            assert proof_block == block_hash
            proofs[transaction.txid] = (proof_hex, block_hash, 11 - offset)
        previous_hash = block_hash
    for index, _amount, funding, success, success_report, _reject, reject_report in drill_material:
        funding_proof, funding_block, funding_confirmations = proofs[funding.txid]
        spend_proof, spend_block, spend_confirmations = proofs[success.txid]
        for report in (success_report, reject_report):
            report["funding_txoutproof_hex"] = funding_proof
            report["funding_block_hash"] = funding_block
            report["funding_confirmations"] = funding_confirmations
        success_report["spend_txoutproof_hex"] = spend_proof
        success_report["spend_block_hash"] = spend_block
        success_report["spend_confirmations"] = spend_confirmations

    chain_evidence = {
        "schema": 1,
        "statement": "veld-bitcoin-core-mainnet-custody-chain-evidence-v1",
        "result": "PASS",
        "bitcoin_network": "main",
        "node_id": "fixture-bitcoin-core-node",
        "node_version": "Bitcoin Core test fixture 30.0",
        "collector_version": "collect-bitcoin-core-custody-evidence-v1",
        "bitcoin_cli_path": "/fixture/bitcoin-cli",
        "bitcoin_cli_sha256": "a" * 64,
        "bitcoind_path": "/fixture/bitcoind",
        "bitcoind_sha256": "b" * 64,
        "bitcoind_pid": 4242,
        "bitcoind_start_time_ticks": 123456,
        "rpc_arguments_sha256": "c" * 64,
        "captured_at_utc": "2026-08-30T18:00:25Z",
        "getblockchaininfo": {
            "chain": "main",
            "blocks": 110,
            "headers": 110,
            "bestblockhash": previous_hash,
            "initialblockdownload": False,
        },
        "headers": headers,
        "txoutproofs": [
            {
                "txid": transaction.txid,
                "block_hash": proofs[transaction.txid][1],
                "gettxoutproof_hex": proofs[transaction.txid][0],
            }
            for transaction in reference_transactions
        ],
    }
    chain_evidence_sha = write_json(root / "bitcoin-core-chain.json", chain_evidence)
    manifest_path = root / "custody-manifest.json"
    manifest_sha = write_json(manifest_path, manifest)
    consensus_manifest = {
        **manifest,
        "range": [0, 999],
        "script_pubkeys": scripts[:1000],
    }
    consensus_path = root / "custody-consensus-manifest.json"
    consensus_sha = write_json(consensus_path, consensus_manifest)
    drills = []
    for index, amount, _funding, success, success_report, reject, reject_report in drill_material:
        success_report["manifest_sha256"] = manifest_sha
        reject_report["manifest_sha256"] = manifest_sha
        success_name = f"success-{index}.json"
        reject_name = f"reject-{index}.json"
        success_sha = write_json(root / success_name, success_report)
        reject_sha = write_json(root / reject_name, reject_report)
        drills.append(
            {
                "descriptor_index": index,
                "funded_sats": amount,
                "script_pubkey_hex": scripts[index],
                "three_of_five_signer_ids": success_report["signer_ids"],
                "three_of_five_spend_txid": success.txid,
                "three_of_five_success_report_path": success_name,
                "three_of_five_success_report_sha256": success_sha,
                "two_of_five_signer_ids": reject_report["signer_ids"],
                "two_of_five_rejection_report_path": reject_name,
                "two_of_five_rejection_report_sha256": reject_sha,
            }
        )
    parent = {
        "schema": 2,
        "statement": "veld-mainnet-funded-custody-threshold-drill-v2",
        "result": "PASS",
        "release_version": "2.8.0",
        "source_commit": source_commit,
        "source_tree": source_tree,
        "completed_at_utc": "2026-08-30T18:00:30Z",
        "bitcoin_network": "main",
        "descriptor_sha256": manifest["descriptor_sha256"],
        "manifest_sha256": manifest_sha,
        "script_range": [0, 10_999],
        "consensus_manifest_sha256": consensus_sha,
        "consensus_script_range": [0, 999],
        "bitcoin_core_chain_evidence_path": "bitcoin-core-chain.json",
        "bitcoin_core_chain_evidence_sha256": chain_evidence_sha,
        "threshold_spend_drills": drills,
    }
    parent_path = root / "funded-custody.json"
    write_json(parent_path, parent)
    return parent_path, manifest_path


class FundedCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_context = tempfile.TemporaryDirectory(prefix="custody-fixture-")
        cls.fixture = Path(cls.fixture_context.name)
        build_fixture(cls.fixture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.fixture_context.cleanup()

    def setUp(self) -> None:
        self.context = tempfile.TemporaryDirectory(prefix="custody-test-")
        self.root = Path(self.context.name)
        shutil.copytree(self.fixture, self.root, dirs_exist_ok=True)
        self.parent = self.root / "funded-custody.json"
        self.manifest = self.root / "custody-manifest.json"
        self.consensus_manifest = self.root / "custody-consensus-manifest.json"

    def tearDown(self) -> None:
        self.context.cleanup()

    def validate(self) -> None:
        V.validate(
            self.parent,
            self.manifest,
            self.consensus_manifest,
            self.root,
            [f"signer-{slot + 1}" for slot in range(5)],
            TEST_TARGET,
        )

    def mutate_subreport(self, prefix: str, mutation) -> None:
        parent = json.loads(self.parent.read_text())
        drill = parent["threshold_spend_drills"][0]
        path_key = prefix + "_report_path"
        sha_key = prefix + "_report_sha256"
        path = self.root / drill[path_key]
        report = json.loads(path.read_text())
        mutation(report)
        drill[sha_key] = write_json(path, report)
        write_json(self.parent, parent)

    def mutate_chain_evidence(self, mutation) -> None:
        parent = json.loads(self.parent.read_text())
        path = self.root / parent["bitcoin_core_chain_evidence_path"]
        evidence = json.loads(path.read_text())
        mutation(evidence)
        parent["bitcoin_core_chain_evidence_sha256"] = write_json(path, evidence)
        write_json(self.parent, parent)

    def test_valid_end_to_end_fixture(self) -> None:
        self.assertEqual(V.descriptor_checksum("raw(deadbeef)"), "89f8spxm")
        self.validate()

    def test_interior_manifest_corruption_is_rejected_after_hash_updates(self) -> None:
        manifest = json.loads(self.manifest.read_text())
        manifest["script_pubkeys"][5000] = (
            "5120" + hashlib.sha256(b"valid-shape-but-wrong-interior").hexdigest()
        )
        manifest_sha = write_json(self.manifest, manifest)
        parent = json.loads(self.parent.read_text())
        parent["manifest_sha256"] = manifest_sha
        for drill in parent["threshold_spend_drills"]:
            for prefix in ("three_of_five_success", "two_of_five_rejection"):
                path = self.root / drill[prefix + "_report_path"]
                report = json.loads(path.read_text())
                report["manifest_sha256"] = manifest_sha
                drill[prefix + "_report_sha256"] = write_json(path, report)
        write_json(self.parent, parent)
        with self.assertRaisesRegex(V.ValidationError, "script 5000 does not derive"):
            self.validate()

    def test_consensus_manifest_must_be_exact_prefix(self) -> None:
        consensus = json.loads(self.consensus_manifest.read_text())
        consensus["script_pubkeys"][500] = (
            "5120" + hashlib.sha256(b"wrong-consensus-prefix").hexdigest()
        )
        consensus_sha = write_json(self.consensus_manifest, consensus)
        parent = json.loads(self.parent.read_text())
        parent["consensus_manifest_sha256"] = consensus_sha
        write_json(self.parent, parent)
        with self.assertRaisesRegex(V.ValidationError, r"exact derived \[0,999\] prefix"):
            self.validate()

    def test_fixture_easy_headers_fail_release_mainnet_floor(self) -> None:
        with self.assertRaisesRegex(V.ValidationError, r"compact target|proof of work.*floor"):
            V.validate(
                self.parent,
                self.manifest,
                self.consensus_manifest,
                self.root,
                [f"signer-{slot + 1}" for slot in range(5)],
            )

    def test_broken_best_chain_link_is_rejected(self) -> None:
        def mutate(evidence):
            raw = bytearray.fromhex(evidence["headers"][5]["getblockheader_false_hex"])
            raw[4] ^= 1
            # Keeping the originally requested hash proves the validator does
            # not accept a relabelled or unlinked raw header.
            evidence["headers"][5]["getblockheader_false_hex"] = raw.hex()

        self.mutate_chain_evidence(mutate)
        with self.assertRaisesRegex(V.ValidationError, "hash differs from raw header"):
            self.validate()

    def test_invalid_schnorr_signature_rejected(self) -> None:
        def mutate(report):
            raw = bytearray.fromhex(report["spend_raw_transaction_hex"])
            tx = V.parse_transaction(bytes(raw))
            signature = next(item for item in tx.inputs[0].witness[:5] if item)
            location = bytes(raw).find(signature)
            raw[location] ^= 1
            report["spend_raw_transaction_hex"] = bytes(raw).hex()

        self.mutate_subreport("three_of_five_success", mutate)
        with self.assertRaisesRegex(V.ValidationError, "invalid custody Schnorr"):
            self.validate()

    def test_tampered_merkle_proof_rejected(self) -> None:
        def mutate(report):
            raw = bytearray.fromhex(report["spend_txoutproof_hex"])
            raw[-3] ^= 1
            report["spend_txoutproof_hex"] = bytes(raw).hex()

        self.mutate_subreport("three_of_five_success", mutate)
        with self.assertRaises(V.ValidationError):
            self.validate()

    def test_two_signature_report_cannot_claim_three(self) -> None:
        self.mutate_subreport(
            "two_of_five_rejection", lambda report: report["signer_slots"].append(2)
        )
        with self.assertRaises(V.ValidationError):
            self.validate()

    def test_success_txid_substitution_rejected(self) -> None:
        self.mutate_subreport(
            "three_of_five_success", lambda report: report.__setitem__("spend_txid", "f" * 64)
        )
        with self.assertRaisesRegex(V.ValidationError, "txid differs"):
            self.validate()

    def test_cross_boundary_report_reuse_rejected(self) -> None:
        parent = json.loads(self.parent.read_text())
        first, second = parent["threshold_spend_drills"][:2]
        second["three_of_five_success_report_path"] = first["three_of_five_success_report_path"]
        second["three_of_five_success_report_sha256"] = first["three_of_five_success_report_sha256"]
        write_json(self.parent, parent)
        with self.assertRaisesRegex(V.ValidationError, "reuse"):
            self.validate()

    def test_descriptor_key_order_substitution_is_rejected(self) -> None:
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        payload, _ = manifest["descriptor"].rsplit("#", 1)
        prefix = f"tr({V.NUMS_INTERNAL_KEY.hex()},multi_a(3,"
        expressions = payload[len(prefix) : -2].split(",")
        expressions[0], expressions[1] = expressions[1], expressions[0]
        payload = prefix + ",".join(expressions) + "))"
        manifest["descriptor"] = payload + "#" + V.descriptor_checksum(payload)
        manifest["descriptor_sha256"] = hashlib.sha256(manifest["descriptor"].encode()).hexdigest()
        manifest_sha = write_json(self.manifest, manifest)
        parent = json.loads(self.parent.read_text(encoding="utf-8"))
        parent["descriptor_sha256"] = manifest["descriptor_sha256"]
        parent["manifest_sha256"] = manifest_sha
        for drill in parent["threshold_spend_drills"]:
            for prefix_name in ("three_of_five_success", "two_of_five_rejection"):
                report_path = self.root / drill[prefix_name + "_report_path"]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                report["descriptor_sha256"] = manifest["descriptor_sha256"]
                report["manifest_sha256"] = manifest_sha
                drill[prefix_name + "_report_sha256"] = write_json(report_path, report)
        write_json(self.parent, parent)
        with self.assertRaisesRegex(V.ValidationError, "does not derive"):
            self.validate()

    def test_operator_identity_order_is_cryptographically_bound(self) -> None:
        with self.assertRaisesRegex(V.ValidationError, "positionally map"):
            V.validate(
                self.parent,
                self.manifest,
                self.consensus_manifest,
                self.root,
                ["signer-2", "signer-1", "signer-3", "signer-4", "signer-5"],
                TEST_TARGET,
            )

    def test_missing_or_spent_reject_reason_is_not_threshold_evidence(self) -> None:
        def mutate(report):
            report["reject_reason"] = "bad-txns-inputs-missingorspent"
            raw = json.loads(report["testmempoolaccept_raw_json"])
            raw[0]["reject-reason"] = report["reject_reason"]
            report["testmempoolaccept_raw_json"] = (
                json.dumps(raw, sort_keys=True, separators=(",", ":")) + "\n"
            )

        self.mutate_subreport("two_of_five_rejection", mutate)
        with self.assertRaisesRegex(V.ValidationError, "threshold-script"):
            self.validate()

    def test_rejection_after_success_broadcast_is_refused(self) -> None:
        def mutate(report):
            report["testmempoolaccept_checked_at_utc"] = "2026-08-30T18:00:01Z"
            report["broadcast_at_utc"] = "2026-08-30T18:00:03Z"

        self.mutate_subreport("three_of_five_success", mutate)
        with self.assertRaisesRegex(V.ValidationError, "only after success broadcast"):
            self.validate()

    def test_symlinked_subreport_is_refused_before_resolution(self) -> None:
        parent = json.loads(self.parent.read_text(encoding="utf-8"))
        path = self.root / parent["threshold_spend_drills"][0]["three_of_five_success_report_path"]
        alternate = self.root / "alternate-success.json"
        path.rename(alternate)
        path.symlink_to(alternate.name)
        with self.assertRaisesRegex(V.ValidationError, "traverses a symlink"):
            self.validate()


if __name__ == "__main__":
    unittest.main()
