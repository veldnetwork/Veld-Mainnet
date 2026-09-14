"""Actual keygen backing decoder and optional isolated Bitcoin Core checks.

This qualifies the evidence boundary, not native mint admission, witness service
migration, operator independence, or production activation.
"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "swap"))
import rtp1_backing_evidence as evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keygen", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--core", type=Path)
    parser.add_argument("--core-sha256")
    parser.add_argument("--proof", type=Path)
    parser.add_argument("--service-lifecycle", action="store_true")
    args = parser.parse_args()
    assert not args.output.exists()
    assert bool(args.core) != bool(args.proof)
    report = {"status": "running", "started_utc": datetime.now(timezone.utc).isoformat(),
        "platform": os.name, "keygen_sha256": hashlib.sha256(args.keygen.read_bytes()).hexdigest(),
        "fixture_sha256": hashlib.sha256(args.fixture.read_bytes()).hexdigest(),
        "checks": {}, "native_issuance_tested": False, "production_access": False,
        "independent_bitcoin_process": bool(args.core), "services_migrated": False}
    source = Path(__file__).resolve().parents[1]
    report["source_sha256"] = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [source / "swap" / name for name in (
            "rtp1_service.py", "rtp1_service_runtime.py", "rtp1_backing_evidence.py", "rtp1_mint_policy.py",
            "veld_signerd.py", "veld_wt_reserve.py", "rpc_url_policy.py")]
        + [Path(__file__).resolve(), source / "tests/rtp1_service_process_checks.py",
            source / "tests/rtp1_descriptor_process_checks.py", source / "swap/veld_custody_binding.py"]}
    core = None
    try:
        with tempfile.TemporaryDirectory(prefix="rtp1-backing-check-") as temporary, ExitStack() as services:
            root = Path(temporary)
            env = dict(os.environ, VELD_VAULT_PASSPHRASE="Disposable-RTP1-backing-check-2026!")

            def run(argv, data=None, expected=0):
                value = subprocess.run([str(a) for a in argv], input=data, text=True,
                    capture_output=True, timeout=180, env=env)
                assert value.returncode == expected, (argv[1], value.returncode, value.stderr[-400:])
                assert env["VELD_VAULT_PASSPHRASE"] not in value.stdout + value.stderr
                return value.stdout

            run([args.fixture, "--prepare-dir", root])
            key = root / "issuer.key"
            run([args.keygen, "new", "--out", key])
            issuer = re.search(r"^address:\s+(\S+)\s*$", run([args.keygen, "show", key]), re.M).group(1)
            auth = json.loads(run([args.fixture, "--rtp1-open-auth"]))
            proof = None
            if args.core:
                assert os.name == "posix" and args.core_sha256
                assert hashlib.sha256(args.core.read_bytes()).hexdigest() == args.core_sha256
                assert os.environ["VELD_PARENT_NET_NS"] != os.readlink("/proc/self/ns/net")
                links = json.loads(subprocess.check_output(["ip", "-j", "link"]))
                assert len(links) == 1 and links[0]["ifname"] == "lo"
                from security_first_activation_network_tests import Bitcoin, btc
                core = Bitcoin(args.core, root / "bitcoin")
                def stop_core():
                    nonlocal core
                    if core is not None:
                        core.stop()
                        assert core.process.returncode == 0
                        core = None
                        report["bitcoin_stopped"] = True
                services.callback(stop_core)
                assert core.rpc("getnetworkinfo")["networkactive"] is False
                assert core.rpc("getblockchaininfo")["chain"] == "regtest"
                core.mine(110)
                funding = core.fund(auth["sats"] + 1000)
                address = core.rpc("decodescript", [auth["custody_script_hex"]])["address"]
                transaction = core.send([funding], [{address: btc(auth["sats"])}, {"data": auth["payload"]}])
                core.mine(140)
                proof = core.proof(transaction)
                proof_path = args.output.with_name(args.output.stem + "-public-proof.json")
                assert not proof_path.exists()
                proof_path.write_text(json.dumps(proof, indent=2) + "\n")
                report["public_proof"] = str(proof_path)
                report["bitcoin_sha256"] = args.core_sha256
            else:
                assert args.proof.is_file() and args.proof.stat().st_size < 270 * 1024
                proof = json.loads(args.proof.read_text())
            proof_input = root / "proof.json"
            proof_input.write_text(json.dumps(proof))
            prepared = json.loads(run([args.fixture, "--rtp1-core-template", issuer, proof_input]))
            payload = {"issuer_script_hex": prepared["inputs"][0]["prev_script_hex"],
                "unsigned_tx_hex": prepared["unsigned_tx_hex"],
                "reserve_prior_state_hex": prepared["reserve_prior_state_hex"],
                "reserve_prior_supply_sats": prepared["reserve_prior_supply_sats"]}
            facts = evidence.validate_backing_facts(json.loads(run(
                [args.keygen, "inspect-rtp1-backing-stdin"], json.dumps(payload))))
            assert facts["issuer"] == issuer and facts["recipient"] == auth["recipient"]
            assert facts["sats"] == auth["sats"] and facts["operation"] == "OPEN"
            assert facts["bitcoin_txid"] == bytes.fromhex(proof["txid"])[::-1].hex()
            assert facts["custody_script_hex"] == auth["custody_script_hex"]
            report["checks"]["actual_native_decoder_matches_core_proof"] = True
            wrong = dict(payload, reserve_prior_supply_sats=True)
            run([args.keygen, "inspect-rtp1-backing-stdin"], json.dumps(wrong), expected=2)
            run([args.keygen, "inspect-rtp1-backing-stdin"], json.dumps(payload)[:-1] + ',"extra":1}', expected=2)
            mutated = dict(payload, unsigned_tx_hex=payload["unsigned_tx_hex"] + "00")
            run([args.keygen, "inspect-rtp1-backing-stdin"], json.dumps(mutated), expected=2)
            report["checks"]["wrong_context_schema_and_trailing_bytes_refused"] = True

            parent_request = {"issuer_script_hex": payload["issuer_script_hex"],
                "unsigned_tx_hex": payload["unsigned_tx_hex"],
                "parent_transactions": [row["parent_tx_hex"] for row in prepared["inputs"]]}
            signing_evidence = json.loads(run([args.keygen, "prepare-signing-stdin"], json.dumps(parent_request)))
            prepared_path = root / "prepared.json"
            prepared_path.write_text(json.dumps(prepared))
            intent, signed = root / "intent.json", root / "signed.hex"
            run([args.keygen, "authorize-intent", key, prepared_path,
                "--operation-type", "BTCVELD_MINT", "--recipient", facts["recipient"],
                "--amount", str(facts["sats"]), "--change-destination", issuer,
                "--operation-identity-digest", signing_evidence["operation_identity_digest"],
                "--maximum-absolute-fee", "100000", "--maximum-fee-rate", "19", "--out", intent])
            run([args.keygen, "sign-tx", key, prepared_path, "--intent", intent, "--out", signed])
            assert "PASS signed-inputs=" in run([args.fixture, "--verify-signed", issuer, prepared_path, signed])
            report["checks"]["core_backed_template_actual_issuer_signature_verified_offline"] = True

            if core:
                policy = {"expected_network": "regtest", "expected_genesis": core.rpc("getblockhash", [0]),
                    "custody_script_hex": auth["custody_script_hex"], "min_confirmations": 144}
                verified = evidence.verify_bitcoin_backing(core.rpc, facts, **policy)
                assert verified["confirmations"] >= 144
                report["backing"] = verified
                if args.service_lifecycle:
                    from rtp1_service_process_checks import exercise
                    report["service_lifecycle"] = exercise(root, run, args.keygen, args.fixture,
                        key, issuer, prepared, facts, verified, signing_evidence, env["VELD_VAULT_PASSPHRASE"])
                    from rtp1_descriptor_process_checks import exercise as descriptor_check
                    report["descriptor_adapter"] = descriptor_check(root, core)
                report["checks"]["real_core_144_confirmations_unspent_successor"] = True
                core.rpc("invalidateblock", [facts["bitcoin_block"]])
                try:
                    evidence.verify_bitcoin_backing(core.rpc, facts, **policy)
                except ValueError:
                    pass
                else:
                    raise AssertionError("orphaned Bitcoin backing was accepted")
                report["checks"]["real_core_reorganization_refused"] = True
                core.rpc("reconsiderblock", [facts["bitcoin_block"]])
                assert evidence.verify_bitcoin_backing(core.rpc, facts, **policy) == verified
                report["checks"]["restored_exact_bitcoin_branch_reverified"] = True
                core.stop()
                assert core.process.returncode == 0
                core = None
                report["bitcoin_stopped"] = True
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["failure"] = {"type": type(error).__name__, "message": str(error)}
        raise
    finally:
        if core is not None:
            try:
                core.stop()
                report["bitcoin_stopped"] = True
            except BaseException as error:
                report["cleanup_failure"] = type(error).__name__
        report["ended_utc"] = datetime.now(timezone.utc).isoformat()
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS native RTP1 backing evidence; issuer/witness service migration remains separate")


if __name__ == "__main__":
    main()
