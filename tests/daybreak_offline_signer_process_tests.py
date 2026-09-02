#!/usr/bin/env python3
"""End-to-end malicious-preparer regression for the production keygen sink."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def run(argv: list[str], env: dict[str, str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, text=True, capture_output=True, env=env, timeout=timeout,
        check=False,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keygen", required=True)
    parser.add_argument("--fixture", required=True)
    args = parser.parse_args()
    keygen = str(Path(args.keygen).resolve())
    fixture = str(Path(args.fixture).resolve())
    checks = 0

    with tempfile.TemporaryDirectory(prefix="veld-offline-signer-") as tmp:
        root = Path(tmp)
        keyfile = root / "offline.key"
        passphrase = "Veld-Daybreak-Offline-Process-Test-Only-31!"
        env = os.environ.copy()
        env["VELD_VAULT_PASSPHRASE"] = passphrase

        prepared = run([fixture, "--prepare-dir", str(root)], env)
        assert prepared.returncode == 0 and "PASS private-dir" in prepared.stdout, prepared.stderr
        checks += 1

        created = run([keygen, "new", "--out", str(keyfile)], env)
        assert created.returncode == 0 and keyfile.is_file(), created.stderr
        checks += 1
        shown = run([keygen, "show", str(keyfile)], env)
        assert shown.returncode == 0, shown.stderr
        match = re.search(r"^address:\s+(\S+)\s*$", shown.stdout, re.MULTILINE)
        assert match, shown.stdout
        address = match.group(1)
        checks += 1

        fixture_dir = root / "fixtures"
        generated = run([fixture, address, str(fixture_dir)], env)
        assert generated.returncode == 0, generated.stderr
        checks += 1

        identity_digest = (fixture_dir / "canonical.identity-digest.txt").read_text(
            encoding="ascii"
        ).strip()
        assert re.fullmatch(r"[0-9a-f]{64}", identity_digest)
        checks += 1

        valid_rows = [row.split("\t") for row in
                      (fixture_dir / "valid-operations.tsv").read_text(
                          encoding="utf-8").splitlines() if row]
        assert {row[0] for row in valid_rows} == {
            "bhdr", "anchor", "rsv1", "rtp1_mint", "c1_reserve"
        }
        checks += 1
        approved_intent: Path | None = None
        for (name, sign_command, operation_type, recipient, amount,
             operation_digest, prepared_name) in valid_rows:
            approved = root / f"approved-{name}.intent.json"
            authorized = run([
                keygen, "authorize-intent", str(keyfile),
                str(fixture_dir / prepared_name),
                "--operation-type", operation_type,
                "--recipient", recipient,
                "--amount", amount,
                "--change-destination", address,
                "--operation-identity-digest", operation_digest,
                "--maximum-absolute-fee", "100000",
                "--maximum-fee-rate", "19",
                "--out", str(approved),
            ], env, timeout=180)
            auth_combined = authorized.stdout + authorized.stderr
            assert authorized.returncode == 0 and approved.is_file(), auth_combined
            assert "No transaction input was signed" in authorized.stderr
            assert passphrase not in auth_combined
            signed = root / f"valid-{name}.signed.hex"
            result = run([
                keygen, sign_command, str(keyfile),
                str(fixture_dir / prepared_name),
                "--intent", str(approved), "--out", str(signed),
            ], env, timeout=180)
            combined = result.stdout + result.stderr
            assert result.returncode == 0 and signed.is_file(), combined
            assert operation_digest in result.stderr and passphrase not in combined
            verified = run([
                fixture, "--verify-signed", address,
                str(fixture_dir / prepared_name), str(signed),
            ], env)
            assert (verified.returncode == 0 and
                    "PASS signed-inputs=" in verified.stdout), (
                        verified.stdout + verified.stderr)
            if name == "rsv1":
                assert "identity bytes:" in result.stderr
                assert "(0 payload bytes)" not in result.stderr
            if name == "bhdr":
                approved_intent = approved
            checks += 7
        assert approved_intent is not None
        checks += 1

        # A public self-digest from the preparer is not authorization, whether
        # supplied bare or nested exactly as the RPC response embeds it.
        for suffix, unapproved in (
            ("bare", fixture_dir / "canonical.intent.json"),
            ("nested", root / "nested.intent.json"),
        ):
            if suffix == "nested":
                nested = {"signing_intent": json.loads(
                    (fixture_dir / "canonical.intent.json").read_text(
                        encoding="utf-8"))}
                unapproved.write_text(json.dumps(nested, separators=(",", ":")),
                                      encoding="utf-8")
            refused_out = root / f"unapproved-{suffix}.signed.hex"
            refused = run([
                keygen, "sign-op", str(keyfile),
                str(fixture_dir / "canonical.prepared.json"),
                "--intent", str(unapproved), "--out", str(refused_out),
            ], env)
            assert refused.returncode in (1, 2) and not refused_out.exists()
            assert "Nothing was signed" in refused.stderr
            checks += 2

        # The authorized document has one exact top-level shape.  In
        # particular, the generic RPC `result` alias accepted by other JSON
        # helpers must never substitute for the signed `signing_intent` member.
        approved_text = approved_intent.read_text(encoding="utf-8")
        approved_shape = json.loads(approved_text)
        result_alias = dict(approved_shape)
        result_alias["result"] = result_alias.pop("signing_intent")
        extra_member = dict(approved_shape)
        extra_member["unexpected"] = {}
        signing_json = json.dumps(
            approved_shape["signing_intent"], separators=(",", ":"))
        authorization_json = json.dumps(
            approved_shape["intent_authorization"], separators=(",", ":"))
        duplicate_member = (
            '{"signing_intent":' + signing_json +
            ',"signing_intent":' + signing_json +
            ',"intent_authorization":' + authorization_json + '}'
        )
        escaped_member = approved_text.replace(
            '"signing_intent"', '"signing_int\\u0065nt"', 1)
        document_cases = {
            "result-alias": json.dumps(result_alias, separators=(",", ":")),
            "extra-member": json.dumps(extra_member, separators=(",", ":")),
            "duplicate-member": duplicate_member,
            "escaped-member": escaped_member,
        }
        for name, content in document_cases.items():
            malformed_document = root / f"{name}.intent.json"
            malformed_document.write_text(content, encoding="utf-8")
            refused_out = root / f"{name}.signed.hex"
            refused = run([
                keygen, "sign-op", str(keyfile),
                str(fixture_dir / "canonical.prepared.json"),
                "--intent", str(malformed_document), "--out", str(refused_out),
            ], env)
            assert refused.returncode in (1, 2) and not refused_out.exists(), (
                refused.stdout + refused.stderr)
            assert "Nothing was signed" in refused.stderr
            checks += 2

        # A real lower authorized rate limit exercises the rate ceiling in the
        # production process rather than mutating an in-memory test structure.
        low_rate_intent = root / "low-rate.intent.json"
        low_rate = run([
            keygen, "authorize-intent", str(keyfile),
            str(fixture_dir / "canonical.prepared.json"),
            "--operation-type", "VELD_BHDR|", "--recipient", "-",
            "--amount", "0", "--change-destination", address,
            "--operation-identity-digest", identity_digest,
            "--maximum-absolute-fee", "100000",
            "--maximum-fee-rate", "18", "--out", str(low_rate_intent),
        ], env)
        assert low_rate.returncode != 0 and not low_rate_intent.exists()
        assert "fee exceeds intent ceiling" in low_rate.stderr
        checks += 2

        wrong_identity_intent = root / "wrong-identity.intent.json"
        wrong_identity = run([
            keygen, "authorize-intent", str(keyfile),
            str(fixture_dir / "canonical.prepared.json"),
            "--operation-type", "VELD_BHDR|", "--recipient", "-",
            "--amount", "0", "--change-destination", address,
            "--operation-identity-digest", "0" * 64,
            "--maximum-absolute-fee", "100000",
            "--maximum-fee-rate", "19", "--out", str(wrong_identity_intent),
        ], env)
        assert wrong_identity.returncode != 0 and not wrong_identity_intent.exists()
        assert "authorization semantics" in wrong_identity.stderr
        checks += 2

        approved_doc = json.loads(approved_intent.read_text(encoding="utf-8"))
        signature = approved_doc["intent_authorization"]["signature_hex"]
        approved_doc["intent_authorization"]["signature_hex"] = (
            ("0" if signature[0] != "0" else "1") + signature[1:]
        )
        tampered_intent = root / "tampered.intent.json"
        tampered_intent.write_text(
            json.dumps(approved_doc, separators=(",", ":")), encoding="utf-8")
        tampered_out = root / "tampered.signed.hex"
        tampered = run([
            keygen, "sign-op", str(keyfile),
            str(fixture_dir / "canonical.prepared.json"),
            "--intent", str(tampered_intent), "--out", str(tampered_out),
        ], env)
        assert tampered.returncode != 0 and not tampered_out.exists()
        assert "authorization signature is invalid" in tampered.stderr
        checks += 2

        rows = []
        for raw in (fixture_dir / "cases.tsv").read_text(encoding="utf-8").splitlines():
            if raw:
                rows.append(raw.split("\t"))
        assert rows and any(row[0] == "canonical" for row in rows)
        checks += 1

        for name, prepared_name, _intent_name, expected in rows:
            signed = fixture_dir / f"{name}.signed.hex"
            result = run([
                keygen, "sign-op", str(keyfile),
                str(fixture_dir / prepared_name),
                "--intent", str(approved_intent),
                "--out", str(signed),
            ], env, timeout=180)
            combined = result.stdout + result.stderr
            assert passphrase not in combined
            checks += 1
            if expected == "pass":
                assert result.returncode == 0, combined
                signed_hex = signed.read_text(encoding="ascii").strip()
                assert signed_hex and len(signed_hex) % 2 == 0
                assert re.fullmatch(r"[0-9a-f]+", signed_hex)
                assert "canonical fees-only relay verified: VELD_BHDR|" in result.stderr
                assert "raw parents txid/vout/value/script authenticated" in result.stderr
                assert "fee rate" in result.stderr and "source digest" in result.stderr
                assert "marker family: VELD_BHDR" in result.stderr
                verified = run([
                    fixture, "--verify-signed", address,
                    str(fixture_dir / prepared_name), str(signed),
                ], env)
                assert (verified.returncode == 0 and
                        "PASS signed-inputs=" in verified.stdout), (
                            verified.stdout + verified.stderr)
                checks += 8
            else:
                assert result.returncode in (1, 2), (
                    f"{name} did not make a controlled refusal: "
                    f"returncode={result.returncode}\n{combined}")
                assert not signed.exists(), f"{name} produced a signed artifact"
                assert "Nothing was signed" in result.stderr
                if name.startswith((
                        "marker_truncated_", "marker_declared_",
                        "marker_direct_", "marker_unsupported_")):
                    assert "REFUSED (operation marker)" in result.stderr
                    checks += 1
                checks += 3

        # Even an attacker-recomputed public intent for a modified input cannot
        # substitute for the detached signer authorization.
        alternate_out = root / "alternate-self-issued.signed.hex"
        alternate = run([
            keygen, "sign-op", str(keyfile),
            str(fixture_dir / "alternate_valid_vout.prepared.json"),
            "--intent", str(fixture_dir / "alternate_vout.intent.json"),
            "--out", str(alternate_out),
        ], env)
        assert alternate.returncode != 0 and not alternate_out.exists()
        assert "Nothing was signed" in alternate.stderr
        checks += 2

    print(f"PASS daybreak_offline_signer_process_tests checks={checks} cases={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
