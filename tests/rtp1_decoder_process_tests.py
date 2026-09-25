"""Keyless decoder interoperability using public receipts from a local native run."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def issuer_script(address):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    value = 0
    for char in address:
        value = value * 58 + alphabet.index(char)
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    raw = b"\0" * (len(address) - len(address.lstrip("1"))) + raw
    assert len(raw) == 25 and raw[0] == 0x46
    assert hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()[:4] == raw[-4:]
    return "76a914" + raw[1:21].hex() + "88ac"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--keygen", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checks = []
    for path in args.receipt:
        assert path.stat().st_size <= 512 * 1024
        receipt = json.loads(path.read_text())
        observed = receipt["inspection"]
        if isinstance(observed, str):
            observed = json.loads(observed)
        if "result" in observed:
            observed = observed["result"]
        unsigned = receipt["unsigned_tx_hex"]
        assert observed["unsigned_tx_sha256"] == hashlib.sha256(bytes.fromhex(unsigned)).hexdigest()
        request = {
            "issuer_script_hex": issuer_script(observed["issuer"]),
            "unsigned_tx_hex": unsigned,
            "reserve_prior_state_hex": observed["reserve_prior_state_hex"],
            "reserve_prior_supply_sats": observed["reserve_prior_supply_sats"],
        }
        run = subprocess.run(
            [str(args.keygen), "decode-mint-stdin"],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        decoded = json.loads(run.stdout)
        assert decoded["from"] == observed["issuer"] and decoded["to"] == observed["recipient"]
        assert decoded["sats"] == observed["sats"] and decoded["num_inputs"] > 0
        assert decoded["memo"].startswith("RTP1:")
        assert (
            hashlib.sha256(bytes.fromhex(decoded["memo"][5:])).hexdigest()
            == observed["proof_sha256"]
        )
        checks.append(
            {
                "receipt": path.name,
                "receipt_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "unsigned_sha256": observed["unsigned_tx_sha256"],
                "amount_sats": decoded["sats"],
                "exact_native_decode": True,
            }
        )
    missing = subprocess.run(
        [str(args.keygen), "decode-mint-stdin"],
        input="{}",
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert missing.returncode != 0 and missing.stdout == ""
    report = {
        "status": "passed",
        "keygen_sha256": hashlib.sha256(args.keygen.read_bytes()).hexdigest(),
        "keyless": True,
        "network_access": False,
        "signing_executed": False,
        "native_receipts": checks,
        "incomplete_request_refused": True,
        "limits": [
            "Decoder checks retained public templates; no fresh signing authority or issuer/witness lifecycle is established."
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("PASS native RTP1 decoder interoperability: " + str(len(checks)) + " receipts")


if __name__ == "__main__":
    main()
