#!/usr/bin/env python3
"""
test_signed_beat.py - end-to-end regression for the SIGNED watchtower heartbeat
(audit F). Proves the beat the watchtower sends is ML-DSA-signed and that the
receiver's verification rejects tampering and wrong-key forgery.

Runs the REAL crypto through veld-keygen's sign-release / verify-release - the exact
path veld_watchtowerd._sign_payload and veld_wt_recv.verify_beat_sig use - over the
REAL canonical_beat_bytes serialization both daemons share. Skips (exit 0) if no
veld-keygen binary is available, so it never blocks a Python-only CI box.

  find veld-keygen: $VELD_KEYGEN, else ./veld-keygen beside this file, else on PATH.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_peg_solvency as sol  # noqa: E402

fails = 0


def check(name, ok):
    global fails
    print("  %-46s %s" % (name, "ok" if ok else "FAIL"))
    if not ok:
        fails += 1


def find_keygen():
    c = os.environ.get("VELD_KEYGEN") or os.path.join(HERE, "veld-keygen")
    if os.path.exists(c):
        return c
    return shutil.which("veld-keygen")


def run(keygen, args, env=None):
    return subprocess.run([keygen] + args, capture_output=True, text=True, timeout=60, env=env)


def pubkey_hex(keygen, keyfile, env):
    out = run(keygen, ["show", keyfile, "--full-pubkey-hex"], env).stdout
    for tok in out.split():
        t = tok.strip()
        if len(t) >= 200 and all(c in "0123456789abcdefABCDEF" for c in t):
            return t.lower()
    return ""


def canonical(**over):
    p = sol.build_beat_payload(
        10 * sol.SATS, 6 * sol.SATS, 100000, tip=42, tip_hash="22" * 32, seq=7, ttl_secs=120
    )
    p.update(over)
    return sol.canonical_beat_bytes(p)


def main():
    # --- pure: canonical bytes are deterministic + exclude the sig envelope --------
    a = canonical()
    check("canonical_beat_bytes deterministic", a == canonical())
    p = sol.build_beat_payload(10 * sol.SATS, 6 * sol.SATS, 100000, 42, "22" * 32, 7, 120)
    p2 = dict(p)
    p2["sig"] = "ab"
    p2["sig_alg"] = "mldsa65"
    check(
        "canonical excludes sig envelope",
        sol.canonical_beat_bytes(p) == sol.canonical_beat_bytes(p2),
    )

    keygen = find_keygen()
    if not keygen:
        print("  (no veld-keygen found - skipping the ML-DSA round-trip)")
        print("\n%s" % ("ALL PASS" if fails == 0 else "FAIL (%d)" % fails))
        return 0 if fails == 0 else 1

    env = dict(os.environ)
    env["VELD_VAULT_PASSPHRASE"] = "beat-regression-pass"
    with tempfile.TemporaryDirectory() as td:
        beatkey = os.path.join(td, "beat.key")
        otherkey = os.path.join(td, "other.key")
        pin = os.path.join(td, "pub.hex")
        bf = os.path.join(td, "beat.bin")
        bft = os.path.join(td, "beat_t.bin")
        sf = os.path.join(td, "beat.sig")
        sff = os.path.join(td, "beat_f.sig")

        run(keygen, ["new", "--out", beatkey], env)
        run(keygen, ["new", "--out", otherkey], env)
        with open(pin, "w") as f:
            f.write(pubkey_hex(keygen, beatkey, env))

        with open(bf, "wb") as f:
            f.write(canonical())
        with open(bft, "wb") as f:
            f.write(
                canonical(
                    backing_liability_sats=6 * sol.SATS - 1,
                    headroom_sats=sol.solvency_headroom(10 * sol.SATS, 6 * sol.SATS - 1, 100000),
                )
            )

        s = run(keygen, ["sign-release", beatkey, bf, sf], env)
        check("sign-release produced a signature", s.returncode == 0 and os.path.exists(sf))
        run(keygen, ["sign-release", otherkey, bf, sff], env)  # forged by a different key

        genuine = run(keygen, ["verify-release", "@" + pin, bf, sf]).returncode
        tampered = run(keygen, ["verify-release", "@" + pin, bft, sf]).returncode
        forged = run(keygen, ["verify-release", "@" + pin, bf, sff]).returncode

        check("genuine beat verifies (rc=0)", genuine == 0)
        check("tampered beat (lowered backing liability) rejected", tampered != 0)
        check("forged beat (wrong key) rejected", forged != 0)

    print("\n%s" % ("ALL PASS" if fails == 0 else "FAIL (%d)" % fails))
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
