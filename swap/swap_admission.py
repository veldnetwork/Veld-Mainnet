#!/usr/bin/env python3
"""Admission-proof contract for public btcVELD mint requests.

The HTTP service owns the rotating beacon and verifies the ML-DSA-65 proof;
the wrap service owns durable per-principal and global accounting. Keeping
the two layers separate makes the cryptographic contract independently
testable without importing (and starting) the production service.
"""
import hashlib
import os
import re
import stat
import tempfile
import threading
import time

try:
    from .rpc_url_policy import run_bounded_subprocess
except ImportError:
    from rpc_url_policy import run_bounded_subprocess


ADMISSION_VERSION = 2
ADMISSION_POW_BITS = 24
ADMISSION_EPOCH_SECONDS = 600
MLDSA65_PUBLIC_KEY_HEX_CHARS = 1952 * 2
MLDSA65_SIGNATURE_HEX_CHARS = 3309 * 2
_HEX64 = re.compile(r"[0-9a-f]{64}")
_NONCE = re.compile(r"[0-9a-f]{16}")
_FOREIGN_PUB = re.compile(r"(?:[0-9a-f]{2})*")
_VELD_PUB = re.compile(r"[0-9a-f]{3904}")
_SIG = re.compile(r"[0-9a-f]{6618}")


def _strict_request_values(coin, amount, H_hex, foreign_pub, veld_pub):
    if (not isinstance(coin, str) or not re.fullmatch(r"[A-Z0-9]{1,8}", coin)):
        raise ValueError("quote admission request body is malformed")
    if type(amount) is not int or amount <= 0 or amount > 9_223_372_036_854_775_807:
        raise ValueError("quote admission request body is malformed")
    if not isinstance(H_hex, str) or not _HEX64.fullmatch(H_hex):
        raise ValueError("quote admission request body is malformed")
    if (not isinstance(foreign_pub, str)
            or len(foreign_pub) > 512
            or not _FOREIGN_PUB.fullmatch(foreign_pub)):
        raise ValueError("quote admission request body is malformed")
    if not isinstance(veld_pub, str) or not _VELD_PUB.fullmatch(veld_pub):
        raise ValueError("quote admission request body is malformed")


def canonical_request_body(coin, amount, H_hex, foreign_pub, veld_pub):
    """Canonical ASCII business body bound by both PoW and ML-DSA.

    Decimal and lowercase-hex encodings are unique. NUL separation prevents
    field-boundary ambiguity without depending on JSON serializer behavior.
    """
    _strict_request_values(coin, amount, H_hex, foreign_pub, veld_pub)
    return b"\x00".join((
        b"VELD-SWAP-QUOTE-BODY-v2", coin.encode("ascii"),
        str(amount).encode("ascii"), H_hex.encode("ascii"),
        foreign_pub.encode("ascii"), veld_pub.encode("ascii"),
    ))


def request_hash(coin, amount, H_hex, foreign_pub, veld_pub):
    return hashlib.sha256(canonical_request_body(
        coin, amount, H_hex, foreign_pub, veld_pub)).digest()


def signature_message(beacon_hex, nonce_hex, canonical_body):
    if not isinstance(beacon_hex, str) or not _HEX64.fullmatch(beacon_hex):
        raise ValueError("quote admission beacon is malformed")
    if not isinstance(nonce_hex, str) or not _NONCE.fullmatch(nonce_hex):
        raise ValueError("quote admission proof is malformed")
    if not isinstance(canonical_body, bytes) or not canonical_body:
        raise ValueError("quote admission request body is malformed")
    # veldCrypto.signMessage and veld-keygen verify-release both sign/verify
    # Hash256d(exact message bytes).  The tuple below therefore has one exact
    # browser/server representation and binds the full request body, not merely
    # a caller-supplied digest.
    return (b"VELD-SWAP-QUOTE-ADMISSION-v2\x00"
            + beacon_hex.encode("ascii") + b"\x00"
            + nonce_hex.encode("ascii") + b"\x00" + canonical_body)


def principal_hash(public_key_hex):
    if (not isinstance(public_key_hex, str)
            or not _VELD_PUB.fullmatch(public_key_hex)):
        raise ValueError("quote admission principal public key is malformed")
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()


def has_leading_zero_bits(digest, bits):
    if not isinstance(digest, bytes) or len(digest) != 32:
        return False
    if type(bits) is not int or bits < 1 or bits > 256:
        return False
    whole, partial = divmod(bits, 8)
    return (digest[:whole] == b"\x00" * whole
            and (partial == 0
                 or digest[whole] >> (8 - partial) == 0))


class AdmissionBeacon:
    """One unpredictable process-local beacon per exact 600-second epoch."""
    def __init__(self, epoch_seconds=ADMISSION_EPOCH_SECONDS, random_bytes=os.urandom):
        if type(epoch_seconds) is not int or epoch_seconds != ADMISSION_EPOCH_SECONDS:
            raise ValueError("swap admission epoch must be exactly 600 seconds")
        self.epoch_seconds = epoch_seconds
        self._random_bytes = random_bytes
        self._lock = threading.Lock()
        self._epoch = -1
        self._beacon = b""

    def current(self, now=None):
        current = int(time.time()) if now is None else now
        if type(current) is not int or current < 0:
            raise ValueError("swap admission clock is invalid")
        epoch = current // self.epoch_seconds
        with self._lock:
            if epoch != self._epoch:
                entropy = self._random_bytes(32)
                if not isinstance(entropy, bytes) or len(entropy) != 32:
                    raise RuntimeError("swap admission entropy source failed")
                self._beacon = hashlib.sha256(
                    b"VELD-SWAP-EPOCH-BEACON-v2\x00"
                    + epoch.to_bytes(8, "big") + entropy).digest()
                self._epoch = epoch
            return {
                "version": ADMISSION_VERSION,
                "algorithm": "sha256-beacon-request-hash-leading-zero-bits",
                "signature_algorithm": "mldsa65-hash256d",
                "bits": ADMISSION_POW_BITS,
                "epoch_seconds": self.epoch_seconds,
                "epoch": epoch,
                "beacon": self._beacon.hex(),
                # Give clients an authenticated-by-origin clock sample from the
                # same observation that selected this epoch.  They use only the
                # bounded *difference* to expires_at, measured thereafter with
                # a monotonic clock, so a skewed desktop wall clock cannot burn
                # work against an already-expired beacon or hammer refreshes.
                "server_time": current,
                "expires_at": (epoch + 1) * self.epoch_seconds,
            }


def verify_mldsa65_with_keygen(public_key_hex, message, signature_hex,
                               keygen_path):
    """Verify with the release's own ML-DSA implementation, fail closed."""
    if (not isinstance(keygen_path, str) or not os.path.isabs(keygen_path)
            or "\x00" in keygen_path):
        raise RuntimeError("admission verifier path must be absolute")
    try:
        info = os.stat(keygen_path, follow_symlinks=False)
    except OSError as exc:
        raise RuntimeError("admission verifier is unavailable") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        raise RuntimeError("admission verifier executable is unsafe")
    if (not isinstance(public_key_hex, str)
            or len(public_key_hex) != MLDSA65_PUBLIC_KEY_HEX_CHARS
            or not _VELD_PUB.fullmatch(public_key_hex)
            or not isinstance(signature_hex, str)
            or len(signature_hex) != MLDSA65_SIGNATURE_HEX_CHARS
            or not _SIG.fullmatch(signature_hex)
            or not isinstance(message, bytes) or not message):
        return False
    with tempfile.TemporaryDirectory(prefix="veld-swap-admission-") as root:
        paths = [os.path.join(root, name) for name in (
            "principal.pub", "request.bin", "request.sig")]
        payloads = [public_key_hex.encode("ascii") + b"\n", message,
                    bytes.fromhex(signature_hex)]
        for path, payload in zip(paths, payloads):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as out:
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
        result = run_bounded_subprocess(
            [keygen_path, "verify-release", "@" + paths[0], paths[1], paths[2]],
            timeout=5, stdout_max=4096, stderr_max=4096,
            description="swap admission ML-DSA verifier")
        return result.returncode == 0


def verify_admission(body, coin, amount, H_hex, foreign_pub, veld_pub,
                     beacon_authority, signature_verifier, now=None,
                     pow_bits=ADMISSION_POW_BITS):
    """Verify current beacon, exact 24-bit PoW, and signed principal tuple."""
    if not isinstance(body, dict):
        raise ValueError("quote admission proof is malformed")
    current = beacon_authority.current(now=now)
    beacon_hex = body.get("admission_beacon")
    nonce_hex = body.get("admission_nonce")
    signature_hex = body.get("admission_signature")
    if (beacon_hex != current["beacon"]
            or not isinstance(nonce_hex, str) or not _NONCE.fullmatch(nonce_hex)
            or not isinstance(signature_hex, str) or not _SIG.fullmatch(signature_hex)):
        raise ValueError("quote admission proof is malformed or not current")
    canonical = canonical_request_body(
        coin, amount, H_hex, foreign_pub, veld_pub)
    digest = hashlib.sha256(
        bytes.fromhex(beacon_hex) + bytes.fromhex(nonce_hex)
        + hashlib.sha256(canonical).digest()).digest()
    if not has_leading_zero_bits(digest, pow_bits):
        raise ValueError("quote admission proof does not meet difficulty")
    message = signature_message(beacon_hex, nonce_hex, canonical)
    if signature_verifier(veld_pub, message, signature_hex) is not True:
        raise ValueError("quote admission principal signature is invalid")
    return principal_hash(veld_pub)
