#!/usr/bin/env python3
"""
veld_wt_recv.py - signer-box receiver for the independent peg watchtower.

Installed on the SIGNER box as the SSH authorized_keys FORCED-COMMAND for the
WATCHTOWER's key ONLY (see swap/deploy/signer-authorized_keys.example):

  command="/usr/bin/python3 /opt/veld-signer/veld_wt_recv.py",no-pty,\
  no-port-forwarding,no-X11-forwarding,no-agent-forwarding <watchtower-pubkey>

It reads ONE JSON beat payload on stdin and does EXACTLY one of two things:

  kind=SOLVENT -> (re)write signer-heartbeat.json, stamped with the receiver's
                  own clock (bounded lifetime). This is what keeps the signer
                  live; it must be refreshed by the watchtower before it expires.
  kind=HALT    -> create the sticky HALT file. Never auto-removed - a human must
                  clear it after investigating (matches the signer's contract).

It can do NOTHING else: no shell, no caller-supplied paths, no key access, no
signing. So the watchtower's SSH key grants only "pause or halt the signer",
never "mint". Any malformed input is rejected and changes nothing (fail-closed).
"""
import json
import fcntl
import os
import subprocess
import sys
import tempfile
import time
import stat

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import veld_peg_solvency as sol  # noqa: E402
from rpc_url_policy import (read_bounded_regular_file,
                            run_bounded_subprocess,
                            strict_json_loads)  # noqa: E402

HEARTBEATF = os.path.join(HERE, "signer-heartbeat.json")
HALTF      = os.path.join(HERE, "HALT")
RECVLOG    = os.path.join(HERE, "wt-recv.log")
LASTSEQF   = os.path.join(HERE, "watchtower-last-seq")
LOCKF      = os.path.join(HERE, ".wt-recv.lock")
MAX_STDIN  = 65536  # a beat is a few hundred bytes; cap the read hard
# Pinned watchtower beat-signing public key. Every beat must
# carry a valid ML-DSA signature from this key, unless an explicit dev opt-out marker
# (beat-unsigned-ok) is present. Missing pin AND missing opt-out => fail-closed refuse.
BEAT_PUBKEY      = os.path.join(HERE, "watchtower-beat-pubkey.hex")
BEAT_UNSIGNED_OK = os.path.join(HERE, "beat-unsigned-ok")
KEYGEN           = os.path.join(HERE, "veld-keygen")


def _log(m):
    try:
        flags = (os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                 getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(RECVLOG, flags, 0o600)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_uid not in (0, os.geteuid()) or
                stat.S_IMODE(info.st_mode) & 0o022):
            os.close(fd)
            return
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write("%d %s\n" % (int(time.time()), m))
    except Exception:
        pass


def _trusted_state_directory(path):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if os.path.realpath(directory) != directory:
        raise RuntimeError("signer state directory must not traverse symlinks")
    info = os.lstat(directory)
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or
            info.st_uid not in (0, os.geteuid()) or
            stat.S_IMODE(info.st_mode) & 0o022):
        raise RuntimeError(
            "signer state directory must be root/service-owned and non-writable")
    return directory


def _atomic_write(path, text):
    directory = _trusted_state_directory(path)
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".",
                               suffix=".tmp", dir=directory)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            fd = -1
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
        dirfd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if fd >= 0:
            os.close(fd)
        if tmp is not None:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass


def _last_sequence():
    """Load durable monotonic sequence; any corruption fails closed."""
    values = []
    if os.path.lexists(LASTSEQF):
        raw = read_bounded_regular_file(
            os.path.abspath(LASTSEQF), 128, "durable watchtower sequence",
            private=True).decode("ascii").strip()
        if not raw.isdigit():
            reject("durable watchtower sequence is corrupt")
        values.append(int(raw))
    if os.path.lexists(HEARTBEATF):
        try:
            old = strict_json_loads(read_bounded_regular_file(
                os.path.abspath(HEARTBEATF), MAX_STDIN,
                "existing signer heartbeat", private=True),
                "existing signer heartbeat")
            ok, why = sol.validate_heartbeat(old)
            if not ok:
                raise ValueError(why)
            seq = old["seq"]
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
                raise ValueError("invalid seq")
            values.append(seq)
        except Exception as e:
            reject("existing heartbeat is unreadable: %s" % e)
    return max(values) if values else 0


def reject(msg):
    _log("REJECT " + msg)
    sys.stderr.write("veld_wt_recv REJECT: " + msg + "\n")
    sys.exit(2)


def verify_beat_sig(p):
    """FAIL-CLOSED: the beat must carry a valid ML-DSA signature from the pinned
    watchtower beat-signing key. A dev/regtest box may opt out by dropping the
    beat-unsigned-ok marker; anything else (no pin, no sig, bad sig) is refused, so a
    compromised custody box cannot substitute a beat even if it reaches this path."""
    if os.path.lexists(BEAT_UNSIGNED_OK):
        read_bounded_regular_file(
            os.path.abspath(BEAT_UNSIGNED_OK), 1024,
            "unsigned-beat development marker")
        return True, "unsigned-ok (dev opt-out)"
    if not os.path.lexists(BEAT_PUBKEY):
        return False, ("no watchtower-beat-pubkey.hex pin and no beat-unsigned-ok "
                       "opt-out (fail-closed)")
    sig_hex = p.get("sig")
    if not isinstance(sig_hex, str) or not sig_hex:
        return False, "beat carries no signature"
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        return False, "signature not hex"
    core = sol.canonical_beat_bytes(p)
    with tempfile.TemporaryDirectory() as td:
        bf = os.path.join(td, "beat.bin")
        sf = os.path.join(td, "beat.sig")
        pf = os.path.join(td, "beat-pubkey.hex")
        with open(bf, "wb") as f:
            f.write(core)
        with open(sf, "wb") as f:
            f.write(sig)
        try:
            pubkey = read_bounded_regular_file(
                os.path.abspath(BEAT_PUBKEY), 1024 * 1024,
                "watchtower beat public key")
        except Exception as e:
            return False, "pinned beat public key is unsafe: %s" % e
        with open(pf, "wb") as f:
            f.write(pubkey)
        try:
            r = run_bounded_subprocess(
                [KEYGEN, "verify-release", "@" + pf, bf, sf],
                timeout=30, stdout_max=64 * 1024, stderr_max=64 * 1024,
                description="watchtower beat verifier")
        except Exception as e:
            return False, "verify subprocess failed: %s" % e
        if r.returncode != 0:
            return False, ("signature invalid: "
                           + (r.stderr.strip()[:160] or "verify-release rc=%d" % r.returncode))
    return True, "ok"


def main():
    try:
        _trusted_state_directory(HALTF)
    except Exception as e:
        reject("signer state directory policy: %s" % e)
    # Read one byte past the hard limit so a valid JSON prefix followed by data
    # cannot be silently accepted after read(MAX_STDIN) truncates the suffix.
    raw_bytes = sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(raw_bytes) > MAX_STDIN:
        reject("payload exceeds %d-byte limit" % MAX_STDIN)
    try:
        raw = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        reject("payload is not valid UTF-8")
    try:
        p = strict_json_loads(raw, "watchtower payload")
    except Exception as e:
        reject("bad json: %s" % e)
    if not isinstance(p, dict):
        reject("bad json: payload root is not an object")

    # Authenticate the beat BEFORE trusting any of its fields.
    ok, why = verify_beat_sig(p)
    if not ok:
        reject("beat signature: " + why)

    ok, why = sol.validate_beat_payload(p)
    if not ok:
        reject("invalid payload: " + why)

    if p["kind"] == "HALT":
        reason = str(p.get("reason", "watchtower HALT"))[:200]
        # Sticky: only set it once; never clear it here. A human clears HALT.
        if not os.path.exists(HALTF):
            _atomic_write(HALTF, "%d WATCHTOWER %s\n" % (int(time.time()), reason))
        _log("HALT set: " + reason)
        sys.stdout.write("halted\n")
        return

    # SOLVENT: serialize concurrent forced-command processes and accept each
    # signed sequence exactly once. Without this durable monotonic check, a
    # captured old beat could be replayed to refresh its receiver-stamped expiry.
    lock_flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
                  getattr(os, "O_CLOEXEC", 0))
    lock_fd = os.open(LOCKF, lock_flags, 0o600)
    lock_info = os.fstat(lock_fd)
    if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_nlink != 1 or
            lock_info.st_uid not in (0, os.geteuid()) or
            stat.S_IMODE(lock_info.st_mode) & 0o022):
        os.close(lock_fd)
        reject("receiver lock is not a trusted regular file")
    os.fchmod(lock_fd, 0o600)
    lock = os.fdopen(lock_fd, "a+")
    fcntl.flock(lock, fcntl.LOCK_EX)
    last_seq = _last_sequence()
    if p["seq"] <= last_seq:
        reject("replayed/out-of-order beat seq=%d <= durable seq=%d" %
               (p["seq"], last_seq))
    hb = sol.stamp_heartbeat(p, time.time())
    # Heartbeat first: if a crash lands between writes, restart also recovers the
    # new seq from this file. Both writes have file+directory fsync barriers.
    _atomic_write(HEARTBEATF, json.dumps(hb, sort_keys=True, separators=(",", ":")))
    _atomic_write(LASTSEQF, str(p["seq"]) + "\n")
    _log("BEAT seq=%s headroom=%s ttl=%d"
         % (hb["seq"], hb["headroom_sats"], int(hb["expires_at"] - hb["issued_at"])))
    sys.stdout.write("ok\n")


if __name__ == "__main__":
    main()
