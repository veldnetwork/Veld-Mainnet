#!/usr/bin/env python3
"""Linux seed-import argv, protected-pipe, and hidden-terminal regression."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import pty
import stat
import subprocess
import tempfile
import termios
import time


CANARY = "".join(f"{value:02x}" for value in range(32))
PASSPHRASE = "F6-Runtime-Test-Only-Do-Not-Use-31!"


def command_line(pid: int) -> bytes:
    path = Path(f"/proc/{pid}/cmdline")
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        data = path.read_bytes()
        if b"from-seed" in data:
            return data
        time.sleep(0.005)
    return path.read_bytes()


def environment(pid: int) -> bytes:
    return Path(f"/proc/{pid}/environ").read_bytes()


def run_pipe(keygen: str, output: Path, payload: bytes,
             env: dict[str, str], inspect: bool = False
             ) -> tuple[subprocess.CompletedProcess[bytes], bytes, bytes]:
    read_fd, write_fd = os.pipe()
    try:
        process = subprocess.Popen(
            [keygen, "from-seed", "--out", str(output),
             "--seed-input-handle", str(read_fd)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, pass_fds=(read_fd,),
        )
        inspected_command = command_line(process.pid) if inspect else b""
        inspected_environment = environment(process.pid) if inspect else b""
        os.close(read_fd)
        read_fd = -1
        if payload:
            os.write(write_fd, payload)
        os.close(write_fd)
        write_fd = -1
        stdout, stderr = process.communicate(timeout=60)
        result = subprocess.CompletedProcess(
            process.args, process.returncode, stdout, stderr)
        return result, inspected_command, inspected_environment
    finally:
        if read_fd >= 0:
            os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def wait_for_prompt(process: subprocess.Popen[bytes], timeout: float = 20.0
                    ) -> bytes:
    assert process.stderr is not None
    os.set_blocking(process.stderr.fileno(), False)
    transcript = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = os.read(process.stderr.fileno(), 4096)
        except BlockingIOError:
            chunk = b""
        if chunk:
            transcript.extend(chunk)
            if b"input hidden" in transcript:
                return bytes(transcript)
        if process.poll() is not None:
            break
        time.sleep(0.02)
    raise AssertionError(f"seed prompt absent: {bytes(transcript)!r}")


def drain_master(master_fd: int) -> bytes:
    os.set_blocking(master_fd, False)
    output = bytearray()
    while True:
        try:
            chunk = os.read(master_fd, 4096)
        except (BlockingIOError, OSError):
            break
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def run_terminal(keygen: str, output: Path, typed: bytes,
                 env: dict[str, str], inspect: bool = False
                 ) -> tuple[int, bytes, bytes, bytes, bytes]:
    master_fd, slave_fd = pty.openpty()
    original = termios.tcgetattr(slave_fd)
    process = subprocess.Popen(
        [keygen, "from-seed", "--out", str(output)],
        stdin=slave_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, close_fds=True,
    )
    prompt = wait_for_prompt(process)
    hidden = termios.tcgetattr(slave_fd)
    assert (hidden[3] & (termios.ECHO | termios.ICANON | termios.ISIG)) == 0
    inspected_command = command_line(process.pid) if inspect else b""
    inspected_environment = environment(process.pid) if inspect else b""
    os.write(master_fd, typed)
    stdout, stderr_tail = process.communicate(timeout=60)
    echoed = drain_master(master_fd)
    restored = termios.tcgetattr(slave_fd)
    os.close(master_fd)
    os.close(slave_fd)
    assert restored == original
    return (process.returncode, stdout, prompt + stderr_tail, echoed,
            inspected_command + b"\n" + inspected_environment)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keygen", required=True)
    args = parser.parse_args()
    keygen = str(Path(args.keygen).resolve())
    checks = 0
    env = os.environ.copy()
    env["VELD_VAULT_PASSPHRASE"] = PASSPHRASE
    assert CANARY not in "\0".join(f"{key}={value}" for key, value in env.items())
    checks += 1

    with tempfile.TemporaryDirectory(prefix="veld-seed-import-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)

        success_path = root / "pipe-success.key"
        success, inspected_command, inspected_environment = run_pipe(
            keygen, success_path, CANARY.encode("ascii"), env, inspect=True)
        assert success.returncode == 0 and success_path.is_file()
        assert stat.S_IMODE(success_path.stat().st_mode) == 0o600
        assert CANARY.encode() not in success.stdout + success.stderr
        assert CANARY.encode() not in inspected_command
        assert b"--seed-input-handle" in inspected_command, inspected_command
        assert CANARY.encode() not in inspected_environment
        checks += 6

        cases = [
            ("malformed", b"g" * 64, b"seed must be 64 hex chars"),
            ("cancelled", b"\x03", b"seed import cancelled"),
            ("eof", b"", b"seed input ended before any data"),
            ("oversized", b"a" * 65, b"exceeds 64 characters"),
        ]
        for name, payload, expected in cases:
            output = root / f"pipe-{name}.key"
            result, _, _ = run_pipe(keygen, output, payload, env)
            assert result.returncode == 2 and not output.exists()
            assert payload not in result.stdout + result.stderr or not payload
            assert expected in result.stderr
            checks += 4

        # A regular file descriptor is not a protected seed channel.
        regular = root / "not-a-pipe"
        regular.write_bytes(b"not seed material")
        descriptor = os.open(regular, os.O_RDONLY)
        try:
            rejected = subprocess.run(
                [keygen, "from-seed", "--out", str(root / "regular.key"),
                 "--seed-input-handle", str(descriptor)],
                pass_fds=(descriptor,), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                timeout=30, check=False,
            )
        finally:
            os.close(descriptor)
        assert rejected.returncode == 2
        assert b"inherited pipe or socket" in rejected.stderr
        checks += 2

        terminal_path = root / "terminal-success.key"
        rc, stdout, stderr, echoed, inspected = run_terminal(
            keygen, terminal_path, CANARY.encode() + b"\n", env, inspect=True)
        assert rc == 0 and terminal_path.is_file()
        assert CANARY.encode() not in stdout + stderr + echoed + inspected
        assert b"from-seed" in inspected
        checks += 3

        cancelled_path = root / "terminal-cancelled.key"
        partial = CANARY[:12].encode()
        rc, stdout, stderr, echoed, inspected = run_terminal(
            keygen, cancelled_path, partial + b"\x03", env, inspect=True)
        assert rc == 2 and not cancelled_path.exists()
        assert b"seed import cancelled" in stderr
        assert partial not in stdout + stderr + echoed + inspected
        checks += 3

        redirected = subprocess.run(
            [keygen, "from-seed", "--out", str(root / "redirected.key")],
            input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, timeout=30, check=False,
        )
        assert redirected.returncode == 2
        assert b"hidden interactive terminal" in redirected.stderr
        checks += 2

        legacy_canary = "LEGACY_TEST_CANARY_NOT_A_SEED"
        for argument, expected in [
            (legacy_canary, b"legacy positional seed import is rejected"),
            ("--seed=" + legacy_canary, b"argument value suppressed"),
        ]:
            result = subprocess.run(
                [keygen, "from-seed", argument, "--out",
                 str(root / "legacy.key")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env=env, timeout=30, check=False,
            )
            assert result.returncode == 2
            assert legacy_canary.encode() not in result.stdout + result.stderr
            assert expected in result.stderr
            checks += 3

        help_result = subprocess.run(
            [keygen], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, env=env, timeout=30, check=False,
        )
        assert help_result.returncode == 2
        assert b"--seed=" not in help_result.stderr
        assert b"inherited" in help_result.stderr
        checks += 3

    print(f"PASS daybreak_seed_import_linux_process_tests checks={checks}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
