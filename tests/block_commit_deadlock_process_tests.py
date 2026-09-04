#!/usr/bin/env python3
"""Strict process watchdog for BLOCK-COMMIT-DEADLOCK-01.

The same fixture is compiled against the failed and remediated sources. The
failed candidate must reach BLOCK_COMMIT_DEADLOCK_ARMED and then fail or time out;
the remediated candidate must return a sealed equality record before the same
bound. Windows requires the observed timeout exactly, while platforms whose
shared mutex diagnoses self-recursion may use the fail-or-timeout oracle.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def kill_child(process: subprocess.Popen[str]) -> None:
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    else:
        process.kill()


def fail(message: str) -> None:
    raise RuntimeError(message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--platform", required=True)
    parser.add_argument(
        "--expect",
        choices=("pass", "timeout", "fail-or-timeout"),
        default="pass",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    fixture = args.fixture.resolve()
    output = args.output.resolve()
    if not fixture.is_file():
        fail(f"fixture not found: {fixture}")
    if args.timeout <= 0 or args.timeout > 120:
        fail("timeout must be in (0, 120]")
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    artifact_root = output / "child-artifacts"
    artifact_root.mkdir()

    started = time.monotonic()
    process = subprocess.Popen(
        [str(fixture), str(artifact_root)],
        cwd=str(fixture.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=os.environ.copy(),
    )
    timed_out = False
    try:
        stdout, _ = process.communicate(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_child(process)
        stdout, _ = process.communicate(timeout=10)
    elapsed = round(time.monotonic() - started, 3)
    (output / "child.log").write_text(stdout, encoding="utf-8")

    armed = "BLOCK_COMMIT_DEADLOCK_ARMED verified_peers=2 height=0" in stdout
    records = [
        line[len("BLOCK_COMMIT_DEADLOCK_JSON ") :]
        for line in stdout.splitlines()
        if line.startswith("BLOCK_COMMIT_DEADLOCK_JSON ")
    ]
    if args.expect in {"timeout", "fail-or-timeout"}:
        if args.expect == "timeout" and not timed_out:
            fail(
                "failed-candidate fixture unexpectedly returned; expected the "
                "deterministic callback-under-chain-lock hang"
            )
        if not armed:
            fail("failed candidate did not arm the exact solved-block path")
        if records:
            fail("failed candidate emitted an impossible completion record")
        if not timed_out and process.returncode == 0:
            fail("failed candidate returned success without a completion record")
        disposition = (
            "expected_prefix_deadlock_timeout"
            if timed_out
            else "expected_prefix_deadlock_failure"
        )
        result = None
    else:
        if timed_out:
            fail(f"remediated child exceeded strict {args.timeout}s watchdog")
        if process.returncode != 0:
            fail(f"remediated child exited {process.returncode}; see child.log")
        if not armed:
            fail("remediated child did not arm exact verified-peer path")
        if len(records) != 1:
            fail(f"expected one sealed result, got {len(records)}")
        result = json.loads(records[0])
        expected = {
            "status": "pass",
            "nodes": 3,
            "verified_peers": 2,
            "height_before": 0,
            "height_after": 1,
            "observer_accepts": 2,
            "observer_relays": 2,
            "shutdown": True,
        }
        for key, value in expected.items():
            if result.get(key) != value:
                fail(f"sealed result mismatch for {key}: {result.get(key)!r}")
        for key in ("tip", "work", "state_digest"):
            value = result.get(key)
            if not isinstance(value, str) or not value:
                fail(f"sealed result missing {key}")
        if int(result.get("supply", 0)) <= 0:
            fail("height-one supply did not advance")
        if int(result.get("checks", 0)) < 35:
            fail("suspiciously low child assertion count")
        disposition = "remediation_pass"

    summary = {
        "schema": "VELD_BLOCK_COMMIT_DEADLOCK_PROCESS_V1",
        "platform": args.platform,
        "expected": args.expect,
        "disposition": disposition,
        "fixture": str(fixture),
        "fixture_sha256": sha256(fixture),
        "pid": process.pid,
        "exit": process.returncode,
        "timed_out": timed_out,
        "watchdog_seconds": args.timeout,
        "elapsed_seconds": elapsed,
        "armed_exact_path": armed,
        "result": result,
    }
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "PASS block_commit_deadlock_process_tests "
        f"platform={args.platform} disposition={disposition} "
        f"elapsed={elapsed}s fixture_sha256={summary['fixture_sha256']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(
            f"FAIL block_commit_deadlock_process_tests: {exc}",
            file=sys.stderr,
        )
        raise SystemExit(1)
