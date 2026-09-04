#!/usr/bin/env python3
"""Run the isolated reserve history in two fresh OS processes."""

from pathlib import Path
import os
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
SUFFIX = ".exe" if os.name == "nt" else ""
BINARY = ROOT / "tests" / f"reserve_tests{SUFFIX}"
LINE = re.compile(
    r"^PASS reserve_tests .* "
    r"canonical_digest=([0-9a-f]{64}) "
    r"production_token_digest=([0-9a-f]{64})$"
)


def run_once() -> tuple[str, str, str]:
    completed = subprocess.run(
        [str(BINARY)], cwd=ROOT, text=True, capture_output=True,
        timeout=120, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stdout + completed.stderr)
    output = completed.stdout.strip()
    match = LINE.fullmatch(output)
    if not match:
        raise RuntimeError(f"unexpected reserve harness output: {output!r}")
    return output, match.group(1), match.group(2)


def main() -> int:
    if not BINARY.is_file():
        raise RuntimeError(f"reserve harness is not built: {BINARY}")
    first = run_once()
    second = run_once()
    if first != second:
        raise RuntimeError(
            "fresh-process replay mismatch:\n" + first[0] + "\n" + second[0]
        )
    print(
        "PASS reserve_process_replay_test processes=2 "
        f"canonical_digest={first[1]} "
        f"production_token_digest={first[2]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
