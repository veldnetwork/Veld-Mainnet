#!/usr/bin/env python3
"""Reject internal development branding in public tracked source."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath
import subprocess
import sys


PROHIBITED = (
    "day" + "break",
    "code" + "x",
    "chat" + "gpt",
    "open" + "ai",
    "clau" + "de",
    "anth" + "ropic",
    "language " + "model",
    "coding " + "agent",
    "ai-" + "generated",
    "assistant-" + "generated",
)

# These byte-for-byte records authenticate the Veld 3.0.0 launch source. They
# intentionally retain historical path names and must never be rewritten.
CONTENT_ALLOWLIST = {
    PurePosixPath("LAUNCH_EQUIVALENCE.tsv"),
    PurePosixPath("PUBLICATION_SOURCE_MANIFEST.tsv"),
}


def tracked_paths(root: Path) -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [
        PurePosixPath(value.decode("utf-8"))
        for value in result.stdout.split(b"\0")
        if value
    ]


def scan(root: Path, paths: list[PurePosixPath]) -> list[str]:
    findings: list[str] = []
    for relative in paths:
        lower_path = relative.as_posix().lower()
        for term in PROHIBITED:
            if term in lower_path:
                findings.append(f"{relative}: tracked path contains {term!r}")

        if relative in CONTENT_ALLOWLIST:
            continue
        data = (root / relative).read_bytes()
        if b"\0" in data:
            continue
        text = data.decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            lower_line = line.lower()
            for term in PROHIBITED:
                if term in lower_line:
                    findings.append(
                        f"{relative}:{line_number}: content contains {term!r}"
                    )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parents[1])
    args = parser.parse_args()
    root = args.root.resolve()
    findings = scan(root, tracked_paths(root))
    if findings:
        print("Public source hygiene check failed:", file=sys.stderr)
        for finding in findings:
            print(f"  {finding}", file=sys.stderr)
        return 1
    print("PASS public-source-hygiene")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
