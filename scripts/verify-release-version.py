#!/usr/bin/env python3
"""Check a built role's deployment version against its source declaration."""

import argparse
import json
from pathlib import Path
import re


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate deployment field: {key}")
        result[key] = value
    return result


def verify(version_header, deployment_text):
    versions = re.findall(
        r'^inline constexpr const char\* CLIENT_VERSION = "([0-9]+\.[0-9]+\.[0-9]+)";$',
        version_header, re.MULTILINE)
    agents = re.findall(
        r'^inline constexpr const char\* CLIENT_USER_AGENT = "/Veld:([0-9]+\.[0-9]+\.[0-9]+)/";$',
        version_header, re.MULTILINE)
    if len(versions) != 1 or agents != versions:
        raise ValueError("source version and user agent must declare one matching version")
    text = deployment_text.strip()
    prefix = "VELD_DEPLOYMENT_INFO_V1_JSON "
    if text.startswith(prefix):
        text = text[len(prefix):]
    info = json.loads(text, object_pairs_hook=unique_fields)
    if not isinstance(info, dict) or info.get("client_version") != versions[0]:
        raise ValueError("built deployment version does not match its source")
    return versions[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--deployment-info", type=Path, required=True)
    args = parser.parse_args()
    try:
        version = verify(
            (args.root / "include/core/version.h").read_text(encoding="utf-8"),
            args.deployment_info.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        parser.exit(1, f"FAIL release version: {exc}\n")
    print(f"PASS release version {version}")


if __name__ == "__main__":
    main()
