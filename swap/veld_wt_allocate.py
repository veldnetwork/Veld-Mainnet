#!/usr/bin/env python3
"""Dedicated wrap-allocation registration forced command.

Install this under a different SSH authorized key than ``veld_wt_reserve.py``.
The wrapper intentionally exposes only immutable allocation registration; it
cannot reserve mint headroom, commit a signed mint, or access issuer keys.
"""
import sys

from veld_wt_reserve import allocation_main


if __name__ == "__main__":
    config_paths = [arg for arg in sys.argv[1:] if arg.startswith("/")]
    unknown = [arg for arg in sys.argv[1:]
               if arg != "--initialize" and not arg.startswith("/")]
    if (unknown or len(config_paths) > 1 or
            sys.argv[1:].count("--initialize") > 1):
        raise SystemExit(
            "usage: veld_wt_allocate.py [absolute-config-path] [--initialize]")
    allocation_main(initialize="--initialize" in sys.argv[1:])
