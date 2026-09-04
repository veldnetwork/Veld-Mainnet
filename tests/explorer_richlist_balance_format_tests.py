#!/usr/bin/env python3
"""Verify rich-list display rounding without reducing API precision."""

from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "include/network/explorer.h").read_text(encoding="utf-8")

checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


display = re.search(
    r'class=\\"rl-v\\"[^\n]*std::fixed\s*\n\s*<<\s*std::setprecision\((\d+)\)\s*<<\s*bal',
    SOURCE,
)
check(display is not None, "rich-list balance display was not found")
check(display.group(1) == "2", "rich-list balances must display two decimal places")

api_start = SOURCE.index('if (resource == "richlist")')
api_end = SOURCE.index('if (resource == "pool")', api_start)
api = SOURCE[api_start:api_end]
check(
    api.count('"balance_veld\\":" << std::setprecision(8) << bal') == 2,
    "rich-list API balance precision was reduced",
)
check(
    "j << std::fixed << std::setprecision(8);" in api,
    "rich-list API stream precision was reduced",
)

print(f"PASS explorer_richlist_balance_format_tests checks={checks}")
