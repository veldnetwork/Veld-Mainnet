#!/usr/bin/env python3
"""Regression checks for the Explorer mobile navigation scroll seam."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLORER = (ROOT / "include" / "network" / "explorer.h").read_text(encoding="utf-8")


def require(fragment: str, label: str) -> None:
    if fragment not in EXPLORER:
        raise AssertionError(label)


require(
    ".nav-bar,.nav-bar.is-sticky{display:flex!important;position:fixed!important;"
    "left:0!important;right:0!important;bottom:0!important;top:auto!important;",
    "mobile navigation remains fixed to the viewport bottom",
)
require(
    "height:var(--mobile-nav-height)!important;"
    "min-height:var(--mobile-nav-height)!important;"
    "max-height:var(--mobile-nav-height)!important;",
    "mobile navigation retains its bounded height",
)
require(
    "box-shadow:0 -2px 0 2px #0A0B0A,0 96px 0 96px #0A0B0A,",
    "dark theme has an opaque overlap above the navigation bar",
)
require(
    "box-shadow:0 -2px 0 2px #EFEFEF,0 96px 0 96px #EFEFEF,",
    "light theme has an opaque overlap above the navigation bar",
)

cache = re.search(r"const CACHE = 'veld-explorer-shell-ui-([^']+)';", EXPLORER)
registration = re.search(r"serviceWorker\.register\('/sw\.js\?ui=([^']+)'", EXPLORER)
if not cache or not registration:
    raise AssertionError("Explorer service-worker cache identifiers are present")
if cache.group(1) != registration.group(1):
    raise AssertionError("Explorer shell and registration cache identifiers match")
if cache.group(1) != "20260904-nav-scroll-seam":
    raise AssertionError("Explorer PWA shell uses the navbar seam revision")

print("PASS explorer_mobile_nav_tests checks=7")
