#!/usr/bin/env python3
"""Regression checks for the portal mobile navigation viewport contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORTAL = (ROOT / "src" / "veld-miner-portal.py").read_text(encoding="utf-8")


def require(fragment: str, label: str) -> None:
    if fragment not in PORTAL:
        raise AssertionError(label)


require(".side{position:fixed!important", "mobile nav is fixed")
require("bottom:0!important", "mobile nav is anchored to the viewport bottom")
require("height:68px!important", "mobile nav has a bounded height")
require("z-index:1000!important", "mobile nav stays above page content")
require("transform:translateZ(0)!important", "mobile compositor keeps nav fixed")
require("padding:max(20px,env(safe-area-inset-top)) 14px calc(88px + env(safe-area-inset-bottom))",
        "page content clears the nav and device safe area")
require("bottom:calc(68px + env(safe-area-inset-bottom,0px))",
        "More menu opens above the fixed nav")
if "box-shadow:0 96px 0 96px" in PORTAL:
    raise AssertionError("legacy oversized navbar shadow must stay removed")

print("PASS portal_mobile_nav_tests checks=8")
