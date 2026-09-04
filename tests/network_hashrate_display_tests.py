#!/usr/bin/env python3
"""Regression checks for the difficulty-implied network hashrate display."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "include" / "network" / "ui_desktop.h").read_text(encoding="utf-8")
EXPLORER = (ROOT / "include" / "network" / "explorer.h").read_text(
    encoding="utf-8"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require(
    UI.count("showRate(parseFloat(d.network_hashrate_est || '0') || 0);") == 2,
    "both dashboard loaders must use the node's difficulty-implied rate",
)
require(
    "var sample = Math.min(h, 10);" not in UI,
    "dashboard must not infer hashrate from a ten-block timing sample",
)
require(
    "expected_hashes_per_block / avg_solve_time" not in UI,
    "dashboard must not retain the retired timing-sample estimator",
)
require(
    "hashrate_hps = difficulty * 4294967296.0 / (double)TARGET_BLOCK_TIME;"
    in EXPLORER,
    "public Explorer must publish the difficulty-implied network rate",
)
require(
    '<div class="tile"><div class="l">Hashrate</div>' in EXPLORER,
    "public Explorer hashrate tile must retain its concise label",
)

print("PASS network_hashrate_display_tests checks=5")
