#!/usr/bin/env python3
"""Regression checks for the difficulty-implied network hashrate display."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "include" / "network" / "ui_desktop.h").read_text(encoding="utf-8")
EXPLORER = (ROOT / "include" / "network" / "explorer.h").read_text(
    encoding="utf-8"
)
ROUTE_CONTEXT = (
    ROOT / "resources" / "explorer-route-context-v1.js"
).read_text(encoding="utf-8")


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
    "difficulty * 4294967296.0" not in EXPLORER,
    "public Explorer must not use Bitcoin's difficulty-one work constant",
)
require(
    "std::ldexp(1.0, shift_exp)" in EXPLORER
    and "static_cast<double>(mantissa)" in EXPLORER
    and "static_cast<double>(TARGET_BLOCK_TIME)" in EXPLORER,
    "public Explorer must derive network rate from the Veld compact target",
)
require(
    '<div class="tile"><div class="l">Hashrate</div>' in EXPLORER,
    "public Explorer hashrate tile must retain its concise label",
)
require(
    "fmtHashrate(d.hashrate)" in EXPLORER
    and "fmt(hr/1000,1)" not in EXPLORER,
    "public Explorer must scale H/s units instead of forcing KH/s",
)

bits = 0x1E106D4F
exponent = bits >> 24
mantissa = bits & 0x007FFFFF
expected_hashes = 2 ** (256 - 8 * (exponent - 3)) / mantissa
network_hps = expected_hashes / 180
require(
    abs(network_hps - 5674.002016) < 0.001,
    "known compact-target vector must resolve to the expected VeldHash rate",
)
require(
    "10-block estimate" not in ROUTE_CONTEXT
    and "refreshObservedHashrate" not in ROUTE_CONTEXT,
    "deployed Explorer route context must not overwrite the canonical rate",
)

print("PASS network_hashrate_display_tests checks=9")
