#!/usr/bin/env python3
"""Regression checks for centered mobile block-detail navigation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLORER = (ROOT / "include/network/explorer.h").read_text(encoding="utf-8")

checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        raise AssertionError(message)


serve_start = EXPLORER.index("    HttpResponse ServeBlock(")
serve_end = EXPLORER.index("    HttpResponse ServeBlockByHeight(", serve_start)
serve_block = EXPLORER[serve_start:serve_end]

check('class=\\"pheader block-detail-header\\"' in serve_block,
      "block detail header must have a dedicated layout class")
check('class=\\"pager block-detail-pager\\"' in serve_block,
      "block detail pager must have a dedicated layout class")
check(serve_block.count('href=\\"/block/height/') >= 2,
      "block detail pager must retain previous and next navigation")
check("Block \" << block->height" in serve_block,
      "block detail pager must retain the current-height label")

mobile_start = EXPLORER.index("@media(max-width:520px){")
mobile_end = EXPLORER.index("}\n\n/* ============== TIER COLORS", mobile_start)
mobile_css = EXPLORER[mobile_start:mobile_end]

check(".block-detail-header{display:block!important}" in mobile_css,
      "mobile block header must give the pager full row width")
check(".block-detail-pager{width:100%;justify-content:center!important;" in mobile_css,
      "mobile block pager must be full-width and centered")

print(f"PASS explorer_block_navigation_layout_tests checks={checks}")
