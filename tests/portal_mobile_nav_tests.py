#!/usr/bin/env python3
"""Regression checks for the portal mobile navigation viewport contract."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PORTAL = (ROOT / "src" / "veld-miner-portal.py").read_text(encoding="utf-8")


def require(fragment: str, label: str) -> None:
    if fragment not in PORTAL:
        raise AssertionError(label)


require('id="mobile-nav"', "dedicated mobile nav exists")
require(
    '<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">',
    "portal uses the wallet iOS standalone viewport mode",
)
require("const CACHE='veld-portal-shell-v17';", "rebuilt PWA shell is cache-busted")
require('id="mobile-nav" aria-label="Primary" hidden', "mobile nav starts hidden until session recovery")
require('$("mobile-nav").hidden=false', "mobile nav is revealed directly after session recovery")
require('</div>\n<nav id="mobile-nav"', "mobile nav is a direct body child, outside the app layout")
require(".side{display:none!important}", "desktop sidebar is hidden on mobile")
require("position:fixed!important;", "mobile nav is fixed")
require("bottom:calc(-1 * env(safe-area-inset-bottom,0px))!important;",
        "mobile nav row is lowered through the iPhone bottom inset")
require("height:68px!important", "mobile nav has a bounded height")
require("z-index:1000!important", "mobile nav stays above portal content")
require("transform:none!important", "navbar does not create a competing containing block")
require(".main{padding-bottom:88px!important}", "page content clears the navbar")
require("bottom:calc(68px - env(safe-area-inset-bottom,0px))!important",
        "More menu opens directly above the fixed wallet navbar")
if "box-shadow:0 96px 0 96px" in PORTAL:
    raise AssertionError("legacy oversized navbar shadow must stay removed")

require(
    'document.querySelectorAll("#nav button.mobile").forEach(button=>{const clone=button.cloneNode(true);clone.classList.add("portal-tab");$("mobile-nav").appendChild(clone)})',
    "mobile nav reuses the exact existing buttons and icons",
)
desktop_nav_start = PORTAL.index('<nav class="nav" id="nav"')
desktop_nav_end = PORTAL.index("</nav>", desktop_nav_start)
desktop_nav = PORTAL[desktop_nav_start:desktop_nav_end]
for page in ("overview", "blockchain", "mining", "explorer", "more"):
    if f'data-page="{page}"' not in desktop_nav:
        raise AssertionError(f"mobile nav source is missing {page}")

print("PASS portal_mobile_nav_tests checks=21")
