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
require("const CACHE='veld-portal-shell-v21';", "PWA shell cache advances with automatic update controls")
require('id="mobile-nav" aria-label="Primary" hidden', "mobile nav starts hidden until session recovery")
require('$("mobile-nav").hidden=!d', "mobile nav visibility follows paired-machine availability")
require('$("app-view").classList.toggle("unpaired",!d)', "pair screen receives the unpaired layout state")
require('.app.unpaired .main{padding-bottom:20px!important}', "pair screen does not reserve navbar spacing")
if '$("mobile-nav").hidden=false' in PORTAL:
    raise AssertionError("pair screen must not reveal the navbar before a machine exists")
require('</div>\n<nav id="mobile-nav"', "mobile nav is a direct body child, outside the app layout")
require(".side{display:none!important}", "desktop sidebar is hidden on mobile")
require("#mobile-nav{display:grid!important;grid-template-columns:repeat(5,minmax(0,1fr));position:fixed;bottom:0;left:0;right:0;",
        "mobile nav divides the available viewport into five equal tabs")
require("transform:translateZ(0);will-change:transform", "mobile nav uses the wallet compositor behavior")
require("#mobile-nav .mob-tab{display:flex;flex-direction:column;align-items:center;justify-content:center;",
        "mobile buttons use the wallet tab layout")
require("--portal-nav-row:56px", "mobile tabs have a compact touch target")
require("--portal-nav-safe:min(8px,env(safe-area-inset-bottom,0px))", "navigation keeps compact bottom clearance without a full extra safe-area strip")
require(".main{padding-bottom:calc(var(--portal-nav-total) + 18px)!important}", "page content clears the complete navbar")
require("bottom:var(--portal-nav-total)", "More menu opens above the tabs and bottom safe area")
if "box-shadow:0 96px 0 96px" in PORTAL:
    raise AssertionError("legacy oversized navbar shadow must stay removed")
if "#mobile-nav" in PORTAL and "bottom:calc(0px - env(safe-area-inset-bottom" in PORTAL:
    raise AssertionError("the discarded safe-area-offset navbar must stay removed")

if 'cloneNode(true)' in PORTAL:
    raise AssertionError("the discarded cloned-navbar implementation must stay removed")
mobile_nav_start = PORTAL.index('<nav id="mobile-nav"')
mobile_nav_end = PORTAL.index("</nav>", mobile_nav_start)
mobile_nav = PORTAL[mobile_nav_start:mobile_nav_end]
if mobile_nav.count('class="mob-tab') != 5:
    raise AssertionError("mobile nav must contain exactly five wallet-style tabs")
for page in ("overview", "blockchain", "mining", "explorer", "more"):
    if f'data-page="{page}"' not in mobile_nav:
        raise AssertionError(f"mobile nav is missing {page}")

menu_start = PORTAL.index('<div class="portal-more" id="portal-more-menu"')
menu_end = PORTAL.index('</div>', menu_start)
if PORTAL.count('id="logout"') != 1 or 'id="logout"' not in PORTAL[menu_start:menu_end]:
    raise AssertionError("the single logout control belongs in More")
require('function showAuth(){closePortalMore();', "logout closes the menu before showing sign-in")
require('.app.unpaired .unpaired-more{display:inline-flex', "More remains accessible before the first machine is paired")

print("PASS portal mobile navigation: equal tabs, safe-area spacing, five routes, logout in More, and unpaired access")
