#!/usr/bin/env python3
"""Regression checks for the Explorer mobile navigation scroll seam."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPLORER = (ROOT / "include" / "network" / "explorer.h").read_text(encoding="utf-8")
LIQUIDITY = (ROOT / "resources" / "explorer-liquidity.html").read_text(encoding="utf-8")


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

registration = re.search(r"serviceWorker\.register\('/sw\.js\?ui=([^']+)'", EXPLORER)
if not registration:
    raise AssertionError("Explorer service-worker registration identifier is present")
if registration.group(1) != "20260904-network-only-v2":
    raise AssertionError("Explorer PWA registers the network-only worker revision")
require("event.waitUntil(self.skipWaiting());",
        "updated service worker activates immediately")
require(".map(key => caches.delete(key))",
        "updated service worker removes stale Explorer shell caches")
require("self.clients.matchAll({",
        "updated service worker enumerates already-open PWA windows")
require("client.navigate(client.url)",
        "updated service worker refreshes already-open PWA windows once")
require("event.respondWith(fetch(event.request, {cache:'no-store'}));",
        "document navigation always uses a fresh network response")
if "cache.addAll" in EXPLORER or "cache.put" in EXPLORER:
    raise AssertionError("service worker must not persist Explorer document shells")

if "flex:1 1 20%;width:20%;min-width:0;max-width:20%" not in LIQUIDITY:
    raise AssertionError("Liquidity gives the More button the same width as the four link tabs")
if "-webkit-appearance:none;appearance:none" not in LIQUIDITY:
    raise AssertionError("Liquidity removes platform-specific button geometry")
if '<button type="button" class="nb-tab nb-more-btn active" data-nav-more="toggle">' not in LIQUIDITY:
    raise AssertionError("Liquidity More control does not match the working Explorer button")
if '.nav-more[data-open="1"]{display:block!important}' not in LIQUIDITY:
    raise AssertionError("Liquidity More menu does not use the working Explorer open state")
if "document.addEventListener('click',function(event){" not in LIQUIDITY or "},true);" not in LIQUIDITY:
    raise AssertionError("Liquidity More control is not delegated in the capture phase")
if "setOpen(!pane.hasAttribute('data-open'),button);" not in LIQUIDITY:
    raise AssertionError("Liquidity More control does not toggle the working Explorer state")
if 'max-width:100vw' not in LIQUIDITY or 'overflow-x:hidden' not in LIQUIDITY:
    raise AssertionError("Liquidity document is not constrained to the viewport")

ROUTE_CONTEXT = (ROOT / "resources" / "explorer-route-context-v1.js").read_text(encoding="utf-8")
if "document.documentElement.dataset.deviceLayout = compactLayout || touchLayout ? 'mobile' : 'desktop';" not in ROUTE_CONTEXT:
    raise AssertionError("Explorer selects its mobile shell before the first body paint")
if "window.location.pathname === '/liquidity'" not in ROUTE_CONTEXT:
    raise AssertionError("route context does not install the Liquidity-only viewport boundary")
if 'veld-liquidity-viewport-containment' not in ROUTE_CONTEXT:
    raise AssertionError("route context is missing the Liquidity containment style")
if 'width:100vw!important;min-width:100vw!important;max-width:100vw!important' not in ROUTE_CONTEXT:
    raise AssertionError("Liquidity navbar is not locked to the visible viewport width")
if 'flex:0 0 20%!important;width:20%!important;min-width:0!important;max-width:20%!important' not in ROUTE_CONTEXT:
    raise AssertionError("Liquidity navbar tabs are not constrained to five equal viewport columns")

print("PASS explorer_mobile_nav_tests checks=25")
