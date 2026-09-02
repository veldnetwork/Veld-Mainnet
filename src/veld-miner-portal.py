#!/usr/bin/env python3
"""Authenticated remote operations portal for Veld node operators."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import stat
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

LOGGER = logging.getLogger(__name__)

VELD_OPERATOR_VERSION = "3.0.0"
VELD_OPERATOR_PROFILE = "veld-public-mainnet-v2"

MAX_BODY = 32 * 1024
SESSION_SECONDS = 12 * 60 * 60
PAIR_SECONDS = 15 * 60
ONLINE_SECONDS = 45
COMMAND_SECONDS = 3 * 60
COMMAND_CLOCK_SKEW = 2 * 60
AUTH_CONCURRENCY = 4
REQUEST_CONCURRENCY = 64
PREPARSE_CONNECTIONS_PER_MINUTE = 12_000
PAIR_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
COOKIE_NAME = "__Host-veld_portal"
DEV_COOKIE_NAME = "veld_portal_dev"
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,47}$")
VERSION_RE = re.compile(r"^[0-9A-Za-z.+_-]{1,32}$")
DEVICE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,96}$")
P256_COORDINATE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
COMMAND_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22}$")
COMMAND_SIGNATURE_RE = re.compile(r"^[A-Za-z0-9_-]{86}$")
COMMAND_KEY_ID_RE = re.compile(r"^[0-9a-f]{64}$")

NO_PAYLOAD_ACTIONS = {
    "node.start",
    "node.stop",
    "updates.check",
    "updates.install",
}
BOOL_ACTIONS = {
    "mining.enabled",
    "privacy.tor",
    "network.reachable",
    "display.reference",
}
ALLOWED_ACTIONS = (
    NO_PAYLOAD_ACTIONS
    | BOOL_ACTIONS
    | {
        "mining.workers",
        "sync.mode",
    }
)


def command_key_id(x_coordinate: str, y_coordinate: str) -> str:
    material = (
        "VELD_PORTAL_KEY_V1\n" + x_coordinate + "\n" + y_coordinate
    ).encode("ascii")
    return hashlib.sha256(material).hexdigest()


def decode_base64url_canonical(value: str, expected_bytes: int) -> bytes:
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))
    except (ValueError, TypeError):
        raise ValueError("invalid base64url value") from None
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if len(decoded) != expected_bytes or not hmac.compare_digest(value, canonical):
        raise ValueError("invalid base64url value")
    return decoded


def validate_command_key(value: Any) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {"kty", "crv", "x", "y"}:
        raise ValueError("invalid command key")
    if value["kty"] != "EC" or value["crv"] != "P-256":
        raise ValueError("unsupported command key")
    x_coordinate, y_coordinate = value["x"], value["y"]
    if (
        not isinstance(x_coordinate, str)
        or not P256_COORDINATE_RE.fullmatch(x_coordinate)
        or not isinstance(y_coordinate, str)
        or not P256_COORDINATE_RE.fullmatch(y_coordinate)
    ):
        raise ValueError("invalid command key")
    try:
        decode_base64url_canonical(x_coordinate, 32)
        decode_base64url_canonical(y_coordinate, 32)
    except ValueError:
        raise ValueError("invalid command key")
    return {
        "x": x_coordinate,
        "y": y_coordinate,
        "id": command_key_id(x_coordinate, y_coordinate),
    }


def canonical_command_payload(action: str, payload: dict[str, Any]) -> str:
    if action in NO_PAYLOAD_ACTIONS:
        if payload:
            raise ValueError("unexpected command payload")
    elif action in BOOL_ACTIONS:
        if set(payload) != {"enabled"} or not isinstance(payload["enabled"], bool):
            raise ValueError("invalid command payload")
    elif action == "mining.workers":
        if set(payload) != {"workers"}:
            raise ValueError("invalid command payload")
        bounded_int(payload["workers"], 1, 256, "workers")
    elif action == "sync.mode":
        if set(payload) != {"mode"} or payload["mode"] != "full":
            raise ValueError("Veld 3.0.0 public mainnet supports full IBD only")
    else:
        raise ValueError("unsupported command")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def command_envelope(command: dict[str, Any]) -> str:
    payload = canonical_command_payload(command["action"], command["payload"])
    return "\n".join(
        (
            "VELD_PORTAL_COMMAND_V3",
            str(command["id"]),
            str(command["sequence"]),
            str(command["issued_at"]),
            str(command["expires_at"]),
            command["nonce"],
            command["action"],
            payload,
        )
    )


def verify_command_signature(
    command: dict[str, Any], key_x: str, key_y: str
) -> bool:
    try:
        x_coordinate = int.from_bytes(
            decode_base64url_canonical(key_x, 32), "big"
        )
        y_coordinate = int.from_bytes(
            decode_base64url_canonical(key_y, 32), "big"
        )
        raw_signature = decode_base64url_canonical(command["signature"], 64)
        der_signature = utils.encode_dss_signature(
            int.from_bytes(raw_signature[:32], "big"),
            int.from_bytes(raw_signature[32:], "big"),
        )
        public_key = ec.EllipticCurvePublicNumbers(
            x_coordinate, y_coordinate, ec.SECP256R1()
        ).public_key()
        public_key.verify(
            der_signature,
            command_envelope(command).encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False

PORTAL_ICON_PATH = (
    Path(__file__).resolve().parents[1] / "resources" / "veld-portal-icon.png"
)
PORTAL_MANIFEST = {
    "id": "/",
    "name": "Veld Node Portal",
    "short_name": "Veld Portal",
    "description": "Secure remote monitoring and control for Veld nodes and miners.",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#080a09",
    "theme_color": "#080a09",
    "orientation": "any",
    "icons": [
        {
            "src": "/icon.png?v=6",
            "sizes": "1024x1024",
            "type": "image/png",
            "purpose": "any maskable",
        }
    ],
}
PORTAL_OFFLINE_HTML = b"""<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><meta name="theme-color" content="#080a09"><title>Veld Portal offline</title><style>:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#080a09;color:#f2f5f2;font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}.card{width:min(430px,100%);padding:25px;border:1px solid #343a36;border-radius:10px;background:#101311}h1{margin:0 0 8px;font:700 24px ui-monospace,Consolas,monospace}p{margin:0;color:#c5cbc7}</style><main class="card"><h1>Portal offline</h1><p>Reconnect to the internet, then reopen or refresh the app. Your node continues running independently.</p></main></html>"""
PORTAL_SERVICE_WORKER = b"""const CACHE='veld-portal-shell-v7';
const ASSETS=['/manifest.webmanifest','/icon.png?v=6','/offline'];
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.addAll(ASSETS)).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{
  const request=event.request;
  if(request.method!=='GET')return;
  const url=new URL(request.url);
  if(url.origin!==self.location.origin||url.pathname.startsWith('/api/'))return;
  if(request.mode==='navigate'){
    event.respondWith(fetch(request).catch(()=>caches.match('/offline')));
    return;
  }
  if(ASSETS.includes(url.pathname))event.respondWith(caches.match(request).then(hit=>hit||fetch(request)));
});
"""


PORTAL_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
  <meta name="theme-color" content="#080a09">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Veld Portal">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/icon.png?v=6" type="image/png">
  <link rel="apple-touch-icon" href="/icon.png?v=6">
  <title>Veld Node Portal</title>
  <style>
    :root{color-scheme:dark;--bg:#080a09;--side:#0d100e;--panel:#101311;--panel2:#151916;--line:#343a36;--soft:#252b27;--text:#f2f5f2;--sub:#c5cbc7;--muted:#89928c;--green:#7ed949;--warn:#d8a64a;--bad:#e16b62;--button:#2d322f;--button-hover:#383e3a}
    *,*::before,*::after{box-sizing:border-box}html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif}button,input,select{font:inherit}button{cursor:pointer}.hidden{display:none!important}
    .app{min-height:100vh;display:grid;grid-template-columns:248px minmax(0,1fr)}.side{position:fixed;inset:0 auto 0 0;width:248px;background:var(--side);border-right:1px solid var(--soft);padding:28px 20px;display:flex;flex-direction:column;z-index:4}.brand{display:flex;align-items:center;gap:13px;margin-bottom:34px}.mark{width:47px;height:47px;border:1px solid #39423c;border-radius:12px;display:grid;place-items:center;background:linear-gradient(145deg,#171b18,#090c0a);box-shadow:inset 0 0 0 1px rgba(255,255,255,.025),0 8px 20px rgba(0,0,0,.28);flex:0 0 47px}.mark svg{width:31px;height:31px;display:block;fill:none;stroke-linejoin:miter}.brand b{font:700 20px ui-monospace,Consolas,monospace}.nav{display:grid;gap:6px}.nav button{border:0;border-left:2px solid transparent;background:transparent;color:var(--sub);text-align:left;padding:12px 14px;border-radius:0}.nav button:hover{color:var(--text);background:#121613}.nav button.active{border-left-color:var(--text);color:var(--text);background:#101311}.nav-icon,.nav-glyph{display:none}.side-foot{margin-top:auto;color:var(--muted);font-size:12px;display:grid;gap:10px}.side-foot a{color:var(--sub);text-decoration:none}.main{grid-column:2;padding:30px clamp(24px,4vw,58px) 70px;min-width:0}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:28px}.page-title h1{font:700 29px ui-monospace,Consolas,monospace;margin:0}.page-title p{color:var(--sub);margin:5px 0 0}.top-actions{display:flex;align-items:center;gap:10px}.device-select{background:var(--panel);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:10px 34px 10px 12px;min-width:180px}.button{border:1px solid #59625c;background:var(--button);color:var(--text);border-radius:6px;padding:10px 16px;min-height:40px}.button:hover{background:var(--button-hover)}.button.ghost{background:transparent}.button.danger{border-color:#734943;color:#f0b2ac}.button:disabled{opacity:.45;cursor:not-allowed}.status{display:inline-flex;align-items:center;color:var(--muted)}.status.online{color:var(--green)}.status.warn{color:var(--warn)}
    .cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px}.cards.network-cards{grid-template-columns:repeat(3,minmax(0,1fr))}.card{background:linear-gradient(145deg,var(--panel),#0d100e);border:1px solid var(--line);border-radius:8px;padding:20px;min-width:0}.card h2,.section h2{font:700 19px ui-monospace,Consolas,monospace;margin:0}.card .value{font:700 29px ui-monospace,Consolas,monospace;margin-top:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.card .label{color:var(--muted);margin-top:5px}.wide{grid-column:span 2}.full{grid-column:1/-1}.section{margin-top:15px;background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:20px}.section-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:18px}.section-head p{color:var(--muted);margin:4px 0 0}.kv{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:1px;background:var(--soft);border:1px solid var(--soft);border-radius:6px;overflow:hidden}.kv div{background:#0d100e;padding:15px}.kv b{display:block;font:700 18px ui-monospace,Consolas,monospace}.kv span{color:var(--muted);font-size:12px}.control-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:24px;align-items:center;padding:15px 0;border-top:1px solid var(--soft)}.control-row:first-child{border-top:0}.control-row h3{margin:0;font:700 16px ui-monospace,Consolas,monospace}.control-row p{margin:4px 0 0;color:var(--muted)}.controls{display:flex;align-items:center;gap:9px;flex-wrap:wrap;justify-content:flex-end}.toggle{width:54px;height:29px;border:1px solid var(--line);border-radius:15px;background:#202521;padding:3px;position:relative}.toggle:after{content:"";position:absolute;top:4px;left:4px;width:19px;height:19px;border-radius:50%;background:var(--muted);transition:.15s}.toggle.on{background:#323e34}.toggle.on:after{left:29px;background:var(--text)}.pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:20px;padding:6px 10px;color:var(--sub);font-size:12px}.warning{color:#f1c778;background:#1b1710;border:1px solid #49381b;border-radius:6px;padding:11px 13px;margin-top:12px}.table{width:100%;border-collapse:collapse}.table th,.table td{text-align:left;padding:13px;border-bottom:1px solid var(--soft)}.table th{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.mono{font-family:ui-monospace,Consolas,monospace}.green{color:var(--green)}.warn{color:var(--warn)}.muted{color:var(--muted)}.empty{text-align:center;color:var(--muted);padding:55px 20px}.log{background:#080a09;border:1px solid var(--soft);border-radius:6px;padding:14px;min-height:260px;white-space:pre-wrap;color:var(--sub);font:13px/1.65 ui-monospace,Consolas,monospace}.local-only{border:1px solid var(--soft);background:#0d100e;border-radius:6px;padding:12px;color:var(--muted)}
    .chart{height:230px;border:1px solid var(--soft);border-radius:7px;background:#0a0d0b;padding:10px}.chart svg,.topology svg{width:100%;height:100%;display:block}.chart .axis{stroke:#3a423d;stroke-width:1}.chart .trace{fill:none;stroke:#dfe5e1;stroke-width:2;vector-effect:non-scaling-stroke}.chart text,.topology text{fill:var(--sub);font:600 12px ui-monospace,Consolas,monospace}.topology{height:430px;border:1px solid var(--soft);border-radius:7px;background:radial-gradient(circle at 50% 48%,#111713 0,#090c0a 58%);padding:4px;overflow:hidden}.topology .orbit{fill:none;stroke-width:1;stroke-dasharray:3 7;vector-effect:non-scaling-stroke}.topology .orbit.fleet{stroke:#283631}.topology .orbit.validator{stroke:#302b38}.topology .orbit.operator{stroke:#303a35}.topology .edge-underlay{fill:none;stroke:#101411;stroke-width:4;vector-effect:non-scaling-stroke}.topology .edge{fill:none;stroke:#81938a;stroke-width:1.25;opacity:.72;vector-effect:non-scaling-stroke}.topology .edge.one{stroke-dasharray:5 7;opacity:.48}.topology .edge.differs{stroke:var(--warn)}.topology .center-ring{fill:none;stroke:#36453d;stroke-width:1}.topology .center-core{fill:url(#topology-center);stroke:#71917f;stroke-width:1.5}.topology .center-label{fill:var(--text);font-size:10px;letter-spacing:.08em}.topology .center-sub{fill:var(--sub);font-size:8px;letter-spacing:.11em}.topology .peer .halo{fill:none;stroke:currentColor;stroke-width:7;opacity:.08}.topology .peer .direct-ring{fill:none;stroke:currentColor;stroke-width:1.4;opacity:.8}.topology .peer .core{stroke-width:1.7}.topology .peer.fleet{color:#79a9c2}.topology .peer.fleet .core{fill:url(#topology-fleet);stroke:#79a9c2}.topology .peer.node{color:#6ab38f}.topology .peer.node .core{fill:url(#topology-node);stroke:#6ab38f}.topology .peer.miner{color:#7ed949}.topology .peer.miner .core{fill:url(#topology-miner);stroke:#7ed949}.topology .peer.validator{color:#9f82cf}.topology .peer.validator .core{fill:url(#topology-validator);stroke:#9f82cf}.topology .peer.differs .core{stroke:var(--warn)}.topology .peer.stale .core,.topology .peer.unavailable .core{fill:#282d2a;stroke:#737b76}.topology .peer text{fill:currentColor;font-size:12px}.topology .peer:hover .core{stroke:#fff;stroke-width:2.4}.topology-legend{display:grid;grid-template-columns:repeat(4,minmax(0,max-content));align-items:center;gap:10px 22px;margin-top:13px;color:var(--muted);font-size:12px}.topology-legend+.topology-legend{padding-top:12px;border-top:1px solid var(--soft)}.topology-legend span{display:inline-flex;align-items:center;min-width:0;white-space:nowrap}.legend-line{display:inline-block;width:27px;border-top:1px solid #81938a;margin-right:8px}.legend-line.one{border-top-style:dashed;opacity:.7}.legend-dot{width:9px;height:9px;border-radius:50%;margin-right:8px;border:1px solid currentColor}.legend-dot.node{color:#6ab38f;background:#203d31}.legend-dot.fleet{color:#79a9c2;background:#21343e}.legend-dot.miner{color:#7ed949;background:#27431a}.legend-dot.validator{color:#9f82cf;background:#3c2d51}.legend-dot.differs{color:var(--warn);background:#503c23}.legend-dot.unavailable{color:#737b76;background:#282d2a}.auth-shell{min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 50% -20%,#142018 0,#080a09 42%)}.auth{width:min(440px,100%);background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:26px}.auth h1{font:700 24px ui-monospace,Consolas,monospace;margin:0 0 6px}.auth p{color:var(--muted);margin:0 0 20px}.field{display:grid;gap:7px;margin:13px 0}.field label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.field input{width:100%;background:#070908;border:1px solid #454d47;border-radius:6px;color:var(--text);padding:12px}.actions{display:flex;gap:9px;align-items:center;margin-top:18px}.error{color:#ef8b82;min-height:22px;margin-top:10px}.pair{display:grid;grid-template-columns:1fr auto;gap:10px}.pair input{text-transform:uppercase;letter-spacing:.15em;font:700 17px ui-monospace,Consolas,monospace;background:#070908;border:1px solid #454d47;border-radius:6px;color:var(--text);padding:11px;min-width:0}.more-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}.portal-more{display:none}.toast{position:fixed;right:22px;bottom:90px;z-index:1200;background:#151916}
    @media(max-width:1050px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media(max-width:900px){html,body{width:100%;min-height:100%;overflow-x:hidden}.app{display:block;min-height:100dvh}.side{position:fixed!important;inset:auto 0 0 0!important;width:100%!important;height:68px!important;min-height:68px!important;max-height:68px!important;padding:0!important;background:#0d100e!important;border:0!important;border-top:1px solid var(--line)!important;display:block!important;overflow:hidden!important;z-index:1000!important;transform:translateZ(0)!important;-webkit-transform:translateZ(0)!important;box-shadow:0 96px 0 96px #0d100e!important}.side>.brand,.side-foot{display:none!important}.nav{width:100%!important;height:68px!important;min-height:68px!important;display:grid!important;grid-template-columns:repeat(5,minmax(0,1fr))!important;gap:0!important;margin:0!important;padding:0!important}.app .side .nav button,.app .side .nav button:hover,.app .side .nav button.active{display:none;position:relative!important;min-width:0!important;width:100%!important;height:68px!important;min-height:68px!important;max-height:68px!important;margin:0!important;border:0!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;color:var(--muted);text-align:center!important;padding:7px 2px 6px!important;font-size:10px!important;line-height:1!important;letter-spacing:.02em!important;appearance:none!important;-webkit-appearance:none!important;transform:none!important;-webkit-tap-highlight-color:transparent;touch-action:manipulation}.app .side .nav button.mobile,.app .side .nav button.mobile:hover,.app .side .nav button.mobile.active{display:flex!important;flex-direction:column!important;align-items:center!important;justify-content:center!important;gap:3px!important}.app .side .nav button.active{color:var(--text)!important}.app .side .nav button.active:before{content:"";position:absolute;top:0;left:50%;width:32px;height:2px;transform:translateX(-50%);border-radius:0 0 3px 3px;background:var(--text)}.nav-icon{display:block!important;width:22px!important;height:22px!important;flex:0 0 22px;stroke:currentColor;stroke-width:1.8;fill:none;stroke-linecap:round;stroke-linejoin:round}.nav-glyph{display:block!important;width:22px;height:22px;flex:0 0 22px;font:400 23px/22px "Segoe UI Symbol","Apple Symbols",sans-serif;color:currentColor}.main{padding:max(20px,env(safe-area-inset-top)) 14px calc(88px + env(safe-area-inset-bottom));min-height:100dvh}.top{align-items:stretch;flex-direction:column;gap:14px;margin-bottom:18px}.top-actions{width:100%;display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:8px}.device-select{width:100%;min-width:0}.status{padding:0 2px;white-space:nowrap}.top-actions .button{padding-inline:12px}.cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.cards.network-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:15px;min-height:104px}.card .value{font-size:22px;white-space:normal;overflow-wrap:anywhere}.section{padding:15px;margin-top:12px}.section-head{display:grid;grid-template-columns:minmax(0,1fr);gap:12px;margin-bottom:15px}.section-head>.pill,.section-head>.controls{justify-self:start}.kv{grid-template-columns:repeat(2,minmax(0,1fr))}.kv div{padding:13px}.control-row{grid-template-columns:1fr;gap:12px}.controls{justify-content:flex-start}.wide{grid-column:span 2}.table{display:block;width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch;overscroll-behavior-inline:contain}.pair{grid-template-columns:1fr}.pair .button{width:100%}.field input,.pair input,.device-select{font-size:16px}.page-title h1{font-size:25px}.page-title p{font-size:13px}.more-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.more-grid .button{min-height:50px}.chart{height:190px}.topology{height:auto;aspect-ratio:760/430;padding:2px}.topology .peer text{font-size:13px}.topology-legend{grid-template-columns:repeat(2,minmax(0,1fr));gap:9px 14px}.auth-shell{align-items:start;padding:max(22px,env(safe-area-inset-top)) 14px}.auth{padding:22px 18px;margin-top:5vh}.portal-more{position:fixed;left:0;right:0;bottom:68px;z-index:1100;display:none;padding:14px;background:rgba(13,16,14,.98);border-top:1px solid var(--line);box-shadow:0 -14px 28px rgba(0,0,0,.35);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px)}.portal-more[data-open="1"]{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.portal-more button{min-height:58px;border:1px solid var(--line);border-radius:7px;background:var(--button);color:var(--text);display:flex;align-items:center;justify-content:flex-start;gap:11px;padding:11px 14px;text-align:left}.portal-more button:hover{background:var(--button-hover)}.portal-more svg{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:1.7;stroke-linecap:round;stroke-linejoin:round}}
    @media(max-width:900px){.portal-more{padding:16px 18px 18px;background:rgba(9,14,11,.985);border-top:1px solid #28332b;box-shadow:0 -12px 40px rgba(0,0,0,.55)}.portal-more[data-open="1"]{grid-template-columns:repeat(3,minmax(0,1fr));gap:10px 12px}.portal-more button{min-height:94px;border:.5px solid #28332b;border-radius:12px;background:#171c18;color:var(--text);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:9px;padding:13px 7px;text-align:center}.portal-more button:hover,.portal-more button:active{background:#1d241f;border-color:#3d4a40}.portal-more button span{font:700 10.5px/1.2 system-ui,-apple-system,"Segoe UI",sans-serif;letter-spacing:.05em;text-transform:uppercase}.portal-more svg{width:26px;height:26px;flex:0 0 26px;stroke-width:1.7}}
    @media(max-width:520px){.topology{aspect-ratio:420/390}}
    @media(max-width:390px){.top-actions{grid-template-columns:minmax(0,1fr) auto}.top-actions .status{grid-row:2;grid-column:1}.top-actions .button{grid-row:2;grid-column:2}.cards{grid-template-columns:1fr}.cards.network-cards{grid-template-columns:repeat(2,minmax(0,1fr))}.wide{grid-column:auto}.card{min-height:0}.kv{grid-template-columns:1fr}.more-grid{grid-template-columns:1fr 1fr}}
    @media(max-width:340px){.cards.network-cards{grid-template-columns:1fr}}
  </style>
</head>
<body>
<section id="auth-view" class="auth-shell hidden"><div class="auth"><div class="brand"><div class="mark" aria-hidden="true"><svg viewBox="0 0 24 24"><defs><linearGradient id="auth-veld-mark" x1="12" y1="2" x2="12" y2="22" gradientUnits="userSpaceOnUse"><stop stop-color="#97D222"/><stop offset=".52" stop-color="#5FAC18"/><stop offset="1" stop-color="#329418"/></linearGradient></defs><path d="M12 2.5 21.5 12 12 21.5 2.5 12Z" stroke="url(#auth-veld-mark)" stroke-width="2.2"/><path d="M12 7 17 12 12 17 7 12Z" stroke="url(#auth-veld-mark)" stroke-width="1.9"/></svg></div><div><b>VELD NODE</b></div></div><h1>Remote access</h1><p>Sign in to manage your paired nodes and miners.</p><div class="field"><label for="account">Account</label><input id="account" maxlength="48" autocomplete="username"></div><div class="field"><label for="password">Password</label><input id="password" type="password" maxlength="128" autocomplete="current-password"></div><div class="actions"><button id="login" class="button">Log in</button><button id="register" class="button ghost">Create account</button></div><div id="auth-error" class="error"></div></div></section>
<div id="app-view" class="app hidden">
  <aside class="side"><div class="brand"><div class="mark" aria-hidden="true"><svg viewBox="0 0 24 24"><defs><linearGradient id="side-veld-mark" x1="12" y1="2" x2="12" y2="22" gradientUnits="userSpaceOnUse"><stop stop-color="#97D222"/><stop offset=".52" stop-color="#5FAC18"/><stop offset="1" stop-color="#329418"/></linearGradient></defs><path d="M12 2.5 21.5 12 12 21.5 2.5 12Z" stroke="url(#side-veld-mark)" stroke-width="2.2"/><path d="M12 7 17 12 12 17 7 12Z" stroke="url(#side-veld-mark)" stroke-width="1.9"/></svg></div><div><b>VELD NODE</b></div></div><nav class="nav" id="nav"><button data-page="overview" class="active mobile"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M4 11.5 12 5l8 6.5V20h-6v-5h-4v5H4z"/></svg><span>Overview</span></button><button data-page="blockchain" class="mobile"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m12 3 8 4-8 4-8-4 8-4Z"/><path d="m4 12 8 4 8-4M4 17l8 4 8-4"/></svg><span>Chain</span></button><button data-page="mining" class="mobile"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M1308 1634Q1362 1634 1408.0 1630.0Q1454 1626 1486 1621Q1525 1617 1554 1610V1577Q1539 1577 1496.5 1575.0Q1454 1573 1392.5 1560.5Q1331 1548 1251.0 1525.0Q1171 1502 1081.5 1459.0Q992 1416 894.0 1353.0Q796 1290 697 1199L1897 1L1786 -108L588 1090Q519 1015 466.0 939.0Q413 863 373.5 787.5Q334 712 306.5 641.5Q279 571 260 509Q217 363 207 228H174Q166 257 162 296Q157 329 154.0 374.5Q151 420 151 476Q151 555 162.0 651.5Q173 748 204.0 851.5Q235 955 289.5 1061.0Q344 1167 432 1266L251 1497L283 1530L520 1353Q619 1439 723.5 1494.5Q828 1550 931.5 1580.5Q1035 1611 1131.0 1622.5Q1227 1634 1308 1634Z" transform="translate(0.270332 20.739977) scale(0.01145475 -0.01145475)" fill="currentColor" stroke="none"/></svg><span>Mining</span></button><button data-page="workers">Workers</button><button data-page="explorer" class="mobile"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="10.5" cy="10.5" r="5.5"/><path d="m15 15 5 5"/></svg><span>Explorer</span></button><button data-page="network">Network</button><button data-page="logs">Logs</button><button data-page="settings">Settings</button><button data-page="more" class="mobile" aria-expanded="false" aria-controls="portal-more-menu"><svg class="nav-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg><span>More</span></button></nav><div class="side-foot"><span>Remote operations portal</span><a href="https://x.com/VeldNetwork" rel="noreferrer">Follow on X @VeldNetwork</a></div></aside>
  <main class="main"><header class="top"><div class="page-title"><h1 id="page-title">Overview</h1><p id="page-subtitle">Your node at a glance.</p></div><div class="top-actions"><select id="device-select" class="device-select"></select><span id="online" class="status">Offline</span><button id="logout" class="button ghost">Log out</button></div></header><div id="page"></div></main>
</div>
<div class="portal-more" id="portal-more-menu" data-open="0" aria-hidden="true">
  <button type="button" data-more-page="workers"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 7h14v10H5zM8 4v3m8-3v3M8 17v3m8-3v3"/></svg><span>Workers</span></button>
  <button type="button" data-more-page="network"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="6" r="2"/><circle cx="6" cy="17" r="2"/><circle cx="18" cy="17" r="2"/><path d="m10.9 7.7-3.8 7.6m6-7.6 3.8 7.6M8 17h8"/></svg><span>Network</span></button>
  <button type="button" data-more-page="logs"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 4h14v16H5zM8 8h8M8 12h8M8 16h5"/></svg><span>Logs</span></button>
  <button type="button" data-more-page="settings"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.6-2-3.4-2.4 1A7 7 0 0 0 15 6l-.4-2.6h-4L10 6a7 7 0 0 0-1.6 1L6 6 4 9.4 6.1 11a7 7 0 0 0 0 2L4 14.6 6 18l2.4-1a7 7 0 0 0 1.6 1l.5 2.6h4L15 18a7 7 0 0 0 1.6-1l2.4 1 2-3.4-2.1-1.6a7 7 0 0 0 .1-1Z"/></svg><span>Settings</span></button>
</div>
<script>
const $=id=>document.getElementById(id);let csrf="",devices=[],selected=0,page="overview",installPrompt=null;
const portalHtmlPolicy=globalThis.trustedTypes?trustedTypes.createPolicy("portal-render",{createHTML:value=>value}):null;
function setHtml(element,value){element.innerHTML=portalHtmlPolicy?portalHtmlPolicy.createHTML(value):value}
const titles={overview:["Overview","Your node at a glance."],blockchain:["Blockchain","Verified chain state and synchronization."],mining:["Mining","VeldHash performance and work admission."],workers:["Workers","CPU mining threads owned by this node."],explorer:["Explorer","Recent verified chain activity."],network:["Network","Peer reachability and connection health."],logs:["Logs","Sanitized operational events from this client."],settings:["Settings","Remote-safe client preferences and release controls."],more:["More","Workers, network, logs, and settings."]};
async function api(path,method="GET",body){const h={Accept:"application/json"};if(body!==undefined)h["Content-Type"]="application/json";if(csrf&&method!=="GET")h["X-CSRF-Token"]=csrf;const r=await fetch(path,{method,headers:h,body:body===undefined?undefined:JSON.stringify(body),credentials:"same-origin"});let j={};try{j=await r.json()}catch{}if(!r.ok)throw new Error(j.error||"Request failed");return j}
const commandDbName="veld-portal-command-v1",commandStore="keys",commandKeyName="operator";let commandKeyPromise=null,actionQueue=Promise.resolve();
function b64url(bytes){let binary="";for(const byte of bytes)binary+=String.fromCharCode(byte);return btoa(binary).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"")}
function hex(bytes){return Array.from(bytes,byte=>byte.toString(16).padStart(2,"0")).join("")}
function openCommandDb(){return new Promise((resolve,reject)=>{const request=indexedDB.open(commandDbName,1);request.onupgradeneeded=()=>request.result.createObjectStore(commandStore);request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(new Error("Secure command storage is unavailable"))})}
async function commandKey(){if(commandKeyPromise)return commandKeyPromise;commandKeyPromise=(async()=>{if(!window.isSecureContext||!crypto?.subtle||!window.indexedDB)throw new Error("Secure command signing is unavailable in this browser");const db=await openCommandDb();let pair=await new Promise((resolve,reject)=>{const request=db.transaction(commandStore,"readonly").objectStore(commandStore).get(commandKeyName);request.onsuccess=()=>resolve(request.result||null);request.onerror=()=>reject(new Error("Secure command key could not be read"))});if(!pair){pair=await crypto.subtle.generateKey({name:"ECDSA",namedCurve:"P-256"},false,["sign","verify"]);await new Promise((resolve,reject)=>{const transaction=db.transaction(commandStore,"readwrite");transaction.objectStore(commandStore).put(pair,commandKeyName);transaction.oncomplete=resolve;transaction.onerror=()=>reject(new Error("Secure command key could not be saved"));transaction.onabort=transaction.onerror})}if(!pair.privateKey||pair.privateKey.extractable||!pair.privateKey.usages.includes("sign"))throw new Error("Secure command key is invalid");const jwk=await crypto.subtle.exportKey("jwk",pair.publicKey);if(jwk.kty!=="EC"||jwk.crv!=="P-256"||!jwk.x||!jwk.y)throw new Error("Secure command public key is invalid");const key={kty:"EC",crv:"P-256",x:jwk.x,y:jwk.y};const digest=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(`VELD_PORTAL_KEY_V1\n${key.x}\n${key.y}`));return {pair,key,id:hex(new Uint8Array(digest))}})().catch(error=>{commandKeyPromise=null;throw error});return commandKeyPromise}
function normalizeEcdsaSignature(buffer){const bytes=new Uint8Array(buffer);if(bytes.length===64)return bytes;if(bytes.length<8||bytes[0]!==0x30||bytes[1]!==bytes.length-2)throw new Error("Browser returned an invalid command signature");let offset=2;const integer=()=>{if(bytes[offset++]!==0x02)throw new Error("Browser returned an invalid command signature");const length=bytes[offset++];if(!length||offset+length>bytes.length)throw new Error("Browser returned an invalid command signature");let value=bytes.slice(offset,offset+length);offset+=length;while(value.length>32&&value[0]===0)value=value.slice(1);if(value.length>32)throw new Error("Browser returned an invalid command signature");const out=new Uint8Array(32);out.set(value,32-value.length);return out};const r=integer(),s=integer();if(offset!==bytes.length)throw new Error("Browser returned an invalid command signature");const out=new Uint8Array(64);out.set(r);out.set(s,32);return out}
function canonicalPayload(action,payload){if(["node.start","node.stop","updates.check","updates.install"].includes(action)){if(Object.keys(payload).length)throw new Error("Invalid command payload");return "{}"}if(["mining.enabled","privacy.tor","network.reachable","display.reference"].includes(action)){if(Object.keys(payload).length!==1||typeof payload.enabled!=="boolean")throw new Error("Invalid command payload");return JSON.stringify({enabled:payload.enabled})}if(action==="mining.workers"){const workers=Number(payload.workers);if(Object.keys(payload).length!==1||!Number.isInteger(workers)||workers<1||workers>256)throw new Error("Invalid command payload");return JSON.stringify({workers})}if(action==="sync.mode"&&Object.keys(payload).length===1&&payload.mode==="full")return JSON.stringify({mode:"full"});throw new Error("Unsupported command")}
function commandEnvelope(command){return `VELD_PORTAL_COMMAND_V3\n${command.id}\n${command.sequence}\n${command.issued_at}\n${command.expires_at}\n${command.nonce}\n${command.action}\n${canonicalPayload(command.action,command.payload)}`}
async function ensureDeviceCommandKey(device,keyInfo){if(device.command_key_id&&device.command_key_id!==keyInfo.id)throw new Error("This browser does not hold the command key trusted by this machine. Remove and pair the machine again locally.");if(!device.command_key_id){await api("/api/v1/devices/trust-key","POST",{id:device.id,command_key:keyInfo.key});device.command_key_id=keyInfo.id;device.command_sequence=0}}
async function signedAction(name,payload={}){const device=current();if(!device)throw new Error("Select a paired machine");const keyInfo=await commandKey();await ensureDeviceCommandKey(device,keyInfo);const issued=Math.floor(Date.now()/1000),command={id:device.id,action:name,payload,sequence:Number(device.command_sequence||0)+1,issued_at:issued,expires_at:issued+180,nonce:b64url(crypto.getRandomValues(new Uint8Array(16))),key_id:keyInfo.id};const signature=await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},keyInfo.pair.privateKey,new TextEncoder().encode(commandEnvelope(command)));command.signature=b64url(normalizeEcdsaSignature(signature));await api("/api/v1/devices/command","POST",command);device.command_sequence=command.sequence;toast("Signed command sent for local approval");await refresh()}
function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}function n(v,d=0){return Number(v||0).toLocaleString(undefined,{maximumFractionDigits:d})}function bytes(v){let x=Number(v||0),u="B";for(const k of ["KB","MB","GB","TB"]){if(x<1024)break;x/=1024;u=k}return n(x,1)+" "+u}function current(){return devices.find(x=>x.id===selected)||devices[0]||null}function snap(d){return d&&d.snapshot||{}}
async function refresh(){const j=await api("/api/v1/devices");csrf=j.csrf||csrf;devices=j.devices||[];if(!devices.some(d=>d.id===selected))selected=devices[0]?.id||0;renderSelector();render()}
function renderSelector(){const s=$("device-select");setHtml(s,devices.length?devices.map(d=>`<option value="${d.id}" ${d.id===selected?"selected":""}>${esc(d.name)}</option>`).join(""):'<option>No paired machines</option>');s.disabled=!devices.length}
function metric(value,label,cls=""){return `<article class="card"><div class="value ${cls}">${value}</div><div class="label">${label}</div></article>`}
function spark(history,key,label,formatter=n){const points=(Array.isArray(history)?history:[]).filter(x=>Number.isFinite(Number(x[key])));if(points.length<2)return `<div class="chart empty">History appears after two reports.</div>`;const values=points.map(x=>Number(x[key])),lo=Math.min(...values),hi=Math.max(...values),span=Math.max(hi-lo,1),plot=points.map((x,i)=>`${42+i*748/(points.length-1)},${15+(hi-Number(x[key]))*170/span}`).join(" ");return `<div class="chart"><svg viewBox="0 0 810 210" preserveAspectRatio="none" role="img" aria-label="${esc(label)}"><line class="axis" x1="42" y1="185" x2="790" y2="185"/><line class="axis" x1="42" y1="15" x2="42" y2="185"/><polyline class="trace" points="${plot}"/><text x="6" y="20">${esc(formatter(hi,1))}</text><text x="6" y="188">${esc(formatter(lo,1))}</text><text x="42" y="205">60m ago</text><text x="752" y="205">now</text></svg></div>`}
function topologyGraph(t){
  if(!t||!Array.isArray(t.nodes)||!t.nodes.length)return '<div class="topology empty">Network map appears when this client reports topology data.</div>';
  const compact=window.matchMedia('(max-width:520px)').matches,width=compact?420:760,height=compact?390:430,cx=width/2,cy=compact?188:208,radiusX=compact?148:280,radiusY=compact?116:132,localKey=String(t.local_id||''),key=x=>String(x.id),seen=new Set(),nodes=t.nodes.slice(0,64).filter(x=>{const k=key(x);if(seen.has(k))return false;seen.add(k);return true}),nodeByKey=new Map(nodes.map(x=>[key(x),x])),positions=new Map();
  const compare=(a,b)=>{const al=key(a)===localKey,bl=key(b)===localKey;if(al!==bl)return al?-1:1;const ai=Number(a.role_index)||0,bi=Number(b.role_index)||0;return ai!==bi?ai-bi:key(a).localeCompare(key(b))};
  const fleet=nodes.filter(x=>x.role==='fleet').sort(compare),validators=nodes.filter(x=>x.role==='validator').sort(compare),operators=nodes.filter(x=>x.role!=='fleet'&&x.role!=='validator').sort(compare);
  const place=(group,scale,phase)=>group.forEach((x,i)=>{const angle=phase+2*Math.PI*i/Math.max(1,group.length);positions.set(key(x),[cx+radiusX*scale*Math.cos(angle),cy+radiusY*scale*Math.sin(angle)])});
  place(fleet,.54,-Math.PI/2);place(validators,.77,validators.length===1?0:-Math.PI/2+Math.PI/5);place(operators,1,compact?-Math.PI/2:Math.PI);
  const used=new Map(),ordinals=new Map(),roleUsed=role=>{if(!used.has(role))used.set(role,new Set());return used.get(role)};
  for(const node of nodes){const ordinal=Number(node.role_index)||0,set=roleUsed(node.role);if(ordinal>0&&!set.has(ordinal)){set.add(ordinal);ordinals.set(key(node),ordinal)}}
  for(const node of nodes){if(ordinals.has(key(node)))continue;const set=roleUsed(node.role);let ordinal=1;while(set.has(ordinal))ordinal++;set.add(ordinal);ordinals.set(key(node),ordinal)}
  const roleLabel=role=>role==='fleet'?'Fleet':role==='miner'?'Miner':role==='validator'?'Validator':'Node',nodeName=node=>`${roleLabel(node.role)} ${String(ordinals.get(key(node))||1).padStart(2,'0')}`;
  const edgePath=(a,b)=>{const dx=b[0]-a[0],dy=b[1]-a[1],lengthSquared=dx*dx+dy*dy;if(lengthSquared<=1)return '';const along=Math.max(0,Math.min(1,((cx-a[0])*dx+(cy-a[1])*dy)/lengthSquared)),nearestX=a[0]+dx*along,nearestY=a[1]+dy*along,distance=Math.hypot(nearestX-cx,nearestY-cy),avoid=compact?45:64;if(distance>=avoid)return `M ${a[0].toFixed(1)} ${a[1].toFixed(1)} L ${b[0].toFixed(1)} ${b[1].toFixed(1)}`;const length=Math.sqrt(lengthSquared),offset=compact?54:78,midX=(a[0]+b[0])/2,midY=(a[1]+b[1])/2;let nx=-dy/length,ny=dx/length;const plus=(midX+nx*offset-cx)**2+(midY+ny*offset-cy)**2,minus=(midX-nx*offset-cx)**2+(midY-ny*offset-cy)**2;if(minus>plus){nx=-nx;ny=-ny}return `M ${a[0].toFixed(1)} ${a[1].toFixed(1)} C ${(a[0]+dx/3+nx*offset).toFixed(1)} ${(a[1]+dy/3+ny*offset).toFixed(1)}, ${(a[0]+2*dx/3+nx*offset).toFixed(1)} ${(a[1]+2*dy/3+ny*offset).toFixed(1)}, ${b[0].toFixed(1)} ${b[1].toFixed(1)}`};
  const edges=(Array.isArray(t.edges)?t.edges:[]).map(edge=>{const first=String(edge.first),second=String(edge.second),a=positions.get(first),b=positions.get(second);if(!a||!b)return '';const path=edgePath(a,b),firstNode=nodeByKey.get(first),secondNode=nodeByKey.get(second),differs=firstNode&&secondNode&&(firstNode.tip_state==='differs'||secondNode.tip_state==='differs'),classes=`edge ${edge.confirmed?'':'one'} ${differs?'differs':''}`;return `${edge.confirmed?`<path class="edge-underlay" d="${path}"/>`:''}<path class="${classes}" d="${path}"/>`}).join('');
  const marks=nodes.map(node=>{const p=positions.get(key(node));if(!p)return '';const isLocal=key(node)===localKey,name=nodeName(node),radius=compact?16:14,state=node.tip_state==='exact'?'exact tip':node.tip_state==='differs'?'tip differs':'status unavailable';return `<g class="peer ${esc(node.role)} ${esc(node.tip_state)}"><title>${esc(name+(isLocal?' · this node':'')+' · '+state)}</title><circle class="halo" cx="${p[0]}" cy="${p[1]}" r="${radius+7}"/>${isLocal?`<circle class="direct-ring" cx="${p[0]}" cy="${p[1]}" r="${radius+5}"/>`:''}<circle class="core" cx="${p[0]}" cy="${p[1]}" r="${radius}"/><text x="${p[0]}" y="${p[1]+radius+16}" text-anchor="middle">${esc(name)}</text></g>`}).join('');
  const orbits=`${fleet.length?`<ellipse class="orbit fleet" cx="${cx}" cy="${cy}" rx="${radiusX*.54}" ry="${radiusY*.54}"/>`:''}${validators.length?`<ellipse class="orbit validator" cx="${cx}" cy="${cy}" rx="${radiusX*.77}" ry="${radiusY*.77}"/>`:''}${operators.length?`<ellipse class="orbit operator" cx="${cx}" cy="${cy}" rx="${radiusX}" ry="${radiusY}"/>`:''}`;
  return `<div class="topology"><svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Sanitized Veld peer topology"><defs><radialGradient id="topology-center" cx="34%" cy="28%"><stop offset="0" stop-color="#26372e"/><stop offset="1" stop-color="#121a16"/></radialGradient><radialGradient id="topology-fleet" cx="34%" cy="28%"><stop offset="0" stop-color="#385363"/><stop offset="1" stop-color="#172832"/></radialGradient><radialGradient id="topology-node" cx="34%" cy="28%"><stop offset="0" stop-color="#2c4b3d"/><stop offset="1" stop-color="#14271f"/></radialGradient><radialGradient id="topology-miner" cx="34%" cy="28%"><stop offset="0" stop-color="#355925"/><stop offset="1" stop-color="#182d14"/></radialGradient><radialGradient id="topology-validator" cx="34%" cy="28%"><stop offset="0" stop-color="#493861"/><stop offset="1" stop-color="#251d31"/></radialGradient></defs>${orbits}${edges}<g aria-hidden="true"><circle class="center-ring" cx="${cx}" cy="${cy}" r="36"/><circle class="center-ring" cx="${cx}" cy="${cy}" r="31"/><circle class="center-ring" cx="${cx}" cy="${cy}" r="27"/><circle class="center-core" cx="${cx}" cy="${cy}" r="23"/><text class="center-label" x="${cx}" y="${cy-2}" text-anchor="middle">VELD</text><text class="center-sub" x="${cx}" y="${cy+11}" text-anchor="middle">NETWORK</text></g>${marks}</svg></div><div class="topology-legend" aria-label="Peer role colors"><span><i class="legend-dot node"></i>Node</span><span><i class="legend-dot fleet"></i>Fleet</span><span><i class="legend-dot miner"></i>Miner</span><span><i class="legend-dot validator"></i>Validator</span></div><div class="topology-legend" aria-label="Link and status legend"><span><i class="legend-line"></i>Seen by both</span><span><i class="legend-line one"></i>One-sided</span><span><i class="legend-dot differs"></i>Tip differs</span><span><i class="legend-dot unavailable"></i>Status unavailable</span></div>`
}
function action(name,payload={}){actionQueue=actionQueue.then(()=>signedAction(name,payload)).catch(error=>toast(error.message,true));return actionQueue}function confirmAction(name,question){if(window.confirm(question))return action(name)}function toggle(name,value){action(name,{enabled:!value})}function toast(msg,bad=false){let t=document.createElement("div");t.className="toast "+(bad?"warning":"pill");t.textContent=msg;document.body.appendChild(t);setTimeout(()=>t.remove(),3600)}
function firstPair(){return `<section class="section"><div class="section-head"><div><h2>Pair your first machine</h2><p>Enable Remote access in the Veld desktop client, then enter the one-time pairing code shown there.</p></div></div><div class="pair"><input id="pair-code" maxlength="9" inputmode="text" autocomplete="one-time-code" placeholder="PAIR CODE"><button class="button" data-portal-action="claim">Pair machine</button></div><div id="pair-error" class="error"></div><div class="local-only">The portal receives operational status only. Commands are signed by a non-exportable key in this app and every change must still be approved on the paired machine. Wallet keys, passphrases, RPC credentials, peer addresses, and identity files never leave it.</div></section>`}
function pageScrollState(){const state={};document.querySelectorAll("#page [data-scroll-key]").forEach(el=>state[el.dataset.scrollKey]=el.scrollLeft);return state}
function restorePageScroll(state){requestAnimationFrame(()=>document.querySelectorAll("#page [data-scroll-key]").forEach(el=>{const value=state[el.dataset.scrollKey];if(Number.isFinite(value))el.scrollLeft=value}))}
function render(){const scroll=pageScrollState();const d=current();const meta=d?titles[page]:["Pair a machine","Connect your first Veld node or miner."];$("page-title").textContent=meta[0];$("page-subtitle").textContent=meta[1];const extra=["workers","network","logs","settings"];document.querySelectorAll("#nav button").forEach(b=>b.classList.toggle("active",!!d&&(b.dataset.page===page||(b.dataset.page==="more"&&extra.includes(page)))));if(!d){$("online").className="status";$("online").textContent="Offline";setHtml($("page"),firstPair());return}$("online").className="status "+(d.online?"online":"");$("online").textContent=d.online?"Online":"Offline";const fn={overview,blockchain,mining,workers,explorer,network,logs,settings,more}[page];setHtml($("page"),fn(d,snap(d)));restorePageScroll(scroll)}
function overview(d,s){return `<div class="cards">${metric(n(d.height),"Block height","green")}${metric(d.sync_lag?n(d.sync_lag)+" behind":"100.0%","Synchronization")}${metric(n(d.peers),"P2P peers")}${metric(n(d.hashrate,1)+" H/s","Total hashrate",d.hashrate?"green":"")}${metric(n(d.blocks),"Accepted blocks")}${metric(n(d.workers),"CPU workers")}${metric(n(s.mempool),"Mempool transactions")}${metric(n(s.supply,2)+" VELD","Circulating supply")}</div><section class="section"><div class="section-head"><div><h2>Node status</h2><p>${esc(d.warning||"Consensus validation is active inside veld-node.")}</p></div><div class="controls"><span class="status ${d.online?'online':''}">${esc(d.mining_state)}</span><button class="button" data-command="${s.process_running?'node.stop':'node.start'}"${s.process_running?' data-confirm="Stop this node gracefully?"':''}>${s.process_running?'Stop node':'Start node'}</button></div></div><div class="kv"><div><b>${d.sync_lag?'Syncing':'Validated'}</b><span>Chain</span></div><div><b>${n(d.peers)}</b><span>Connections</span></div><div><b>${s.mining_ready?'Ready':'Waiting'}</b><span>Work admission</span></div><div><b>v${esc(d.version)}</b><span>Client build</span></div></div>${d.last_command?`<div class="warning">Last command: ${esc(d.last_command.action)} | ${esc(d.last_command.state)}</div>`:""}</section><section class="section"><div class="section-head"><div><h2>Chain activity</h2><p>Locally reported verified chain height over the last hour.</p></div></div>${spark(d.history,"height","Verified chain height")}</section>`}
function blockchain(d,s){return `<div class="cards">${metric(n(d.height),"Locally verified height","green")}${metric(d.sync_lag?n(d.sync_lag):"0","Blocks behind")}${metric(bytes(s.chain_bytes),"Chain storage")}${metric("Disabled","Snapshot bootstrap")}</div><section class="section"><div class="section-head"><div><h2>Synchronization mode</h2><p>Veld 3.0.0 public mainnet validates from genesis.</p></div></div><div class="control-row"><div><h3>Full initial block download</h3><p>Validate the complete chain from genesis.</p></div><button class="button" data-command="sync.mode" data-mode="full">Selected</button></div></section>`}
function mining(d,s){return `<div class="cards">${metric(esc(d.mining_state),"Mining status",s.mining_active?"green":"")}${metric(n(d.hashrate,2)+" H/s","Total hashrate",d.hashrate?"green":"")}${metric(n(d.workers),"CPU workers")}${metric(n(d.blocks),"Accepted blocks")}${metric(n(s.total_hashes),"Session hashes","wide")}${metric(s.mining_ready?"Admitted":"Waiting","Work admission","wide")}</div><section class="section"><div class="section-head"><div><h2>Hashrate history</h2><p>Measured aggregate VeldHash rate over the last hour.</p></div></div>${spark(d.history,"hashrate","VeldHash rate",(x,p)=>n(x,p)+" H/s")}</section><section class="section"><div class="control-row"><div><h3>CPU mining</h3><p>Enable mining for the next app-managed start.</p></div><button class="toggle ${s.mining_enabled?'on':''}" aria-label="Toggle mining" data-command="mining.enabled" data-enabled="${!!s.mining_enabled}"></button></div><div class="control-row"><div><h3>Worker count</h3><p>Choose an exact worker count from 1 to 256.</p></div><div class="controls"><button class="button ghost" data-worker-delta="-1">-</button><span class="pill">${n(d.workers||s.configured_workers||1)} workers</span><button class="button ghost" data-worker-delta="1">+</button></div></div></section>`}
function setWorkers(delta){const d=current(),s=snap(d);const value=Math.max(1,Math.min(256,Number(d.workers||s.configured_workers||1)+delta));action('mining.workers',{workers:value})}
function workers(d,s){let count=Number(d.workers||s.configured_workers||0),rate=count?Number(d.hashrate||0)/count:0;let rows=Array.from({length:count},(_,i)=>`<tr><td>CPU ${i+1}</td><td class="green">${s.mining_active?'Hashing':'Waiting'}</td><td>${n(rate,2)} H/s</td><td>VeldHash</td></tr>`).join("");return `<section class="section"><div class="section-head"><div><h2>Local VeldHash workers</h2><p>Per-worker rates are estimates from the measured aggregate.</p></div><span class="status ${s.mining_active?'online':''}">${s.mining_active?'Running':'Paused'}</span></div>${rows?`<table class="table"><thead><tr><th>Worker</th><th>State</th><th>Est. rate</th><th>Algorithm</th></tr></thead><tbody>${rows}</tbody></table>`:'<div class="empty">No mining workers are configured.</div>'}</section>`}
function explorer(d,s){const blocks=Array.isArray(s.recent_blocks)?s.recent_blocks:[];const rows=blocks.map(b=>`<tr><td>#${n(b.height)}</td><td>${esc(b.hash||"")}</td><td>${n(b.tx_count)} tx</td><td>${n(b.reward,4)} VELD</td><td>${esc(b.winner||"")}</td></tr>`).join("");return `<div class="cards">${metric(n(d.height),"Chain height","green")}${metric(n(s.mempool),"Mempool")}${metric(n(s.supply,2)+" VELD","Supply")}${metric(n(d.blocks),"Session blocks")}</div><section class="section"><div class="section-head"><div><h2>Recent blocks</h2><p>Locally verified block feed.</p></div><a class="button ghost" href="https://explorer.veld.network" target="_blank" rel="noreferrer">Open public explorer</a></div>${rows?`<table class="table" data-scroll-key="recent-blocks"><thead><tr><th>Height</th><th>Hash</th><th>Transactions</th><th>Reward</th><th>Winner</th></tr></thead><tbody>${rows}</tbody></table>`:'<div class="empty">Recent block data will appear after the next report.</div>'}</section>`}
function topologyRoles(t,fallback={}){const roles={fleet:0,node:0,miner:0,validator:0},seen=new Set();if(t&&Array.isArray(t.nodes)&&t.nodes.length){for(const peer of t.nodes){const id=String(peer.id);if(seen.has(id))continue;seen.add(id);if(Object.prototype.hasOwnProperty.call(roles,peer.role))roles[peer.role]++}return roles}for(const role of Object.keys(roles))roles[role]=Number(fallback[role]||0);return roles}
function network(d,s){const topology=s.topology||{},roles=topologyRoles(topology,s.peer_roles||{}),nodeCount=Array.isArray(topology.nodes)?topology.nodes.length:0,eligible=Math.max(Number(topology.eligible_nodes)||0,nodeCount),reporting=Number(topology.reporting_nodes)||0,coverage=eligible?`${n(reporting)} / ${n(eligible)} reporting`:`${n(reporting)} reporting`;return `<div class="cards network-cards">${metric(n(d.peers),"Direct peers","green")}${metric(n(d.inbound),"Inbound")}${metric(n(s.outbound),"Outbound")}${metric(`${n(s.exact_tip)} / ${n(d.peers)}`,"Exact tip agreement")}${metric(s.port_mapped?'Available':'Unavailable',"Inbound mapping")}${metric(s.tor?'Tor only':'Clearnet',"Transport")}</div><section class="section"><div class="section-head"><div><h2>Peer topology</h2><p>Public links. Dotted means one-sided reporting, not inbound direction. Rotating identities are used and addresses are never sent.</p></div><span class="pill">${n(d.peers)} direct · ${coverage}</span></div>${topologyGraph(topology)}</section><section class="section"><div class="section-head"><div><h2>Peer classes</h2><p>Network-wide identities in the current report.</p></div></div><div class="kv"><div><b>${n(roles.fleet)}</b><span>Fleet</span></div><div><b>${n(roles.node)}</b><span>Nodes</span></div><div><b>${n(roles.miner)}</b><span>Miners</span></div><div><b>${n(roles.validator)}</b><span>Validators</span></div></div></section>`}
function logs(d,s){const events=Array.isArray(s.events)?s.events:[];return `<section class="section"><div class="section-head"><div><h2>Operational events</h2><p>Sanitized status events only. Raw logs and local paths stay on the machine.</p></div></div><div class="log">${events.length?events.map(esc).join("\n"):"Waiting for sanitized client events..."}</div></section>`}
function settingRow(title,detail,actionName,value,disabled=false){return `<div class="control-row"><div><h3>${title}</h3><p>${detail}</p></div><button class="toggle ${value?'on':''}" ${disabled?'disabled':''} data-command="${actionName}" data-enabled="${!!value}"></button></div>`}
function installedPortal(){return window.matchMedia('(display-mode: standalone)').matches||window.navigator.standalone===true}
function settings(d,s){const pair=installedPortal()?'':`<section class="section"><div class="section-head"><div><h2>Pair another machine</h2><p>Enable Remote access in the desktop client, then enter its one-time code.</p></div></div><div class="pair"><input id="pair-code" maxlength="9" placeholder="PAIR CODE"><button class="button" data-portal-action="claim">Pair machine</button></div><div id="pair-error" class="error"></div></section>`;return `<section class="section"><div class="section-head"><div><h2>Node preferences</h2><p>Changes that affect transport or sync apply on the next start.</p></div></div>${settingRow("CPU mining","Run VeldHash workers when the node starts.","mining.enabled",s.mining_enabled)}${settingRow("Tor-only privacy","Route peer traffic through Tor.","privacy.tor",s.tor,s.process_running)}${settingRow("Attempt inbound reachability","Ask the router for an inbound P2P mapping.","network.reachable",s.reachable,s.process_running||s.tor)}${settingRow("Show public height reference","Use the public explorer for visual sync progress only.","display.reference",s.reference)}</section><section class="section"><div class="section-head"><div><h2>Release and updates</h2><p>Installed v${esc(d.version)}</p></div><div class="controls"><button class="button" data-command="updates.check">Check now</button><button class="button" data-command="updates.install" data-confirm="Install the signed update and restart this node?">Update now</button></div></div><div class="local-only">Signed feed verification and package installation run on the paired machine. Identity creation, keyfile import, and passphrase entry stay local and are never sent through this portal.</div></section>${pair}<section class="section"><div class="section-head"><div><h2>Current machine</h2><p>Rename or remove this paired machine.</p></div></div><div class="control-row"><div><h3>Machine name</h3><p>${esc(d.name)}</p></div><div class="controls"><button class="button ghost" data-portal-action="rename">Rename</button><button class="button danger" data-portal-action="remove">Remove</button></div></div></section>`}
function more(){const installed=installedPortal();return `<section class="section"><div class="more-grid"><button class="button" data-open-page="workers">Workers</button><button class="button" data-open-page="network">Network</button><button class="button" data-open-page="logs">Logs</button><button class="button" data-open-page="settings">Settings</button>${installed?'':`<button class="button" data-portal-action="install">Install portal</button>`}</div></section>`}
async function installPortal(){if(installPrompt){installPrompt.prompt();await installPrompt.userChoice;installPrompt=null;render();return}toast('Open your browser menu and choose Add to Home Screen')}
async function claim(){try{const keyInfo=await commandKey();await api("/api/v1/devices/claim","POST",{code:$("pair-code").value,command_key:keyInfo.key});$("pair-code").value="";refresh()}catch(e){$("pair-error").textContent=e.message}}async function renameDevice(){const d=current(),name=prompt("Machine name",d.name);if(name){await api("/api/v1/devices/rename","POST",{id:d.id,name});refresh()}}async function removeDevice(){const d=current();if(confirm("Remove this machine from your portal?")){await api("/api/v1/devices/revoke","POST",{id:d.id});selected=0;refresh()}}
function showAuth(){csrf="";$("auth-view").classList.remove("hidden");$("app-view").classList.add("hidden")}function showApp(){$("auth-view").classList.add("hidden");$("app-view").classList.remove("hidden");refresh()}async function auth(mode){$("auth-error").textContent="";try{const j=await api("/api/v1/"+mode,"POST",{account:$("account").value,password:$("password").value});csrf=j.csrf;$("password").value="";showApp()}catch(e){$("auth-error").textContent=e.message}}
window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();installPrompt=event});
window.addEventListener('appinstalled',()=>{installPrompt=null;if(page==='more')render()});
if('serviceWorker' in navigator)window.addEventListener('load',()=>navigator.serviceWorker.register('/service-worker.js',{scope:'/'}).catch(()=>{}));
function closePortalMore(){const menu=$("portal-more-menu"),button=document.querySelector('#nav button[data-page="more"]');menu.dataset.open="0";menu.setAttribute("aria-hidden","true");button?.setAttribute("aria-expanded","false")}
function togglePortalMore(){const menu=$("portal-more-menu"),opening=menu.dataset.open!=="1";menu.dataset.open=opening?"1":"0";menu.setAttribute("aria-hidden",opening?"false":"true");document.querySelector('#nav button[data-page="more"]')?.setAttribute("aria-expanded",opening?"true":"false")}
function handlePortalClick(event){if(!(event.target instanceof Element))return;const target=event.target.closest("[data-portal-action],[data-command],[data-worker-delta],[data-open-page]");if(!target||target.disabled)return;if(target.dataset.openPage){page=target.dataset.openPage;render();return}if(target.dataset.workerDelta){setWorkers(Number(target.dataset.workerDelta));return}if(target.dataset.portalAction){const handlers={claim,install:installPortal,rename:renameDevice,remove:removeDevice},handler=handlers[target.dataset.portalAction];if(handler)Promise.resolve(handler()).catch(error=>toast(error.message,true));return}if(target.dataset.command){if(target.dataset.confirm&&!window.confirm(target.dataset.confirm))return;const payload={};if(Object.prototype.hasOwnProperty.call(target.dataset,"enabled"))payload.enabled=target.dataset.enabled!=="true";if(target.dataset.mode)payload.mode=target.dataset.mode;action(target.dataset.command,payload)}}
document.addEventListener("click",handlePortalClick);document.querySelectorAll("#nav button").forEach(b=>b.addEventListener("click",e=>{if(b.dataset.page==="more"){e.stopPropagation();togglePortalMore();return}closePortalMore();page=b.dataset.page;render()}));document.querySelectorAll("[data-more-page]").forEach(b=>b.addEventListener("click",()=>{page=b.dataset.morePage;closePortalMore();render()}));document.addEventListener("click",e=>{const menu=$("portal-more-menu"),button=document.querySelector('#nav button[data-page="more"]');if(menu.dataset.open==="1"&&!menu.contains(e.target)&&!button.contains(e.target))closePortalMore()});document.addEventListener("keydown",e=>{if(e.key==="Escape")closePortalMore()});$("device-select").addEventListener("change",e=>{selected=Number(e.target.value);render()});$("login").addEventListener("click",()=>auth("login"));$("register").addEventListener("click",()=>auth("register"));$("logout").addEventListener("click",async()=>{try{await api("/api/v1/logout","POST",{})}catch{}showAuth()});api("/api/v1/session").then(j=>{csrf=j.csrf;showApp()}).catch(showAuth);setInterval(()=>{if(!$("app-view").classList.contains("hidden"))refresh()},5000);
</script></body></html>"""


class RateLimiter:
    def __init__(self) -> None:
        self._entries: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow_many(
        self, checks: tuple[tuple[str, str, int, int], ...]
    ) -> bool:
        now = time.monotonic()
        if not checks:
            return True
        for identity, bucket, limit, seconds in checks:
            if (
                not isinstance(identity, str)
                or not 1 <= len(identity) <= 96
                or not isinstance(bucket, str)
                or not 1 <= len(bucket) <= 96
                or not 1 <= limit <= 1_000_000
                or not 1 <= seconds <= 3600
            ):
                return False
        keys = [(identity, bucket) for identity, bucket, _, _ in checks]
        if len(set(keys)) != len(keys):
            return False
        with self._lock:
            if len(self._entries) >= 4096:
                for stale_key, stale_entries in list(self._entries.items()):
                    while stale_entries and stale_entries[0] <= now - 3600:
                        stale_entries.popleft()
                    if not stale_entries:
                        self._entries.pop(stale_key, None)
            new_keys = sum(key not in self._entries for key in keys)
            if len(self._entries) + new_keys > 8192:
                return False
            # Inspect every bucket before appending to any of them.  A denied
            # account/device charge cannot partially burn an unrelated global
            # or client quota.
            for identity, bucket, limit, seconds in checks:
                entries = self._entries.get((identity, bucket))
                if entries is None:
                    continue
                while entries and entries[0] <= now - seconds:
                    entries.popleft()
                if len(entries) >= limit:
                    return False
            for identity, bucket, _, _ in checks:
                self._entries[(identity, bucket)].append(now)
            return True

    def allow(self, address: str, bucket: str, limit: int, seconds: int) -> bool:
        return self.allow_many(((address, bucket, limit, seconds),))


def rate_identity(value: str) -> str:
    """Return one bounded canonical direct-socket identity."""
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        parsed = parsed.ipv4_mapped
    canonical = str(parsed)
    return canonical if len(canonical) <= 45 else "unknown"


def account_rate_identity(account: str) -> str:
    """Case-insensitive, fixed-size key for pre-scrypt account budgets."""
    normalized = account.lower().encode("ascii")
    return "account:" + hashlib.sha256(normalized).hexdigest()


def route_rate_bucket(path: str) -> str:
    known = {
        "/", "/healthz", "/manifest.webmanifest", "/service-worker.js",
        "/offline.html", "/icon.png", "/api/v1/session", "/api/v1/devices",
        "/api/v1/register", "/api/v1/login", "/api/v1/logout",
        "/api/v1/device/report", "/api/v1/devices/claim",
        "/api/v1/devices/trust-key", "/api/v1/devices/command",
        "/api/v1/devices/rename", "/api/v1/devices/revoke",
    }
    return path if path in known else "/other"


class ProxyMetadataError(ValueError):
    pass


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        return list(headers.get_all(name, []))
    return [
        str(value)
        for key, value in dict(headers).items()
        if str(key).lower() == name.lower()
    ]


def load_proxy_token(path: Path) -> bytes:
    """Read a regular, single-link, owner-only 32-byte hex proxy token."""
    if os.name == "nt":
        # The production portal topology is nginx on Linux.  Python's Windows
        # stat API cannot prove a protected owner-only DACL; do not silently
        # downgrade that file boundary on an unsupported host.
        raise ValueError("protected proxy token files require the production POSIX host")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (hasattr(os, "geteuid") and info.st_uid != os.geteuid())
            or info.st_mode & 0o077
            or info.st_size > 66
        ):
            raise ValueError("proxy token file must be regular, single-link, owner-only, and bounded")
        raw = os.read(fd, 67)
    finally:
        os.close(fd)
    encoded = raw.rstrip(b"\r\n")
    if not re.fullmatch(rb"[0-9a-f]{64}", encoded):
        raise ValueError("proxy token must be exactly 64 lowercase hex characters")
    return bytes.fromhex(encoded.decode("ascii"))


class TrustedProxyBoundary:
    def __init__(self, peer: str | None = None, token: bytes | None = None) -> None:
        if (peer is None) != (token is None):
            raise ValueError("trusted proxy peer and token must be configured together")
        self.peer = rate_identity(peer) if peer is not None else None
        if peer is not None and self.peer == "unknown":
            raise ValueError("trusted proxy peer must be one IP literal")
        if token is not None and len(token) != 32:
            raise ValueError("trusted proxy token must be 32 bytes")
        self.token = token

    def resolve(self, socket_peer: str, headers: Any) -> str:
        peer = rate_identity(socket_peer)
        if peer == "unknown":
            raise ProxyMetadataError("invalid socket peer")
        authorization = _header_values(headers, "X-Veld-Proxy-Authorization")
        clients = _header_values(headers, "X-Veld-Client-IP")
        legacy = sum(
            (_header_values(headers, name) for name in
             ("X-Forwarded-For", "X-Real-IP", "Forwarded")),
            [],
        )
        if legacy or len(authorization) > 1 or len(clients) > 1:
            raise ProxyMetadataError("ambiguous or untrusted forwarding metadata")
        if bool(authorization) != bool(clients):
            raise ProxyMetadataError("incomplete forwarding metadata")
        if not authorization:
            # No authenticated metadata: every request from the proxy peer is
            # deliberately one shared, rate-limited identity.
            return "peer:" + peer
        if self.peer is None or peer != self.peer or self.token is None:
            raise ProxyMetadataError("forwarding metadata from an untrusted peer")
        value = authorization[0]
        match = re.fullmatch(r"VeldProxy v1=([0-9a-f]{64})", value)
        if not match:
            raise ProxyMetadataError("proxy authentication failed")
        supplied = bytes.fromhex(match.group(1))
        if not hmac.compare_digest(self.token, supplied):
            raise ProxyMetadataError("proxy authentication failed")
        client = rate_identity(clients[0])
        if client == "unknown":
            raise ProxyMetadataError("invalid forwarded client identity")
        return "client:" + client


class ConcurrentBudget:
    def __init__(self, memory_limit: int = 128, work_limit: int = 64) -> None:
        self.memory_limit = memory_limit
        self.work_limit = work_limit
        self.memory = 0
        self.work = 0
        self.history = 0
        self._lock = threading.Lock()

    def acquire(self, memory: int, work: int, history: bool = False) -> bool:
        with self._lock:
            if (
                self.memory + memory > self.memory_limit
                or self.work + work > self.work_limit
                or history and self.history >= 4
            ):
                return False
            self.memory += memory
            self.work += work
            self.history += int(history)
            return True

    def release(self, memory: int, work: int, history: bool = False) -> None:
        with self._lock:
            self.memory -= memory
            self.work -= work
            self.history -= int(history)


class PortalStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock = threading.RLock()
        self._initialize()
        self._dummy_password_hash = self.password_hash(secrets.token_urlsafe(32))

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        return db

    @contextmanager
    def database(self):
        db = self.connect()
        try:
            with db:
                yield db
        finally:
            db.close()

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.database() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS accounts(
                  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL, created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS sessions(
                  token_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL,
                  csrf TEXT NOT NULL, expires_at INTEGER NOT NULL,
                  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE);
                CREATE TABLE IF NOT EXISTS devices(
                  id INTEGER PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL,
                  account_id INTEGER, pair_code TEXT UNIQUE, pair_expires INTEGER,
                  command_key_x TEXT NOT NULL DEFAULT '',
                  command_key_y TEXT NOT NULL DEFAULT '',
                  command_key_id TEXT NOT NULL DEFAULT '',
                  command_sequence INTEGER NOT NULL DEFAULT 0,
                  name TEXT NOT NULL, version TEXT NOT NULL DEFAULT '',
                  last_seen INTEGER NOT NULL DEFAULT 0, height INTEGER NOT NULL DEFAULT 0,
                  sync_lag INTEGER NOT NULL DEFAULT 0, hashrate REAL NOT NULL DEFAULT 0,
                  workers INTEGER NOT NULL DEFAULT 0, peers INTEGER NOT NULL DEFAULT 0,
                  inbound INTEGER NOT NULL DEFAULT 0, blocks INTEGER NOT NULL DEFAULT 0,
                  mining_state TEXT NOT NULL DEFAULT 'Waiting', warning TEXT NOT NULL DEFAULT '',
                  snapshot_json TEXT NOT NULL DEFAULT '{}', created_at INTEGER NOT NULL,
                  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
                CREATE TABLE IF NOT EXISTS commands(
                  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL,
                  account_id INTEGER NOT NULL, action TEXT NOT NULL,
                  payload_json TEXT NOT NULL DEFAULT '{}', state TEXT NOT NULL,
                  sequence INTEGER NOT NULL DEFAULT 0,
                  issued_at INTEGER NOT NULL DEFAULT 0,
                  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                  nonce TEXT NOT NULL DEFAULT '', key_id TEXT NOT NULL DEFAULT '',
                  signature TEXT NOT NULL DEFAULT '',
                  delivered_at INTEGER, completed_at INTEGER, result TEXT NOT NULL DEFAULT '',
                  FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE,
                  FOREIGN KEY(account_id) REFERENCES accounts(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS commands_device ON commands(device_id,state,id);
                CREATE INDEX IF NOT EXISTS commands_completed ON commands(completed_at);
                CREATE TABLE IF NOT EXISTS samples(
                  id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL,
                  captured_at INTEGER NOT NULL, height INTEGER NOT NULL,
                  hashrate REAL NOT NULL, peers INTEGER NOT NULL,
                  inbound INTEGER NOT NULL, mining_active INTEGER NOT NULL,
                  FOREIGN KEY(device_id) REFERENCES devices(id) ON DELETE CASCADE);
                CREATE INDEX IF NOT EXISTS samples_device_time
                  ON samples(device_id,captured_at);
            """)
            device_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(devices)")
            }
            device_migrations = {
                "snapshot_json": "TEXT NOT NULL DEFAULT '{}'",
                "command_key_x": "TEXT NOT NULL DEFAULT ''",
                "command_key_y": "TEXT NOT NULL DEFAULT ''",
                "command_key_id": "TEXT NOT NULL DEFAULT ''",
                "command_sequence": "INTEGER NOT NULL DEFAULT 0",
            }
            for name, declaration in device_migrations.items():
                if name not in device_columns:
                    db.execute(f"ALTER TABLE devices ADD COLUMN {name} {declaration}")
            command_columns = {
                row["name"] for row in db.execute("PRAGMA table_info(commands)")
            }
            command_migrations = {
                "sequence": "INTEGER NOT NULL DEFAULT 0",
                "issued_at": "INTEGER NOT NULL DEFAULT 0",
                "nonce": "TEXT NOT NULL DEFAULT ''",
                "key_id": "TEXT NOT NULL DEFAULT ''",
                "signature": "TEXT NOT NULL DEFAULT ''",
            }
            for name, declaration in command_migrations.items():
                if name not in command_columns:
                    db.execute(f"ALTER TABLE commands ADD COLUMN {name} {declaration}")
            db.execute(
                """CREATE UNIQUE INDEX IF NOT EXISTS commands_device_sequence
                   ON commands(device_id,sequence) WHERE sequence>0"""
            )
            # Protocol 3 never delivers legacy unsigned mutations. They remain
            # visible in history, but are permanently retired during migration.
            db.execute(
                """UPDATE commands SET state='superseded',completed_at=?
                   WHERE state IN ('queued','delivered') AND signature=''""",
                (int(time.time()),),
            )

    @staticmethod
    def password_hash(password: str, salt: bytes | None = None) -> str:
        salt = salt or secrets.token_bytes(16)
        derived = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=32768,
            r=8,
            p=1,
            maxmem=64 * 1024 * 1024,
            dklen=32,
        )
        return (
            "scrypt$32768$"
            + base64.urlsafe_b64encode(salt).decode()
            + "$"
            + base64.urlsafe_b64encode(derived).decode()
        )

    @staticmethod
    def verify_password(password: str, encoded: str) -> bool:
        try:
            kind, rounds, salt_text, hash_text = encoded.split("$")
            if kind != "scrypt" or rounds != "32768":
                return False
            expected = base64.urlsafe_b64decode(hash_text)
            candidate = hashlib.scrypt(
                password.encode(),
                salt=base64.urlsafe_b64decode(salt_text),
                n=32768,
                r=8,
                p=1,
                maxmem=64 * 1024 * 1024,
                dklen=32,
            )
            return hmac.compare_digest(candidate, expected)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def create_account(self, name: str, password: str) -> int | None:
        try:
            with self.lock, self.database() as db:
                cur = db.execute(
                    "INSERT INTO accounts(name,password_hash,created_at) VALUES(?,?,?)",
                    (name.lower(), self.password_hash(password), int(time.time())),
                )
                return int(cur.lastrowid)
        except sqlite3.IntegrityError:
            return None

    def authenticate(self, name: str, password: str) -> int | None:
        with self.database() as db:
            row = db.execute(
                "SELECT id,password_hash FROM accounts WHERE name=?", (name.lower(),)
            ).fetchone()
        valid = self.verify_password(
            password, row["password_hash"] if row else self._dummy_password_hash
        )
        return int(row["id"]) if row and valid else None

    def new_session(self, account_id: int) -> tuple[str, str]:
        token, csrf, now = (
            secrets.token_urlsafe(32),
            secrets.token_urlsafe(24),
            int(time.time()),
        )
        with self.lock, self.database() as db:
            db.execute("DELETE FROM sessions WHERE expires_at<?", (now,))
            db.execute(
                "INSERT INTO sessions(token_hash,account_id,csrf,expires_at) VALUES(?,?,?,?)",
                (self.token_hash(token), account_id, csrf, now + SESSION_SECONDS),
            )
            db.execute(
                """DELETE FROM sessions WHERE account_id=? AND token_hash NOT IN (
                       SELECT token_hash FROM sessions WHERE account_id=?
                       ORDER BY expires_at DESC LIMIT 8)""",
                (account_id, account_id),
            )
        return token, csrf

    def session(self, token: str) -> sqlite3.Row | None:
        if not token:
            return None
        with self.database() as db:
            return db.execute(
                "SELECT account_id,csrf FROM sessions WHERE token_hash=? AND expires_at>=?",
                (self.token_hash(token), int(time.time())),
            ).fetchone()

    def delete_session(self, token: str) -> None:
        with self.lock, self.database() as db:
            db.execute(
                "DELETE FROM sessions WHERE token_hash=?", (self.token_hash(token),)
            )

    @staticmethod
    def pair_code() -> str:
        return (
            "".join(secrets.choice(PAIR_ALPHABET) for _ in range(4))
            + "-"
            + "".join(secrets.choice(PAIR_ALPHABET) for _ in range(4))
        )

    def device_known(self, token: str) -> bool:
        with self.database() as db:
            return (
                db.execute(
                    "SELECT 1 FROM devices WHERE token_hash=?",
                    (self.token_hash(token),),
                ).fetchone()
                is not None
            )

    def device_belongs(self, account_id: int, device_id: int) -> bool:
        with self.database() as db:
            return (
                db.execute(
                    "SELECT 1 FROM devices WHERE id=? AND account_id=?",
                    (device_id, account_id),
                ).fetchone()
                is not None
            )

    def report(self, token: str, report: dict[str, Any]) -> dict[str, Any]:
        now, token_hash = int(time.time()), self.token_hash(token)
        with self.lock, self.database() as db:
            db.execute(
                "DELETE FROM devices WHERE account_id IS NULL AND pair_expires<?",
                (now - PAIR_SECONDS,),
            )
            row = db.execute(
                """SELECT id,account_id,pair_code,pair_expires,
                          command_key_x,command_key_y,command_key_id,command_sequence
                   FROM devices WHERE token_hash=?""",
                (token_hash,),
            ).fetchone()
            if row is None:
                for _ in range(8):
                    code = self.pair_code()
                    try:
                        cur = db.execute(
                            "INSERT INTO devices(token_hash,pair_code,pair_expires,name,created_at) VALUES(?,?,?,?,?)",
                            (token_hash, code, now + PAIR_SECONDS, report["name"], now),
                        )
                        row = {
                            "id": int(cur.lastrowid),
                            "account_id": None,
                            "pair_code": code,
                            "pair_expires": now + PAIR_SECONDS,
                            "command_key_x": "",
                            "command_key_y": "",
                            "command_key_id": "",
                            "command_sequence": 0,
                        }
                        break
                    except sqlite3.IntegrityError:
                        continue
                else:
                    raise RuntimeError("pair code allocation failed")
            device_id = int(row["id"])
            code, expires = row["pair_code"], int(row["pair_expires"] or 0)
            if row["account_id"] is None and (not code or expires < now):
                code, expires = self.pair_code(), now + PAIR_SECONDS
            db.execute(
                """UPDATE devices SET pair_code=?,pair_expires=?,name=?,version=?,last_seen=?,height=?,sync_lag=?,hashrate=?,workers=?,peers=?,inbound=?,blocks=?,mining_state=?,warning=?,snapshot_json=? WHERE id=?""",
                (
                    code if row["account_id"] is None else None,
                    expires if row["account_id"] is None else None,
                    report["name"],
                    report["version"],
                    now,
                    report["height"],
                    report["sync_lag"],
                    report["hashrate"],
                    report["workers"],
                    report["peers"],
                    report["inbound"],
                    report["blocks"],
                    report["mining_state"],
                    report["warning"],
                    json.dumps(report["snapshot"], separators=(",", ":")),
                    device_id,
                ),
            )
            latest_sample = db.execute(
                "SELECT captured_at FROM samples WHERE device_id=? ORDER BY captured_at DESC LIMIT 1",
                (device_id,),
            ).fetchone()
            if latest_sample is None or int(latest_sample["captured_at"]) <= now - 10:
                snapshot = report["snapshot"]
                db.execute(
                    """INSERT INTO samples(
                    device_id,captured_at,height,hashrate,peers,inbound,mining_active)
                    VALUES(?,?,?,?,?,?,?)""",
                    (
                        device_id,
                        now,
                        report["height"],
                        report["hashrate"],
                        report["peers"],
                        report["inbound"],
                        1 if snapshot.get("mining_active") else 0,
                    ),
                )
                db.execute("DELETE FROM samples WHERE captured_at<?", (now - 86400,))
            ack_id = report.get("ack_id", 0)
            if ack_id:
                db.execute(
                    """UPDATE commands SET state=?,completed_at=?,result=?
                              WHERE id=? AND device_id=? AND state IN ('queued','delivered')""",
                    (
                        report["ack_status"],
                        now,
                        report["ack_message"],
                        ack_id,
                        device_id,
                    ),
                )
            db.execute(
                "UPDATE commands SET state='expired',completed_at=? WHERE device_id=? AND expires_at<? AND state IN ('queued','delivered')",
                (now, device_id, now),
            )
            db.execute(
                "DELETE FROM commands WHERE completed_at IS NOT NULL AND completed_at<?",
                (now - 30 * 86400,),
            )
            db.execute(
                """DELETE FROM commands
                   WHERE device_id=? AND state NOT IN ('queued','delivered')
                     AND id NOT IN (
                       SELECT id FROM commands WHERE device_id=?
                       ORDER BY id DESC LIMIT 256)""",
                (device_id, device_id),
            )
            protocol = int(report.get("portal_protocol", 1))
            command = None
            if protocol >= 3 and row["account_id"] is not None:
                pending = db.execute(
                    """SELECT id,action,payload_json,sequence,issued_at,expires_at,
                              nonce,key_id,signature
                       FROM commands
                       WHERE device_id=? AND state IN ('queued','delivered')
                         AND expires_at>=? AND signature<>''
                       ORDER BY sequence LIMIT 1""",
                    (device_id, now),
                ).fetchone()
                if pending:
                    db.execute(
                        "UPDATE commands SET state='delivered',delivered_at=COALESCE(delivered_at,?) WHERE id=?",
                        (now, pending["id"]),
                    )
                    command = {
                        "id": int(pending["id"]),
                        "action": pending["action"],
                        "payload": json.loads(pending["payload_json"]),
                        "sequence": int(pending["sequence"]),
                        "issued_at": int(pending["issued_at"]),
                        "expires_at": int(pending["expires_at"]),
                        "nonce": pending["nonce"],
                        "key_id": pending["key_id"],
                        "signature": pending["signature"],
                    }
            paired = row["account_id"] is not None
        response = {
            "portal_protocol": min(protocol, 3),
            "paired": paired,
            "pair_code": None if paired else code,
            "pair_expires": 0 if paired else expires,
            "report_interval": 5 if protocol >= 2 else 15,
        }
        if protocol >= 2:
            response["command"] = command
        if protocol >= 3:
            response["device_id"] = device_id
            response["command_key"] = (
                {
                    "x": row["command_key_x"],
                    "y": row["command_key_y"],
                    "id": row["command_key_id"],
                }
                if paired and row["command_key_id"]
                else None
            )
        return response

    def claim(self, account_id: int, code: str, key: dict[str, str]) -> bool:
        with self.lock, self.database() as db:
            cur = db.execute(
                """UPDATE devices SET account_id=?,pair_code=NULL,pair_expires=NULL,
                       command_key_x=?,command_key_y=?,command_key_id=?,command_sequence=0
                   WHERE pair_code=? AND pair_expires>=? AND account_id IS NULL""",
                (
                    account_id,
                    key["x"],
                    key["y"],
                    key["id"],
                    code,
                    int(time.time()),
                ),
            )
            return cur.rowcount == 1

    def enroll_command_key(
        self, account_id: int, device_id: int, key: dict[str, str]
    ) -> str:
        with self.lock, self.database() as db:
            row = db.execute(
                "SELECT command_key_id FROM devices WHERE id=? AND account_id=?",
                (device_id, account_id),
            ).fetchone()
            if row is None:
                return "missing"
            current = row["command_key_id"]
            if current and current != key["id"]:
                return "conflict"
            if not current:
                db.execute(
                    """UPDATE devices SET command_key_x=?,command_key_y=?,
                           command_key_id=?,command_sequence=0
                       WHERE id=? AND account_id=? AND command_key_id=''""",
                    (key["x"], key["y"], key["id"], device_id, account_id),
                )
            return "ok"

    def devices(self, account_id: int) -> list[dict[str, Any]]:
        now = int(time.time())
        with self.database() as db:
            rows = db.execute(
                """SELECT id,name,version,last_seen,height,sync_lag,hashrate,workers,
                          peers,inbound,blocks,mining_state,warning,snapshot_json,
                          command_key_id,command_sequence
                   FROM devices WHERE account_id=? ORDER BY name COLLATE NOCASE,id""",
                (account_id,),
            ).fetchall()
            result = []
            for row in rows:
                item = dict(row)
                try:
                    item["snapshot"] = json.loads(item.pop("snapshot_json"))
                except (ValueError, TypeError):
                    item["snapshot"] = {}
                    item.pop("snapshot_json", None)
                command = db.execute(
                    "SELECT action,state,result,created_at FROM commands WHERE device_id=? ORDER BY id DESC LIMIT 1",
                    (item["id"],),
                ).fetchone()
                item["last_command"] = dict(command) if command else None
                history = db.execute(
                    """SELECT captured_at,height,hashrate,peers,inbound,mining_active
                                        FROM samples WHERE device_id=? AND captured_at>=?
                                        ORDER BY captured_at""",
                    (item["id"], now - 3600),
                ).fetchall()
                item["history"] = [dict(sample) for sample in history]
                item["online"] = now - int(item["last_seen"]) <= ONLINE_SECONDS
                result.append(item)
        return result

    def queue_command(
        self, account_id: int, command: dict[str, Any]
    ) -> int | None:
        now = int(time.time())
        device_id = command["id"]
        with self.lock, self.database() as db:
            owned = db.execute(
                """SELECT command_key_x,command_key_y,
                          command_key_id,command_sequence FROM devices
                   WHERE id=? AND account_id=?""",
                (device_id, account_id),
            ).fetchone()
            if not owned:
                return None
            if not owned["command_key_id"]:
                raise ValueError("Secure control key is not enrolled")
            if not hmac.compare_digest(owned["command_key_id"], command["key_id"]):
                raise ValueError("Command key does not match this machine")
            if not verify_command_signature(
                command, owned["command_key_x"], owned["command_key_y"]
            ):
                raise ValueError("Command signature is invalid")
            if command["sequence"] != int(owned["command_sequence"]) + 1:
                raise ValueError("Refresh the portal before sending another command")
            active = db.execute(
                "SELECT COUNT(*) FROM commands WHERE device_id=? AND state IN ('queued','delivered') AND expires_at>=?",
                (device_id, now),
            ).fetchone()[0]
            if active >= 5:
                raise ValueError("Wait for the pending client command to finish")
            db.execute(
                "UPDATE commands SET state='superseded',completed_at=? WHERE device_id=? AND action=? AND state='queued'",
                (now, device_id, command["action"]),
            )
            cur = db.execute(
                """INSERT INTO commands(
                       device_id,account_id,action,payload_json,state,sequence,
                       issued_at,created_at,expires_at,nonce,key_id,signature)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    device_id,
                    account_id,
                    command["action"],
                    canonical_command_payload(command["action"], command["payload"]),
                    "queued",
                    command["sequence"],
                    command["issued_at"],
                    now,
                    command["expires_at"],
                    command["nonce"],
                    command["key_id"],
                    command["signature"],
                ),
            )
            db.execute(
                "UPDATE devices SET command_sequence=? WHERE id=? AND account_id=?",
                (command["sequence"], device_id, account_id),
            )
            return int(cur.lastrowid)

    def rename(self, account_id: int, device_id: int, name: str) -> bool:
        with self.lock, self.database() as db:
            return (
                db.execute(
                    "UPDATE devices SET name=? WHERE id=? AND account_id=?",
                    (name, device_id, account_id),
                ).rowcount
                == 1
            )

    def revoke(self, account_id: int, device_id: int) -> bool:
        with self.lock, self.database() as db:
            return (
                db.execute(
                    "DELETE FROM devices WHERE id=? AND account_id=?",
                    (device_id, account_id),
                ).rowcount
                == 1
            )


def bounded_int(value: Any, minimum: int, maximum: int, field: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not minimum <= value <= maximum
    ):
        raise ValueError(f"invalid {field}")
    return value


def bounded_number(value: Any, maximum: float, field: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 <= float(value) <= maximum
    ):
        raise ValueError(f"invalid {field}")
    return float(value)


def clean_text(value: Any, maximum: int, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > maximum
        or any(ord(c) < 32 and c not in "\t" for c in value)
    ):
        raise ValueError(f"invalid {field}")
    return value


def validate_snapshot(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict) or len(value) > 28:
        raise ValueError("invalid client snapshot")
    bool_fields = {
        "process_running",
        "snapshot_eligible",
        "full_ibd",
        "tor",
        "reachable",
        "reference",
        "mining_enabled",
        "mining_active",
        "mining_ready",
        "port_mapped",
    }
    int_limits = {
        "mempool": 10**7,
        "chain_bytes": 10**16,
        "outbound": 10000,
        "exact_tip": 10000,
        "last_block_age": 10**9,
        "total_hashes": 10**19,
        "configured_workers": 256,
    }
    number_limits = {"supply": 21_000_000.0}
    allowed = (
        bool_fields
        | set(int_limits)
        | set(number_limits)
        | {"peer_roles", "topology", "recent_blocks", "events"}
    )
    if set(value) - allowed:
        raise ValueError("unexpected client snapshot field")
    out: dict[str, Any] = {}
    for field in bool_fields:
        item = value.get(field, False)
        if not isinstance(item, bool):
            # Request-schema violations consistently map to HTTP 400.
            raise ValueError(f"invalid {field}")  # noqa: TRY004
        out[field] = item
    for field, maximum in int_limits.items():
        out[field] = bounded_int(value.get(field, 0), 0, maximum, field)
    for field, maximum in number_limits.items():
        out[field] = bounded_number(value.get(field, 0), maximum, field)
    roles = value.get("peer_roles", {})
    if not isinstance(roles, dict) or set(roles) - {
        "fleet",
        "node",
        "miner",
        "validator",
        "unknown",
    }:
        raise ValueError("invalid peer roles")
    out["peer_roles"] = {
        key: bounded_int(item, 0, 10000, "peer role") for key, item in roles.items()
    }
    topology = value.get("topology", {})
    if not isinstance(topology, dict) or set(topology) - {
        "generated_at",
        "reporting_nodes",
        "eligible_nodes",
        "local_id",
        "nodes",
        "edges",
    }:
        raise ValueError("invalid topology")
    clean_topology = {
        "generated_at": bounded_int(
            topology.get("generated_at", 0), 0, 10**12, "topology timestamp"
        ),
        "reporting_nodes": bounded_int(
            topology.get("reporting_nodes", 0), 0, 10000, "reporting nodes"
        ),
        "eligible_nodes": bounded_int(
            topology.get("eligible_nodes", 0), 0, 10000, "eligible nodes"
        ),
        "local_id": bounded_int(
            topology.get("local_id", 0), 0, 2**64 - 1, "local topology id"
        ),
    }
    nodes = topology.get("nodes", [])
    if not isinstance(nodes, list) or len(nodes) > 64:
        raise ValueError("invalid topology nodes")
    clean_nodes, node_ids = [], set()
    for node in nodes:
        if not isinstance(node, dict) or set(node) != {
            "id",
            "role",
            "role_index",
            "tip_state",
            "updated_at",
        }:
            raise ValueError("invalid topology node")
        node_id = bounded_int(node.get("id"), 1, 2**64 - 1, "topology node id")
        role = node.get("role")
        tip_state = node.get("tip_state")
        if role not in {"fleet", "node", "miner", "validator"} or tip_state not in {
            "exact",
            "differs",
            "stale",
            "unavailable",
        }:
            raise ValueError("invalid topology node state")
        if node_id in node_ids:
            raise ValueError("duplicate topology node")
        node_ids.add(node_id)
        clean_nodes.append(
            {
                "id": node_id,
                "role": role,
                "role_index": bounded_int(
                    node.get("role_index"), 0, 10000, "topology role index"
                ),
                "tip_state": tip_state,
                "updated_at": bounded_int(
                    node.get("updated_at"), 0, 10**12, "topology node timestamp"
                ),
            }
        )
    edges = topology.get("edges", [])
    if not isinstance(edges, list) or len(edges) > 192:
        raise ValueError("invalid topology edges")
    clean_edges, edge_keys = [], set()
    for edge in edges:
        if (
            not isinstance(edge, dict)
            or set(edge) != {"first", "second", "confirmed"}
            or not isinstance(edge.get("confirmed"), bool)
        ):
            raise ValueError("invalid topology edge")
        first = bounded_int(edge.get("first"), 1, 2**64 - 1, "topology edge")
        second = bounded_int(edge.get("second"), 1, 2**64 - 1, "topology edge")
        if first == second or first not in node_ids or second not in node_ids:
            raise ValueError("invalid topology edge endpoint")
        key = tuple(sorted((first, second)))
        if key in edge_keys:
            continue
        edge_keys.add(key)
        clean_edges.append(
            {"first": first, "second": second, "confirmed": edge["confirmed"]}
        )
    clean_topology["nodes"] = clean_nodes
    clean_topology["edges"] = clean_edges
    out["topology"] = clean_topology
    blocks = value.get("recent_blocks", [])
    if not isinstance(blocks, list) or len(blocks) > 12:
        raise ValueError("invalid recent blocks")
    clean_blocks = []
    for block in blocks:
        if not isinstance(block, dict) or set(block) - {
            "height",
            "timestamp",
            "tx_count",
            "reward",
            "hash",
            "winner",
        }:
            raise ValueError("invalid recent block")
        clean_blocks.append(
            {
                "height": bounded_int(
                    block.get("height", 0), 0, 10**12, "block height"
                ),
                "timestamp": bounded_int(
                    block.get("timestamp", 0), 0, 10**12, "block timestamp"
                ),
                "tx_count": bounded_int(
                    block.get("tx_count", 0), 0, 10**7, "transaction count"
                ),
                "reward": bounded_number(
                    block.get("reward", 0), 21_000_000.0, "block reward"
                ),
                "hash": clean_text(block.get("hash", ""), 72, "block hash"),
                "winner": clean_text(block.get("winner", ""), 72, "block winner"),
            }
        )
    out["recent_blocks"] = clean_blocks
    events = value.get("events", [])
    if not isinstance(events, list) or len(events) > 20:
        raise ValueError("invalid events")
    out["events"] = [clean_text(item, 160, "event") for item in events]
    return out


def validate_report(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict) or len(data) > 20:
        raise ValueError("invalid report")
    allowed = {
        "portal_protocol",
        "name",
        "version",
        "height",
        "sync_lag",
        "hashrate",
        "workers",
        "peers",
        "inbound",
        "blocks",
        "mining_state",
        "warning",
        "snapshot",
        "ack_id",
        "ack_status",
        "ack_message",
    }
    if set(data) - allowed:
        raise ValueError("unexpected report field")
    name, version, state = (
        data.get("name"),
        data.get("version"),
        data.get("mining_state"),
    )
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
        raise ValueError("invalid machine name")
    if not isinstance(version, str) or not VERSION_RE.fullmatch(version):
        raise ValueError("invalid version")
    if state not in {"Mining", "Syncing", "Paused", "Node only", "Stopped", "Warning"}:
        raise ValueError("invalid mining state")
    warning = clean_text(data.get("warning", ""), 160, "warning")
    ack_id = bounded_int(data.get("ack_id", 0), 0, 2**63 - 1, "acknowledgement")
    ack_status = data.get("ack_status", "")
    ack_message = clean_text(
        data.get("ack_message", ""), 160, "acknowledgement message"
    )
    if ack_id and ack_status not in {"completed", "failed", "local_confirmation"}:
        raise ValueError("invalid acknowledgement status")
    if not ack_id and (ack_status or ack_message):
        raise ValueError("orphan acknowledgement")
    protocol = bounded_int(data.get("portal_protocol", 1), 1, 3, "portal protocol")
    return {
        "portal_protocol": protocol,
        "name": name.strip(),
        "version": version,
        "mining_state": state,
        "warning": warning,
        "hashrate": bounded_number(data.get("hashrate"), 1e18, "hashrate"),
        "height": bounded_int(data.get("height"), 0, 10**12, "height"),
        "sync_lag": bounded_int(data.get("sync_lag"), 0, 10**9, "sync lag"),
        "workers": bounded_int(data.get("workers"), 0, 1024, "workers"),
        "peers": bounded_int(data.get("peers"), 0, 10000, "peers"),
        "inbound": bounded_int(data.get("inbound"), 0, 10000, "inbound"),
        "blocks": bounded_int(data.get("blocks"), 0, 10**12, "blocks"),
        "snapshot": validate_snapshot(data.get("snapshot")),
        "ack_id": ack_id,
        "ack_status": ack_status,
        "ack_message": ack_message,
    }


def validate_command(data: Any) -> dict[str, Any]:
    required = {
        "id",
        "action",
        "payload",
        "sequence",
        "issued_at",
        "expires_at",
        "nonce",
        "key_id",
        "signature",
    }
    if not isinstance(data, dict) or set(data) != required:
        raise ValueError("invalid command")
    device_id = bounded_int(data["id"], 1, 2**63 - 1, "device")
    action, payload = data["action"], data["payload"]
    if action not in ALLOWED_ACTIONS or not isinstance(payload, dict):
        raise ValueError("unsupported command")
    canonical_command_payload(action, payload)
    sequence = bounded_int(data["sequence"], 1, 2**63 - 1, "command sequence")
    issued_at = bounded_int(data["issued_at"], 1, 2**63 - 1, "command time")
    expires_at = bounded_int(data["expires_at"], 1, 2**63 - 1, "command expiry")
    nonce, key_id, signature = data["nonce"], data["key_id"], data["signature"]
    if not isinstance(nonce, str) or not COMMAND_NONCE_RE.fullmatch(nonce):
        raise ValueError("invalid command nonce")
    if not isinstance(key_id, str) or not COMMAND_KEY_ID_RE.fullmatch(key_id):
        raise ValueError("invalid command key")
    if not isinstance(signature, str) or not COMMAND_SIGNATURE_RE.fullmatch(signature):
        raise ValueError("invalid command signature")
    try:
        decode_base64url_canonical(nonce, 16)
        decode_base64url_canonical(signature, 64)
    except ValueError:
        raise ValueError("invalid signed command encoding") from None
    now = int(time.time())
    if abs(issued_at - now) > COMMAND_CLOCK_SKEW:
        raise ValueError("Command time is outside the allowed window")
    if expires_at <= now or not 30 <= expires_at - issued_at <= COMMAND_SECONDS:
        raise ValueError("Command expiry is invalid")
    command = {
        "id": device_id,
        "action": action,
        "payload": payload,
        "sequence": sequence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
        "key_id": key_id,
        "signature": signature,
    }
    command_envelope(command)
    return command


class PortalHandler(BaseHTTPRequestHandler):
    server_version = "VeldPortal"
    sys_version = ""

    @property
    def app(self) -> PortalServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)
        self._client_rate_identity: str | None = None
        self._budget_charge: tuple[int, int, bool] | None = None
        self._handling_request = False
        self._parsed_admission = False
        self._malformed_charged = False
        self._malformed_allowed = False
        self._request_path = "/"

    def finish(self) -> None:
        self.release_request_budget()
        super().finish()

    def release_request_budget(self) -> None:
        charge = getattr(self, "_budget_charge", None)
        if charge is not None:
            self.app.concurrent_budget.release(*charge)
            self._budget_charge = None

    def handle_one_request(self) -> None:
        # BaseHTTPRequestHandler dispatches unsupported methods only after
        # parse_request().  Reset identity and accounting per request so a
        # keep-alive peer cannot reuse authenticated proxy metadata, and
        # release the route work envelope after this request rather than only
        # when the TCP connection finally closes.
        self._client_rate_identity = None
        self._parsed_admission = False
        self._malformed_charged = False
        self._malformed_allowed = False
        self._request_path = "/"
        self._handling_request = True
        try:
            super().handle_one_request()
        finally:
            self._handling_request = False
            self.release_request_budget()

    def parse_request(self) -> bool:
        # This is the one method-independent parsed-request boundary.  It runs
        # before GET, POST, HEAD, OPTIONS, PUT, or an arbitrary method can be
        # dispatched, and therefore no parsed request can bypass proxy,
        # client, route, global, or concurrent-work admission.
        if not super().parse_request():
            return False
        if getattr(self.headers, "defects", ()):
            self.send_error(400, "Malformed request headers")
            return False
        try:
            self._request_path = urlsplit(self.path).path.rstrip("/") or "/"
        except ValueError:
            self.send_error(400, "Malformed request target")
            return False
        if not self.admit_or_reply(self._request_path):
            self.close_connection = True
            return False
        self._parsed_admission = True
        return True

    def charge_malformed_request(self) -> bool:
        if self._malformed_charged:
            return self._malformed_allowed
        identity = getattr(self, "_client_rate_identity", None)
        if identity is None:
            peer = rate_identity(
                self.client_address[0] if self.client_address else "unknown"
            )
            identity = "peer:" + peer
        self._malformed_allowed = self.app.limiter.allow_many(
            (
                (identity, "malformed-request", 60, 60),
                ("global", "malformed-request", 300, 60),
                ("global", "malformed-work", 600, 60),
            )
        )
        self._malformed_charged = True
        return self._malformed_allowed

    def send_error(
        self, code: int, message: str | None = None, explain: str | None = None
    ) -> None:
        del message, explain
        # Errors raised before central parsed admission include invalid request
        # lines, overlong lines, and malformed/oversized header sets.  Charge
        # them to the direct peer plus the independent global malformed/work
        # budgets; forwarding metadata is not trusted before parsing succeeds.
        if self._handling_request and not self._parsed_admission:
            if not self.charge_malformed_request():
                code = 429
        self.close_connection = True
        body = json.dumps(
            {
                "error": (
                    "Malformed request budget exceeded"
                    if code == 429 else "Request refused"
                )
            },
            separators=(",", ":"),
        ).encode()
        self._headers(code, "application/json; charset=utf-8", len(body))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def client_rate_identity(self) -> str:
        if getattr(self, "_client_rate_identity", None) is None:
            peer = self.client_address[0] if self.client_address else "unknown"
            self._client_rate_identity = self.app.proxy.resolve(peer, self.headers)
        return self._client_rate_identity

    def admit_request(self, path: str) -> tuple[bool, bool]:
        if self._budget_charge is not None:
            return False, True
        identity = self.client_rate_identity()
        route = route_rate_bucket(path)
        history = "history" in route
        expensive = path in {
            "/api/v1/register", "/api/v1/login", "/api/v1/device/report"
        }
        memory, work = ((16, 16) if history else ((8, 8) if expensive else (4, 1)))
        # Charge concurrent resources before cookie parsing or the session DB.
        if not self.app.concurrent_budget.acquire(memory, work, history):
            return False, True
        self._budget_charge = (memory, work, history)
        try:
            token = self.session_token()
            row = self.app.store.session(token) if token else None
        except Exception:
            self.release_request_budget()
            raise
        checks: list[tuple[str, str, int, int]] = [
            ("global", "requests", 6000, 60),
            ("global", "route:" + route, 1200 if not expensive else 600, 60),
        ]
        if row:
            account_id = int(row["account_id"])
            session_identity = "session:" + hashlib.sha256(
                token.encode("ascii", "ignore")
            ).hexdigest()
            checks.extend(
                (
                    (f"account:{account_id}", "authenticated", 600, 60),
                    (session_identity, "authenticated", 300, 60),
                )
            )
        else:
            checks.append((identity, "unauthenticated", 120, 60))
        if not self.app.limiter.allow_many(tuple(checks)):
            self.release_request_budget()
            return False, False
        return True, False

    def boundary_reply(self, status: int, value: dict[str, Any]) -> None:
        self.close_connection = True
        self.reply(status, value)

    def admit_or_reply(self, path: str) -> bool:
        try:
            accepted, busy = self.admit_request(path)
        except ProxyMetadataError:
            peer = rate_identity(
                self.client_address[0] if self.client_address else "unknown"
            )
            if self.app.limiter.allow_many(
                (
                    ("peer:" + peer, "invalid-proxy", 60, 60),
                    ("global", "invalid-proxy", 600, 60),
                    ("global", "boundary-work", 1200, 60),
                )
            ):
                self.boundary_reply(403, {"error": "Proxy metadata refused"})
            else:
                self.boundary_reply(
                    429, {"error": "Proxy metadata rate exceeded"}
                )
            return False
        except (CookieError, ValueError):
            if not self.charge_malformed_request():
                self.boundary_reply(
                    429, {"error": "Malformed request budget exceeded"}
                )
            else:
                self.boundary_reply(400, {"error": "Invalid request"})
            return False
        if accepted:
            return True
        if busy:
            self.boundary_reply(
                503, {"error": "Portal resource budget exhausted"}
            )
        else:
            self.boundary_reply(429, {"error": "Request rate exceeded"})
        return False

    def _headers(
        self,
        status: int,
        content_type: str,
        length: int = 0,
        csp_nonce: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
        )
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        if not self.app.insecure_http:
            self.send_header(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if csp_nonce:
            content_security_policy = (
                "default-src 'none'; "
                f"script-src 'nonce-{csp_nonce}'; script-src-attr 'none'; "
                f"style-src 'nonce-{csp_nonce}'; style-src-attr 'none'; "
                "connect-src 'self'; img-src 'self'; manifest-src 'self'; "
                "worker-src 'self'; object-src 'none'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'self'; trusted-types portal-render; "
                "require-trusted-types-for 'script'"
            )
        else:
            content_security_policy = (
                "default-src 'none'; object-src 'none'; frame-ancestors 'none'; "
                "base-uri 'none'; form-action 'none'"
            )
        self.send_header("Content-Security-Policy", content_security_policy)

    def reply(
        self, status: int, value: dict[str, Any], cookie: str | None = None
    ) -> None:
        body = json.dumps(value, separators=(",", ":")).encode()
        self._headers(status, "application/json; charset=utf-8", len(body))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> Any:
        lengths = self.headers.get_all("Content-Length", [])
        transfer_encodings = self.headers.get_all("Transfer-Encoding", [])
        content_types = self.headers.get_all("Content-Type", [])
        # The loopback backend sits behind a reverse proxy. Accept exactly one
        # canonical length and no transfer coding so the proxy and backend can
        # never disagree about where this request ends and the next begins.
        if transfer_encodings or len(lengths) != 1 or len(content_types) != 1:
            raise ValueError("ambiguous request framing")
        length_text = lengths[0]
        if not re.fullmatch(r"[1-9][0-9]*", length_text) or not (
            0 < int(length_text) <= MAX_BODY
        ):
            raise ValueError("invalid request size")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("JSON required")
        return json.loads(self.rfile.read(int(length_text)).decode("utf-8"))

    def session_token(self) -> str:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        morsel = cookie.get(self.app.cookie_name)
        return morsel.value if morsel else ""

    def authenticated(self, csrf: bool = False) -> sqlite3.Row | None:
        row = self.app.store.session(self.session_token())
        if not row or (
            csrf
            and not hmac.compare_digest(
                self.headers.get("X-CSRF-Token", ""), row["csrf"]
            )
        ):
            return None
        return row

    def rate(self, bucket: str, limit: int, seconds: int) -> bool:
        return self.app.limiter.allow(
            self.client_rate_identity(), bucket, limit, seconds
        )

    def auth_rate(self, account: str, registration: bool) -> bool:
        # These limits are evaluated before scrypt.  The global budget cannot
        # be reset by source/header rotation, the account budget cannot be
        # reset by IP rotation or ASCII case variants, and registration has a
        # separate, tighter resource envelope.
        if registration:
            checks = (
                ("portal-auth-global", "registration", 24, 3600),
                (account_rate_identity(account), "registration-account", 3, 3600),
            )
            peer_limit = ("registration-peer", 12, 3600)
        else:
            checks = (
                ("portal-auth-global", "login", 120, 600),
                (account_rate_identity(account), "login-account", 8, 600),
            )
            peer_limit = ("login-peer", 60, 600)
        return self.app.limiter.allow_many(
            tuple(checks) +
            ((self.client_rate_identity(), *peer_limit),) +
            (("portal-password-global", "password-verification",
              120 if not registration else 24, 600 if not registration else 3600),)
        )

    def device_rate(self, account_id: int, device_id: int) -> bool:
        if not self.app.store.device_belongs(account_id, device_id):
            return False
        return self.app.limiter.allow_many(
            (
                (f"account:{account_id}", "device-operation", 300, 60),
                (f"device:{device_id}", "device-operation", 120, 60),
                ("global", "device-operation", 3000, 60),
            )
        )

    def do_GET(self) -> None:
        path = self._request_path
        if path == "/healthz":
            self.reply(200, {"ok": True})
        elif path == "/api/v1/session":
            row = self.authenticated()
            self.reply(
                200, {"authenticated": True, "csrf": row["csrf"]}
            ) if row else self.reply(401, {"error": "Not signed in"})
        elif path == "/api/v1/devices":
            row = self.authenticated()
            self.reply(
                200,
                {
                    "csrf": row["csrf"],
                    "devices": self.app.store.devices(int(row["account_id"])),
                },
            ) if row else self.reply(401, {"error": "Not signed in"})
        elif path == "/manifest.webmanifest":
            body = json.dumps(PORTAL_MANIFEST, separators=(",", ":")).encode()
            self._headers(200, "application/manifest+json; charset=utf-8", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/service-worker.js":
            self._headers(
                200, "application/javascript; charset=utf-8", len(PORTAL_SERVICE_WORKER)
            )
            self.send_header("Service-Worker-Allowed", "/")
            self.end_headers()
            self.wfile.write(PORTAL_SERVICE_WORKER)
        elif path == "/icon.png":
            try:
                body = PORTAL_ICON_PATH.read_bytes()
            except OSError:
                return self.reply(404, {"error": "Not found"})
            self._headers(200, "image/png", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/offline":
            nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
            body = PORTAL_OFFLINE_HTML.replace(
                b"<style>", f'<style nonce="{nonce}">'.encode("ascii"), 1
            )
            self._headers(
                200, "text/html; charset=utf-8", len(body), csp_nonce=nonce
            )
            self.end_headers()
            self.wfile.write(body)
        elif path == "/":
            nonce = base64.b64encode(secrets.token_bytes(24)).decode("ascii")
            body = (
                PORTAL_HTML.replace(
                    "<style>", f'<style nonce="{nonce}">', 1
                )
                .replace("<script>", f'<script nonce="{nonce}">', 1)
                .encode()
            )
            self._headers(
                200, "text/html; charset=utf-8", len(body), csp_nonce=nonce
            )
            self.end_headers()
            self.wfile.write(body)
        else:
            self.reply(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = self._request_path
        try:
            if path in {"/api/v1/register", "/api/v1/login"}:
                data = self.read_json()
                if not isinstance(data, dict):
                    return self.reply(400, {"error": "Invalid request"})
                name, password = data.get("account"), data.get("password")
                if (
                    not isinstance(name, str)
                    or not ACCOUNT_RE.fullmatch(name)
                    or not isinstance(password, str)
                    or not 12 <= len(password) <= 128
                ):
                    return self.reply(
                        400,
                        {
                            "error": "Use a 3 to 48 character account name and a password of at least 12 characters."
                        },
                    )
                if not self.auth_rate(
                    name, registration=path.endswith("register")
                ):
                    return self.reply(
                        429, {"error": "Too many attempts. Try again later."}
                    )
                if not self.app.auth_slots.acquire(blocking=False):
                    return self.reply(
                        503, {"error": "Authentication service is busy. Try again."}
                    )
                try:
                    if path.endswith("register"):
                        account_id = self.app.store.create_account(name, password)
                        if account_id is None:
                            return self.reply(
                                409, {"error": "Account name is unavailable"}
                            )
                    else:
                        account_id = self.app.store.authenticate(name, password)
                        if account_id is None:
                            return self.reply(
                                401, {"error": "Account or password is incorrect"}
                            )
                finally:
                    self.app.auth_slots.release()
                token, csrf = self.app.store.new_session(account_id)
                flags = f"{self.app.cookie_name}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
                if not self.app.insecure_http:
                    flags += "; Secure"
                return self.reply(200, {"ok": True, "csrf": csrf}, flags)

            if path == "/api/v1/device/report":
                authorizations = self.headers.get_all("Authorization", [])
                if len(authorizations) != 1:
                    return self.reply(401, {"error": "Invalid device credential"})
                authorization = authorizations[0]
                token = authorization[7:] if authorization.startswith("Bearer ") else ""
                if not DEVICE_TOKEN_RE.fullmatch(token):
                    return self.reply(401, {"error": "Invalid device credential"})
                known = self.app.store.device_known(token)
                token_identity = "device-token:" + hashlib.sha256(
                    token.encode("ascii")
                ).hexdigest()
                report_checks: list[tuple[str, str, int, int]] = [
                    ("global", "device-report", 2000, 60),
                    (token_identity if known else self.client_rate_identity(),
                     "device-report" if known else "device-enrollment",
                     180 if known else 8, 60 if known else 3600),
                ]
                if not self.app.limiter.allow_many(tuple(report_checks)):
                    return self.reply(429, {"error": "Report rate exceeded"})
                return self.reply(
                    200, self.app.store.report(token, validate_report(self.read_json()))
                )

            row = self.authenticated(csrf=True)
            if not row:
                return self.reply(401, {"error": "Not signed in"})
            data, account_id = self.read_json(), int(row["account_id"])
            if path == "/api/v1/logout":
                self.app.store.delete_session(self.session_token())
                flags = f"{self.app.cookie_name}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                if not self.app.insecure_http:
                    flags += "; Secure"
                return self.reply(200, {"ok": True}, flags)
            if path == "/api/v1/devices/claim":
                if not self.app.limiter.allow_many(
                    (
                        (f"account:{account_id}", "claim", 12, 600),
                        (self.client_rate_identity(), "claim", 12, 600),
                        ("global", "claim", 600, 600),
                    )
                ):
                    return self.reply(
                        429, {"error": "Too many pairing attempts. Try again later."}
                    )
                if not isinstance(data, dict) or set(data) != {
                    "code",
                    "command_key",
                }:
                    return self.reply(400, {"error": "Invalid pairing request"})
                code = str(data["code"]).strip().upper()
                if not re.fullmatch(
                    r"[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}",
                    code,
                ):
                    return self.reply(400, {"error": "Enter the complete pairing code"})
                command_key = validate_command_key(data["command_key"])
                return (
                    self.reply(200, {"ok": True})
                    if self.app.store.claim(account_id, code, command_key)
                    else self.reply(404, {"error": "Code is invalid or expired"})
                )
            if path == "/api/v1/devices/trust-key":
                if not isinstance(data, dict) or set(data) != {
                    "id",
                    "command_key",
                }:
                    return self.reply(400, {"error": "Invalid key enrollment"})
                device_id = bounded_int(data["id"], 1, 2**63 - 1, "device")
                if not self.app.store.device_belongs(account_id, device_id):
                    return self.reply(404, {"error": "Machine not found"})
                if not self.device_rate(account_id, device_id):
                    return self.reply(429, {"error": "Device rate exceeded"})
                result = self.app.store.enroll_command_key(
                    account_id,
                    device_id,
                    validate_command_key(data["command_key"]),
                )
                if result == "missing":
                    return self.reply(404, {"error": "Machine not found"})
                if result == "conflict":
                    return self.reply(
                        409,
                        {
                            "error": "This machine already trusts a different command key. Re-pair it locally to replace that key."
                        },
                    )
                return self.reply(200, {"ok": True})
            if path == "/api/v1/devices/command":
                command = validate_command(data)
                device_id = int(command["id"])
                if not self.app.store.device_belongs(account_id, device_id):
                    return self.reply(404, {"error": "Machine not found"})
                if not self.device_rate(account_id, device_id):
                    return self.reply(429, {"error": "Device rate exceeded"})
                command_id = self.app.store.queue_command(account_id, command)
                return (
                    self.reply(200, {"ok": True, "command_id": command_id})
                    if command_id
                    else self.reply(404, {"error": "Machine not found"})
                )
            if path in {"/api/v1/devices/rename", "/api/v1/devices/revoke"}:
                device_id = bounded_int(
                    data.get("id") if isinstance(data, dict) else None,
                    1,
                    2**63 - 1,
                    "device",
                )
                if not self.app.store.device_belongs(account_id, device_id):
                    return self.reply(404, {"error": "Machine not found"})
                if not self.device_rate(account_id, device_id):
                    return self.reply(429, {"error": "Device rate exceeded"})
                if path.endswith("rename"):
                    name = data.get("name")
                    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 48:
                        return self.reply(400, {"error": "Machine name is invalid"})
                    ok = self.app.store.rename(account_id, device_id, name.strip())
                else:
                    ok = self.app.store.revoke(account_id, device_id)
                return (
                    self.reply(200, {"ok": True})
                    if ok
                    else self.reply(404, {"error": "Machine not found"})
                )
            self.reply(404, {"error": "Not found"})
        except (ValueError, json.JSONDecodeError) as exc:
            if not self.charge_malformed_request():
                self.reply(429, {"error": "Malformed request budget exceeded"})
            else:
                self.reply(400, {"error": str(exc) or "Invalid request"})
        # Keep the service fail-closed and the client response generic at the
        # outer HTTP boundary; the full exception stays in operator logs.
        except Exception:
            LOGGER.exception("Unhandled portal request failure")
            self.reply(500, {"error": "Request could not be completed"})


class PortalServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(
        self,
        address: tuple[str, int],
        store: PortalStore,
        insecure_http: bool = False,
        trusted_proxy_peer: str | None = None,
        proxy_token: bytes | None = None,
    ) -> None:
        super().__init__(address, PortalHandler)
        self.store = store
        self.insecure_http = insecure_http
        self.cookie_name = DEV_COOKIE_NAME if insecure_http else COOKIE_NAME
        self.limiter = RateLimiter()
        self.proxy = TrustedProxyBoundary(trusted_proxy_peer, proxy_token)
        self.concurrent_budget = ConcurrentBudget()
        # request_slots remains the hard 64-thread pre-parse semaphore.  The
        # separate explicit budget accounts for slow/partial TCP clients and
        # is independently observable and fail-closed.
        self.preparse_budget = ConcurrentBudget(
            memory_limit=REQUEST_CONCURRENCY, work_limit=REQUEST_CONCURRENCY
        )
        self.auth_slots = threading.BoundedSemaphore(AUTH_CONCURRENCY)
        self.request_slots = threading.BoundedSemaphore(REQUEST_CONCURRENCY)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.request_slots.acquire(blocking=False):
            request.close()
            return
        if not self.preparse_budget.acquire(1, 1):
            self.request_slots.release()
            request.close()
            return
        if not self.limiter.allow(
            "global", "preparse-connections", PREPARSE_CONNECTIONS_PER_MINUTE, 60
        ):
            self.preparse_budget.release(1, 1)
            self.request_slots.release()
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.preparse_budget.release(1, 1)
            self.request_slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.preparse_budget.release(1, 1)
            self.request_slots.release()


def is_loopback_listener(value: str) -> bool:
    if value.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Veld remote node operations portal")
    parser.add_argument(
        "--version",
        action="version",
        version=f"Veld Operator {VELD_OPERATOR_VERSION}",
    )
    parser.add_argument("--deployment-info", action="store_true")
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument(
        "--database", type=Path, default=Path("/var/lib/veld-monitor/portal.sqlite3")
    )
    parser.add_argument("--trusted-proxy-peer")
    parser.add_argument("--proxy-token-file", type=Path)
    parser.add_argument("--insecure-http", action="store_true", help="development only")
    args = parser.parse_args()
    if args.deployment_info:
        print(
            json.dumps(
                {
                    "binary_role": "operator-portal",
                    "client_version": VELD_OPERATOR_VERSION,
                    "profile_id": VELD_OPERATOR_PROFILE,
                    "public_gettxhistory_compiled": False,
                    "snapshot_bootstrap_compiled": False,
                    "upnp_compiled": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    if not is_loopback_listener(args.listen):
        parser.error(
            "the portal backend must listen on loopback behind a local HTTPS proxy"
        )
    if (args.trusted_proxy_peer is None) != (args.proxy_token_file is None):
        parser.error(
            "--trusted-proxy-peer and --proxy-token-file must be configured together"
        )
    if args.proxy_token_file is not None and not args.proxy_token_file.is_absolute():
        parser.error("--proxy-token-file must be an absolute path")
    try:
        proxy_token = (
            load_proxy_token(args.proxy_token_file)
            if args.proxy_token_file is not None else None
        )
    except (OSError, ValueError) as exc:
        parser.error(f"proxy token refused: {exc}")
    old_umask = os.umask(0o077)
    try:
        server = PortalServer(
            (args.listen, args.port), PortalStore(args.database), args.insecure_http,
            args.trusted_proxy_peer, proxy_token,
        )
    finally:
        os.umask(old_umask)
    print(f"Veld Portal listening on {args.listen}:{args.port}", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
