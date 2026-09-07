# Hosted wallet UI source

`obsidian-moss-v1.css` is the current stylesheet served by the public wallet.
Its SHA-256 is
`bd5dbeb0adb2116ac3f786294422d684f45e205ad1981f1477ce540e2f61f18e`.
The live asset uses the content-addressed name
`obsidian-moss-bd5dbeb0adb2.css` so existing browser caches cannot retain the
previous light-mode button colors.

The application HTML and JavaScript live in
[`include/network/ui_desktop.h`](../../include/network/ui_desktop.h).
The portal frontend lives in
[`src/veld-miner-portal.py`](../../src/veld-miner-portal.py).

The public wallet's existing backend also uses a narrow nginx compatibility
overlay. Its current source is
[`veld-wallet-ui-current.conf`](../reverse-proxy/veld-wallet-ui-current.conf). It removes the
old Auto-compound implementation and the old balance-unit override from that
backend's HTML response. The source header already contains these changes;
the overlay preserves the running backend while the web UI is updated.
Use it only in the wallet HTML location with `sub_filter_once off`, upstream
compression disabled, and the existing authentication and security headers
preserved. Validate against the complete expected response before applying
it; account for the wallet's fresh per-response security nonce without
removing or weakening its Content Security Policy.

These hosted changes were deployed without a client version bump. The
published Windows client remains 3.0.8. The Windows New pair code button
layout in the current source is held for the next signed client release.

The exact source for the existing signed client remains on GitHub's
`release/3.0.8` branch. Current development source and web updates are on
`main`; they do not retroactively change that release identity.
