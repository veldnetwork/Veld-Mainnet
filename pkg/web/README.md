# Hosted wallet UI source

`obsidian-moss-v1.css` is the current stylesheet served by the public wallet.
Its SHA-256 is
`4da187f9345a658c0999e6a644bfe4cf9edfacb7e8fbc1664a15eb5e3b49604c`.
The live asset uses the content-addressed name
`obsidian-moss-4da187f9345a.css` so existing browser caches cannot retain the
previous dark-theme balance-unit override.

The application HTML and JavaScript live in
[`include/network/ui_desktop.h`](../../include/network/ui_desktop.h).
The portal frontend lives in
[`src/veld-miner-portal.py`](../../src/veld-miner-portal.py).

The public wallet's existing backend also uses a narrow nginx compatibility
overlay. Its current source is
[`veld-wallet-ui.conf`](../reverse-proxy/veld-wallet-ui.conf). It removes the
old Auto-compound implementation and the old balance-unit override from that
backend's HTML response. The source header already contains these changes;
the overlay preserves the running backend while the web UI is updated.
Use it only in the wallet HTML location with `sub_filter_once off`, upstream
compression disabled, and the existing authentication and security headers
preserved. Validate against the complete expected response before applying
it; account for the wallet's fresh per-response security nonce without
removing or weakening its Content Security Policy.

These hosted changes were initially deployed without a client version bump.
The 3.0.9 client package incorporates them and the Windows New pair code button
layout correction alongside the mining update.

The exact source for each signed client is retained on its release branch.
Current development source and web updates are on `main`; they do not
retroactively change an earlier release identity.
