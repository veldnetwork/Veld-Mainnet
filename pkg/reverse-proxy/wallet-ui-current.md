# Current hosted wallet overlay

`veld-wallet-ui-current.conf` is the qualified frontend overlay for the existing
hosted desktop service. The maintained wallet implementation is
`include/network/ui_desktop.h`; its Activity functions match the served overlay.
The Liquidity document is `website/liquidity/index.html`, including the exact
supplied artwork inside an SVG viewport.

The overlay replaces the previous wallet substitution snippets and inline
`sub_filter` directives in the wallet `location /` block. Include it once with
`sub_filter_once off`. Retain the proxy's security headers and `no-store` policy.
Do not combine it with the prior snippets or the legacy broad
`return Promise.resolve([])` history substitution.

The qualified running desktop executable SHA-256 is
`ef814382c4c2a4f65a47031b9cdf6ed6ccd6498ed84a8f8023f5f8790b030e4e`.
Before replacing that executable, regenerate or remove this compatibility
overlay and compare the complete served document with the intended frontend.
Do not reuse an overlay from another release as an error fallback.

Qualification parses the served scripts, exercises older sends beyond the first
50 rows, bounded batches, cursor failures, duplicate rows and address changes,
and verifies the exact document through an isolated nginx fixture. Browser
checks cover the supplied artwork and a recorded seven-page history. Deployment
uses file-hash guards, backups, `nginx -t`, a graceful reload and public readback.
Node and miner processes are not restarted.
