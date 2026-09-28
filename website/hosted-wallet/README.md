# Hosted wallet presentation

`presentation.conf` inserts the hosted styles and scripts and renames the Rewards
navigation label. The wallet implementation is `include/network/ui_desktop.h`.

Serve these assets under `/assets/`, along with `../wallet-hosted-3.2.2.js` and
`../content-help-v1.css`. The HTML-only substitutions in
`../../pkg/reverse-proxy/veld-content-help-wallet.conf` provide the same optional
help controls on installed clients. Include them once with `sub_filter_once off`.
Keep the existing HTTPS origin, CSP, RPC method restrictions, host checks,
request limits and proxy metadata controls. The new navigation bootstrap calls
the native external-value-aware landing-page function; all operation-specific
activation gates stay in the native page and node.
