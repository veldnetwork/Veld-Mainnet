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

`wallet-pending-confirmation-v1.js` supplies the native pending-confirmation
lookup fix to hosted clients while released binaries remain unchanged. It uses
the complete bond registry's registration height to locate older registrations, then requires
the exact transaction's canonical confirmation before the existing journal and
pending list reconcile it. The regression suite enforces native/hosted parity.
It does not sign, broadcast, change bond state, or change the page layout.

`wallet-bond-balance-v1.js` likewise carries the native balance-loading function
and its small bond helpers, with source parity enforced by
`wallet_bond_balance_tests.js`. Bonded and total balances use actual held vault
principal, including pending returns, independently of the current registration
minimum or RPC completion order. Remove these compatibility assets once the
hosted native binary includes the same fixes.
