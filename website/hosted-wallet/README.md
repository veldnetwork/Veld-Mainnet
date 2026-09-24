# Hosted wallet presentation

`presentation.conf`
replaces the retired 219 KB nginx function-rewriting overlay. It inserts static
assets and renames a navigation label; it does not replace wallet authorization,
transaction serialization, signature checks, pending-spend logic or fee policy.

Serve these assets under `/assets/`, along with `../wallet-hosted-3.2.2.js`.
Keep the existing HTTPS origin, CSP, RPC method restrictions, host checks,
request limits and proxy metadata controls. The new navigation bootstrap calls
the native external-value-aware landing-page function; all operation-specific
activation gates stay in the native page and node.
