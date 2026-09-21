# Hosted wallet presentation

These assets were captured from the existing owned wallet deployment on
21 September 2026 and are now recorded with exact hashes. They are additional
hosted source, not part of the frozen 3.2.2 binary-build tree. `presentation.conf`
replaces the retired 219 KB nginx function-rewriting overlay. It inserts static
assets and renames a navigation label; it does not replace wallet authorization,
transaction serialization, signature checks, pending-spend logic or fee policy.

Serve these assets under `/assets/`, along with `../wallet-hosted-3.2.2.js`.
Keep the existing HTTPS origin, CSP, RPC method restrictions, host checks,
request limits and proxy metadata controls. The new navigation bootstrap calls
the native external-value-aware landing-page function; all operation-specific
activation gates stay in the native page and node. Never use the old
`veld-wallet-ui-current.conf` JavaScript substitutions with the 3.2.2 binary.

The hosted service uses the exact production Linux desktop binary from commit
`1f77a67365ff9c3c36dae2a624feb35615446202`. Migration preserves the systemd unit,
service UID, protected data directory, browser-local wallet state and node PID.
The private canary and actual HTTPS page passed all eleven tabs at mobile and
desktop widths, current browser signer initialization and the 9,499/9,500 fee
policy boundary. No mainnet transaction was signed or broadcast by these UI
checks. Rollback restores both the old binary and its matching nginx config.
