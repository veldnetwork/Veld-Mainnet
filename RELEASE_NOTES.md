# Veld 3.0.0 release notes

Release date: 2026-09-02
Status: released; public-mainnet-v2 initial stabilization

## Release identity

- Version: `3.0.0`
- Release ID: `VELD-3.0.0-BUILD-02-03388b12-c540616f`
- Launch source commit: `03388b12f8125ac0f321984730a9906064f48f62`
- Launch source tree: `c540616f288fe38fffa1ce061598425b6e53fcbc`
- Deployment identity: `veld-public-mainnet-v2`
- State digest: `VELD_STATE_DIGEST_v8`
- Protocol version: `2`
- Genesis fingerprint:
  `880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b`

The public source repository is a clean publication commit. Compiled program
sources, build controllers, launchers, vendored code, resources, and package
scripts match the launch source exactly. Release-facing documentation was
updated after launch without changing BUILD-02. See `SOURCE_IDENTITY.md`.

## Mainnet status

Veld 3.0.0 public mainnet launched from the compiled production genesis on
2 September 2026. Initial stabilization is active. The final ordinary-wallet
transaction, carrying-block, and one-at-a-time persisted restart checks remain
live operational gates and must not be reported as complete before execution.

## Consensus and activation rules

- Maximum supply: 21,000,000 VELD.
- No premine or treasury allocation.
- CPU-oriented VeldHash proof of work.
- Staking activates at 10,000 VELD of canonical issued supply.
- Ordinary stake range: 1,000 to 10,000 VELD per address.
- A finality validator requires a 10,000 VELD qualifying bond.
- Governance activates at 50,000 VELD of canonical issued supply.
- btcVELD minting and redemption remain inactive until genuine
  seven-qualified-validator finality and its required warm-up are satisfied.

## Security and release boundary

BUILD-02 contains the resolved local-work admission deadlock fix and binds
external block-template submission to exact, short-lived, one-use authority.
Public-mainnet binaries also refuse snapshot bootstrap, UPnP, test profiles,
and public whole-chain transaction-history scans.

Only packages whose signed manifest and file hashes validate as BUILD-02 are
official binaries. Source publication does not alter or re-sign those packages.
