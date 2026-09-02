# Contributing to Veld

Veld accepts narrowly scoped, reviewable changes that preserve explicit
deployment and consensus boundaries.

## Before proposing a change

- Start from the intended branch and record its commit and tree.
- Keep production, public-testnet, btcVELD-regtest, and developer profiles
  separate.
- Do not include wallets, keys, credentials, runtime datadirs, private evidence,
  generated binaries, or build output.
- Explain any consensus, supply, finality, reserve, state-digest, network
  identity, or updater impact. A display-only version change must not alter a
  consensus version, genesis, network magic, address encoding, or wire format.
- Add deterministic boundary tests for consensus changes and failure-path tests
  for security-sensitive changes.

## Build and test

Use [BUILDING.md](BUILDING.md) for production-role builds. Build into empty
directories outside the source tree and retain the controller's source,
compiler, dependency, definition, deployment, and hash evidence. Validation
profiles and sanitizers are separate gates and are never release artifacts.

Run the tests relevant to the changed surface on every supported platform.
Consensus changes should cover the value immediately below a boundary, the
boundary itself, and the value immediately above it. Security regressions
should demonstrate both the accepted path and fail-closed rejection.

## Change discipline

Keep commits small and describe the user-visible or security-relevant outcome.
Do not weaken compile-time profile interlocks, signature checks, TLS/RPC
authentication, fleet no-mine exclusions, or secret-handling rules to make a
test pass. Do not add production shortcuts or hidden activation switches.

Security reports must follow [SECURITY.md](SECURITY.md). Do not open a public
issue for a suspected vulnerability.

## Licensing

By contributing material you have the right to submit, you agree that it may be
distributed under `AGPL-3.0-only` for Veld-authored source. Preserve all
third-party copyright, attribution, and license notices. Do not contribute
material with incompatible or unknown terms.
