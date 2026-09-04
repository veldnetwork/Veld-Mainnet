# Veld 3.0.4 release notes

Release date: pending
Status: Windows client maintenance candidate

## 3.0.4 maintenance scope

Veld 3.0.4 restores bounded indexed address history, keeps the explorer PWA on
its last successful page during transient web failures, restores the signed
clearnet batch launcher, exports one portable encrypted mining keyfile after
sign-in, reports the real snapshot-bootstrap state, preserves snapshot
eligibility across updates, and lets an operator explicitly request a new
one-time portal pairing code from Settings.

This maintenance release does not change consensus, protocol version,
deployment identity, genesis, state-digest format, or existing chain data.

## Veld 3.0.3 release notes

## 3.0.3 maintenance scope

Veld 3.0.3 fixes canonical publication of a fully validated winning fork. A
candidate block body that remained volatile through replay is now persisted
before the database callback validates and publishes the complete replacement
suffix. A failed body write restores the prior canonical frame and retries
without treating the valid branch as a consensus failure.

This maintenance release does not change consensus, protocol version,
deployment identity, genesis, state-digest format, or existing chain data.

## Veld 3.0.2 release notes

## 3.0.2 maintenance scope

Veld 3.0.2 prevents repeated IBD request streams from exhausting peer response
budgets while block validation is still advancing. It also adds official
signed-snapshot bootstrap. Imported state is replayed locally and remains
quarantined from RPC, inbound P2P, explorer, mining, and validator signing
until an independent genesis IBD reaches the exact same tip and complete state
digest. Full IBD remains available with `--full-ibd` or `--no-snapshot`.

This maintenance release does not change consensus, protocol version,
deployment identity, genesis, state-digest format, or existing chain data.

## Veld 3.0.1 release notes

Release date: 2026-09-02
Status: Windows client maintenance release candidate

## 3.0.1 maintenance scope

Veld 3.0.1 replaces the Windows client package with a genuinely
self-contained build. The C++ runtime, unwind runtime, and LevelDB are linked
into the official executables, so the package contains no DLL files and does
not depend on MSYS2 being installed. The downloadable layout is reduced to the
signed GUI launcher, node, wallet, updater, Tor setup script, change notice,
consolidated license notices, and signed release metadata.

This maintenance release does not change consensus, protocol version,
deployment identity, genesis, state-digest format, or existing chain data.

## Veld 3.0.0 launch identity

## Release identity

- Previous version: `3.0.0`
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
Veld 3.0.1 public-mainnet binaries refuse snapshot bootstrap, UPnP, test
profiles, and public whole-chain transaction-history scans. Veld 3.0.2 replaces
that snapshot refusal with the signed, independently validated quarantine
design described above.

Only packages whose signed manifest and file hashes validate as BUILD-02 are
official binaries. Source publication does not alter or re-sign those packages.
