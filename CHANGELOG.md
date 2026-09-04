# Changelog

All notable public-source changes are recorded here. Signed binary identity is
recorded separately from source-publication commits.

## 3.0.4 - 2026-09-03

### Fixed

- Restored public address transaction history through a bounded persistent
  index rather than request-time whole-chain scanning.
- Made explorer document navigation retain the last successful shell during
  transient upstream failures instead of displaying a white refresh page.
- Preserved signed-snapshot eligibility across maintenance updates and exposed
  the actual selected, eligible, validating, or unavailable state in the GUI.
- Exported one portable encrypted `.veld-keys` copy of the mining identity
  after successful sign-in without generating a second wallet.
- Added a locally confirmed portal re-pair action that revokes prior portal
  command trust and issues a new one-time pairing code.
- Restored the signed `Start Veld Node.bat` launcher in the minimal Windows
  package and made that launcher explicitly select clearnet.
- Reworded the initial peer-discovery status so a normal connection delay is
  not reported as a persistent no-peer warning.

### Compatibility

- Consensus rules, protocol version, deployment identity, genesis, state
  digest v8, existing blocks, wallets, addresses, and datadirs are unchanged.

## 3.0.3 - 2026-09-03

### Fixed

- Persisted every fully validated winning side-branch block body before the
  canonical reorganization publication callback, preventing a valid fork from
  repeatedly rolling back when its final candidate body had remained volatile.

### Compatibility

- Consensus rules, protocol version, deployment identity, genesis, state
  digest v8, existing blocks, wallets, addresses, and datadirs are unchanged.

## 3.0.2 - 2026-09-03

### Fixed

- Prevented repeated IBD block-request streams from exhausting peer
  response-work budgets while consensus validation is still advancing.

### Added

- Added signed public-mainnet snapshot bootstrap with launch-chain anchoring,
  strict archive extraction, and service quarantine until an independent full
  genesis IBD reaches the exact same tip and consensus-state digest.

## 3.0.1 - 2026-09-02

### Changed

- Linked the Windows C++ runtime, unwind runtime, and LevelDB into the official
  node, wallet, and GUI executables.
- Reduced the graphical Windows client package to its required runtime files
  and consolidated license notices.
- Added a fail-closed PE import gate and regression coverage that prohibit
  loose libc++, libc++abi, libunwind, LevelDB, and winpthread DLL dependencies.

### Compatibility

- Protocol version 2, `veld-public-mainnet-v2`, the production genesis,
  consensus rules, state digest v8, addresses, wallets, and datadirs are
  unchanged.

## 3.0.0 - 2026-09-02

### Changed

- Coordinated the public client and launcher identity at 3.0.0 while retaining
  protocol version 2, the `veld-public-mainnet-v2` deployment identity, the
  existing genesis fingerprint, state digest v8, and `RTP1`/`RVS1` reserve
  wire formats.
- Changed the owner-authorized public-mainnet staking activation threshold from
  100,000 VELD to 10,000 VELD of canonical issued supply. The finality-validator
  bond remains exactly 10,000 VELD per validator and the seven-validator
  finality requirement is unchanged.
- Aligned explorer and desktop-wallet activation text and fallback displays
  with the 10,000 VELD threshold.
- Aligned the desktop first-liquidity flow with the public market-seed policy:
  the first authorized valid seed can establish the immutable opening anchor,
  while legacy profiles retain the fixed-ratio rule.

### Added

- Deterministic staking-boundary and version/network-identity tests.
- Public build, contribution, security, threat-model, release, licensing,
  dependency-notice, and trademark documentation.
- Exact BUILD-02 source identity and live-mainnet operator checks.

### Unchanged security boundaries

- 21,000,000 VELD hard cap with no premine or treasury allocation.
- CPU mining and fleet no-mine role separation.
- btcVELD finality gate and rolling canonical Bitcoin reserve.
- Production/test profile interlocks and updater signature refusal.

Veld 3.0.0 BUILD-02 launched on `veld-public-mainnet-v2` from fresh compiled
genesis. btcVELD minting and redemption remain inactive until the genuine
seven-qualified-validator finality requirement is satisfied.
