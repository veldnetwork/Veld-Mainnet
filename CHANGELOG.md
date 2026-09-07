# Current source — 2026-09-06

### Deployed portal and hosted wallet updates

- Format wallet governance rules as wrapping cards on phones and a two-column
  layout on larger screens, preserving the existing rule text.
- Label verified many-input, single-output self transfers as Consolidation in
  wallet Activity and recent transactions. Preserve transfer amounts and fees;
  ordinary self transfers remain distinct. No automatic cleanup or validator
  exit policy changes.

- Keep one full network topology chart visible on the portal Network tab.
  Restore the original chart layout and peer-class counts; remove the separate
  selected-machine chart and network-overview toggle.
- Correct the collector registry for the operator-confirmed miners that the
  legacy peer feed labeled as nodes because it omits role information.
- Replace ambiguous inbound mapping Unavailable text with Not mapped,
  Not reported, or Not current as appropriate, and explain when outbound
  connections remain active. No router settings or miner processes change.
- Add an Add machine action beside the portal's machine selector and in
  Settings, including installed PWA mode. Pairing retains existing machines
  and preserves the entered code through background status refreshes.
- Keep the wallet's Stake shortcut available before staking activation;
  transaction submission continues to require activation.
- Remove wallet Auto-compound controls, saved-preference handling, the
  background timer, and automatic staking. Manual staking is unchanged.
- Match the balance's VELD unit typography between light and dark themes.
- Publish the hosted wallet stylesheet and compatibility overlay alongside
  the application source. These web updates do not change the client version.

### Awaiting the next Windows client release

- Place New pair code immediately beside Open portal in Windows Settings,
  with Copy code to their left when a code is available. This native layout
  change is in source only; it is not part of the published 3.0.8 package.

# Veld 3.0.8 — 2026-09-06

- Fix startup after a signed snapshot's foreground chain advances while
  independent background validation is still pending.
- Validate the original snapshot height, hash and state commitment on restart;
  retain its original independent validation target and saved progress.
- Fully verify the post-snapshot blocks during startup replay. Mining and
  endorsing remain paused until independent validation completes.
- Retain the 3.0.7 Windows updater launcher correction and H2,880 activation.

# Veld 3.0.7 — 2026-09-06

- Restart Windows signed updates through Start Veld Node.bat with installed
  package verification, the installation working directory and literal paths.
- Keep the terminal restart launcher and signed update version protections.
- Retain consensus security activation at H2,880 from 3.0.6.

# Changelog

All notable public-source changes are recorded here. Signed binary identity is
recorded separately from source-publication commits.

## 3.0.6 - 2026-09-06

- Schedule the consensus security corrections at block 2,880.
- Preserve finality and validator liability rules, bind governance votes to
  their branch-local round, and retain the corrected staking query callback.
- Retain directional peer sessions used for synchronization evidence.
- Advance the signed update identity so existing 3.0.5 clients can accept
  the new manifest. Publish exact build identities and source with the release.

## 3.0.5 - 2026-09-03

### Fixed

- Locked both wallet staking controls by default and kept them disabled until
  the live mainnet node reports that canonical issued supply has reached the
  10,000 VELD staking-activation threshold.
- Added a fail-closed submission guard so an unavailable or inactive staking
  status cannot reach transaction preparation from the wallet interface.
- Removed alternate-chain terminology from the public wallet, Explorer, and
  portal source surfaces while retaining isolated developer profiles and their
  production-build exclusion gates.

### Compatibility

- Consensus rules, the 10,000 VELD activation threshold, protocol version,
  deployment identity, genesis, state digest v8, existing blocks, wallets,
  addresses, and datadirs are unchanged.

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
