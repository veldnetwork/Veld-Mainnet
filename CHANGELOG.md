# Changelog

Notable changes to published source. Hosted updates and signed client packages
are tracked separately; publishing source does not release new binaries.

## 3.1.0 - 2026-09-08

Published after the block-2,880 consensus upgrade and sustained fleet chain
agreement were verified. Existing addresses, chain data, and reward allocation
remain compatible.

### Mining

- Detect Windows physical cores within process affinity for worker defaults and
  presets, with a conservative fallback when topology is unavailable.
- Apply the miner's 1–64 worker limit consistently in the CLI, Windows settings
  and portal. Show and adjust the saved next-start count separately from live
  worker telemetry.
- Test separate-process nonce searches and worker policies for SMT, non-SMT,
  mixed-core and restricted-affinity configurations.
- Fill mining scratch memory and datasets in complete stream blocks, preserving
  the existing byte stream and cryptographic implementation.
- Start the integer square-root calculation at its first relevant bit while
  preserving exact integer results.
- Keep each worker's hashed header stable across timestamp refreshes, including
  the header attached to a near-miss report.
- Retain completed hash counts when a search is canceled, count only actual work,
  and finish the progress sampler before publishing the exact final total.
- Add production-size hash vectors, concurrent search tests, and an offline
  benchmark. Coinbase allocation, staking eligibility, difficulty rules, and
  the existing independent search origins are unchanged.

## 3.0.9 - 2026-09-07

### Mining

- Randomize each mining search's initial nonce so machines using the same
  payout address can contribute independent work when their templates match.
- Preserve all 64 nonce bits in mining results and progress reports.
- Add regression coverage for worker allocation, wraparound, and random-source
  failure. Consensus rules, rewards, and the block-2,880 activation are unchanged.

### Wallet

- Include the current light-mode action-button palette in the desktop wallet
  and retain the corresponding hosted stylesheet and proxy overlay.

### Repository maintenance

- Organize developer, operator, release, and security documentation.
- Use descriptive regression-test names and source comments.
- Add contribution templates and shared formatting conventions.
- Refresh the source-input manifest while retaining dependency bytes and pins.

## Source maintenance - 2026-09-07

### Deployed portal and hosted wallet updates

- Match light-mode action buttons throughout the wallet to the light-grey My
  Wallet palette, including login, forms, governance, and installation controls.

- Remove the oversized blank strip below the portal's mobile tabs. Keep the
  navbar anchored to the bottom, with compact clearance and matching page/menu spacing.

- Report advertised peer roles through authenticated getpeerinfo and merge
  current role reports in the topology collector. New miners no longer depend
  on a saved address label; older exporters cannot overwrite a current role.
  Preserve network identities, connections, consecutive labels and address privacy.

- Match Consolidate now to the light-grey wallet actions in light mode. Replace
  the bare automatic-cleanup checkbox with a labelled switch, a separated settings
  row, and keyboard focus feedback. Preserve the default-off preference and consent.

- Fit the portal's compact bottom navigation within the phone's safe area and
  keep page content and the More menu above it. Move Log out from the header
  into More, with access on mobile, desktop, and before the first machine is paired.

- Number topology labels consecutively within each currently displayed role.
  Close numbering gaps as peers leave, and keep graph order consistent when
  switching paired machines. Saved registry indices no longer determine the
  chart labels; identity matching and connection data are preserved.

- Follow address-history cursors in Activity so older sends remain visible in
  Sent/Fees after newer mining rewards. Retain small fees, show incomplete reads
  explicitly, and provide bounded batches with a Load older activity action.
  Prevent overlapping refreshes and responses for a previously selected address
  from replacing the current view.
- Embed the supplied btcVELD artwork in the Liquidity page, preserving its detail
  without a separate image download. Publish the current hosted wallet overlay
  and Liquidity page source; these web changes do not require a client release.

- Render temporary Explorer page errors as an HTML retry page so mobile browsers
  do not download a small untyped response. Retain rate limits, retry status,
  security headers and existing API handling.
- Load a complete current document when navigating to Mempool or transaction
  details, so formatting and page scripts initialize on the first click.
  Fetch Explorer and wallet documents and assets without browser caching,
  remove legacy service-worker page caches, and stop serving expired API
  responses after upstream errors. Keep the bounded five-second public API cache.

- Shorten the homepage download instructions and update the Rules page's sync
  explanation. Document independent snapshot verification, restart behavior,
  and compiled chain identifiers with their matching RPC representations.

- Simplify wallet cleanup with optional help, a charcoal action button, and concise
  output guidance. Include consolidation and other fee-bearing activity in Sent/Fees
  and retain small fees in row and summary displays.
- Use the same target-implied network hashrate estimate and precision in the wallet
  and Explorer. Refresh the Explorer node count every five seconds independently
  of block height, with bounded reads and explicit unavailable/stale handling.
- Trim trailing zeros from Explorer fee totals. Display the mining card reward
  as 3.13 VELD with its exact value in help, and distinguish Miner in green
  and Vault in gold. Reward issuance and distribution amounts are unchanged.

- Format wallet governance rules as wrapping cards on phones and a two-column
  layout on larger screens, preserving the existing rule text.
- Label verified many-input, single-output self transfers as Consolidation in
  wallet Activity and recent transactions. Preserve transfer amounts and fees;
  ordinary self transfers remain distinct. Validator exit rules are unchanged.

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

- Make wallet cleanup manual by default, with a visible automatic-cleanup opt-in
  for this browser. Restore the fragmentation warning and Consolidate now action,
  explain transaction fees and confirmation waits, and stop new automatic batches
  after opt-out, wallet locking or switching, or another operation starting.
  Existing implicit automatic-cleanup settings do not enable the new option.

### Awaiting the next Windows client release

- Add explicit text content types and no-store headers to the node Explorer's
  rate-limit and busy responses. The hosted fix is deployed independently.

- Place New pair code immediately beside Open portal in Windows Settings,
  with Copy code to their left when a code is available. This native layout
  change is in source only; it is not part of the published 3.0.8 package.

## 3.0.8 - 2026-09-06

- Fix startup after a signed snapshot's foreground chain advances while
  independent background validation is still pending.
- Validate the original snapshot height, hash and state commitment on restart;
  retain its original independent validation target and saved progress.
- Fully verify the post-snapshot blocks during startup replay. Mining and
  endorsing remain paused until independent validation completes.
- Retain the 3.0.7 Windows updater launcher correction and block 2,880 activation.

## 3.0.7 - 2026-09-06

- Restart Windows signed updates through Start Veld Node.bat with installed
  package verification, the installation working directory and literal paths.
- Keep the terminal restart launcher and signed update version protections.
- Retain consensus security activation at block 2,880 from 3.0.6.

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
