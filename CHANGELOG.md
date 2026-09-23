# Changelog

Notable changes to published source. Hosted updates and signed client packages
are tracked separately; publishing source does not release new binaries.

## 3.2.5 - Mining computation efficiency

- Use an eight-block ChaCha20 path when the CPU and operating system support
  AVX2, retaining the existing SSE2 and scalar fallbacks.
- Reduce integer square-root work with exact integer Newton iteration. Results
  remain identical to the previous implementation, including rounding boundaries.
- Use bounded native integer division on supported x86-64 compilers and inline
  the VM instruction dispatch to reduce repeated computation overhead.
- Reuse private scratch allocations in the sequential pool verifier and scan
  helper, preserving full initialization, light verification and request bounds.
- Apply the shared computation improvements to solo and pool mining and native
  verification. No consensus, nonce allocation, reward or fee rules change.

Offline performance results do not promise a particular live hashrate or block
frequency. Release artifacts retain exact source and signed package identities.

## 3.2.4 - Pool controls and interface stability

- Add signed portal controls for pool start and stop using each device's saved settings.
- Reduce Pool-tab hover flicker and align mobile navigation layouts.
- Preserve mining mode, pool accounts and wallet state through signed updates.

No consensus or economic rule changes.

## 3.2.3 - Pool performance and recovery

- Reuse each pool mining thread's VeldHash scratch allocation, preserving exact
  consensus hash results and per-nonce initialization.
- Use larger work batches and bounded concurrent requests, leaving capacity for
  submitting proofs while new work is requested.
- Reduce gateway connection and authenticated journal replay overhead without
  weakening authorization, durable writes or integrity checks.
- Retain pool accounts, endpoint, payout address, CPU settings and explicit
  mining resume preference through signed updates.

No consensus, supply, reward allocation, fee or activation-height changes.
Custody migration qualification remains a separate development effort and is
not cleared or activated by this maintenance release.

- Keep pool workers waiting through temporary backend peer-readiness changes;
  require fresh native admission before delivering new work.
- Retry authenticated temporary pool proxy failures without accepting their
  response as work or relaxing certificate and successful-response validation.
- Recover pool state from its authenticated journal rather than trusting the
  rebuildable database cache.
- Package only checksummed Python source, refusing unmanifested bytecode.
- Exclude outdated or unconfirmed peer tips from the public active-node graph
  without blocking their P2P connections or ability to catch up.
- Use the shared charcoal style for the homepage download button.
- Organize pool, btcVELD, operator, and activation documentation with module guides.
- Separate quick-start instructions from release qualification and source identity.

## 3.2.2 - Pool client and portal maintenance

- Buffered Pool-page scrolling, charcoal scrollbar and controls, green Paid accent.
- Clear distinction between configured CPU workers and workers currently hashing.
- Bounded 256-nonce work batches and retry of transient template-publication races.
- Current pool worker telemetry, stable Pool page rendering, restored Pool icon,
  and removal of How To from the portal only.
- Preserve deployed remote-update controls and ownership/capability checks.
- Correct native CI dependencies and mandatory-settlement test assumptions.

No consensus, supply, reward, custody, fee or activation-height change from 3.2.1.
The scheduled block 9,500 upgrade remains in place. Signed package identity and
executed checks are recorded in [source identity](docs/source-identity.md) and
[qualification scope](docs/release-3.2.2-qualification.md).

## Hosted/source follow-up to 3.2.1

- Give Pool a distinct icon, place it after How To, and use neutral status styling.
- Separate validator registration availability from existing validator operations.
- Clarify the 1,000 VELD lottery requirement, carryover, and bond waiting period.
- Correct public release documentation and preserve exact binary-source attribution.

## 3.2.1 - 2026-09-21

- Keep minimized Node windows on the taskbar and bring the running instance forward when reopened.
- Rebuild the public pool website with responsive pool statistics, recent block confirmations, distinct reward categories, setup help and private payment history. Add bounded read-only hashrate and journal-derived income/payment summaries without changing accounting or mining policy.
- Add configurable Windows pool mining, persistent work accounting, shared mining, lottery and ordinary staking rewards, restricted payout signing, and an authenticated operator panel.
- Combine a wallet's balances across its worker accounts when checking the payout minimum; preserve each account's exact entitlement and payment recovery records.
- Bind pool workers to the Windows app's lifetime so closing or losing the app cannot leave hidden miners running.
- Preserve verified block-download progress across late duplicates and read the stop hash after the complete block locator, avoiding truncated recovery batches.
- Use charcoal action buttons and stable pool status fields across the client and pool interfaces.
- Activate SHA-384 destinations and removal of the aggregate validator staking floor at block 9,500; retain individual bonds and historical rules.
- Include the 3.2.1 mainnet candidate's flat 0.30% AMM fee in both swap directions from block 9,500. Preserve earlier fee rules for historical validation.
- Remove opening-price deviation penalties after activation; fees remain in the output asset for liquidity providers. Bitcoin backing and custody requirements remain unchanged.
- Match wallet previews and transaction preparation to the inclusion-height fee policy, and refresh quotes when the policy changes.
- Prevent competing validator processes and restored chain directories from forgetting signing decisions within one OS profile.
- Stop validator signing on damaged or changed safety journals; retain exact finality votes for safe restart and retry.
- Save browser-wallet input reservations before signing and exact signed transactions before broadcasting.
- Recover uncertain sends across browser restarts and resume interrupted signing of the original transaction.
- Keep spendable balances consistent with saved input reservations across wallet tabs and reversible confirmations.

## 3.2.0 - 2026-09-12

- Classify staking and co-mining payouts from their funding pools and restore them to the Rewards tab, including existing history.
- Stop near-miss submissions after a confirmed entry, retain eligibility across restarts, and retry claims that expire without confirming.
- Refresh mining candidates for newly received near-miss claims and select at most one entry per wallet in a window.
- Restore co-mining credits when rolling back a block and report the correct lottery window boundaries.
- Re-evaluate the mining clock guard after local time corrections without waiting for peers to reconnect.
- Keep worker status text inside its column.
- Add optional automatic signed updates, configurable in Node Settings or the paired portal.
- Keep mining during download and verification, then resume the previously running node with its saved workers after installation.
- Transfer the session unlock through a one-use Windows-protected handoff bound to the identity and exact packages.
- Delay automatic retries after failures and defer installation while the local wallet is open.
- Reopen the verified node app directly after updates and rollbacks, preserving custom data directories and avoiding another launcher prompt.
- Allow the old node and app to complete their bounded shutdown before committing an update.

## 3.1.10 - 2026-09-11

- Completing portal pairing enables remote start, stop, encrypted sign-in, and signed updates without another PC prompt.
- Preserve existing pairing keys and replay state when enabling remote control after an update.
- Reject changed pairing keys, corrupt saved trust, replayed commands, and revoked remote access.
- Explain when an older installed client needs an initial update before unattended control is available.

## 3.1.9 - 2026-09-11

- Start and stop a paired Windows node and run signed updates from the portal
  after one approval on the PC.
- Sign in and start mining remotely with a passphrase encrypted in the browser
  for the paired PC. The portal never receives the plaintext passphrase.
- Preserve the remote control grant, encryption key, settings, and worker count
  across updates. Turning off Remote access blocks commands immediately.
- Keep existing clients and pairings compatible; reject expired, replayed, or
  altered commands and erase completed sign-in ciphertext from the relay queue.
- Repair hosted Explorer block history when a valid block exceeds the bulk
  display budget, including the existing block 4602. Page layout is unchanged.

No consensus rules or mining parameters change.

## 3.1.8 - 2026-09-11

- Refresh mining timestamps by elapsed wall-clock time on every worker.
- Cancel active hash workers when the node stops, avoiding the shutdown timeout.
- Retry failed near-miss submissions without consuming the submission window.
- Exclude expired near-miss claims from new blocks and remove their pending
  descendants; report the reason when a locally mined block is rejected.
- Discard authenticated claims for an expired canonical parent without
  penalizing peers that still relay them.
- Check signed transaction size before staking and explain when wallet cleanup
  is needed; avoid browser failures when validating large transaction hex.
- Correct co-mining pool percentage metadata to the existing 20% allocation.
- Remove the separate Windows update-repair launcher and the wallet login
  dialog's biometric-removal button.
- Include connection self-dial prevention and checkpoint publisher maintenance.

Existing mainnet consensus rules remain unchanged. See the
[release notes](docs/release-notes.md) for behavior and compatibility.

## 3.1.7

Connection-owned background tip announcements, durable updater and settings
storage, bounded RPC shutdown, and exact per-connection diagnostics. See the
[release notes](docs/release-notes.md) for behavior and compatibility details.

## Hosted web and source maintenance - 2026-09-10

- Keep the installed Explorer PWA's navigation controls mounted while opening
  Mempool; preserve fresh responses, history, and native navigation on failure.
- Synchronize the hosted Explorer theme, reward colors, staking wording and
  bounded recent-block loading with the public source.
- Update the operator version and Windows guides to 3.1.6, including the repair
  launcher and preservation of existing chain storage.

These maintenance changes do not replace the signed 3.1.6 packages or tag.

## 3.1.6 - 2026-09-09

- Serialize updater lock handoff and recover interrupted transactions during
  Settings update checks and installation.
- Allow healthy slow downloads, with bounded deadlines and retries for
  transient transfer failures.
- Include a signed repair helper for updating an existing Windows installation.
- Scope GUI node discovery to the selected executable and render connection
  diagnostics as readable messages while retaining raw logs and warnings.
- Include the 3.1.4 static Windows runtime and 3.1.5 preservation of existing
  chain storage during snapshot-enabled startup.

This release retains the consensus rules and activation heights from 3.1.3.
See [release notes](docs/release-notes.md) for update instructions and limits.

## Documentation maintenance - 2026-09-09

- Update the whitepaper, rules, and staking guides for ASERT at block 3,840, the 500 VELD ordinary stake, and the unchanged 1,000 VELD lottery requirement.
- Replace internal review labels with descriptive explanations and test names; preserve regression coverage and release history.

## 3.1.3 - 2026-09-09

- Keep the co-mining lottery minimum at 1,000 VELD across block 3,840.
- Separate wallet co-mining eligibility from the 500 VELD ordinary-staking minimum.
- Reject lottery eligibility for stakes even one atomic unit below 1,000 VELD.
- Preserve the previously scheduled ASERT and migration activation at block 3,840.

This correction supersedes 3.1.2. Miners and node operators must update again
before block 3,840. The initial 3.1.2 implementation incorrectly lowered the
co-mining requirement with ordinary staking.

## 3.1.2 - 2026-09-09

### Consensus activation at block 3,840

- Introduce per-block ASERT difficulty adjustment with a 180-second target and
  a 2,700-second half-life.
- Coordinate the ordinary/co-mining minimum stake reduction to 500 VELD with
  validator, governance, and retained-state migration on a 480-block boundary.
- Unify state-aware coinbase validation after activation and preserve historical
  validation before it, including exact authenticated fee conservation.
- Resolve fee-only coinbase precedence at periodic vault boundaries without
  changing the existing allocations or supply cap.

### Recovery and monitoring

- Make independent verification progress durable across file contention and
  branch changes, and serialize canonical validation receipts.
- Complete snapshot quarantine and cleanup after interrupted recovery.
- Authenticate finality journal rows before pruning expired entries.
- Correct Windows daemon stop tracking and bound recovery restart loops.
- Distinguish verification-related RPC pauses from port-binding failures.
- Separate GUI/daemon identities and unavailable status from zero-valued
  telemetry; retain diagnostic transitions and connection reasons.
- Verify each built role's version against the canonical source declaration.

Production activation is scheduled at block 3,840. Update before that height.
See [release notes](docs/release-notes.md) for compatibility and update guidance.

## Hosted and source documentation - 2026-09-08

- Record the published 3.1.1 source, binary identities, and accepted checkpoint
  feed. Refresh the homepage download metadata and hosted checkpoint rules.
- Update the embedded rules wording in source for the next signed client
  package. The existing 3.1.1 tag and signed binaries remain unchanged.

## 3.1.1 - 2026-09-08

### Checkpoints

- Pin the independently verified public-mainnet block at height 2,800 in
  block admission, replay, synchronization, and reorganization anchoring.
- Replace the public-mainnet ML-DSA-65 checkpoint verification key after the
  original signing credential could not be recovered. Other network profiles
  retain their existing key and checkpoint history.
- Verify signed checkpoint field binding, invalid-signature rejection,
  compiled-pin boundaries, and network-profile isolation.

Downloaded checkpoints remain advisory. The compiled historical pin is enforced
by 3.1.1; existing 3.1.0 binaries do not gain the pin or replacement public key.
This update retains the existing chain, proof of work, rewards, staking rules,
protocol version, and block-2,880 activation. No new activation height is set.

## 3.1.0 - 2026-09-08

Published after the block-2,880 consensus upgrade and sustained fleet chain
agreement were verified. Existing addresses, chain data, and reward allocation
remain compatible.

### Mining

- Detect Windows physical cores within process affinity for worker defaults and
  presets, with a conservative fallback when topology is unavailable.
- Apply the miner's 1â€“64 worker limit consistently in the CLI, Windows settings
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
