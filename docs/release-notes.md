## 3.1.8 - Mining and wallet reliability

Mining workers refresh their block timestamp as the clock advances, including
on slow CPUs and after a paused search. This prevents a long hash search from
submitting a stale timestamp that distorts the following difficulty adjustment.
The 180-second target remains an average; individual block times still vary.

Failed near-miss submissions can be retried within the same co-mining window.
The local submission allowance is consumed only when the transaction enters
the mempool. Pool metadata reports the existing 20% reward allocation.

Expired near-miss claims are removed from the mempool and excluded from new
mining candidates. Previously, a claim left pending after its target block
passed could invalidate repeated block attempts. Valid claims and ordinary
transactions remain eligible, and local rejection logs include the reason.

The Windows package removes the separate update-repair launcher. Updates and
interrupted-update recovery remain available through Settings and the normal
launcher. Existing chain data, identity, worker count, and pairing are retained.
The wallet login dialog no longer offers biometric removal while locked.

Staking checks the final signed transaction size before requesting signatures.
Wallets with too many small outputs receive a short cleanup instruction instead
of failing after signing. Transaction hex validation handles large valid inputs
consistently in mobile browsers. Automatic cleanup remains opt-in.

Includes the intervening connection, checkpoint publisher, and wallet display
maintenance in published source. No consensus rules, stake requirements,
reward allocations, or activation heights change. No hard fork is required.

## 3.1.7 - Connection and update reliability

Independent background validation now sends tip announcements from each
connection's own timer. Valid background peers remain connected through the
normal handshake deadline, including after reconnects and while the foreground
supervisor is busy. Network identity checks and IP-distinct admission remain
unchanged.

Windows updates retry temporary file locks, verify installed payloads, and
retain actionable transaction results. Settings, worker count, sync preference,
remote monitoring, and protected pairing state survive saves and replacement.
Unreadable persistent identity is reported rather than silently replaced.
Repair uses the verifier from the fresh complete package, so an older node's
missing runtime DLL cannot prevent signed verification of its replacement.

Shutdown closes queued validation before waiting for the active chain commit,
also cancels direct peer validation that has not started its commit,
interrupts outstanding RPC work, and uses a cancellable watchdog. The validation
worker retains normal Windows scheduling and I/O priority instead of making
networking and shutdown wait for a background-priority lock owner.
Prewarm and reorganization notifications share their respective wait mutexes,
preventing missed shutdown wakes.
Logs distinguish current-chain catch-up from independent historical validation.
Peer diagnostics describe the exact connection. The wallet's lockup API reports
the effective ordinary staking minimum consistently.

This release retains static Windows runtime dependencies and local-chain
preservation. Snapshot receipt validation and mining admission remain enforced.
No consensus rules, validator bond amounts, or activation heights change.

# Release notes

## 3.1.6 - Consolidated Windows updater repair

Fixes a race between update handoff and the transaction lock. Commit now
waits for the installing process to finish preparing the transaction.
Healthy slow archive downloads can continue beyond 30 seconds, with bounded
total and idle deadlines and retries for transient failures. Signature,
checksum, path, archive-size and downgrade protections remain enforced.

Settings update checks and installs recover interrupted transactions under
the existing exclusive lock. Failed installs display the helper's actual
reason. A signed Repair Veld Update helper lets a fresh complete package
update an existing installation while preserving its data directory.

The GUI identifies the node from its selected installation, and the Logs
view renders connection diagnostics in plain language. Warnings, unknown
events, and the complete raw log remain available.

Includes the 3.1.4 static Windows runtime and 3.1.5 local-chain preservation
fixes. There are no changes to network consensus or activation heights.

To update, open **Settings**, check for updates, and choose **Install** when
the signed update is offered. If an older updater cannot complete the update,
extract the complete 3.1.6 Windows package and run **Repair Veld Update.bat**
against the existing installation. Keep the existing data directory and
identity backup.

Snapshot bootstrap still requires independent background verification before
mining. Version 3.1.6 does not bypass that requirement. A node shutdown can
still reach its twenty-second fallback timeout; a follow-up repair is under
investigation. These notes describe the released fixes, not every possible
failure on an uninspected installation.

## 3.1.5 - Preserve local synchronization progress

Windows startup now limits automatic signed snapshot import to a fresh
datadir. Existing chain storage and pending verification are retained even
when a newer official snapshot exists. This prevents an ordinary restart or
update from replacing previously verified history and starting another
independent genesis verification. Partial local databases remain available
for normal recovery or inspection instead of being overwritten.

Existing snapshot validation obligations remain enforced. This update does
not automatically restore a previously replaced database or bypass proof
verification. The DLL and signed updater repairs from 3.1.4 are included.
There are no changes to consensus rules or activation heights.

## 3.1.4 - Windows runtime packaging

Windows packaging correction: OpenSSL is now linked into each executable, so
the node and wallet do not require `libcrypto-3-x64.dll` or a developer PATH.
The build rejects non-system DLL imports and runs command-line startup checks
with only Windows system directories on PATH. This fixes the missing-DLL
startup failure and the resulting signed-updater rollback to the older client.
Terminal launcher version declarations are also synchronized with the signed
package. Keep existing wallet and chain data when updating.

The 3.1.3 network rules and block-3,840 activation schedule are unchanged.

## Retained 3.1.3 network correction

Update before **block 3,840**. This correction supersedes 3.1.2 and preserves
the intended distinction between ordinary staking and the co-mining lottery.

## Stake requirements

| Requirement | Before block 3,840 | From block 3,840 |
| --- | --- | --- |
| Ordinary staking | 1,000 VELD | 500 VELD |
| Co-mining lottery | 1,000 VELD | 1,000 VELD |
| Validator bond | 10,000 VELD | 10,000 VELD |

The initial 3.1.2 binary incorrectly applied the ordinary-staking reduction to
co-mining eligibility. Version 3.1.3 uses the independent co-mining threshold
for near-miss admission, alternate-branch validation, local share submission,
and payout selection. The wallet reads a separate co-mining requirement and
reports unavailable policy explicitly. A stake below 1,000 VELD does not meet
the lottery requirement, including a shortfall of one atomic unit.

## Network upgrade

The previously scheduled **3,840** activation remains unchanged. ASERT adjusts
difficulty after each block toward the **180-second** target with a
**2,700-second** half-life. Ordinary staking drops to 500 VELD at that height;
the coordinated coinbase and validator/governance state migrations remain on
the same settlement boundary. Reward allocations, maximum stake, maturity,
lockups, and the historical block-2,880 rules are unchanged.

The correction restores the existing pre-activation lottery rule and prevents
3.1.2 from introducing the unintended lower threshold. All miners and node
operators, including those who already installed 3.1.2, must update before
block 3,840. Mixed 3.1.2/3.1.3 validation after activation can disagree on
near-miss submissions or payouts involving stakes below 1,000 VELD.

## Updating

Use the signed updater or the [official download](https://veld.network/#download).
Close the existing client before replacing it. Keep your chain data and wallet
backups; a routine update does not require a full resynchronization.

The client recovery, checkpoint, GUI/daemon diagnostics, and mining improvements
from 3.1.2 are retained. See the [3.1.2 notes](releases/3.1.2.md) for that history.
