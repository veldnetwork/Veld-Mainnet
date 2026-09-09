# Veld 3.1.4

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
