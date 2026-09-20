# Private pool mainnet qualification candidate

This candidate can build unsigned public-profile artifacts. It is not an
approved release, deployment or completed qualification result.

The owner postponed the unpublished candidate activation to block **9,500**
on 20 September 2026. This supersedes the 9,000 candidate. Validator registration,
SHA-384 destinations and the 0.30% flat AMM fee use the same inclusion boundary.
At the observed height 8,807, 693 blocks remained (about 34.7 hours at the
180-second target, not a wall-clock guarantee). Recheck the tip and rollout
coverage before releasing or activating; no production rollout is established
by this document.

Public validation retains the aggregate registration prerequisite through
block 9,499 and removes it at inclusion height 9,500. The individual 10,000 VELD
bond, 1,000 VELD co-mining eligibility, governance, finality and custody gates
remain unchanged. Previously distributed binaries carrying the 9,000 rules
must be replaced or stopped before their old boundary. Changing this source
does not change binaries already installed. Selected-miner package signing is
authorized; public release, deployment and publication remain on hold.

Build the dedicated Linux backend and pool with `build/mainnet-v2-pool.sh`
from this clean candidate checkout. Build Windows node, desktop and GUI roles
with `build/mainnet-v2-windows.sh`; supply the attested node and desktop output
directories when building the GUI. The GUI includes the matching native pool
worker. Keep all output directories outside the source checkout.

Mainnet qualification uses a new private backend datadir and newly generated
test identities. Existing wallets, custody keys and installed mining processes
are not test fixtures. Independently validate from genesis before permitting
mining. Pin explicit backend peers, worker endpoint, TLS trust and payout
addresses. Keep RPC and signing capabilities inaccessible to the gateway.

Record canonical income and at least 120 confirmations plus actual native
spendability before testing payouts. Mainnet maturity cannot be accelerated.
Operator fee funds and pool-member liabilities must remain separate. A pool
test does not authorize buying stake, custody funding, validator enrollment,
btcVELD activation, a public pool endpoint or publication of these artifacts.

The disposable co-mining and validator fixtures remain mandatory evidence,
but they do not establish funded mainnet co-mining or mainnet custody readiness.
Record missing prerequisites and unexecuted cases as incomplete.
