# Private pool mainnet qualification candidate

This candidate can build unsigned public-profile artifacts. It is not an
approved release, deployment or completed qualification result.

The owner authorized a new mainnet activation on 19 September 2026. The
candidate selects block 12,000, with 3,675 blocks remaining at the observed
height 8,325. This is approximately 7.7 days at the target block interval,
not a wall-clock guarantee. The inherited proposed height 6,200 is superseded.
Public validation retains the aggregate registration prerequisite through
block 11,999 and removes it at inclusion height 12,000. The individual 10,000 VELD bond,
1,000 VELD co-mining eligibility, governance, finality and custody gates remain
unchanged. This is a coordinated consensus upgrade. Production nodes must be
updated before the boundary. Candidate configuration does not prove rollout;
record the deployed versions and exact release identities independently.

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
