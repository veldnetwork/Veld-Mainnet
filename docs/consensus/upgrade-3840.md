# Network upgrade at block 3,840

Veld 3.1.3 activates the coordinated public-mainnet-v2 upgrade at block 3,840.
The initial 3.1.2 artifacts incorrectly apply the ordinary minimum to the
lottery after activation. The correction keeps the separate lottery floor;
a 3.1.3 client is required before that height. Installing the client
does not activate the new consensus rules ahead of schedule.

| Parameter | Before activation | From block 3,840 |
| --- | --- | --- |
| Difficulty | Historical LWMA | Per-block ASERT |
| Block-time target | 180 seconds | 180 seconds |
| ASERT half-life | Not applicable | 2,700 seconds |
| Minimum ordinary stake | 1,000 VELD | 500 VELD |
| Co-mining stake threshold | 1,000 VELD | 1,000 VELD (unchanged) |
| Maximum ordinary stake per address | 10,000 VELD | Unchanged |
| Validator bond | 10,000 VELD | Unchanged |

The lottery stake floor remains 1,000 VELD. A 500 VELD ordinary stake can
participate in vault distributions but does not qualify for co-mining.
Lockups, coinbase maturity, supply cap, and reward allocations are unchanged.
The candidate block's inclusion height selects the applicable minimum. Wallet
preparation and mempool admission must use the next inclusion height, and the
confirmed transaction must satisfy its actual inclusion context.

ASERT uses accepted branch history and deterministic integer arithmetic to
adjust the target after each block. Its 45-minute half-life controls the
response to accumulated schedule error. It does not promise exactly three
minutes between blocks or lower the next target solely because wall-clock time
passes without an accepted block. Historical LWMA remains necessary for replay.

At the same 480-block settlement boundary, validator attribution, governance
operation formats, and retained state migrate under the upgraded rules.
Separate participation thresholds still govern validator services, finality,
governance, and btcVELD. The block-2,880 rules remain intact.

The upgrade also establishes one state-aware coinbase policy for direct
admission, alternate branches, independent replay, and mining preflight. Exact
effective subsidy plus authenticated fees, required categories, and supply
conservation remain mandatory. The existing fee-only allocation takes
precedence on periodic vault boundaries once effective subsidy is zero.
See [coinbase accounting](coinbase-policy.md) for historical compatibility and
regression coverage.

The release also improves snapshot progress persistence, interrupted recovery,
Windows process handling, and status diagnostics. These client changes do not
replace independent verification or reset existing chain data. See the
[release notes](../release-notes.md), [whitepaper](../WHITEPAPER.md), and
[staking guide](https://veld.network/how-to/stake-veld/).

The schedule is compiled in `include/core/constants.h`; ASERT is implemented in
`include/core/asert.h`. Production profiles cannot use fixture height overrides.
