# Rewards-vault payout candidate

This candidate adds a 20,000 VELD reserve target to rewards-vault distribution.
Its public activation height is **zero (disabled)**. Historical blocks retain
their existing payout rule. Activation requires a separately reviewed protocol
release and a coordinated future height.

## Budget

At each 480-block distribution boundary, let:

- `B` be the rewards-vault funds available in the parent block's state, after
  any fee reserve. Canonical settlements have zero fee reserve.
- `I` be the existing consensus definition of the cycle's coinbase inflow.
- `R` be `20,000 × 100,000,000` base units.

All calculations use integer base units and round down.

```text
backstop = floor(B × 8 / 100)
ordinary = min(backstop, floor(I × 9 / 10))
surplus  = min(backstop, max(0, B - R))
budget   = max(ordinary, surplus)     # only after reserve-policy activation
```

Before activation, the existing ordinary budget is unchanged. Below the target,
ordinary payouts continue. Above it, surplus can increase the budget without
exceeding the existing 8% cycle limit. This is a **reserve target, not locked
principal or an exact maximum balance**. Ordinary payouts can cross the target.
Recipient limits, rounding and the absence of eligible stake can leave more
than the target in the vault.

For example, with 21,000 VELD available and 300 VELD of cycle coinbase inflow,
the ordinary budget is 270 VELD. The activated policy increases that budget to
1,000 VELD. At 22,000 VELD, the 8% limit restricts the budget to 1,760 VELD.
These are budgets before recipient allocation, not guaranteed individual yields.

## Preserved rules

The change does not mint funds, alter issuance or borrow staking principal.
Validator bonds remain in their separate custody vault. Eligible bond yield
continues to share the rewards budget through its escrow. Existing weighted
stake allocation, the 75% limit per recipient, minimum distribution amount and
zero-fee consolidation remain in force. Unused funds return to the rewards vault.

Settlement uses parent state. The boundary block's own subsidy and
endorsement settlement cannot be spent by that block's rewards-vault payout.
Those funds become available to subsequent distributions. Unclaimed endorsement
rewards already received by the vault count toward its balance and surplus;
they are not reclassified as coinbase inflow.

The independent miner-fee policy still sends 100% of native transaction fees to
miners after its activation. The reserve rule neither redirects those fees nor
changes the halving schedule or co-mining retirement allocation.

## Estimates and verification

Block construction and validation call the same integer budget function. RPC
and explorer estimates also use that function. At the parent of a distribution
boundary, the preview uses the exact inflow window for that settlement. Otherwise
it uses the last completed cycle and current balance. RPC responses identify the
reference height, active policy, next-distribution policy and estimated budget.

Wallet yield estimates preserve a zero budget and show unavailable data instead
of inventing a percentage of the vault balance. The ordinary-staking APR uses
the sum of estimated ordinary-recipient payouts, excluding bond-yield escrow
and unused budget. It is annualized without compounding. Actual payouts still
depend on the recipient weights at settlement.

Qualification includes disabled and activated policies, integer extremes,
concentration limits, rounding, absent recipients and bond-yield allocation.
The funded native journey mines its own test funds, submits signed transfers
and stake markers, compares independently calculated payouts, refuses incorrect
settlements, reorganizes an activated boundary, independently replays history and
reopens durable state. It crosses both private test halving heights. These tests
do not activate mainnet or represent independent production validator operators.
