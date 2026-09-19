# Market-priced VELD swaps: 3.2.1 production candidate

Status: included in the isolated production source candidate, scheduled at
mainnet block **9,000**. This document does not establish a signed release,
deployment or activation on the running network.
Starting source: `1e28248ee6b5c248f54b79d22766dab97ba65b69`, tree
`3535475029fbcd949165bb363275ec58a1f2fceb`. Build receipts identify the exact
resulting commit, tree and binary hashes; qualification must match those artifacts.

## Economic decision

Use **30 basis points (0.30%) in either direction** as a provisional launch
setting. This preserves the existing base LP fee and removes the penalty for
trading away from an old opening price. It is not an empirically established
economic optimum. The objective is a balance between viable liquidity provision
and affordable trading; neither trading demand nor LP participation has been
calibrated to a live Veld market in this analysis.

There is no price target for VELD. The reserves and constant-product rule set
execution prices; arbitrage can move them with the market. btcVELD's Bitcoin
backing/redemption remains a separate obligation. Removing the VELD price anchor
from fee calculation changes neither that backing nor its custody protections.

The fee remains in the **output asset**, deducted after the integer gross-output
calculation. LPs own it through their existing shares. There is no protocol cut.
The native transaction fee is separate. A 0.30% fee is not a 0.30% total trading
cost: depth-dependent price impact and integer rounding still apply.

## What the analysis establishes

The local sensitivity study compares 5/10/20/25/30/40/50/75/100 bps over 54
synthetic combinations of volatility, potential turnover, assumed willingness
to pay and reserve depth, with four common random seeds per combination.
Each path spans seven modeled days. It uses constant-product output fees,
external arbitrage and fee-sensitive order participation. None of its price,
volume, volatility or elasticity inputs are Veld observations or forecasts.

| Fee | Mean retained organic volume vs 5 bps | Scenarios with highest modeled LP return among tested fees |
|---|---:|---:|
| 0.20% | 81.6% | 1 / 54 |
| 0.30% | 72.3% | 2 / 54 |
| 0.50% | 58.0% | 6 / 54 |
| 1.00% | 36.7% | 38 / 54 |

These results **do not** establish 0.30% as the LP-profit maximum. In these
assumed regimes, 1% frequently produces better modeled LP returns but much less
organic volume. Because 1% is the largest tested fee, its wins do not even
establish an interior optimum for this simplified model. At 0.30%, LP excess
return versus a continuously rebalanced benchmark is nonnegative in only
26/54 scenarios. Fees do not guarantee LP profitability.

The model omits endogenous liquidity supply, strategic order routing/MEV,
outages and endogenous market price formation. Its fixed native fee and
synthetic numeraire are approximations. Equal scenario weighting is a sensitivity
display, not a probability distribution. No finite simulation substitutes for
calibration. The launch recommendation favors the existing base rate and a
predictable neutral rule, rather than claiming optimization has been solved.

Relevant primary research:
- [Optimal Fees for Liquidity Provision in Automated Market Makers](https://arxiv.org/abs/2508.08152)
  studies fee tradeoffs under volatility, volume and routing-cost assumptions.
- [Automated Market Making and Loss-Versus-Rebalancing](https://arxiv.org/abs/2208.06046)
  separates adverse-selection costs from fee income.

Before selecting a different rate, collect canonical volume and active liquidity,
quote-to-execution rates, trade-size/depth distributions, actual fee income,
markouts against independent market observations and LP net returns including
inventory risk. Fit and validate demand sensitivity out of sample. Compare
candidate rates under those measured regimes and explicit objectives. A fee
change must be prospective and coordinated; this candidate introduces no oracle,
automatic fee controller, coordinator discretion or new governance power.

## Consensus and migration

`BTCVELD_AMM_FLAT_FEE_ACTIVATION_HEIGHT` is **9,000 in public mainnet builds**,
coordinated with the candidate's existing validator upgrade. Other production
profiles retain height 0 (inactive). Only an isolated test-chain build with test
hooks may override it. The accelerated component-test boundary is height 100;
tests also exercise the actual public boundary at blocks 8,999/9,000/9,001.

Before activation, the old four-band algorithm executes unchanged. At and after
activation, the same canonical quote entrypoint applies 30 bps without using
price deviation. Validation and application use inclusion height, including
replay and rollback. Existing anchors remain positive, serialized and committed
in the unchanged state digest; the patch neither rewrites old state nor assigns
a new reference price. Band/deviation fields are not applicable in the new rule.

This is a consensus change: differing fees produce differing payouts and token
state. Deployment at the selected height requires coordinated upgraded
validators/miners and services, full candidate-chain and
restart/reorganization qualification, and compatible wallets. Quotes signed
under the old rule may be invalid if included after activation. Refresh them;
do not grandfather a second fee rule or weaken exact-output checks. The wallet
refuses a prepared transaction when the policy changes after preview.

All custody, seven-validator activation, seed authority, seed lock, token balance
floors, pool caps, minimum output, covenant, signature, supply and fee-routing
checks remain in their existing paths. Changing the fee does not open the peg.

## Verification scope

`tests/qualify_amm_fee_policy.py` runs the same native probe against historical,
public-mainnet and activated-test source. It checks an independent integer
reference, extreme starting deviations, both directions, activation boundaries,
quote immutability and module snapshot rollback/replay. Embedded wallet functions
are executed directly by Node.js and compared with native results. Windows
component executables are run natively, not merely cross-compiled.

These are component tests. They do not establish full-node disk recovery, a
funded peg lifecycle, live mainnet swap execution, or GUI usability. The existing
mainnet pool test separately must earn a real block, mature the actual receipt
and independently reconcile confirmed miner payments before it can pass.
