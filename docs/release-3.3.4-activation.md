# 3.3.4 candidate activation schedule

The selected public-mainnet activation height is **34,750**. The requested time
is **Friday, November 13, 2026, at noon MST (America/Denver), or 19:00 UTC**.
The height is fixed; its arrival time depends on block production.

At 01:03 UTC on November 11, both checked fleet nodes agreed on block 33,427.
The 180-second target interval placed block 34,750 near 19:12 UTC on November 13.
The preceding 144-block average placed it near 18:46 UTC. These are projections,
not a timestamp activation rule or a guaranteed time range.

The same height activates the validator-bond policy, permanent native fees to
miners, the subsidy schedule, and the rewards-vault reserve policy. The finality
set continues to use its frozen snapshot, maturity, quorum, and warm-up rules.
Vault distributions continue on their existing 480-block boundaries. Selecting
this height does not immediately finalize the chain, pay rewards, or return bonds.

The first and second halvings remain at blocks **700,801** and **1,401,601**.
Co-mining retirement remains at the first halving. Historical protocol activation
at block 3,840 and all other historical gates are unchanged. Production appchain
hosting remains paused and the production pool remains stopped.

The user's Friday selection replaces the earlier 3,360-block release-notice
plan with approximately 1,323 blocks of lead from the observed tip. This does
not alter governance voting or its separate 3,360-block protocol-proposal
timelock, and it is not evidence of a passed governance proposal.

This is an **unsigned, unpublished candidate**. The previous inactive candidate
and its qualification evidence remain preserved. Shipping verification, operator
readiness and the remaining applicable release gates must pass before publication.
If readiness misses this height, revise the schedule before publishing; do not
silently distribute an already-activated consensus change.
