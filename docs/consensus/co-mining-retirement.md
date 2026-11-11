# Co-mining retirement candidate

This candidate pins the public-mainnet subsidy schedule to block 34,750.
Publication and coordinated deployment remain subject to release qualification;
see the [activation schedule](../release-3.3.4-activation.md).

The first reduced block is 700,801, after four complete protocol years. Ordinary
subsidies then become 60% block miner, 20% vault and 20% validator pool. Integer
remainders stay with the miner. Co-mining receives no new issuance. Every 100th
block still sends its entire subsidy to the vault. Native fees follow their
separate policy: 100% to the miner permanently, including these blocks and after
the supply cap. The second halving remains at 1,401,601; there is no third.

The last normal lottery draw is block 700,800. It uses the existing eligibility,
1,000 VELD stake floor, slot selection and payout rules. Previous payouts remain
ordinary UTXOs. Retirement does not change staking records, locks or withdrawal
rules. Unfilled lottery slots remain in the protocol pool reserve; this update
does not reassign or confiscate that reserve. No recurring reserve roll-forward
transactions or new entries are permitted after retirement. A future use of the
reserve requires an explicitly reviewed protocol change.

All decisions use the candidate block's height. Historical validation remains
available, and an unfinalized reorganization back across the boundary restores
the corresponding earlier rules. Retirement does not bypass finalized history.

Protocol-upgrade governance retains its existing hard floor of ten participating
YES/NO validator votes. Its dynamic participation requirement can rise above ten;
approval requires 67% of participating YES/NO votes, followed by the existing
seven-protocol-day timelock. This is separate from the minimum five-key finality
set and its strict greater-than-two-thirds certificate threshold.

A future governance-approved upgrade may restore co-mining with an explicit
allocation, eligibility policy and activation height. The current governance
engine records voting outcomes; it does not automatically execute reward changes.
Software adoption remains necessary. This candidate has no automatic return
switch and does not promise retrospective rewards during the retired period.
