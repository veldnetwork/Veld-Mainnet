# 3.3.4 activation schedule

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

The signed [3.3.4 release](https://github.com/veldnetwork/Veld-Mainnet/releases/tag/v3.3.4)
was published on November 12, 2026. Upgrade before block 34,750. Release tags and
packages are immutable; later changes on `main` do not replace those binaries.
The source commit is `83fad356169eaf42e7bc83b652d687837b02d9f9`.

## Wallet, Explorer and bonds

Registration uses the next inclusion height. At tip 34,748, the next block still
requires 10,000 VELD. At tip 34,749, a transaction for block 34,750 requires
5,000 VELD, plus its fee. Wallet preparation, transaction validation and the
Explorer's registration minimum follow that same boundary. An old prepared
transaction is checked again when submitted and included; a page display does
not override consensus. Refresh an older open client page after upgrading.

An existing 10,000 VELD bond stays recorded at its actual amount. Eligible
excess principal requires an owner-signed return request and the full evidence
window; activation alone does not return it. See
[excess-bond returns](validator-excess-bond-return.md).

Finality uses the policy at each frozen snapshot height. Epoch 72 retains its
pre-activation snapshot at 34,559. Epoch 73 uses the snapshot at 35,039 and the
five-key minimum with equal capped bond weights. Registration maturity,
consecutive qualifying snapshots, warm-up and strict quorum still apply.
Three validators therefore do not immediately enable finality.

The seven-validator btcVELD activation threshold is separate and unchanged.
Governance retains its ten-vote participation minimum, 67% approval threshold
and 3,360-block protocol timelock. The scheduled release is not evidence of a
passed governance proposal.

## Validator operation

Keep one active signing machine per validator key. Other miners may share its
payout address in address-only mode. Preserve the identity's signing history
when updating or moving machines; see [validator signing safety](operations/validator-signing-safety.md).
Ordinary double-sign and locked-finality slashing rules remain in force.
