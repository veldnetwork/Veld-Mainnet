# btcVELD launch state — owner implementation record (2026-07-18)

**Status:** OWNER-DIRECTED AND IMPLEMENTED IN THE SOURCE CANDIDATE; the final
release signature, frozen-tree identity, native Windows evidence, and August 30
genesis ceremony remain pending. This record does not declare the artifact GO.

This entry supersedes only the earlier rule that made btcVELD economics wait
for validator finality plus a promoted Bitcoin anchor. It does not weaken the
finality or anchor consensus rules and does not alter any other owner-selected
cap, fee, minimum, reservation lifecycle, or later-stall behavior.

**Superseded launch-gate overlay (owner direction 2026-08-04):** btcVELD
economic transitions now remain closed until the chain completes the existing
seven-validator finality activation. A promoted Bitcoin anchor is not an
additional unlock prerequisite. This is a one-time latch: a later validator
count drop alone does not re-lock the peg. A later 60-block loss of finalized
checkpoint progress pauses only new custody exposure; completion, transfer,
redeem, and AMM remain available. The numbered 2026-07-18 launch-live
statements below are retained only as historical rationale; this overlay is current.

## Normative launch decision

For the fresh genesis:

1. btcVELD issuer mint and redeem remain closed until the chain reaches their
   compiled launch height and completes the one-time seven-validator finality
   activation.
2. The permissionless btcVELD/Veld AMM and its four-band, output-asset fee model
   open after that same one-time activation. The first valid LP may
   choose the opening ratio, subject to the selected 50 VELD and 50,000
   btcVELD-sat first-seed floors and the resulting permanent locked-LP core,
   plus all existing caps and floors. The lock is an LP-supply lock; swaps can
   change the two reserve quantities.
3. Auxiliary cross-chain services have no launch role and are not deployed.
4. Validator finality activates btcVELD once; Bitcoin anchors remain additive
   security and are not a second activation gate.
   Anchor targets still require real finality, and anchor promotion remains
   digest-committed. Validator activation is the one-time initial prerequisite;
   anchor promotion is not.
5. **Owner completion-exception approval (2026-07-19):** once the peg has
   unlocked, a later finality stall rejects every transition that creates new
   mint exposure: C1R1, C1E1, direct issuer MNP1, and MSPV. It preserves only
   C1C1 gap closure, exact C1F1 funding of a canonical already-exposed
   allocation, and exact MNP2 credit of a canonical already-funded allocation.
   Every normal structural, issuer-authorization, lifecycle, commitment,
   amount, recipient, Bitcoin-SPV, outpoint, and nullifier check remains in
   force. Redeem remains available. **2026-07-21 ratification overlay:** the
   owner subsequently approved the implemented 60-block liveness window and
   continued AMM swaps during such a later stall. This later direction closes
   the source-policy choice but does not fabricate the detached post-freeze
   owner signature; the signed final freeze must bind it to the exact source
   and evidence before an unconditional mainnet GO declaration.
6. Irreversible Bitcoin payout for a redeem still waits for a real finalized
   burn. Launch-live burn consensus is not permission to pay against an
   unfinalized fork.

## Required implementation identity

All consensus, mempool, candidate-preview, replay, reorg, RPC, service, and UI
paths derive permissions from the same candidate-height launch/liveness state.
The implementation must fail closed if the compiled launch profile is absent
or if an impossible finality frame is presented. It must not infer launch
permission from a promoted anchor or from the legacy finality/anchor security
milestone helper.

## Required evidence

- Boundary tests for inactive profile, pre-activation closure, live finality,
  and later finality stall, including rejection without partial state mutation.
- Full-node proof that block 1 remains closed and the first post-activation
  candidate creates the AMM shell without requiring an anchor.
- Same-carrier and no-anchor MINT + first-seed proofs, with malformed optional
  anchor isolation.
- Alternate-branch and clean-replay equality for token, AMM, BTC-header, and
  anchor state.
- Linux and native Windows source/build/replay qualification, followed by the
  signed frozen-tree and ceremony evidence required by the release gate.

## Values deliberately unchanged

This historical 2026-07-18 decision does not change the 50 VELD / 50,000-sat locked seed core, the
four fee bands, dual output-asset LP fees, pool/supply/custody caps, the 10,000
sat public WRAP minimum, the then-current 62,500-sat issuer per-mint maximum, C1 capacity or
lifetime rules, finality evidence rules, anchor confirmation rules, or the
final payout hold. The phase-specific completion exception above is the
owner's explicit selection; it does not alter any C1 amount or proof rule.

Superseded amount policy (owner direction 2026-08-04): the separate issuer
per-address/per-mint maximum was removed. The only live amount ceiling is
remaining effective custody headroom; the 10,000-sat minimum remains.
