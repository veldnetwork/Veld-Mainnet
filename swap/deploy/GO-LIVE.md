# btcVELD service go-live

This runbook covers the live Bitcoin header relay, custody, mint, redemption,
signer, issuer, watchtower, and AMM services. Retired trading and payment-channel
products are not part of this deployment.

## Before activation

- Confirm every fleet node is on the same signed Veld release and consensus
  constants.
- Confirm Bitcoin header relay health and recent anchor inclusion.
- Confirm issuer and signer services use the reviewed custody cap and current
  signer allowlist.
- Confirm watchtowers and heartbeat monitoring are live.
- Confirm the one-time seven-validator peg activation has latched. A later
  validator-count drop does not freeze redemption or existing allocations;
  sustained finality loss pauses only new mint exposure.
- Confirm `wallet.veld.network/#btcveld` reports the same activation and custody
  state as the node RPC.

## Activation check

1. Wrap the smallest supported Bitcoin amount to a fresh Veld wallet.
2. Verify the deposit reaches the required Bitcoin confirmation depth.
3. Verify exactly one btcVELD credit is committed on Veld.
4. Redeem that btcVELD and verify the burn reaches the payout workflow.
5. Confirm the AMM accepts an ordinary trade and its reserves remain solvent.

Record transaction identifiers, block heights, deployed binary hashes, and the
non-secret configuration hashes. Do not record keys, passphrases, RPC tokens, or
custody credentials.

## Stop conditions

Pause new mint exposure if header relay, finality liveness, custody solvency, or
signer quorum is unhealthy. Keep redemption and already-exposed completion paths
available unless consensus itself rejects them.
