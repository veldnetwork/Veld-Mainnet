# Live mainnet checks

Operators should continuously compare multiple independently running nodes.
Normal proof-of-work variance is not a failure; persistent disagreement is.

## Consensus and chain state

- Height, tip hash, parent linkage, encoded target, and cumulative work agree.
- Canonical supply, UTXO digest, and complete state digest agree.
- Block timestamps, difficulty transitions, coinbase value, and fee accounting
  remain valid.
- Mempool contents converge and confirmed transactions disappear from mempools.

## Mining and work admission

- The miner runs the signed BUILD-02 node and has at least two exact-tip peers.
- Hash counters advance while mining is active; work tickets are prepared and
  claimed once without deadlock, replay, or stale-template acceptance.
- Ordinary block-time variance is recorded without being misclassified as a
  product defect.

## Network and services

- P2P peer count, propagation delay, orphan/reorganization rate, process health,
  disk, memory, file descriptors, system clock, and firewall state are healthy.
- RPC stays authenticated and non-public; reverse proxies expose only intended
  wallet and Explorer routes.
- Homepage downloads, signed manifests, Wallet, Explorer, and Rules remain
  reachable and consistent with live chain data.

## Activation gates

- Staking remains inactive until canonical issued supply reaches 10,000 VELD.
- Governance remains inactive until canonical issued supply reaches 50,000 VELD.
- btcVELD minting and redemption remain inactive until seven qualified finality
  validators and the required consecutive-epoch warm-up are genuinely present.
- Exchange deposits and bridge-dependent custody should remain restricted until
  the live ordinary-wallet carrying-block and persisted restart checks pass.

## Stop and preserve evidence

Halt production mining and wallet-facing services if nodes persistently diverge,
a valid ordinary transaction is unexpectedly rejected or omitted from stable
templates, a carrying block deadlocks or is rejected, restart reconstructs a
different state, signed binary identity changes, or unexpected supply appears.
Preserve datadirs and logs before remediation; do not patch consensus state in
place.
