# VELD Protocol Whitepaper

## A memory-hard proof-of-work network with native staking, co-mining, validator finality, and Bitcoin utility

**Protocol version:** Veld Core 3.1.3

**Document version:** 9 September 2026

**Network:** veld-public-mainnet-v2

**Coordinated upgrade:** Block 3,840

---

## Abstract

VELD is a proof-of-work network with a maximum native supply of 21,000,000 VELD and no premine. Its UTXO ledger combines CPU-oriented, memory-hard mining with native staking, a co-mining lottery, and bonded validators. Qualified validator finality can support Bitcoin anchoring and activation of btcVELD, a representation of Bitcoin held in custody. An on-chain automated market maker provides VELD/btcVELD exchange once its activation conditions are satisfied.

The target block interval is 180 seconds. Veld 3.1.3 activates per-block ASERT difficulty adjustment at block 3,840, using a 2,700-second half-life. At the same inclusion height, the ordinary staking minimum decreases from 1,000 to 500 VELD. The co-mining lottery minimum stays at 1,000 VELD. The validator bond, maximum ordinary stake, lockups, reward maturity, and established reward allocation remain unchanged.

The upgrade also coordinates coinbase validation and validator, governance, and retained-state transitions at a 480-block settlement boundary. Client changes improve independent verification progress, interrupted snapshot recovery, Windows process management, and diagnostic reporting. Installing a release and activating its consensus rules are separate events: operators must install 3.1.3 before height 3,840.

This paper describes the released implementation and its activation boundaries. Historical blocks retain the rules applicable at their height. The corresponding source, network parameters, and signed release records provide the implementation references for this document.

## 1. Network and activation model

### 1.1 Public network identity

The public network is `veld-public-mainnet-v2`. This chain began on 2 September 2026 under the Veld 3.0.0 public-mainnet-v2 release. Earlier preparation balances and block history are not balances or history on this ledger.

Nodes identify the network through its compiled profile, genesis fingerprint, protocol capabilities, and launch-chain anchor. An application version alone is not a network identity. Two peers can remain connected while running software that applies different future consensus rules.

The public genesis fingerprint is:

```
880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b
```

Operators can inspect `getnetworkinfo` and the release identity records to compare the profile and genesis fingerprint. RPC block-hash display order must be distinguished from the fingerprint's byte order. Matching identifiers and height do not establish completed independent verification.

### 1.2 Height-based changes

Veld 3.1.3 schedules the coordinated upgrade at block 3,840. This is a multiple of the 480-block settlement interval. The candidate block's inclusion height selects the applicable rules, including when a transaction was prepared before activation but confirmed afterward.

| Rule | Below block 3,840 | From block 3,840 |
|---|---|---|
| Difficulty adjustment | Historical LWMA and bootstrap rules | ASERT after every block |
| Ordinary staking minimum | 1,000 VELD | 500 VELD |
| Co-mining stake minimum | 1,000 VELD | 1,000 VELD (unchanged) |
| Maximum ordinary stake per address | 10,000 VELD | 10,000 VELD |
| Validator registration bond | 10,000 VELD | 10,000 VELD |
| Coinbase validation | Historical admission and replay rules | Unified state-aware policy |
| Validator, governance, and retained state | Existing formats and state rules | Coordinated migration |

The independent rules activated at block 2,880 remain in force. The 3.1.3 upgrade does not replace the genesis, reset balances, change the supply cap, or require ordinary users to move funds. Existing stakes retain their lockup conditions. A lower minimum does not shorten a lock or create an automatic withdrawal.

### 1.3 Consensus and operating policy

Consensus rules determine whether every validating node accepts a block. Relay policy determines what a node forwards or places in its mempool. Wallet policy governs transaction preparation and user interaction. Snapshot distribution, the hosted wallet, the Explorer, the Portal, and custody services are operational components with their own availability and trust boundaries.

Documentation and dashboards describe those components; they do not override validation. A signed update proves the origin and integrity of the distributed files. It does not certify every operating condition or make a future activation complete before its height is reached.

## 2. Native ledger and proof of work

### 2.1 Ledger and signatures

VELD uses an unspent-transaction-output ledger. Inputs must reference spendable outputs, satisfy their authorization or covenant, and conserve value. Validation includes duplicate-spend checks, maturity, signatures, transaction structure, module-specific rules, and the coinbase's permitted issuance and fees.

Native transaction signatures use ML-DSA-65. The same signature family is used for validator messages and signed release artifacts where required. Address hashes, proof of work, Bitcoin custody, and endpoint security have separate assumptions; the use of post-quantum signatures does not remove those dependencies.

| Parameter | Value |
|---|---:|
| Atomic units per VELD | 100,000,000 |
| Target interval | 180 seconds |
| Nominal blocks per protocol day | 480 |
| Nominal blocks per protocol year | 175,200 |
| Maximum block size | 8,000,000 bytes |
| Maximum transactions per block | 4,096 |
| Coinbase maturity | 100 blocks |
| Reorganization horizon | A branch removing 100 or more blocks is rejected |

### 2.2 VeldHash

VeldHash is designed to make memory capacity and bandwidth material to mining. The production profile uses a 1 GiB epoch dataset, a 2 MiB scratchpad per worker, and a generated program of integer and signed fixed-point operations. Dataset epochs span 256 blocks. Fixed-point rules avoid native floating-point behavior in consensus.

Full miners retain the epoch dataset. A light-verification path recomputes the required dataset words without retaining the entire dataset. It is a validation option, not a competitive mining mode. Known-answer vectors and cross-profile checks compare the results of the supported paths.

Workers are software mining threads. The best worker count depends on CPU architecture, memory bandwidth, available memory, and concurrent validation work. More workers need not produce a higher sustained hashrate. Each mining process has an independent search origin, including when multiple machines use the same payout address. The Portal monitors those machines separately; sharing an address does not make them a mining pool.

Memory hardness can alter the cost of specialized hardware and large CPU farms, but it does not equalize hashrate or establish independent ownership of miners. Block-winning probability remains related to contributed valid work.

### 2.3 ASERT difficulty adjustment

From block 3,840, ASERT calculates the required target after every block using the canonical branch's anchor, elapsed block time, and height progression. It compares elapsed time with the schedule implied by the 180-second target and applies an exponential correction with a 2,700-second half-life. The implementation uses deterministic integer arithmetic and canonical compact-target encoding.

When blocks accumulate ahead of the target schedule, the required target decreases and difficulty rises. When the chain falls behind the schedule, the target increases and difficulty falls, within the proof-of-work limit. The half-life controls the response to accumulated schedule error; it is not a promised block interval and does not schedule a wall-clock reset.

The next target is derived from accepted parent-chain evidence. Merely waiting without another accepted block does not continuously lower the next target. Random block discovery and changes in hashrate can still produce long or short intervals. ASERT responds after each accepted block instead of waiting for a periodic LWMA retarget boundary.

Historical LWMA remains necessary for validating blocks below activation. Reorganization and independent replay must select the target from the same candidate-parent history. The change applies to difficulty calculation; VeldHash and the 180-second target are retained.

## 3. Supply, fees, and coinbase accounting

### 3.1 Issuance

The maximum supply is 21,000,000 VELD. There is no premine or separately minted founder allocation. The scheduled base subsidy is 3.13926940 VELD per block. An integer remainder adjustment at the 175,200-block annual boundary produces 550,000 VELD per protocol year until the supply cap limits issuance. This is a block-based schedule, not a guaranteed calendar issuance rate.

The effective subsidy is the scheduled subsidy limited by remaining supply headroom. The final subsidized block can therefore issue less than the ordinary reward. Transaction fees redistribute existing units and do not increase issued supply.

### 3.2 Subsidy allocation

Before staking activation at 10,000 VELD of canonical issued supply, ordinary block subsidies are divided between the miner and vault. After staking activation, ordinary blocks use four participation categories. A positive multiple of 100 is a periodic vault-funding block while effective subsidy remains positive.

| Context with positive subsidy | Miner | Co-mining | Vault | Validator pool |
|---|---:|---:|---:|---:|
| Ordinary block before staking activation | 50% | 0% | 50% | 0% |
| Ordinary block after staking activation | 50% | 20% | 20% | 10% |
| Every 100th block | 0% | 0% | 100% | 0% |

During the subsidy era, included transaction fees go to the vault in addition to its subsidy allocation. Allocations use integer atomic units: prescribed category percentages round down and the miner receives the applicable subsidy remainder. The lower staking minimum does not change these shares.

When effective subsidy is zero, the fee-only policy gives 40% of authenticated fees to the vault, 10% to the validator pool, and the remainder to the miner. This policy takes precedence at every height, including a periodic vault boundary. A block with no subsidy and no fees uses the canonical zero-value representation rather than inventing a payment category.

### 3.3 Consistent validation at activation

From block 3,840, direct admission, alternate-branch validation, independent replay, and mining preflight apply one state-aware coinbase policy. The policy derives fee-only status from the candidate parent's issued supply. It authenticates fees against the parent UTXO state and enforces exact permitted value, payout categories, output shape, and output bounds.

The correction replaces historical reward-multiple backstops with exact subsidy-plus-fee accounting for upgraded blocks. This matters for otherwise valid large-fee blocks and for zero-subsidy blocks on periodic vault boundaries. Canonical miner templates must satisfy the same mandatory checks as received blocks. Required settlement transactions and finality-certificate authentication remain separate checks.

Historical admission and replay behavior is retained below activation. The change does not retroactively invalidate an accepted history or reinterpret its monetary state. The source's coinbase accounting document describes the historical compatibility and output-boundary details.

## 4. Ordinary staking and vault distributions

### 4.1 Access and limits

Staking activates once canonical issued supply reaches 10,000 VELD. That supply gate has been reached on public mainnet. The minimum new ordinary stake is 1,000 VELD below block 3,840 and 500 VELD from that inclusion height. The maximum ordinary stake remains 10,000 VELD per address. Spendable funds must also cover the transaction fee.

Ordinary staking is available through Veld Wallet. Users import their encrypted keyfile, unlock it locally, verify the intended address, choose an amount and lockup, and review the transaction before signing. Importing a keyfile accesses the same wallet; it does not move funds. Wallet keys and passphrases must be kept private and backed up separately.

### 4.2 Lockups

| Tier | Lockup in blocks | Approximate days at target | Base weight |
|---|---:|---:|---:|
| Base | 3,360 | 7 | 1.00x |
| Short | 6,720 | 14 | 1.10x |
| Medium | 14,400 | 30 | 1.25x |
| Long | 43,200 | 90 | 1.50x |

The unlock height controls maturity. Calendar durations are estimates based on 180-second blocks. Staked outputs cannot be spent as ordinary funds while locked. Reaching the unlock height permits an unstake transaction; it does not automatically withdraw the position. Partial unstaking must obey the same maturity, ownership, remaining-position, and fee rules enforced by the wallet and node.

### 4.3 Mining activity weights

Eligible mining activity can increase an address's relative vault weight. The established activity windows and tier multipliers are unchanged by 3.1.3.

| Mining tier | Active days required / window | Multiplier |
|---|---:|---:|
| Bronze | 7 / 14 | 1.10x |
| Silver | 25 / 30 | 1.25x |
| Gold | 165 / 180 | 1.50x |
| Platinum | 335 / 365 | 1.80x |
| Diamond | 1,000 / 1,095 | 3.00x |

Ordinary distribution weight combines eligible stake, mining multiplier, and lockup multiplier. The combined multiplier is capped at 3.00x. Weight changes a participant's relative share of a bounded distribution; it does not change issuance or specify an interest rate.

### 4.4 Distribution limits

The vault settles every 480 blocks. The budget is bounded by both 90% of the preceding cycle's vault inflow and 8% of spendable vault balance. Transaction costs, available inputs, eligible weight, recipient bounds, and integer rounding further determine the actual payments.

One eligible recipient cannot receive more than 75% of the cycle's distribution budget. Excess remains in the vault rather than being redistributed to the remaining recipients in that cycle. Undistributed amounts are retained. These limits constrain spending; they do not establish perpetual reserve growth or a fixed future payment.

Ordinary wallet stakes remain on-chain while the browser is closed. The hosted wallet is an interface, not the owner of those funds. A user needs the correct keyfile and passphrase to authorize a later transaction.

## 5. Co-mining lottery

The co-mining pool receives 20% of ordinary block subsidies after staking activation. It distributes through a draw every 100 blocks. Qualification combines ordinary stake at the mining address with valid near-miss proof of work included in the canonical chain during the relevant window.

A near miss satisfies the protocol's share target without satisfying the full block target. It must refer to eligible recent chain state, meet signature and uniqueness requirements, and be admitted on-chain. The client submits qualifying work automatically. A locally found or merely broadcast share is not yet an included share.

The co-mining stake threshold remains 1,000 VELD before and after block 3,840. Ordinary staking at 500 VELD does not qualify an address for the lottery. The same ordinary stake can contribute to vault distributions and co-mining eligibility; a separate duplicate lock is not required. Staking to a different address does not qualify the miner's address.

Each eligible address receives one entry, regardless of the number of qualifying near misses. Up to four near-miss records may be included in a block. The draw selects up to five distinct addresses, increasing to up to 20 when at least 1,000 addresses qualify. Winners receive one slot each; unfilled slots carry forward subject to integer rounding.

Lowering the ordinary staking minimum gives smaller balances access to vault distributions; it does not lower the lottery threshold. The signature, work, inclusion, uniqueness, lockup, and per-address entry rules remain. One address is an accounting identity, not proof of one independent person or one physical computer.

## 6. Validators, finality, and checkpoints

### 6.1 Validator participation

After staking activates, the validator subsystem unlocks when aggregate ordinary stake reaches 10,000 VELD. Validator registration requires a 10,000 VELD bond. This bond is distinct from the 500 VELD ordinary staking minimum and remains slashable under the validator rules. Registration maturity and the existing 480-block settlement schedule are retained.

The validator pool receives 10% of ordinary block subsidy after staking activation. Payouts depend on eligible endorsements in the settlement window. A pool allocation is not evidence that a validator has qualified for payment. Where no eligible endorsement recipient exists, the applicable settlement rules determine routing; the allocation must not be interpreted as an unconditional payout to operators.

At block 3,840, validator attribution and governance operations transition with retained state on the coordinated schedule. Updated clients bind operations to their required identity, signature, and inclusion context. Reorganization and replay reconstruct the same applicable state. This transition does not automatically satisfy the separate participation gates for governance, finality, or btcVELD.

### 6.2 Bond penalties and yield

Ordinary endorsement equivocation and locked-finality equivocation have distinct penalties. For ordinary endorsement double-sign evidence, the settlement allocates 25% to the reporter, 25% to the vault, and 50% back to the offender. A finality-equivocation settlement returns nothing to the offender, pays 25% to the reporter, and sends 75% to a provably unspendable output. The offending key is permanently barred from re-registration under the slashing rules.

Bonded principal participates in vault distributions with a 1.50x lockup weight. Its yield is escrowed and vests over a rolling 43,200-block delay. Slashing confiscates unvested yield in addition to the applicable bond penalty; already released yield is not retroactively reclaimed.

### 6.3 Qualified validator finality

Finality requires at least seven eligible validators and caps voting weight at 10,000 VELD per validator. The set is determined from chain state at epoch boundaries. Validators use signed PREVOTE and PRECOMMIT messages that bind the network, epoch, phase, round, validator-set snapshot, source, and target.

A quorum certificate requires strictly more than two-thirds of eligible capped voting weight. Equal-weight membership therefore requires five signatures out of seven. Qualification and warm-up rules apply before the service becomes active. Certificates must be authenticated and retained; an observed certificate or dashboard label cannot replace those checks.

### 6.4 Historical checkpoint protection

Veld 3.1.3 retains the verified historical checkpoint introduced in 3.1.1 at block 2,800. A conflicting history is rejected at that compiled checkpoint. Downloaded signed checkpoints are advisory and cannot move the compiled pin. The checkpoint authority and the release-signing authority have different roles.

The bounded reorganization horizon, compiled checkpoint, and qualified validator finality are distinct protections. They do not eliminate the need to validate proof of work, signatures, transactions, and state. Unconfirmed or recently confirmed transactions can still be affected by a permitted reorganization.

### 6.5 Bitcoin anchoring

After qualified finality and its warm-up, Bitcoin transactions can commit finalized VELD checkpoints. VELD nodes verify the corresponding Bitcoin header chain and inclusion proofs. A locally verified and retained anchor adds a boundary against conflicting VELD histories.

Bitcoin header relay and anchoring are different operations. Relaying headers pays ordinary VELD transaction fees and does not itself spend Bitcoin. Publishing an anchor transaction on Bitcoin incurs Bitcoin network fees. Bitcoin anchors strengthen already-finalized history; they are not an additional independent threshold for unlocking btcVELD.

## 7. btcVELD and Bitcoin custody

### 7.1 Denomination and activation

btcVELD has eight decimal places, with one atomic unit corresponding to one Bitcoin satoshi represented by the system. The accounting relationship is one btcVELD to one BTC held in custody. Market execution prices and redemption completion depend on liquidity and operating conditions.

btcVELD becomes available after seven qualified validators complete the required finality warm-up. The qualification is a one-time activation condition. New exposure can subsequently be restricted by liveness and safety gates; existing completion and redemption paths retain their separate checks. Installing 3.1.3 alone does not activate these services.

### 7.2 Shared supply and replay accounting

Issuer-assisted and SPV-verified mint paths share an absolute 10 BTC ceiling and a Bitcoin-outpoint replay domain. Issued supply and outstanding reserved capacity consume applicable headroom. There is no separate per-address or per-mint ceiling that permits the shared cap to be exceeded.

Issuer-assisted issuance has an additional work-linked exposure tier. SPV minting remains subject to the absolute cap and Bitcoin proof rules without using that issuer-only tier. Every mint must satisfy its path's authorization, backing, uniqueness, confirmation, and state-transition requirements.

The positive touched-account floor is 1,000 satoshis; an affected account must end at zero or at least that floor. Floors and capacity limits bound retained state. They do not demonstrate solvency by themselves.

### 7.3 Assisted wrapping, redemption, and monitoring

Assisted wrapping reserves capacity before exposing a Bitcoin deposit address. Funding proofs consume the identified outpoint, and the exact completion path credits the recipient while closing the reservation. Reserved capacity cannot be treated as unused headroom for another mint.

Redemption requests burn or commit the applicable btcVELD through the prescribed transaction flow and require valid Bitcoin payout evidence. The fixed 480-block redemption window is limited to 20% of the 10 BTC absolute cap: 2 BTC per window. A request exceeding remaining window capacity is rejected rather than partially accepted.

Custody depends on its configured Bitcoin signing threshold, correct payout processing, canonical VELD and Bitcoin state, and available funds. The issuer requires a fresh authenticated solvency heartbeat before authorizing new exposure. Nodes independently enforce the on-chain mint, reserve, and redemption rules. Watchtower availability and authenticated status must be distinguished from a complete proof of custody solvency.

## 8. On-chain liquidity

The VELD/btcVELD AMM is a constant-product pool available after the peg's activation conditions are met. The first successful seed establishes the pool's reference ratio. Later reserve prices move through trading. Seed floors, permanently locked initial liquidity, transaction limits, and the first-seed liveness checks remain part of admission.

Swaps use deterministic integer arithmetic. Fees are charged in the asset received and remain in the pool's reserves. Liquidity-provider shares represent proportional ownership of the reserves, including retained fees. Withdrawal claims that proportion of both assets, subject to the transaction's validation rules.

| Trade effect or post-trade deviation from reference | Fee |
|---|---:|
| Improves the ratio or remains within 5% | 0.30% |
| Above 5% through 10% | 0.50% |
| Above 10% through 20% | 0.75% |
| Above 20% | 1.00% |

All AMM swap fees stay with the pool. Native VELD transaction fees are separate. Pool reserves share the applicable aggregate btcVELD custody ceiling; liquidity does not create a second independent allowance for represented Bitcoin.

A positive liquidity position has a 1,000-unit floor and the active-identity ceiling is 65,536. Existing positions can change within the required retained-state and arithmetic rules. These bounds control storage and admission rather than setting a market price.

Liquidity provision exposes the owner to changing asset proportions, adverse prices, shallow liquidity, contract defects, and btcVELD custody or redemption disruption. Retained fees can be less than losses from price divergence. A reference ratio and fee schedule are not a promise of a stable price.

## 9. Governance

Governance activates when at least five validators have bonded an aggregate 50,000 VELD of qualifying weight. Each validator contributes at most the 10,000 VELD minimum bond toward this activation threshold. Ordinary staking and governance participation are separate roles.

Registered, recently active validators submit proposals and vote. The voting window is 6,720 blocks. General proposals require 51% yes; the quorum is seven votes when at least seven validators are recently active and otherwise follows the majority rule for the active set. Protocol-upgrade proposals require 67% yes with at least ten votes, followed by a 3,360-block timelock.

The 3.1.3 migration applies the upgraded operation formats and retained-state rules at the same inclusion-height boundary as ASERT and the minimum-stake change. Historical records continue to use their applicable validation rules. A passing proposal records on-chain approval; it does not replace binaries or silently rewrite compiled consensus parameters. Protocol changes still require published source, an activation plan, and operator adoption.

## 10. Synchronization and recovery

### 10.1 Independent validation

A node validates transactions, proof of work, and module state locally. Initial block download can run from peers. An eligible clearnet start may import an official signed snapshot after checking its signature, deployment identity, launch anchor, structure, and hashes.

A snapshot accelerates access to stored data but does not replace independent validation. A separate chainstate verifies from genesis and must match the snapshot's height, block hash, and complete state. Mining, validator signing, inbound peer service, RPC, and the local Explorer remain quarantined while the required independent verification is incomplete. Matching the foreground height alone does not make a node ready to mine.

`--full-ibd` and `--no-snapshot` skip snapshot import. Previously imported data still requires its applicable verification. Tor-only synchronization uses peers without HTTPS snapshot downloads. Invalid or mismatched data is not silently accepted as verified state.

### 10.2 Recovery retained from 3.1.2

The client persists independent verification progress through protected atomic writes, checks saved progress against canonical state, and refreshes progress when a reorganization changes the corresponding block. Interrupted snapshot quarantine and cleanup are completed consistently across restarts. Validation receipts cover non-mining nodes and separate payout addresses and are serialized with canonical transitions.

Finality journals retain authentication and expiry handling during restoration. A recovered file or matching tip is not enough to bypass the required evidence. Once the independent result is qualified, the client records it and restarts once to enable the normal services. Mining still waits for ordinary peer synchronization.

Windows process management recognizes an already-running daemon, handles stop/restart transitions, and bounds repeated recovery relaunches. Repeatedly force-restarting a client that is making progress can delay completion. A routine software upgrade does not require deleting the data directory or regenerating wallet identities.

### 10.3 Diagnostic interpretation

The GUI version and running daemon identity are reported separately. A diagnostic record can include daemon build identity, network profile, activation information, process state, verification progress, warnings, and connection reasons. Unavailable local status is represented as unknown rather than proof of zero hashrate or an inactive miner.

During snapshot verification, deliberately paused wallet/RPC access is distinguished from a port-binding failure. Connection identifiers support diagnosis without displaying peer addresses. A reconnect, missing report, or incomplete synchronization sample does not alone identify a common fleet failure or justify a destructive resynchronization.

## 11. Wallets, operations, and updates

The official services are the homepage and download site, the Explorer, Veld Wallet, and the mining Portal. The how-to library covers wallet creation and backup, importing a keyfile, staking and unstaking, first synchronization, CPU mining, multiple machines, updates, and remote monitoring.

Wallet transaction signing occurs locally. Operators must protect encrypted keyfiles, their passphrases, the device, and any authorized remote account. The Portal provides monitoring and permitted client controls; it does not independently certify every machine's consensus state.

Use the signed updater or download from `https://veld.network/#download`. Verify the package manifest and detached Veld signature with the expected release authority. GUI and terminal distributions have separate signed feeds. Source tags, source archives, and signed binary manifests identify related but distinct artifacts.

Miners and node operators must install 3.1.3 before block 3,840. Keep wallet backups and existing chain data. The upgrade retains the network identity and checkpoint protection. Operators should verify the daemon's version, profile, completed synchronization, fresh peer evidence, and canonical tip after updating.

For service health, height alone is insufficient. Useful evidence includes a stable process, completed independent verification, fresh distinct outbound peers, matching block hash and complete state digest, and progress observed over time. Fleet counts and public address groups do not reveal the health or ownership of every physical miner.

## 12. Security assumptions and protocol limits

Proof-of-work security depends on honest work, timely propagation, correct validation, and resistance to resource exhaustion. CPU-oriented mining does not prevent concentration or collusion. A reorganization can alter recent transaction inclusion; clients must reconcile their UTXOs, mempool, derived indexes, and reward displays with the canonical chain.

Validator finality adds accountable signing but depends on sufficient eligible participation and key security. A set of different keys is not proof of different owners. Bitcoin anchors depend on verified Bitcoin work, inclusion, confirmations, and durable local observation. None replaces native transaction validation.

btcVELD depends on custody, Bitcoin proofs, replay protection, retained reserve state, signer availability, and payout operation. The aggregate cap limits exposure but does not insure funds. Liquidity adds market and contract risks. Staking multipliers and lottery entries describe allocation rules rather than fixed returns.

The software is subject to implementation and operational failure. Source review, regression tests, crash-recovery fixtures, platform builds, and signed publication provide evidence about specific behavior. They do not establish a warranty or eliminate the need for monitoring, backups, independent review, and coordinated upgrades.

## 13. Implementation and release references

This revision describes Veld 3.1.3, source commit `e4921fd8d736e76c3ce5d81574c492ba00d0e60c` and source tree `e80fb25bde90ffff4fe711280fcc408458b174cf`. The initial 3.1.2 artifacts incorrectly share the ordinary-staking threshold with co-mining after activation. The correction restores the independent 1,000 VELD lottery floor. Operators require the 3.1.3 client before block 3,840. The original signed release identity remains preserved.

| Area | Source reference |
|---|---|
| Network, activation, and monetary parameters | `include/core/constants.h` |
| ASERT integer calculation | `include/core/asert.h` |
| VeldHash | `include/mining/veldhash.h` |
| Block admission and replay | `include/core/blockchain.h` |
| Coinbase economics and compatibility | `docs/consensus/coinbase-policy.md` |
| Staking and co-mining | `include/consensus/staking.h`, `include/consensus/nms.h` |
| Validator and governance state | `include/consensus/validators.h`, `include/consensus/governance.h` |
| Coordinated state migration | `include/consensus/security_state_migration.h` |
| btcVELD and the pool | `include/core/onchain_tokens.h`, `include/core/amm_pool.h` |
| Node lifecycle and recovery | `src/veld-node.cpp`, `include/node/node.h` |
| Build and package identity | `BUILDING.md`, `docs/source-identity.md` |

Public references:

- Source and release: https://github.com/veldnetwork/Veld-Mainnet/releases/tag/v3.1.3
- Signed downloads: https://veld.network/#download
- Network rules: https://explorer.veld.network/rules
- How-to library: https://veld.network/how-to/
- Staking guide: https://veld.network/how-to/stake-veld/
- Release identity: https://veld.network/downloads/RELEASE-IDENTITY-3.1.3.json

## 14. Glossary

**ASERT:** An exponential difficulty adjustment that uses elapsed chain time and height progression relative to an anchor. VELD activates it at block 3,840.

**LWMA:** Linearly weighted moving average; VELD's historical difficulty algorithm below the upgrade.

**Atomic unit:** One hundred-millionth of a VELD.

**Coinbase:** The block transaction distributing its permitted subsidy and fees.

**Effective subsidy:** Scheduled issuance limited by the remaining supply headroom.

**Inclusion height:** The height of the block that contains a transaction or operation.

**Near miss:** Valid share evidence that meets the co-mining target without meeting the full block target.

**Finality certificate:** Authenticated validator votes meeting the required quorum and context rules.

**Bitcoin anchor:** A verified Bitcoin commitment to finalized VELD history.

**btcVELD:** Bitcoin represented on VELD under the custody, issuance, and redemption rules.

**AMM:** Automated market maker; VELD's on-chain constant-product VELD/btcVELD pool.

**Independent verification:** Validation from genesis in separate state, including proof of work, before a snapshot can be qualified.

**State digest:** A deterministic commitment used to compare the complete relevant chain state.

**VeldHash:** VELD's memory-hard proof-of-work algorithm.
