# VELD Protocol Whitepaper

## A memory-hard proof-of-work network with native staking, co-mining, validator finality, and Bitcoin utility

**Network:** veld-public-mainnet-v2

**Release:** Veld 3.3.4, published 12 November 2026

**Activation:** Mainnet block 34,750

**Ordinary staking minimum:** 500 VELD

---

## Abstract

VELD is a proof-of-work network with a maximum native supply of 21,000,000 VELD and no premine. Its UTXO ledger combines CPU-oriented, memory-hard mining with native staking, a co-mining lottery, and bonded validators. Qualified validator finality can support Bitcoin anchoring and activation of btcVELD, a representation of Bitcoin held in custody. An on-chain automated market maker provides VELD/btcVELD exchange once its activation conditions are satisfied.

The target block interval is 180 seconds. ASERT adjusts difficulty after every accepted block using a 2,700-second half-life. Ordinary staking is active with a minimum of 500 VELD and a maximum of 10,000 VELD per address. Co-mining requires 1,000 VELD of ordinary stake at the mining address. Validator registration requires a separate 10,000 VELD bond before block 34,750 and 5,000 VELD from that block. The 3.3.4 activation is governed by block height; the requested 13 November 2026 noon Denver/MST time is an estimate, not a timestamp rule.

Nodes independently validate proof of work, transactions, monetary accounting, and participation state. Signed snapshots support synchronization, while independent validation from genesis remains mandatory before a snapshot-backed node can mine, endorse, or serve its normal interfaces. Durable progress and verified recovery records allow that validation to continue across restarts.

## 1. Network and current mainnet rules

### 1.1 Public network identity

The public network is `veld-public-mainnet-v2`, launched on 2 September 2026.

Nodes identify the network through its compiled profile, genesis fingerprint, protocol capabilities, and launch-chain anchor. An application version alone is not a network identity. Two peers can remain connected while running software that applies different future consensus rules.

The public genesis fingerprint is:

```
880a0057852ffcfa35119a83e556802848ed5cb469b260fb9fbd20e8b97ae77b
```

Operators can inspect `getnetworkinfo` and the release identity records to compare the profile and genesis fingerprint. RPC block-hash display order must be distinguished from the fingerprint's byte order. Matching identifiers and height do not establish completed independent verification.

### 1.2 Current mainnet parameters

| Rule | Current value |
|---|---|
| Difficulty adjustment | ASERT after every accepted block |
| Target block interval | 180 seconds |
| ASERT half-life | 2,700 seconds |
| Minimum new ordinary stake | 500 VELD |
| Maximum ordinary stake per address | 10,000 VELD |
| Co-mining stake minimum | 1,000 VELD at the mining address |
| Validator registration bond | 10,000 VELD before block 34,750; 5,000 VELD from that block |
| Vault and validator settlement interval | 480 blocks |

Staking positions retain their chosen lockup conditions. Reaching the unlock height permits an unstake transaction; funds do not withdraw automatically.

### 1.3 Consensus and operating policy

Consensus rules determine whether every validating node accepts a block. Relay policy determines what a node forwards or places in its mempool. Wallet policy governs transaction preparation and user interaction. Snapshot distribution, the hosted wallet, the Explorer, the Portal, and custody services are operational components with their own availability and trust boundaries.

Documentation and dashboards describe those components; they do not override validation. A signed update proves the origin and integrity of the distributed files. It does not certify every operating condition or satisfy a service's participation requirements.

## 2. Native ledger and proof of work

### 2.1 Ledger and signatures

VELD uses an unspent-transaction-output ledger. Inputs must reference spendable outputs, satisfy their authorization or covenant, and conserve value. Validation includes duplicate-spend checks, maturity, signatures, transaction structure, module-specific rules, and the coinbase's permitted issuance and fees.

Native transaction signatures use ML-DSA-65. The same signature family is used for validator messages and signed release artifacts where required. Address hashes, proof of work, Bitcoin custody, and endpoint security have separate assumptions; the use of post-quantum signatures does not remove those dependencies.

Under the separately activated SHA-384 destination rules, a version-one key destination commits to the complete 1,952-byte ML-DSA-65 public key with SHA-384. The preimage binds the destination version, network and compiled genesis identity. Its authorization script contains the full 48-byte commitment; it does not truncate it to HASH160. The existing signature and full-transaction signing commitment remain required.

Legacy destinations remain valid. Creating a new-format wallet is opt-in and does not move existing funds. The opt-in destination format is not a general spending-policy format. Staking, validator, governance, token, AMM and custody identities retain their existing formats, and unsupported operations from a new-format identity are refused. The five system addresses and Bitcoin custody descriptors are not automatically migrated. It would therefore be incorrect to describe every existing address or the entire system as quantum resistant.

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

ASERT calculates the required target after every block using the canonical branch's anchor, elapsed block time, and height progression. It compares elapsed time with the schedule implied by the 180-second target and applies an exponential correction with a 2,700-second half-life. The implementation uses deterministic integer arithmetic and canonical compact-target encoding.

When blocks accumulate ahead of the target schedule, the required target decreases and difficulty rises. When the chain falls behind the schedule, the target increases and difficulty falls, within the proof-of-work limit. The half-life controls the response to accumulated schedule error; it is not a promised block interval and does not schedule a wall-clock reset.

The next target is derived from accepted parent-chain evidence. Merely waiting without another accepted block does not continuously lower the next target. Random block discovery and changes in hashrate can still produce long or short intervals. ASERT responds after each accepted block.

Reorganization and independent replay must select the target from the same candidate-parent history. VeldHash supplies the proof of work for the resulting target.

## 3. Supply, fees, and coinbase accounting

### 3.1 Issuance

The maximum supply is 21,000,000 VELD. There is no premine or separately minted founder allocation. Veld 3.3.4 enables two launch-based halvings at activation block 34,750. The first reduced block is 700,801, after four complete protocol years; the second is 1,401,601, after eight. There is no third halving.

Each protocol year contains 175,200 blocks. Annual issuance is 550,000 VELD for the first four years, 275,000 for the next four, and 137,500 thereafter until the supply cap limits issuance. The corresponding ordinary base subsidies are 3.13926940, 1.56963470 and 0.78481735 VELD. The final block of each protocol year receives the integer division remainder. Height zero retains its historical subsidy. This is a block-based schedule, not a guaranteed calendar issuance rate.

The effective subsidy is the scheduled subsidy limited by remaining supply headroom. The final subsidized block can therefore issue less than the ordinary reward. Transaction fees redistribute existing units and do not increase issued supply.

### 3.2 Subsidy allocation

Staking is active on public mainnet. Ordinary block subsidies use four participation categories. Every 100th block is a periodic vault-funding block while effective subsidy remains positive.

| Context with positive subsidy | Miner | Co-mining | Vault | Validator pool |
|---|---:|---:|---:|---:|
| Ordinary block before height 700,801 | 50% | 20% | 20% | 10% |
| Ordinary block from height 700,801 | 60% | 0% | 20% | 20% |
| Every 100th block | 0% | 0% | 100% | 0% |

From block 34,750, 100% of authenticated native transaction fees go to the block miner permanently. This includes every 100th block, partial final subsidies and the fee-only era after the supply cap. Fee routing does not change subsidy allocations. Prescribed subsidy percentages round down in atomic units and the miner receives the applicable remainder.

Historical blocks retain their original rules: before activation, subsidy-era fees go to the vault, and the zero-subsidy fee allocation is 40% vault, 10% validators and the remainder to the miner. A block with no subsidy and no fees uses the canonical zero-value representation. Internal exchange trading fees and AMM swap fees are separate from native transaction fees.

### 3.3 Coinbase validation

Direct admission, alternate-branch validation, independent replay, and mining preflight apply one state-aware coinbase policy. The policy derives fee-only status from the candidate parent's issued supply. It authenticates fees against the parent UTXO state and enforces exact permitted value, payout categories, output shape, and output bounds.

Canonical miner templates must satisfy the same mandatory subsidy-plus-fee checks as received blocks, including large-fee blocks and zero-subsidy blocks on periodic vault boundaries. Required settlement transactions and finality-certificate authentication remain separate checks.

## 4. Ordinary staking and vault distributions

### 4.1 Access and limits

Staking is active on public mainnet. The minimum new ordinary stake is 500 VELD. The maximum ordinary stake is 10,000 VELD per address. Spendable funds must also cover the transaction fee.

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

Eligible mining activity can increase an address's relative vault weight.

| Mining tier | Active days required / window | Multiplier |
|---|---:|---:|
| Bronze | 7 / 14 | 1.10x |
| Silver | 25 / 30 | 1.25x |
| Gold | 165 / 180 | 1.50x |
| Platinum | 335 / 365 | 1.80x |
| Diamond | 1,000 / 1,095 | 3.00x |

Ordinary distribution weight combines eligible stake, mining multiplier, and lockup multiplier. The combined multiplier is capped at 3.00x. Weight changes a participant's relative share of a bounded distribution; it does not change issuance or specify an interest rate.

### 4.4 Distribution limits

The rewards vault settles every 480 blocks. Before block 34,750, its budget is the smaller of 90% of the cycle's coinbase inflow and 8% of available parent-state funds. From activation, surplus above a 20,000 VELD reserve target can increase that budget, still within the 8% limit. With available balance B, cycle coinbase inflow I and target R, all in atomic units:

```
backstop = floor(B * 8 / 100)
ordinary = min(backstop, floor(I * 9 / 10))
surplus = min(backstop, max(0, B - R))
budget = max(ordinary, surplus)
```

The target is not locked principal or an exact maximum balance. Ordinary payouts continue below it and can cross it. The boundary block's own incoming rewards are not spendable by that boundary's payout. Validator bond principal is held separately. Available inputs, eligible weight, recipient bounds and integer rounding determine actual payments.

One eligible recipient cannot receive more than 75% of the cycle's distribution budget. Excess remains in the vault rather than being redistributed to the remaining recipients in that cycle. Undistributed amounts are retained. These limits constrain spending; they do not establish perpetual reserve growth or a fixed future payment.

Ordinary wallet stakes remain on-chain while the browser is closed. The hosted wallet is an interface, not the owner of those funds. A user needs the correct keyfile and passphrase to authorize a later transaction.

## 5. Co-mining lottery

Until its retirement at block 700,801, the co-mining pool receives 20% of ordinary block subsidies. It distributes through a draw every 100 blocks. Qualification combines ordinary stake at the mining address with valid near-miss proof of work included in the canonical chain during the relevant window.

A near miss satisfies the protocol's share target without satisfying the full block target. It must refer to eligible recent chain state, meet signature and uniqueness requirements, and be admitted on-chain. The client submits qualifying work automatically. A locally found or merely broadcast share is not yet an included share.

Co-mining requires at least 1,000 VELD of ordinary stake locked at the mining address. The same stake can contribute to vault distributions and co-mining eligibility; a separate duplicate lock is not required. Staking to a different address does not qualify the miner's address.

Each eligible address receives one entry, regardless of the number of qualifying near misses. Up to four near-miss records may be included in a block. The draw selects up to five distinct addresses, increasing to up to 20 when at least 1,000 addresses qualify. Winners receive one slot each; unfilled slots carry forward subject to integer rounding.

Qualification requires the stake, signature, work, inclusion, uniqueness, and lockup checks described above. One address is an accounting identity, not proof of one independent person or one physical computer.

The final normal draw is block 700,800. Retirement stops new lottery entries and draws; previous payouts and stake principal remain intact. Unassigned pool reserves are retained, not redistributed by this update. A future governance-approved software upgrade could restore co-mining with explicit rules and an activation height; no automatic return is enabled.

## 6. Validators, finality, and checkpoints

### 6.1 Validator participation

Every validator supplies its own correctly funded and authorized custodial bond: 10,000 VELD before block 34,750 and 5,000 VELD from that block. Registration uses the transaction inclusion height; at tip 34,749 the next block uses the new minimum, plus the transaction fee. This bond is distinct from ordinary stake and remains slashable. Funding, identity, signatures, synchronization, independent validation, applicable maturity and the 480-block settlement schedule remain enforced. Registration alone does not earn endorsement rewards.

The validator pool receives 10% of ordinary block subsidy before the first halving and 20% from block 700,801. Payouts depend on eligible endorsements in the settlement window. A pool allocation is not evidence that a validator has qualified for payment. Where no eligible endorsement recipient exists, the applicable settlement rules determine routing; the allocation must not be interpreted as an unconditional payout to operators.

Validator and governance operations bind their required identity, signature, and inclusion context. Reorganization and replay reconstruct the corresponding state. Governance, finality, and btcVELD each have separate participation requirements.

### 6.2 Bond penalties and yield

Ordinary endorsement equivocation and locked-finality equivocation have distinct penalties. For ordinary endorsement double-sign evidence, the settlement allocates 25% to the reporter, 25% to the vault, and 50% back to the offender. A finality-equivocation settlement returns nothing to the offender, pays 25% to the reporter, and sends 75% to a provably unspendable output. The offending key is permanently barred from re-registration under the slashing rules.

Bonded principal participates in vault distributions with a 1.50x lockup weight. Its yield is escrowed and vests over a rolling 43,200-block delay. Slashing confiscates unvested yield in addition to the applicable bond penalty; already released yield is not retroactively reclaimed.

Deregistering stops active participation but does not immediately return the principal. The bond remains held through the complete applicable evidence window, including finality votes, and returns only at its canonical settlement boundary. A pending bond cannot be reused to fund another registration. Durable local signing journals record intent before signing and refuse conflicting claims after restart; their protection depends on preserving and reconciling the journal rather than restoring an old file and immediately resuming signing.

An existing 10,000 VELD bond remains recorded at its full amount. From activation, its owner can request return of eligible excess above 5,000 VELD without deregistering. Return waits through the full 43,200-block evidence horizon covering the request epoch, then the applicable 480-block settlement boundary. The full bond remains slashable while waiting; a slash or deregistration cancels the partial-return path. Activation does not automatically return funds.

Keep one active signing machine per validator key and preserve its signing journals when updating or moving machines. Other miners can share the payout address in address-only mode. Separate machines with the same key do not share a local journal and can sign conflicting histories.

### 6.3 Qualified validator finality

Finality uses the policy at each frozen epoch snapshot. Pre-activation snapshots require seven eligible validators and cap weight at 10,000 VELD per key. Snapshots from block 34,750 use a five-key minimum and equal weights capped at the new 5,000 VELD bond minimum. Existing larger bonds do not gain extra voting weight. Validators use signed PREVOTE and PRECOMMIT messages that bind the network, epoch, phase, round, validator-set snapshot, source, and target.

A quorum certificate requires strictly more than two-thirds of eligible capped weight: four signatures from a five-key set, or five from seven. Registration maturity, consecutive qualifying snapshots and warm-up remain mandatory. Epoch 72 retains its old-policy snapshot at 34,559; epoch 73 uses the new-policy snapshot at 35,039. Three validators do not enable finality.

Standby means qualified finality is not available; validated proof-of-work operation continues under the existing rules. Certificates must be authenticated and retained. Neither height nor a dashboard label proves a qualifying set. btcVELD retains its separate seven-validator activation requirement.

### 6.4 Checkpoint protection

Public-mainnet clients enforce a compiled checkpoint at block 2,800. A conflicting history is rejected at that compiled checkpoint. Downloaded signed checkpoints are advisory and cannot move the compiled pin. The checkpoint authority and the release-signing authority have different roles.

The bounded reorganization horizon, compiled checkpoint, and qualified validator finality are distinct protections. They do not eliminate the need to validate proof of work, signatures, transactions, and state. Unconfirmed or recently confirmed transactions can still be affected by a permitted reorganization.

### 6.5 Bitcoin anchoring

After qualified finality and its warm-up, Bitcoin transactions can commit finalized VELD checkpoints. VELD nodes verify the corresponding Bitcoin header chain and inclusion proofs. A locally verified and retained anchor adds a boundary against conflicting VELD histories.

Bitcoin header relay and anchoring are different operations. Relaying headers pays ordinary VELD transaction fees and does not itself spend Bitcoin. Publishing an anchor transaction on Bitcoin incurs Bitcoin network fees. Bitcoin anchors strengthen already-finalized history; they are not an additional independent threshold for unlocking btcVELD.

## 7. btcVELD and Bitcoin custody

### 7.1 Denomination and activation

btcVELD has eight decimal places, with one atomic unit corresponding to one Bitcoin satoshi represented by the system. The accounting relationship is one btcVELD to one BTC held in custody. Market execution prices and redemption completion depend on liquidity and operating conditions.

btcVELD becomes available after seven qualified validators complete the required finality warm-up. The qualification is a one-time activation condition. New exposure can subsequently be restricted by liveness and safety gates; existing completion and redemption paths retain their separate checks.

### 7.2 Shared supply and replay accounting

Issuer-assisted and SPV-verified mint paths share an absolute 10 BTC ceiling and a Bitcoin-outpoint replay domain. Issued supply and outstanding reserved capacity consume applicable headroom. There is no separate per-address or per-mint ceiling that permits the shared cap to be exceeded.

Issuer-assisted issuance has an additional work-linked exposure tier. SPV minting remains subject to the absolute cap and Bitcoin proof rules without using that issuer-only tier. Every mint must satisfy its path's authorization, backing, uniqueness, confirmation, and state-transition requirements.

The positive touched-account floor is 1,000 satoshis; an affected account must end at zero or at least that floor. Floors and capacity limits bound retained state. They do not demonstrate solvency by themselves.

### 7.3 Assisted wrapping, redemption, and monitoring

Assisted wrapping reserves capacity before exposing a Bitcoin deposit address. Funding proofs consume the identified outpoint, and the exact completion path credits the recipient while closing the reservation. Reserved capacity cannot be treated as unused headroom for another mint.

Redemption requests burn or commit the applicable btcVELD through the prescribed transaction flow and require valid Bitcoin payout evidence. The fixed 480-block redemption window is limited to 20% of the 10 BTC absolute cap: 2 BTC per window. A request exceeding remaining window capacity is rejected rather than partially accepted.

Custody depends on its configured Bitcoin spending policy, correct payout processing, canonical VELD and Bitcoin state, and available funds. The community-custody product target is exactly three-of-five signing by five independent community operators, with no fleet custody keys, recovery shares or emergency signing authority. Candidate enrollment alone cannot grant authority over existing custody funds.

A three-of-five threshold is not, by itself, unique payout authorization: two quorums may overlap in only one malicious signer. Honest signers additionally need one independently verified authoritative payout intent, exact transaction binding and durable commitment-before-signing records. Restart, partial signatures, backup restoration and update rollback must preserve that intent. A timeout cannot revoke a Bitcoin signature that already exists.

The native intent and issuer/witness migration, managed Windows custody worker and independent-operator qualification are separate delivery and activation gates. This paper does not represent them as deployed or comprehensively qualified. The intended client manages its internal signer without a separate participant-administered service; a process wrapper alone does not establish protected custody-key access.

The issuer requires fresh authenticated solvency evidence before authorizing new exposure. Nodes independently enforce on-chain mint, reserve and redemption rules. Watchtower availability, a passing configuration check or several isolated passing tests do not establish funded custody readiness.

## 8. On-chain liquidity

The VELD/btcVELD AMM is a constant-product pool available after the peg's activation conditions are met. The first successful seed establishes the pool's reference ratio. Later reserve prices move through trading. Seed floors, permanently locked initial liquidity, transaction limits, and the first-seed liveness checks remain part of admission.

Swaps use deterministic integer arithmetic. Fees are charged in the asset received and remain in the pool's reserves. Liquidity-provider shares represent proportional ownership of the reserves, including retained fees. Withdrawal claims that proportion of both assets, subject to the transaction's validation rules.

The swap fee is 30 basis points (0.30%) in either direction, regardless of deviation from the opening ratio. VELD has no target price or stablecoin obligation. Reserve depth and constant-product pricing determine execution and price impact; btcVELD's Bitcoin backing is a separate custody obligation. The flat fee is a provisional policy choice, not a demonstrated economic optimum or a guarantee of profitable liquidity provision.

All AMM swap fees stay with the pool. Native VELD transaction fees are separate. Pool reserves share the applicable aggregate btcVELD custody ceiling; liquidity does not create a second independent allowance for represented Bitcoin.

A positive liquidity position has a 1,000-unit floor and the active-identity ceiling is 65,536. Existing positions can change within the required retained-state and arithmetic rules. These bounds control storage and admission rather than setting a market price.

Liquidity provision exposes the owner to changing asset proportions, adverse prices, shallow liquidity, contract defects, and btcVELD custody or redemption disruption. Retained fees can be less than losses from price divergence. A reference ratio and fee schedule are not a promise of a stable price.

## 9. Governance

Governance requires at least five qualifying validator bonds. Before block 34,750, the aggregate threshold is 50,000 VELD with at most 10,000 counted per key. From that height, the threshold is 25,000 VELD with at most 5,000 counted per key. Ordinary staking and governance participation are separate roles.

Registered, recently active validators submit proposals and vote. The voting window is 6,720 blocks. General proposals require 51% yes; the quorum is seven votes when at least seven validators are recently active and otherwise follows the majority rule for the active set. Protocol-upgrade proposals require 67% yes and at least ten participating YES/NO votes, followed by a 3,360-block timelock. The dynamic participation requirement can be higher; five-key finality does not lower the upgrade-vote floor.

A passing proposal records on-chain approval; it does not replace binaries or silently rewrite compiled consensus parameters. Protocol changes require published source, an activation plan, and operator adoption.

## 10. Synchronization and recovery

### 10.1 Independent validation

A node validates transactions, proof of work, and module state locally. Initial block download can run from peers. An eligible clearnet start may import an official signed snapshot after checking its signature, deployment identity, launch anchor, structure, and hashes.

A snapshot accelerates access to stored data but does not replace independent validation. A separate chainstate verifies from genesis and must match the snapshot's height, block hash, and complete state. Mining, validator signing, inbound peer service, RPC, and the local Explorer remain quarantined while the required independent verification is incomplete. Matching the foreground height alone does not make a node ready to mine.

`--full-ibd` and `--no-snapshot` skip snapshot import. Previously imported data still requires its applicable verification. Tor-only synchronization uses peers without HTTPS snapshot downloads. Invalid or mismatched data is not silently accepted as verified state.

### 10.2 Durable recovery

The client persists independent verification progress through protected atomic writes, checks saved progress against canonical state, and refreshes progress when a reorganization changes the corresponding block. Interrupted snapshot quarantine and cleanup are completed consistently across restarts. Validation receipts cover non-mining nodes and separate payout addresses and are serialized with canonical transitions.

Finality journals retain authentication and expiry handling during restoration. A recovered file or matching tip is not enough to bypass the required evidence. Once the independent result is qualified, the client records it and restarts once to enable the normal services. Mining still waits for ordinary peer synchronization.

Windows process management recognizes an already-running daemon, handles stop/restart transitions, and bounds repeated recovery relaunches. Repeatedly force-restarting a client that is making progress can delay completion. A routine software upgrade does not require deleting the data directory or regenerating wallet identities.

### 10.3 Diagnostic interpretation

The GUI version and running daemon identity are reported separately. A diagnostic record can include daemon build identity, network profile, process state, verification progress, warnings, and connection reasons. Unavailable local status is represented as unknown rather than proof of zero hashrate or an inactive miner.

During snapshot verification, deliberately paused wallet/RPC access is distinguished from a port-binding failure. Connection identifiers support diagnosis without displaying peer addresses. A reconnect, missing report, or incomplete synchronization sample does not alone identify a common fleet failure or justify a destructive resynchronization.

## 11. Wallets, operations, and updates

The official services are the homepage and download site, the Explorer, Veld Wallet, and the mining Portal. The how-to library covers wallet creation and backup, importing a keyfile, staking and unstaking, first synchronization, CPU mining, multiple machines, updates, and remote monitoring.

Wallet transaction signing occurs locally. Operators must protect encrypted keyfiles, their passphrases, the device, and any authorized remote account. The Portal provides monitoring and permitted client controls; it does not independently certify every machine's consensus state.

Use the signed updater or download from `https://veld.network/#download`. Verify the package manifest and detached Veld signature with the expected release authority. GUI and terminal distributions have separate signed feeds. Source tags, source archives, and signed binary manifests identify related but distinct artifacts.

Automatic updating is opt-in and checks on an hourly schedule. A verified update preserves configured mining mode, payout identity, CPU settings and Portal pairing. Pool mining does not require custody of the payout wallet key or a wallet passphrase. Solo mining can resume only when its separately protected, authorized resume mechanism is available. A failed signature or invalid package must not be installed. Operators should verify the running daemon identity, profile, synchronization state and mining mode after an update.

For service health, height alone is insufficient. Useful evidence includes a stable process, completed independent verification, fresh distinct outbound peers, matching block hash and complete state digest, and progress observed over time. Fleet counts and public address groups do not reveal the health or ownership of every physical miner.

### 11.1 Shared mining pool

The official production pool is paused as of this revision. The following describes the supported client and accounting design, not a claim that the service is accepting work.

Veld Node supports Solo and Pool modes. Pool mode accepts a TLS endpoint, a miner-owned payout address and CPU settings. Members do not need to buy VELD, stake personal funds, deposit coins, upload a keyfile or reveal private keys. Joining a payout address is not authorization to inspect private account details or alter another account.

The gateway serves versioned jobs with durable, non-overlapping 64-bit nonce assignments. The full node creates complete canonical candidates, including mandatory settlement and finality information. Workers receive neither backend template-authorization credentials nor signing keys. Native VeldHash verifies submissions against the network target and the frozen accounting target; invalid, duplicate, stale and temporarily busy outcomes remain distinct.

Block income uses expected-work-weighted PPLNS with a candidate lookback equal to two network blocks of expected work. Beneficiaries are frozen at the earning event. The winning share is included once. Only the pool's actual miner-category receipt is mining income; the total coinbase, vault, validator and network lottery allocations are not payable pool earnings.

The pool uses one co-mining identity with a separately operator-funded stake of at least 1,000 VELD. A genuine near miss must be signed, included and eligible in the canonical window before it constitutes an entry. Workers do not receive separate on-chain entries. Actual lottery winnings use a separate frozen qualification-window contribution record. Ordinary staking yield earned by the pool identity is also shared with contributors under its recorded distribution policy. Operator-contributed principal and fee funds remain separate from miner liabilities.

The published settings are a 1% service fee, a 1 VELD automatic payment threshold, daily batching, and at least 120 canonical confirmations plus actual spendability. The threshold applies to the eligible amount at a payout destination across its accounts; separate private account access is retained. Sub-threshold earnings are retained. Daily processing is not a promise of daily earnings.

Pending means attributed income that is not yet payable. Available means matured, reconciled earnings eligible for payment. Paid requires a canonical confirmed payment. Input reservations and durable payment intentions prevent concurrent spending. Exact signed bytes are stored before broadcast; a lost response triggers reconciliation or identical rebroadcast, never an automatic second economic payment. Backup recovery must reconcile the signer journal and independently validated chain before spending resumes. Unexplained income or a deficit is quarantined rather than silently assigned to other miners.

Public monitoring shows pool work, chain progress, rewards, payment history and service health. Private account information and operator settings require separate authenticated access. A mined block or an accepted share alone does not prove a completed payout. The qualification evidence must cover the actual recipient wallet, native Windows client, restart and payment recovery.

### 11.2 Exchange and developer platform

Veld Exchange maintains custodial trading balances and an off-chain order book separately from the native chain. Confirmed deposits and withdrawals connect those balances to their respective networks. Internal trades produce exchange operator fees; they are not native miner execution activity.

The developer workspace and SDK target a separate, valueless application-chain testnet with wallet approvals, token actions, FUEL accounting and developer-program deployment. FUEL represents execution credit backed by appchain VELD claims; one VELD corresponds to 1,000 FUEL before execution fees. Native mainnet balances and custodial exchange balances are separate. Production appchain hosting remains paused; the native 3.3.4 release does not launch production contracts, merged-mining income, a creator marketplace or collectibles.

## 12. Security assumptions and protocol limits

Proof-of-work security depends on honest work, timely propagation, correct validation, and resistance to resource exhaustion. CPU-oriented mining does not prevent concentration or collusion. A reorganization can alter recent transaction inclusion; clients must reconcile their UTXOs, mempool, derived indexes, and reward displays with the canonical chain.

Validator finality adds accountable signing but depends on sufficient eligible participation and key security. A set of different keys is not proof of different owners. Bitcoin anchors depend on verified Bitcoin work, inclusion, confirmations, and durable local observation. None replaces native transaction validation.

btcVELD depends on custody, Bitcoin proofs, replay protection, retained reserve state, signer availability, and payout operation. The aggregate cap limits exposure but does not insure funds. Liquidity adds market and contract risks. Staking multipliers and lottery entries describe allocation rules rather than fixed returns.

The software is subject to implementation and operational failure. Source review, regression tests, crash-recovery fixtures, platform builds, and signed publication provide evidence about specific behavior. They do not establish a warranty or eliminate the need for monitoring, backups, independent review, and coordinated upgrades.

## 13. Implementation and release references

| Area | Source reference |
|---|---|
| Network and monetary parameters | `include/core/constants.h`, `include/consensus/subsidy_schedule.h` |
| Coordinated 3.3.4 activation | `docs/release-3.3.4-activation.md` |
| Vault reserve and excess bonds | `docs/vault-reserve-policy.md`, `docs/validator-excess-bond-return.md` |
| ASERT integer calculation | `include/core/asert.h` |
| VeldHash | `include/mining/veldhash.h` |
| Block admission and replay | `include/core/blockchain.h` |
| Coinbase economics and compatibility | `docs/consensus/coinbase-policy.md` |
| Staking and co-mining | `include/consensus/staking.h`, `include/consensus/nms.h` |
| Validator and governance state | `include/consensus/validators.h`, `include/consensus/governance.h` |
| Authenticated state transitions | `include/consensus/security_state_migration.h` |
| btcVELD and AMM liquidity | `include/core/onchain_tokens.h`, `include/core/amm_pool.h` |
| Shared mining pool and payments | `pool/`, `include/pool/`, `src/veld-pool-client.cpp` |
| SHA-384 destination migration | `docs/sha384-destinations.md` |
| Node lifecycle and recovery | `src/veld-node.cpp`, `include/node/node.h` |
| Build and package identity | `BUILDING.md`, `docs/source-identity.md` |

Public references:

- Public source repository: https://github.com/veldnetwork/Veld-Mainnet
- Signed downloads: https://veld.network/#download
- Network rules: https://explorer.veld.network/rules
- How-to library: https://veld.network/how-to/
- Staking guide: https://veld.network/how-to/stake-veld/
- Veld 3.3.4 signed release: https://github.com/veldnetwork/Veld-Mainnet/releases/tag/v3.3.4
- Release source: `83fad356169eaf42e7bc83b652d687837b02d9f9`. Later maintenance on main does not replace signed binaries.
- Developer testnet documentation: https://veld.network/developers/

## 14. Glossary

**ASERT:** An exponential difficulty adjustment that uses elapsed chain time and height progression relative to an anchor.

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
