# Coinbase accounting

A block's permitted coinbase value is its effective subsidy plus transaction
fees resolved against the candidate parent's UTXO state. Fees redistribute
existing units; only effective subsidy increases issued supply. The effective
subsidy is the scheduled reward, including the existing annual adjustment,
limited by the remaining supply headroom.

`ComputeCoinbaseAllocation` defines the integer allocations. For a positive
subsidy, the established rules remain:

| Context | Miner | Co-mining pool | Vault | Validator pool |
| --- | --- | --- | --- | --- |
| Every positive multiple of 100 blocks | 0 | 0 | Entire subsidy and fees | 0 |
| Ordinary block before staking activation | Half the subsidy, rounded down | 0 | Remaining subsidy and all fees | 0 |
| Ordinary block after staking activation | Subsidy remaining after the other shares | 20% of subsidy, rounded down | 20% of subsidy, rounded down, plus all fees | 10% of subsidy, rounded down |

Once effective subsidy is zero, every height uses the existing fee-only policy:
40% of fees to the vault, 10% to the validator pool, and the remainder to the
miner. Percentage allocations round down in integer units. This takes precedence
over the periodic subsidy rule, including on a multiple of 100.

Each positive category has exactly one output. The miner output is canonical
P2PKH. Zero-value payment categories are omitted. When there is neither subsidy
nor fees, the coinbase contains the canonical empty OP_RETURN, or only the
bounded finality metadata outputs. Mixing the empty marker with finality
metadata is not a canonical zero-value representation. Finality authentication
and all other transaction/module checks remain separate mandatory validation.

## Coordinated upgrade and history

The corrected admission policy is gated by `ProtocolUpgradeActive`. Public-mainnet
activation is scheduled at block 3,840. This document specifies that compatibility
boundary; it does not constitute release approval.

Before activation, the historical tip-only reward-multiple backstop and replay
semantics are retained. They can disagree on otherwise canonical coinbases with
large fees. Applying that backstop retroactively to replay would narrow historical
acceptance. Removing it from historical tip admission would expand acceptance.
Either change requires its own explicit compatibility decision.

The historical 200-output ingress ceiling is also preserved before activation.
Historical independent replay did not apply that ceiling. Mining preflight now
includes the complete historical direct rule, so it does not approve a template
that ingress would refuse. After activation, the output envelope is derived
from the existing 235 finality-fragment bound plus at most four payment
categories. The exact category checks, per-script and block-size limits, and
certificate authentication remain mandatory. This explicitly expands future
ingress acceptance for otherwise valid large certificates; it does not
retroactively change historical admission or replay.

At and after activation, direct admission, candidate-parent replay and mining
preflight use `ValidateCoinbasePolicy`. Its exact subsidy-plus-fees, category,
output-shape and count checks replace the fixed reward-multiple limits. The
structural check derives fee-only status from parent supply. It cannot be
selected by the coinbase declaring its own subsidy or fees.

Mining preflight acquires the chain's shared lock and verifies the parent before
reading UTXOs. Alternate-branch validation runs after reconstructing that
branch's parent state. Standard input authentication, duplicate-spend checks,
mandatory settlements, supply conservation and module transitions remain in
their existing acceptance paths.

## Regression coverage

`tests/coinbase_policy_tests.cpp` covers allocation, category and representation
boundaries against an independent arithmetic oracle. Its baseline control
observes the historical predicate disagreements without a network reproduction.
`tests/coinbase_chain_integration_tests.cpp` exercises signed fee transactions,
production template construction, LevelDB persistence, reorganization,
independent admission and disk replay across an isolated activation boundary.
The latter uses a distinct test-chain identity and bypasses the proof-of-work
hash comparison and host future-time bound. It retains branch target, median
time, transaction and state validation, but does not establish shipping-profile
proof-of-work or public-network qualification.

`tests/coinbase_compatibility_tests.cpp` emits a differential transcript that
can be compiled against the preserved audited source and the corrected source.
It covers both sides of the independent 2880 boundary and the private upgrade
boundary. This compares coinbase predicates with controlled UTXO inputs; it is
not a replay of historical mainnet blocks or a transaction-signature test.

`tests/coinbase_cap_admission_tests.cpp` exercises partial subsidy and fee-only
descendants through the node's admission, module and LevelDB callbacks. It also
checks rejection during alternate-branch validation and compares accepted state
after a reorganization. Its accounting parent represents assumed prior issuance:
the fixture creates no spendable funds and pays fees from signed, mature outputs
earned in the private prefix. It does not establish a genesis-to-cap history.
Reorganization ancestors stay at or above that assumed parent; replay from
genesis would reconstruct the prefix's original supply instead.

`tests/coinbase_builder_metadata_tests.cpp` compares node construction, RPC
template dispatch and standalone mining at supported heights. External builders
must refuse settlement heights that require node-owned payout engines. The
fixture also verifies fresh signed finality certificates, invalid signature,
network-domain and quorum controls, and state equality after a reorganization.
Its validator membership, prior finality record and cap supply are assumed
parent state, not a validator-registration or snapshot-authentication test.
The 2,000-member mode exercises an authenticated 207-fragment certificate;
the seven-member mode is the smaller certificate control.
`tests/coinbase_output_limit_tests.cpp` covers the historical and upgraded
output/category boundaries separately from certificate authentication.

These two node fixtures retain transaction signatures, monetary validation,
mandatory payouts and module persistence, while using the isolated hash/clock
seams. `tests/coinbase_fixture_profile_tests.py` compiles the private helper's
presence and its absence in both public profiles, and verifies that public
profiles reject the private test macros. No production activation is selected
by these tests. The source-check workflow runs admission, cap-state, small
certificate and large certificate cases as separate native jobs.

Wallet source wiring and controlled caller mutations run in the portable
qualification gate through `python tests/run_checks.py --suite source`.
