# Mining pool implementation

This package connects a TLS worker gateway to Veld's canonical block builder,
native VeldHash verifier, durable accounting, and restricted signing helpers.
The Windows client retains Solo mode and can select compatible pool endpoints.

## Module map

| Component | Source | Responsibility |
| --- | --- | --- |
| Worker gateway | [gateway.py](gateway.py), [protocol.py](protocol.py) | Bounded TLS requests, worker authentication, and account viewing |
| Coordinator | [service.py](service.py), [coordinator.py](coordinator.py) | Job lifecycle, durable nonce leases, admission, and maintenance |
| Node adapter | [backend.py](backend.py), [node_service.py](node_service.py), [native.py](native.py) | Canonical templates, native proof checks, and normal submission |
| Accounting | [accounting.py](accounting.py), [rewards.py](rewards.py) | Exact work weights, frozen beneficiaries, and reward categories |
| Persistence | [journal.py](journal.py), [records.py](records.py) | Authoritative records, derived indexes, and recovery |
| Pool identity | [identity.py](identity.py) | Funded staking, genuine near-miss inclusion, and lottery state |
| Payments | [payments.py](payments.py) | Entitlements, reservations, exact signed bytes, and reconciliation |
| Operator controls | [admin.py](admin.py), [operator.py](operator.py), [admin_web/](admin_web/) | Separate authenticated administrative interface |
| Public dashboard | [public_status.py](public_status.py), [overview.py](overview.py), [web/](web/) | Bounded public statistics and private account views |
| Qualification | [qualification/](qualification/) | Isolated native builds, fault injection, and economic reconciliation |

Native entry points are under [src/](../src/): `veld-pool-client.cpp`,
`veld-pool-work.cpp`, `veld-pool-identity.cpp`, and `veld-pool-payout.cpp`.
The Windows panel is [include/gui/pool_panel.h](../include/gui/pool_panel.h).

## Build and operate

Use [BUILDING.md](../BUILDING.md) for toolchains and clean-source requirements.
The dedicated Linux controller builds an unsigned production-profile pool:

```sh
./build/mainnet-v2-pool.sh ../veld-build-out/linux-pool
```

Client setup is described in the [pool mining guide](../docs/operations/pool-mining.md).
Service installation and upgrade instructions are in [pkg/pool/README.md](../pkg/pool/README.md).
Read [architecture and recovery](../docs/operations/pool-candidate.md) before
operating accounting or signing services.

The public gateway must not receive signing keys, backend RPC credentials,
template authorization tokens, or administrative access. Account viewing uses
separate credentials. A payout address is neither an authentication secret nor
permission to change an account's destination.

Restore journals, independent rollback anchors, and exact signed transactions
as one reconciled authority. Never reset accounting to clear a recovery refusal.
Operator stake principal and fee funds are separate from miner liabilities.

## Verification

Focused `test_*.py` modules live next to the implementation they exercise.
The [qualification guide](qualification/README.md) defines the complete Linux
entrypoint, disposable state, native Windows requirements, and evidence format.
Its accelerated history and component fixtures must remain separate from
production profiles and live economic verification.

The [release qualification record](../docs/release-3.2.2-qualification.md) identifies
which exact artifacts were exercised. The presence of implementation or tests
does not establish completed pool or custody qualification.
