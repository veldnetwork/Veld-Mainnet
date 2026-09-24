# Architecture

Veld uses C++20 for its native programs and Python for the portal, pool, and
btcVELD services. Shared native implementation is organized under `include/`. Production
profiles and role definitions are selected by the build controllers.

## Programs

| Entry point | Responsibility |
| --- | --- |
| [veld-node.cpp](../src/veld-node.cpp) | Chainstate, peers, validation, mining, and node RPC |
| [veld-desktop.cpp](../src/veld-desktop.cpp) | Wallet, local web service, and authenticated node connection |
| [veld-node-gui.cpp](../src/veld-node-gui.cpp) | Windows launcher, package verification, and settings |
| [veld-validator.cpp](../src/veld-validator.cpp) | Endorsements and finality voting |
| [veld-keygen.cpp](../src/veld-keygen.cpp) | Key generation, encrypted files, and offline signing |
| [veld-miner-portal.py](../src/veld-miner-portal.py) | Paired-machine monitoring and operator controls |
| [veld-pool-client.cpp](../src/veld-pool-client.cpp) | Seedless TLS pool worker using native VeldHash |
| [veld-pool-work.cpp](../src/veld-pool-work.cpp) | Native pool proof verification |
| [veld-pool-identity.cpp](../src/veld-pool-identity.cpp) | Restricted pool-identity transaction construction and signing |
| [veld-pool-payout.cpp](../src/veld-pool-payout.cpp) | Restricted recipient payment construction and signing |

The fleet build uses the node entry point with mining disabled at compile
time. The standalone validator uses authenticated node RPC; it does not
maintain a separate LevelDB chainstate.

## Modules

| Directory | Responsibility |
| --- | --- |
| [include/core/](../include/core/) | Blocks, transactions, scripts, storage, UTXOs, mempool, and transaction engines |
| [include/consensus/](../include/consensus/) | Staking, validators, finality, governance, Bitcoin proofs, and state digests |
| [include/node/](../include/node/) | Orchestration, snapshot bootstrap, and local work admission |
| [include/mining/](../include/mining/) | VeldHash, candidate selection, and mining workers |
| [include/network/](../include/network/) | P2P, RPC, Explorer, desktop UI, and network identity |
| [include/wallet/](../include/wallet/) | Key storage, transaction signing, and offline signing policy |
| [include/crypto/](../include/crypto/) | Cryptographic adapters and verified primitives |
| [include/compat/](../include/compat/) | Platform sockets, files, processes, and transports |
| [include/gui/](../include/gui/) | Windows client panels, process ownership, and update recovery |
| [include/pool/](../include/pool/) | Native worker protocol, transport, and diagnostics |
| [pool/](../pool/) | Gateway, work coordination, durable reward/payment accounting, and dashboards |
| [swap/](../swap/) | btcVELD issuer, reserve, witness, redemption, relay, and custody services |

## Validation and state

The node validates transactions and blocks before committing canonical state.
Reorganizations reconstruct affected state against the alternate branch.
Consensus state includes staking, validators, finality, governance, and btcVELD
accounting in addition to the UTXO set.

Snapshot bootstrap is bound to signed network, genesis, height, tip, and state
metadata. Independent validation from genesis must complete before the node
leaves bootstrap quarantine. A snapshot accelerates availability of data; its
signature does not replace consensus validation.

Local mining and signing share a work-admission coordinator. It binds work to
the node's validated state and peer view. Ordinary inbound block validation
uses its own admission path. Test hooks are excluded from production profiles.

See the [threat model](security/threat-model.md) for the authentication, storage,
finality, and reserve boundaries that changes must preserve.

## Web applications and packaging

The wallet and Explorer include embedded HTML, CSS, and JavaScript in native
headers. Additional hosted assets live in `resources/` and `website/`.
The portal serves its application from the Python entry point.
Hosted asset updates and native client releases are separate operations.
The pool's public dashboard and authenticated operator interface are separate
applications under `pool/web/` and `pool/admin_web/`. Their credentials and
privileges are distinct. See the [pool module guide](../pool/README.md) and
[btcVELD module guide](../swap/README.md) for service boundaries.

Third-party source and generated cryptographic assets are tracked by the
[PQC provenance manifest](../vendor/pqc/provenance/PQC_PROVENANCE.tsv). Keep
their byte representation intact unless intentionally updating the dependency
and its verification records.
