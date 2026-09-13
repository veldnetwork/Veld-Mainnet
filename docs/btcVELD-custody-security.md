# btcVELD custody requirements and current limits

The 3.2.1 source candidate is not a custody activation or a security clearance.
Native reserve authorization, refund retirement, intended-chain issuer readiness,
and the integrated community signer still require qualification. A release
signature establishes artifact authenticity; it does not establish those properties.

## Fixed custody policy

- Exactly three usable signatures from five independent community operators.
- No fleet custody keys, backups, recovery shares, or emergency signing authority.
- One Veld Node product. The proposed signer may use a bundled, automatically
  managed internal worker; participants must not administer a separate service.
- Candidate enrollment grants no authority over existing custody funds.
- Every spending path in the complete descriptor must obey the approved authority.
  Finding a 3-of-5 script fragment does not qualify other script or key paths.

Staking, co-mining eligibility, validator bonding, validator registration, and the
seven-validator btcVELD gate remain separate requirements. Changing the network-wide
validator registration prerequisite does not activate custody or qualify an issuer.

## Implemented controls and their boundaries

| Component | Source behavior | What it does not establish |
| --- | --- | --- |
| Payout collection | `swap/veld_redeemd.py` requires fixed 3-of-5 mode, validates contributions against the exact transaction, continues bounded collection, and requires Bitcoin finalization and payout-policy checks. There is no single-wallet fallback. | Five distinct IDs or commands do not prove independent operators or custody keys. |
| Signer persistence | `swap/veld_payout_signerd.py` commits local payout decisions before signing. | A local first-proposal record does not establish a globally unique authorization. |
| Custody binding | `swap/veld_custody_binding.py` validates the configured custody domain and transaction binding. | A configuration check is not a full descriptor ceremony, recovery test, or funded deployment qualification. |
| Native reserve compatibility | The legacy payout coordinator and policy signer refuse a node response containing `reserve_semantics`. | Refusal prevents an incompatible path from running; it does not implement or qualify native payout authorization. |
| Issuer authority | The issuer validator requires the intended authority and fails closed when that contract is incomplete. | Arbitrary flags, invented identities, or an otherwise valid configuration cannot satisfy production readiness. |
| Protected tokens | The watchtower reads and validates the current protected token before each request. Missing or invalid replacements fail closed. | Source parity and local rotation checks do not prove a deployed service was updated. |

## Unresolved payout authority

Two three-member subsets of five can overlap in only one member, and that member
may be dishonest. Local commitment logs and quorum overlap alone therefore do not
prove conflicting payout authorizations impossible.

Each honest signer needs independently verifiable, authoritative evidence that
binds a unique payout intent to its exact transaction and custody inputs. The
authority design must cover concurrent coordinators, chain reorganizations,
partial signatures, retries, restart, backup restoration, software rollback, and
old/new custody epochs. Adding another coordinator database or sorting inputs is
not sufficient. Any new consensus or authority mechanism requires an explicit
compatibility and activation decision.

The design must state its malicious-participant, coordinator, Veld finality,
Bitcoin confirmation, and recovery assumptions. A timeout does not invalidate
previously issued signatures or make their inputs safe to authorize again.

## Required before production activation

1. Establish five independent operators and qualify the complete custody
   descriptor, identities, key access, backup custody, and migration ceremony.
2. Implement and verify unique payout authorization and safe handling of every
   surviving partial signature, refund, reorganization, and recovery path.
3. Establish intended network/genesis binding, issuer identity and active
   authority, independent reservation witness, custody inventory, and reconciliation.
4. Qualify the managed client worker on Windows and Linux, including constrained
   signing transport, resource bounds, updates, rollback, and signing independent
   of the mining switch. Mining-resume credentials do not prove custody-key isolation.
5. Demonstrate the existing seven-validator gate and other native activation
   conditions. Do not weaken a gate to make readiness checks pass.
6. Rehearse incident containment and recovery without deleting or rewinding
   commitments. Preserve ledgers and reconcile previously authorized transactions
   before resuming. Maintenance cannot promise a usable quorum if fewer than three
   other healthy signers remain.

Funded activation and production configuration changes require separately
authorized operational evidence. Until these requirements are met, keep custody
activation blocked and describe source repairs separately from operational readiness.
