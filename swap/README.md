# btcVELD services

This directory contains Bitcoin relay, reservation, issuer, witness, redemption,
custody, and reconciliation components. Native consensus and transaction code
remain under [include/](../include/). Published source is separate from service
activation and custody readiness.

## Service map

| Area | Entry points and modules |
| --- | --- |
| Bitcoin headers and anchors | [veld_btcrelayd.py](veld_btcrelayd.py), [veld_anchord.py](veld_anchord.py) |
| Deposit admission and reservations | [veld_wrapd.py](veld_wrapd.py), [veld_c1_reservationd.py](veld_c1_reservationd.py), [swap_admission.py](swap_admission.py) |
| Issuer and mint policy | [veld_mintd.py](veld_mintd.py), [veld_signerd.py](veld_signerd.py), [rtp1_mint_policy.py](rtp1_mint_policy.py) |
| Independent witness and backing evidence | [rtp1_watchtower.py](rtp1_watchtower.py), [rtp1_backing_evidence.py](rtp1_backing_evidence.py), [issuer_signing_evidence.py](issuer_signing_evidence.py) |
| Redemption and payout | [veld_redeemd.py](veld_redeemd.py), [veld_payout_signerd.py](veld_payout_signerd.py), [veld_redeem_commitment.py](veld_redeem_commitment.py) |
| Native settlement and transport | [native_custody_service.py](native_custody_service.py), [native_custody_settlement.py](native_custody_settlement.py), [native_custody_wire.py](native_custody_wire.py) |
| Reconciliation | [reconcile_mint_state.py](reconcile_mint_state.py), [reconcile_witness_restore.py](reconcile_witness_restore.py), [veld_peg_solvency.py](veld_peg_solvency.py) |
| Shared boundaries | [rpc_url_policy.py](rpc_url_policy.py), [instance_lock.py](instance_lock.py), [veld_chain_identity.py](veld_chain_identity.py), [veld_custody_binding.py](veld_custody_binding.py) |

The implementations include migration and legacy compatibility paths. Select the
intended protocol and chain explicitly; similarly named services are not
interchangeable deployment profiles.

## Configuration and dependencies

- [System design](../docs/btcVELD-DEX-design.md)
- [Custody security](../docs/btcVELD-custody-security.md)
- [Intended-chain and issuer binding](deploy/ISSUER-CHAIN-BINDING.md)
- [Issuer/witness runbook](deploy/MINT-SIGNER-WITNESS-RUNBOOK.md)
- [Full-descriptor policy](deploy/CUSTODY-DESCRIPTOR-POLICY.md)
- [Windows file boundaries](deploy/WINDOWS-OPERATOR-FILE-BOUNDARY.md)
- [Activation prerequisites](deploy/GO-LIVE.md)

Python dependencies and hashes are pinned in [requirements.txt](requirements.txt).
JavaScript dependency inputs are under [jsdeps/](jsdeps/). Preserve dependency
licenses and [provenance records](../THIRD_PARTY_NOTICES.md).

Files under `deploy/` are configuration references and operator tools, not
evidence of active authority. Keep real keys, credentials, reservations, custody
inventories, and runtime databases outside the repository. Examples must not be
used to infer live signer identities, descriptors, or funding.

## Authority and verification

The custody policy remains exactly **3 of 5 independent community operators**,
with no fleet custody keys or recovery authority. Candidate enrollment does not
grant authority over existing custody funds. Threshold signing alone does not
prove unique payout authorization or safe recovery from surviving signatures.

Component tests are the adjacent `test_*.py` modules and disposable fixtures in
[fixtures/](fixtures/). Inspect each test's dependencies and network scope before
execution. Use disposable keys and isolated networks for funded service tests.
Passing unit tests does not qualify the complete issuer/witness pipeline,
custody migration, managed signer, or funded mainnet operation. See the
[release qualification limits](../docs/release-3.2.2-qualification.md).
