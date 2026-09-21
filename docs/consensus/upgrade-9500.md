# Public-mainnet upgrade at block 9,500

Veld 3.2.1 introduced the coordinated boundary at **height 9,500**. Version 3.2.2
retains it. Miners and node operators must use a compatible release before that
height. Historical blocks keep their original validation rules; installing a
client does not apply the new rules to earlier history.

| Area | Behavior at and after activation | Preserved requirements |
| --- | --- | --- |
| Destinations | Opt-in versioned SHA-384 commitments to the complete ML-DSA-65 public key | ML-DSA-65 signatures, existing destinations, historical validation |
| Validator participation | Registration and eligible work no longer depend on aggregate ordinary stake | Individual 10,000 VELD bond, funding/signature checks, maturity, slashing, and exit rules |
| AMM swaps | Flat 30 basis points (0.30%) in either direction; no opening-price deviation penalty | Constant-product execution, output-asset fee treatment, Bitcoin backing, and custody gates |

Validator registration is separate from forming a finality quorum. The upgrade
does not remove finality membership or warm-up rules, governance requirements,
or the seven-validator btcVELD gate. Registration alone creates no automatic
endorsement reward.

Ordinary staking remains **500 VELD minimum** under the rules introduced at
height 3,840. Co-mining eligibility remains **1,000 VELD** for the participating
economic identity. Supply, issuance, subsidy allocations, and staking terms are
unchanged by the 9,500 upgrade.

New destinations are opt-in. Existing funds are not moved and existing wallet
addresses are not silently replaced. The swap fee is separate from the native
transaction fee and price impact; it does not fix VELD's market price.

Implementation details and evidence:

- [Destination encoding and migration](../sha384-destinations.md)
- [AMM fee policy and analysis limits](../amm-market-fee-candidate.md)
- [Protocol whitepaper](../WHITEPAPER.md)
- [Release source and binary identity](../source-identity.md)
- [3.2.2 qualification scope](../release-3.2.2-qualification.md)

Source review and tests do not establish that every network operator has updated
or that custody services are ready for activation. Check live deployment state
separately from the tagged source and signed package identity.
