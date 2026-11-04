# Security policy

## Reporting a vulnerability

Do not disclose a suspected vulnerability in a public issue, discussion,
social post, block, transaction, or public network probe. Use the repository's
GitHub Security tab and its private vulnerability-reporting form. If that form
is unavailable, contact a repository owner privately and ask for a private
reporting channel before sending technical details.

Include only what is needed to reproduce and assess the issue:

- the affected commit, build identity, platform, and deployment profile;
- the affected component and expected security property;
- deterministic reproduction steps or a minimal proof of concept;
- impact, preconditions, and whether any real funds or credentials may be at
  risk; and
- proposed mitigations, if known.

Never include production private keys, wallet seeds, passphrases, RPC tokens,
OAuth credentials, signing keys, or private user data. Do not test against
public infrastructure, other people's systems, or live funds without prior
written authorization.

Maintainers should acknowledge receipt privately, preserve evidence, reproduce
the report in an isolated environment, assess affected versions, and coordinate
a fix and disclosure. Response or remediation time is not guaranteed.

## Security properties in scope

Security review should treat these properties as high impact:

- the 21,000,000 VELD supply cap and deterministic reward accounting;
- block, transaction, mempool, template, replay, and reorganization validity;
- validator admission, exact bond weight, quorum, finality, and slashing rules;
- btcVELD custody provenance, reserve accounting, mint/redemption gates,
  Bitcoin fork selection, payout/default handling, and rollback;
- state-digest v8 completeness and deterministic reconstruction;
- network, genesis, datadir, proof, and deployment-profile separation;
- private-key storage, local signing, authenticated RPC, remote TLS, P2P trust,
  NAT traversal, and forwarded-identity limits;
- production/test profile interlocks, build identity, release verification, and
  updater signature refusal; and
- fleet no-mine compile-time and runtime exclusion.

The public mainnet profile is `veld-public-mainnet-v2`. A report that depends on
test hooks, btcVELD regtest, accelerated subsidy, diagnostic instrumentation, or
another profile must say so explicitly. Test-only behavior is not evidence that
the production profile accepts the same behavior.

## Supported source

Security support applies to the current published release and its exact source
identity. Release-candidate branches and unsigned artifacts are review material,
not authorized releases. Older builds may be unsupported even if they remain
available in source history.

This policy is not a warranty, certification, or claim that the software is
free of vulnerabilities.
