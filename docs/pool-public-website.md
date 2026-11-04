# Public pool website

The gateway serves the website in `pool/web/`. The page makes no third-party
requests, loads no external fonts or scripts, and uses charcoal actions.
`GET /v1/public` supplies a strict allowlist of anonymous service statistics.
The same-origin private account and history APIs require the account's viewing
token. Knowing a payout address is not authorization. Tokens stay in tab memory;
Clear, reload and page exit remove private access. Clear also aborts outstanding
requests and removes the rendered private values. No destination changes,
signing controls or administrative functions are exposed by the website.

## Meaning of the statistics

- Active accounts requested authenticated work within 120 seconds. This is not
  a count of machines, connected full nodes, or measured hashing threads.
- Estimated pool hashrate is the sum of `2^256 / accounting_target` for newly
  verified shares divided by elapsed seconds, over at most 600 seconds. This is
  a statistical estimate, not a hardware measurement or capacity guarantee.
  Ten-second buckets bound storage to 61 buckets. A partially expired bucket
  is dropped conservatively, potentially understating the window by less than
  ten seconds. Sixty seconds of observation are required after startup. Replay
  never counts old work as freshly produced hashes. Delayed verification can
  briefly distort the estimate. The page reports its sample count and duration.
- Pool blocks count canonical pending or available miner receipts. Recent rows
  retain up to twelve block identities, including explicitly marked orphaned
  receipts. A zero-miner-output special block creates no miner income receipt
  and is not included in this statistic. This is not a count of all submitted
  candidates. Maturity requires canonical depth and actual spendability.
- Reward-category totals are actual pool receipts in the canonical pending or
  available state, before any applicable service fee. They are not promises,
  estimates of unearned income, or the full coinbase. Operator principal and
  fee float are excluded. Ordinary staking yield is shared under the owner's
  pool terms. Co-mining is identified as disabled when not active.
- Paid totals and transaction counts include only confirmed payment intents.
  Confirmation loss removes them until reconfirmed; signed reservations remain
  protected by the unchanged payment engine. No recipients or signing data are
  included in the anonymous projection.

The income and payment projections rebuild from existing authenticated journals
and apply before/after transitions idempotently. They cannot authorize spending,
choose beneficiaries, alter fee policy or change share admission. Health reads
use bounded cached summaries rather than rescanning lifetime income/payment
records. Public reporting retains strict schema, size and transport boundaries.
An unavailable or malformed report is displayed as unavailable; last-known
values are explicitly identified as potentially stale, not replaced with zero.

## Qualification

Run the Python pool tests using the existing isolated qualification launcher:

```sh
python3 -m pool.qualification.run --through focused --output /absolute/new/evidence
```

Use native Linux root with `--service-roles` for the separate-UID regression.
The focused development stop does not claim complete native pool qualification.
`pool/test_overview.py` covers exact rate reference calculations, bounded bins,
idempotent confirmation changes, reorgs, journal replay and public privacy.

On Windows with Node.js, Playwright, Microsoft Edge and WSL Ubuntu with Python
and OpenSSL, one command creates the loopback-only fixture, runs the browser
exercise and shuts the fixture down. Use a new output directory:

```sh
node pool/qualification/website.cjs C:\absolute\new\evidence 34648
```

The lower-level browser driver accepts an already prepared loopback-only TLS
fixture exposing the real gateway/account APIs:

```sh
node pool/qualification/public_dashboard.cjs https://localhost:PORT ACCESS_JSON CA_PEM OUTPUT_DIRECTORY
```

ACCESS_JSON contains disposable `endpoint`, `account`, and `token` only. The
driver refuses a non-loopback origin and independently verifies the test CA and
hostname before using a disposable browser trust override. It checks responsive
layout, charcoal actions, API values, authentication, history pagination, clear
and reload, no storage/cookies, response bounds, stale reporting and recovery.
Its fixture receipts are synthetic. They do not prove native mining, signatures,
lottery qualification or economic payouts. No production token is appropriate.

## Packaging and rollout

The production pool controller includes `overview.py` with the coordinator,
payment service and strict public projection, and byte-copies `pool/web/`.
Stage all changed Python modules and all four assets together in the next clean
source build. A source snapshot or website-only archive is not a newly signed
full pool release. Do not relabel earlier native test results as this source.

Deployment remains a separate owner decision. During an authorized rollout,
follow the pool service install and upgrade procedure, preserve all journals,
anchors and exact signed bytes, and verify `/v1/public` and authenticated reads
after restart. This change adds no persistent format or economic state; a
rollback uses the earlier complete service version and its matching assets,
never older journals. The original lifetime records remain authoritative.
