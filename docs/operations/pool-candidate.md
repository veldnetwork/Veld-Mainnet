# Isolated pool candidate

This is unfinished development source, not a launch-qualified package. No public
pool endpoint is configured. Production keys, real funds, and public-chain writes
are outside this candidate's qualification scope.

## Connected development path

The TLS gateway exposes only registration, work, submission, and private account
viewing. It forwards bounded messages to a local coordinator socket. It does not
receive the backend's RPC token, template admission token, or signing seeds.
Worker and account-view credentials are different. A payout address alone does
not authorize private account viewing. Registered payout addresses are immutable.

The coordinator obtains complete candidates from the node's canonical mining
builder. Settlement and finality metadata use the same construction path as solo
mining. Submitted blocks still pass normal node admission and module validation.
The fleet role continues to refuse mining template construction.

Nonce leases are recorded before delivery. Their high-water mark belongs to the
chain and immutable template, not a connection, expiring token, or job alias.
Receipt identity additionally binds the nonce. Expiry never recycles a range.
Only verified VeldHash work receives credit. Busy verification is retryable.

## Accounting policy

Each job freezes its accounting target. A valid share's expected-work weight is
exactly 2^256 divided by that target, under the native strict-less-than proof rule.
The PPLNS cutoff is the winning receipt's durable arrival sequence. The lookback
is twice the winning job's network expected work. The oldest included share may
contribute a fractional boundary weight. Startup allocates over the work actually
present. The winning share appears once. Invalid or stale receipts earn no credit.

Credits refer only to actually received miner-category income. Special blocks
with no miner income produce zero credit. Exact fractional base units remain in
the earning records. Whole spendable units are calculated with an interval that
proves the integer result, falling back to exact rational arithmetic at ambiguous
boundaries. A rounded display never alters the underlying entitlement.

The candidate service fee is zero. Automatic batches use a 1 VELD threshold and
daily scheduling. Chain receipts require at least 120 canonical confirmations
and actual node-reported spendability. Sub-threshold balances remain recorded.

## Native client and dashboard

The existing Windows client now has a Pool mining tab. Its bundled seedless
worker verifies TLS and the compiled chain identity, performs native VeldHash,
and holds only worker/account-view credentials. It does not import a wallet.
The panel supports a configurable HTTPS endpoint, payout address, private lab
CA, CPU count, start/stop, accepted-work status and balances. An explicit start
saves resume intent; Stop clears it. Different endpoint/address profiles retain
separate credentials and earnings. Installation alone does not start mining.

The public-release package verifier requires the helper in its signed manifest.
Production controller packaging includes the helper; final artifact qualification
remains required. Manually built qualification executables do not bypass the
clean-source release gate.
The current GUI lab disables production node, portal and updater startup and
uses an isolated state directory. Its result is native Windows pool-path proof,
not a whole public-client installation or solo-mode qualification.

The gateway serves a dashboard with private account balances and payment history.
View credentials are distinct from mining credentials. The dashboard keeps them
in memory, clears them on page exit, and sends no credentials in URLs. Browser
usability and client-to-dashboard access setup still need integrated qualification.

The owner's additional instruction overrides the earlier draft's yield policy:
ordinary yield from the operator's pool stake is to be shared with contributors.
Operator-contributed stake principal and fee/operating funds remain separate.
A native isolated exercise has verified a funded 1,000 VELD stake, genuine NMS
inclusion, a lottery win, an ordinary yield distribution, and payments of both
shared categories to two contributors. Independent recipient wallets matched.
This verifies that path; its full failure/reorganization matrix and the exact
final candidate still require qualification before advertising completion.

## Payment boundary

The private payment engine freezes deductions and input reservations before
invoking the native payout constructor. It uses a separate operator fee key and
does not reduce miner payments to cover network fees. The helper constructs only
the specified ordinary recipient outputs and change back to the two funding
identities; it has no raw-message, staking, withdrawal, or arbitrary-operation API.
It uses the existing ML-DSA and transaction implementations.

Exact signed bytes are persisted before broadcast. A timeout, failed response,
or disconnected confirmation retains the same obligation and bytes. It does not
authorize a replacement economic payment. A deficit caused by orphaned income
stops new payments for reconciliation. The coordinator and private payment
engine are within the accounting trust boundary; process separation alone is
not a proof against a compromised administrator.

The separate payment journal and rollback anchor must survive restoration.
Rewinding a database index alone is recoverable. Rewinding the authoritative
journal against a surviving newer anchor is refused. Loss or rollback of both
is not automatically recoverable and must never be handled by starting an empty
payment database. The native recovery exercise covers crashes before signing,
after native signing, after the signed journal, after broadcast, on both sides of
confirmation-journal acknowledgement, and a lost response. Each recovered one
economic payment. Old derived indexes recover from the surviving current journal;
stale authoritative history is refused. Native competing branches have also
verified exact-byte re-payment after a disconnected confirmation, removal of
orphaned immature income, and refusal of a fork beyond the unchanged 100-block
consensus limit. The remaining reward and validator reorganization cases and
the exact final candidate still require qualification.

## Qualification state

An intermediate native Windows exercise has now connected a GUI-managed worker
and a second native process to the real private backend over TLS, mined accepted
blocks through height 100, matured income for at least 120 confirmations,
restarted the coordinator/gateway, and confirmed ML-DSA-signed payouts. Both
recipient wallets matched the ledger on an independent P2P-validating node.
The GUI displayed the paid balance and retained it when closed and automatically
resumed. The lab uses a disposable ASERT chain and controlled historical
construction time; it does not alter reward amounts or skip proof verification.

Separate current native Windows and Linux transport tests reject wrong trust
roots/hostnames and malformed HTTP/JSON responses. Current Linux tests also
exercise token rotation, missing/invalid replacements, symlinks, special files,
unsafe permissions and bounded credential reads. These focused fixtures do not
replace adversarial testing of the combined deployed service.

Run the connected Linux exercises with:

```sh
sudo python3 -m pool.qualification.run --service-roles --output /absolute/new/evidence-directory
```

See `pool/qualification/README.md` for dependencies, isolated profiles and exact
coverage limits. This runner emits an explicit incomplete verdict for missing
required cases, even when its implemented exercises pass.

The Linux services have been exercised under the packaged systemd restrictions
with separate temporary identities, native work, independent validation, an
account-preserving upgrade and ordered shutdown. A five-minute native load
exercise reports observed share throughput, RPC latency and memory; it does not
establish maximum public capacity. The remaining full gate includes clean native
Windows installation and solo-mode interaction, the remaining co-mining and
validator failure cases, native finality certificates, and a clean combined run
on the exact final candidate.
Passing primitive benchmarks or a worker-to-wallet probe cannot replace it.
Public deployment, mainnet activation, signing, and publication are not authorized.
