# Pool service architecture and recovery

This guide describes the pool implementation and its isolated qualification
boundary. The public client includes Pool mode. Configuration examples and qualification
commands do not select production credentials or authorize live transactions.
See the [mining guide](pool-mining.md) for client setup.

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

The service fee is zero. Automatic batches use a 1 VELD threshold and
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
Production controller packaging includes the helper. Manually built qualification
executables do not bypass the clean-source release gate.

The gateway serves a dashboard with private account balances and payment history.
View credentials are distinct from mining credentials. The dashboard keeps them
in memory, clears them on page exit, and sends no credentials in URLs.

Ordinary yield from the operator's pool stake is shared with contributors.
Operator-contributed stake principal and fee/operating funds remain separate.

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
payment database. Old derived indexes recover from the surviving current journal;
stale authoritative history is refused.
