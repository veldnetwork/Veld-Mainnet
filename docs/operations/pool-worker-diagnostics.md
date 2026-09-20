# Pool worker failures

The seedless worker stops on certificate, identity, schema and non-retryable
service failures. Temporary transport/service failures retain the bounded retry
path. Diagnostic improvements do not authorize bypassing these checks.

After a fatal runtime error, private `pool-status.json` and the final process
receipt include `failure_code` and `failure_stage`. The Windows Pool tab renders
the corresponding fixed message. The first fatal error is retained while other
CPU workers stop; a later retry cannot overwrite it with a mining message.

Stages are configuration, registration, work, hashing, submission, balance and
state. Codes distinguish certificate/trust configuration, remote refusal, HTTP
framing, response schema, work/chain identity, account identity, private state,
and an unclassified local failure. These are diagnostic categories, not a claim
that the original cause is known. A remote refusal does not explain the server's
internal policy decision.

Only predefined categories are persisted. Raw exception text, remote error
messages, credentials and URLs are not echoed in these diagnostics. Startup
errors are reported on the process error stream; a private status-write failure
still leaves a bounded process receipt. Account credentials and previously
earned balances are not rewritten to recover from a refusal.

For investigation, collect the failure code/stage, client build identity and
time. Configuration and account files contain private access credentials and
are not diagnostic attachments. Check service health and the corresponding
private server evidence before retrying a terminal failure.

Local verification uses `python -m pool.test_client_diagnostics --binary WORKER
--openssl OPENSSL`. The suite runs the actual native worker over loopback TLS
with disposable credentials and deliberately invalid replies. Zero-TTL cases
perform no hashing; the submission-refusal case hashes one native VeldHash test
vector and submits it only to the loopback fault fixture. This suite establishes bounded diagnosis and refusal/retry
behavior, not valid mining, a payment, or production readiness.
