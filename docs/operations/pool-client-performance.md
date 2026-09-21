# Pool client performance qualification

The client retains one private VeldHash scratch allocation per CPU worker.
Every nonce still rebuilds the complete canonical scratch state, registers and
program. The network target remains the VeldHash input; the accounting target
only determines which completed proofs are submitted. Validation callers use
the fresh-workspace path by default. A workspace must never be shared across
concurrent callers.

The authenticated transport allows at most four concurrent requests per client,
including at most three work requests. This leaves a connection slot for proof
submission or account retrieval. Queueing consumes the existing 20-second
transport deadline. Neither queueing nor a retry extends a job's expiry.
Certificate verification, bounded responses, exact-proof retries and server
admission limits remain unchanged.

New GUI configurations request 1,024 nonces per lease. Existing configurations
with smaller batches remain valid; the native client accepts up to the server's
existing 4,096-nonce limit. Job TTL remains capped at ten seconds. Unused nonces
remain reserved rather than being recycled. Larger leases never earn credit by
themselves: only independently verified proofs enter accounting.

## Reproducible checks

Use all three public profile definitions for hashing and native client tests:
`VELD_MAINNET_POW`, `VELD_PUBLIC_MAINNET`, and `VELD_PUBLIC_RELEASE`. Never reduce
the dataset size for a production-parameter benchmark.

- `tests/mining_workspace_tests.cpp`: retained known-answer vectors, two
  independent workers, fresh/reused parity, and refusal/recovery after a wrong
  target. Pass `tests/fixtures/veldhash-3.0.9-vectors.txt` to the executable.
- `tests/mining_workspace_benchmark.cpp`: full production dataset, alternating
  fresh/reused trials, identical nonce sequences and output checksums. This is
  an offline single-thread benchmark, not pool throughput or mining E2E.
- `tests/pool_request_budget_tests.cpp`: request bounds, reserved proof
  capacity, queue deadlines, exception cleanup and concurrent admission.
- `python -m pool.test_client_scheduling --binary PATH --openssl PATH`: native
  workers over private loopback TLS, 14/64 threads, legacy/new/maximum batch
  sizes and rejection of an oversized job. Zero-TTL jobs are explicitly
  synthetic; no hashing or earnings are claimed by this transport fixture.
- `python -m pool.test_client_diagnostics --binary PATH --openssl PATH`:
  certificate/identity/schema refusal, bounded retries and private-error
  redaction using loopback fixtures.
- `tests/pool_gui_worker_ownership_tests.cpp`: real Windows Pool controls write
  the new default and own the native worker across normal exit and a crash.
  The fixture connects only to a closed loopback port.
- `python -m unittest pool.test_core -v`: exact accounting, receipt cutoffs,
  journal recovery and refusal of rollback. Focused tests, not native E2E.

Record compiler, source identity, flags, binary hashes and raw results for the
exact candidate. Keep dirty development builds distinct from clean production
controller builds. The full Windows release controller additionally requires
matching node/wallet provenance before packaging the GUI and worker together.

## Interpretation and rollout

Compare paired trials on the same hardware; record background load. A local
hash-loop improvement is not a guarantee of the same live pool gain. The pool
hashrate estimate uses verified shares over a window and naturally fluctuates.
Measure client hashes, retries, stale/invalid work, server verification backlog,
connection throttles and actual block admission separately.

An unsigned candidate is not a replacement for a signed installed client. Stage
these changes through the normal package, updater and release qualification.
Do not silently replace workers in a running signed installation or launch
additional background mainnet workers to benchmark the change.
