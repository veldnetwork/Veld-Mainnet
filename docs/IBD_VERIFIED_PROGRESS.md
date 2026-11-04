# Initial download scheduling

Full IBD validates every historical block through ordinary proof, transaction,
module, custody and persistence checks. Snapshot signatures do not replace
independent validation. Mining admission and peer-tip evidence are unchanged.

## Forward progress and work budgets

The expensive-proof limiter retains its concurrency limits and its existing
per-source and process-wide rate envelopes. A successful forward peer block can
return exactly the rate charge for its initial proof after complete commit and
the module/persistence callback. This prevents valid historical synchronization
from being limited to eight blocks per peer per minute.

The receipt is move-only and single-use, remains separate from the concurrency
lease, and is bound to its original budget window. Only strictly increasing
credited heights qualify. Invalid blocks, failed commits, deferred work,
duplicates, side branches, reorganization replay, near-miss verification and RPC
work do not receive this credit. Returning a rate charge does not release a
concurrency slot. An old receipt cannot refund a newer window's work.

This is scheduling policy, not a change to block validity or fork choice.
Successful, fully validated progress can use the available validation capacity;
unsuccessful work retains the original abuse limits. Global and source credit
high-water marks conservatively limit repeated history and concurrent chainstates.

## Download continuation

A connection records distinct increasing locally validated bodies. After a
complete 32-body batch, its event loop may request the next suffix at a cadence
of at most one continuation per second. Unknown bodies, raw wire claims,
unverified queue entries, duplicate heights and another peer's progress do not
count. Reconnection starts with no continuation receipts.

Partial batches and stalled peers retain the ten-second idle retry. Existing
orphan, queue, byte, serving-work and peer limits remain in place. The validated
download cursor is still independent of trusted peer-height and mining evidence.

For a handshaken outbound peer with a locally issued GETBLOCKS request in the
last 30 seconds, the normal ingestion lane can retain one 32-body batch during
IBD. Unsolicited traffic, inbound peers, expired requests and post-IBD traffic
retain the two-job per-source limit. This avoids discarding a requested batch
while storage is busy. The 16 MiB per-source byte ceiling, global/lane count and
byte ceilings, protected-lane reservation, round-robin fairness and proof
concurrency/rate rules are unchanged. Multiple connections share source limits.

## Qualification

`ibd_pow_budget_tests.cpp` covers credit ownership, replay heights, unchanged
failure budgets, other work classes, concurrency and window rollover.
`ibd_sync_liveness_tests.cpp` covers completed-batch continuation and idle retry.
`pool_download_continuation_tests.cpp` covers the actual bounded locator path,
unknown and duplicate bodies and connection replacement using synthetic history.
`ibd_ingest_window_tests.cpp` checks solicited-batch retention and the unchanged
unsolicited, inbound, expiry, reconnect, byte and global queue limits.
Production-path speed and historical-validation claims additionally require
fresh native-node IBD measurements; these focused fixtures do not establish them.
