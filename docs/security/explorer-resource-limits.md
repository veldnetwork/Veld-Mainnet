# Explorer block-page resource accounting

Applies to the Explorer hash and height HTML block-page routes. This is an engineering allocation model, not measured process RSS.

- Both aliases take all 128 Explorer memory units before routing. Other admitted
  Explorer work drains first; one block page can be active at a time.
- The height alias resolves a canonical hash without retaining a body. It then
  uses the same renderer as the hash alias.
- The renderer caps each target or historical serialized body at 1 MiB. Cold
  storage applies this limit before deserialization. A resident oversized body
  is checked before a request-owned copy; that size check can temporarily
  serialize an existing transaction bounded by the consensus 8,000,000-byte block
  envelope. Ordinary consensus/RPC callers retain the existing envelope.
- At most two request-owned decoded bodies coexist: the target and one historical
  body. Referenced output metadata is capped at 8,192 outpoints. It contains no
  script, transaction or block ownership.
- Per-body structural expansion is dominated by output records (at least nine
  serialized bytes each), input records (at least 41), at most 4,096 transaction
  records, script allocations, and container capacity. A conservative 32 MiB
  allocation allowance for each 1 MiB decoded body covers supported 64-bit record
  sizes, capacity growth and ordinary per-allocation overhead. A further 32 MiB
  covers the bounded raw loader/serializer transients, including an oversized
  resident-body size check; 32 MiB covers metadata, bounded HTML and headroom.
- Output flows and accumulated rows are checked against 2 MiB construction
  thresholds. The existing 4 MiB final response cap remains. The small append
  that crosses a threshold is bounded by the capped target body/scripts.

A target body above the display budget returns HTTP 503 with a block-RPC hint.
Historical bodies above the display budget are not decoded, and unresolved fees
remain unknown. Larger valid blocks remain valid consensus data and available
through their existing block RPC interfaces. Reverse proxies and pages should
handle this deliberate display limit.

This allocation model does not establish measured process RSS or total service
capacity under load. Platform allocator behavior, shared chain caches and
non-block Explorer routes are outside the claimed request-owned bound. Do not
advertise 128 MiB as an absolute process memory limit.
