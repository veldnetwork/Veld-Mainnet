# Pool gateway connection reuse

The private worker gateway can reuse a TLS connection after a successful
authenticated work, submit, account or history operation when the caller
explicitly requests `Connection: keep-alive`. It still authenticates every
operation independently through the coordinator. No account authority is
associated with a connection. Anonymous routes, invalid framing, denied
credentials, resource errors, and normal legacy `Connection: close` requests
close the connection as before.

Each connection serves at most 16 responses and has a two-second idle timeout.
The existing 32 gateway slots, 16 coordinator slots, per-action rates, body
bounds, signature checks and durable accounting remain unchanged. The private
coordinator's bounded kernel accept queue is 32 instead of Python's default
five, so short scheduling bursts need not fail before an active handler can be
admitted. Operator handlers and their queue remain capped at four.

Small responses are buffered up to 64 KiB per handler and TCP_NODELAY is enabled.
This avoids unnecessary small TLS writes and acknowledgement waits when using
a retained connection. It does not change work, hash targets, fees or payouts.

## Reverse proxy

With nginx 1.24, a bounded upstream cache allows installed clients to benefit
without changing their own one-request connections. Example for the existing
private TLS upstream (replace the port and trusted CA path with reviewed values):

```nginx
upstream veld_pool_worker_backend {
    server 127.0.0.1:34643;
    keepalive 2;
    keepalive_requests 16;
    keepalive_timeout 1s;
}
```

For the existing authenticated worker API location, change only the upstream
and explicit connection preference:

```nginx
proxy_pass https://veld_pool_worker_backend;
proxy_set_header Connection keep-alive;
```

Retain HTTP/1.1, upstream certificate verification, the trusted CA, expected TLS
name, request/rate/connection limits, buffering, response-error mappings, and
disabled response caching. Do not add retries for non-idempotent requests.
Keep registration, public status, and static routes on their existing policy.

The cache is per nginx worker; two entries across four workers retain at most
eight idle upstream connections. Active plus idle connections are still bounded
by the gateway's existing slot cap. This setting is not an increase in the
gateway's admission or verification capacity.

## Qualification

- `python3 -B -m unittest pool.test_gateway_keepalive`: real TLS, Unix IPC and
  coordinator authorization with disposable state and a mock node; reuse cannot
  authorize another account or turn a worker token into a viewing token.
- `python3 -B -m pool.test_gateway_latency --baseline PATH`: actual gateway/TLS
  with synthetic coordinator payloads; validates old clients, response integrity,
  limits, idle expiry, 16-request expiry and refusal closure. A disposable network
  namespace can add delay to its loopback interface for latency measurements.
- `unshare --net -- python3 -B -m pool.test_gateway_proxy`: native nginx proxy,
  actual TLS gateway and Unix IPC in an isolated namespace; checks existing
  one-request clients, upstream connection reuse, concurrent delivery and refusal
  of an incorrect upstream certificate identity. Requires nginx, openssl and ip.

These focused transport tests do not establish mining or payout E2E. Rebuild
the pool with its normal production controller from the exact clean source.
Retain economic state and signing journals across rollout. Recheck live work,
submission errors, verification backlog and latency; do not infer a hashrate
increase directly from a transport latency reduction.

Reference: [nginx upstream keepalive documentation](https://nginx.org/en/docs/http/ngx_http_upstream_module.html#keepalive).
# Recovery read performance

Journal recovery uses a separate 64 KiB buffered reader whose device/inode must
match the durable append handle. Every bounded record, hash-chain link, rollback
anchor and cached index identity is still checked. The append handle remains
unbuffered and its write/fsync ordering is unchanged. SQLite projections remain
rebuildable, never authoritative. This does not prune or checkpoint away history.

A disposable 1 MiB regression reproduced 1,050,249 byte reads through the old
durable writer; the repaired recovery never reads that writer. Windows and Linux
recovery tests include cache tampering, oversized/truncated records, old backups,
nested replay, retained signatures and append after reopen. This measures recovery
behavior, not mining hashrate or whole-service restart time.
