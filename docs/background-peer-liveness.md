# Background peer liveness

An independent historical chainstate owns an outbound network server but does
not run the foreground node supervisor. Relying on that supervisor to call
BroadcastTipsig leaves the historical connections without their initial tip
announcement. A receiving node can therefore close a connection after its
90-second handshake grace period even while the connection exchanges blocks
and responds to pings.

Each PeerState now owns its tip-announcement timer. After VERSION/VERACK, the
network event loop queues the chainstate's canonical height and hash
immediately and refreshes them every 30 seconds. The timestamp advances only
after the message has been accepted by the send queue. A new connection starts
with a fresh timer, including after a server stop/start.

This changes the sender's liveness responsibility. It does not extend the
receiver's deadlines, accept malformed tips, bypass network identity checks,
promote an assumed snapshot, enable mining before independent validation, or
replace IP-distinct peer quorum with connection counts.

SnapshotConnectionTips provides an explicit view for per-connection
diagnostics. SnapshotPeerTips retains IP grouping by default for admission
callers, so connections behind the same public address do not become separate
quorum votes.

## Regression coverage

The source-checks workflow includes:

- background_peer_liveness_tests: real outbound background servers and a real
  receiving server share loopback. Two background connections survive the
  unchanged reaper, foreground supervision pauses for a minute, and one
  background server stops, starts and reconnects. The replacement remains
  connected for another 130 seconds. Peers that omit TIPSIG or supply a
  protocol-current frame with a zero tip hash still expire. All connections
  from that IP remain one quorum source.
- reliability_background_peer_tests: a loopback wire observer checks the full
  canonical tip message, prompt initial delivery, periodic delivery through
  110 seconds, and bounded stop. An isolated identity profile also supports a
  missing-required-identity negative control.
- reliability_peer_diagnostics_tests: same-IP connections, missing tips,
  unknown hashes, retired connections, and reconnects retain separate
  diagnostic identities while the quorum view remains IP-distinct.

The native runtime tests use disposable chain profiles and loopback sockets.
Linux CI additionally isolates them in a network namespace. They do not use
production data, wallets, mining keys, or live peers.

These regressions qualify the connection behavior. A public release still
requires qualification of its exact production builds, package dependencies,
signed update transaction, retained settings and pairing state, and downloaded
artifact identities.
