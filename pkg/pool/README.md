# Private pool service setup

This installer stages an unsigned candidate. It does not create users, import
funds, start a backend, connect to peers, enroll a validator or activate a fork.
Use only a disposable network for this candidate. Public deployment is separate.

Requirements: native x86-64 Linux, Python 3.11 or newer, OpenSSL 3, LevelDB and
the exact runtime dependencies recorded by the build controller; systemd for
service management. Windows clients need the matching bundled native worker.

Use `install.py --package PACKAGE --prefix VERSION_DIRECTORY --config CONFIG_DIRECTORY
--state STATE_DIRECTORY --core-user PRIVATE_CORE_USER --gateway-user GATEWAY_USER`.
Every path must be absolute. The version directory must be new. The installer
verifies every runtime artifact against the pool manifest before staging it.

The two service users must differ. The private core user owns node RPC access,
operator identity signing and payout signing. Those components are within the
accounting trust boundary. The gateway user owns only its TLS key and gateway
configuration. It cannot read the node, signing keys, journals or rollback anchors.

Render the configuration using `configure.py --help` for the complete required
paths, addresses, scripts, private peer and ports. Select `--runtime-network
regtest` only for the disposable qualification artifacts; public builds refuse
alternate transport modes. Then run `provision.py --config CONFIG_DIRECTORY
--state STATE_DIRECTORY --core-user PRIVATE_CORE_USER --gateway-user GATEWAY_USER`
as root. It applies the complete core/gateway filesystem separation, including
the setgid IPC directory, without starting services or creating keys.

Signing seeds are raw 32-byte seeds in core-owned 0700 directories and 0600
files; never include them in the distributed package. The native helper refuses
incorrectly protected key files. Supply the disposable backend passphrase and
TLS certificate/key at the rendered paths, then rerun the idempotent provisioner
to apply their ownership. The automated lab creates these test-only inputs.

The generated systemd units initially allow only loopback traffic. Configuration
must pin the compiled genesis/profile, explicit peers, explicit ports and HTTPS
endpoint. No default public endpoint is supplied. A separate reviewed private
subnet allow rule is needed to attach another test machine. Configure the backend
wrapper with `enabled: true` only after verifying these private-network settings.

For the optional secured operator panel, pass `--admin-user` consistently to
install/configure/provision and follow [ADMIN.md](ADMIN.md). It uses a third
service identity, private loopback HTTPS and its own UID-checked control socket.
It is never routed through the public worker gateway. Setup does not activate it.

The backend wrapper launches the ordinary mining-capable node with full IBD,
transaction indexing, explicit peers and no competing solo mining thread. Its
RPC token stays encrypted in the node directory. The existing local export
utility produces an owner-only runtime token used by the private coordinator;
rotation is re-exported and an invalid replacement stops service. The public
gateway receives neither that token nor template admission tokens.

When identity or payment signing is configured, the coordinator requires the
backend to report an operational transaction index before opening its journals.
It checks again during maintenance and pauses signing while the index is
unavailable. Keep `--txindex` enabled and allow validation/index recovery to
finish; bounded recent-history searches are not a substitute for this index.
Recovery uses the full canonical transaction index for signed payments and
operator transactions without a saved block reference, including receipts
older than the recent 2,016-block window. An unavailable lookup retains the
original signed bytes and input reservations; it never creates a replacement
economic payment.

Stop gateway first, then coordinator, then backend. Back up closed core journals
and key material with authenticated encryption; retain newer rollback anchors
independently. Copying an older SQLite index is safe only when the current
authoritative journal and anchor remain intact. Never reset journals or anchors
to silence a recovery refusal. Loss of both requires halted payments and manual
economic reconciliation, not automatic re-payment.

Install upgrades into a new version directory. Stop all three units, take a
consistent backup, verify artifact identities and switch the unit paths. Preserve
state/configuration/anchors and verify outstanding exact signed transactions
before resuming. Binary rollback is safe only if the older binary accepts the
current journal format and canonical chain rules. Never roll back payment or
nonce journals together with an executable. Refuse unsupported downgrade paths.

New payment batches use `operator-payment-policy-v3`: the automatic minimum
applies to the combined available whole units for one payout address. The batch
freezes each account's quota and destination. Payments preserve exact per-account
deductions, private history and any unpaid remainder. A shared payout address
does not grant access to another account. Existing batches without this scope
keep their original per-account minimum until completed; daily scheduling stays
unchanged. Never rewrite a historical batch or reset signed obligations to force
an earlier payout. Once a v3 batch exists, an older payment engine that lacks
destination grouping is not a supported rollback target. Keep payments stopped
until a compatible engine has replayed the current journal and reconciled it.

The isolated installation exercise runs these restrictions in temporary systemd
units under distinct service identities. It verifies accepted native work,
independent validation, denied gateway access to secrets, an account-preserving
upgrade, and ordered shutdown. Staging files alone is not qualification; the
exact final packaged artifacts must pass this exercise again.
