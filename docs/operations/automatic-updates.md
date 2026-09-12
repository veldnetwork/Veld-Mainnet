# Automatic Windows node updates

This feature is prepared for the next Windows client release. Released 3.1.10
clients do not include it.

Turn on **Automatic updates** in Node Settings or in the paired portal's
**Release and updates** section. It is off until enabled. Unlock and start
the node once, locally or through **Sign in & mine** in the portal.

While the Veld app remains open, it checks the signed release feed every
30 minutes. Mining continues while the package downloads and its signatures
and file hashes are checked. The node stops only when the verified package
is ready. After installation, the app resumes the previously running node
with its saved mining preference, worker count, identity, data directory,
sync progress, and pairing. A stopped node stays stopped. Automatic
installation waits while the local wallet is open.

No passphrase is sent to the update service or stored in settings. Immediately
before an update restart, the app creates a one-use unlock handoff protected
by Windows for the current user. It is bound to the installation, identity,
and exact old and new package manifests. The new app consumes it once, after
normal signed-package verification. It expires after one hour. Corrupt,
expired, mismatched, unreadable, or incompletely rolled-back state cannot
unlock a node. This feature does not configure unattended Windows login or
mining after a normal PC reboot.

Download and verification failures leave the running node alone. Automatic
checks retry after 30 minutes; a failed installation defers the next check
for six hours after restart. A successful rollback to a client supporting
the handoff can also resume the prior node. Legacy clients cannot consume
the handoff and require one sign-in when first upgraded to this feature.

Native Windows tests exercise settings preservation, owner-only protected
handoffs across fresh processes, replay, expiry, tampering, file locks,
identity and manifest binding, rollback, and a failed updater child while
the original process remains alive. Portal tests cover the signed opt-in
command, persistence, authentication, and replay rejection. Release
qualification must additionally exercise the final signed package upgrade
and mining on mainnet before publication.
