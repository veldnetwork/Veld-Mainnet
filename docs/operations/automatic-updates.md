# Automatic Windows node updates

Turn on **Automatic updates** in Node Settings or in the paired portal's
**Release and updates** section. It is off until enabled. Unlock and start
the node once, locally or through **Sign in & mine** in the portal.

While the Veld app remains open, it checks the signed release feed every
hour, with an initial check shortly after startup or enabling the setting.
Mining continues while the package downloads and its signatures
and file hashes are checked. The node stops only when the verified package
is ready. A stopped node stays stopped. Automatic
installation waits while the local wallet is open.

An update or rollback reopens the verified node app directly. It does not
return to the launcher's interactive update question. The selected data
directory is carried through the updater and restart, including when the
node was stopped. The handoff allows up to 90 seconds for the old app's
bounded node shutdown and worker cleanup.

No passphrase is sent to the update service or stored in settings. Immediately
before an update restart, the app creates a one-use unlock handoff protected
by Windows for the current user. It is bound to the installation, identity,
and exact old and new package manifests. The new app consumes it once, after
normal signed-package verification. It expires after one hour. Corrupt,
expired, mismatched, unreadable, or incompletely rolled-back state cannot
unlock a node. This feature does not configure unattended Windows login or
mining after a normal PC reboot.

Download and verification failures leave the running node alone. Automatic
checks retry after one hour; a failed installation also defers the next check
for one hour after restart. Legacy clients cannot consume
the handoff and require one sign-in when first upgraded to this feature.

Native Windows tests exercise settings preservation, owner-only protected
handoffs across fresh processes, replay, expiry, tampering, file locks,
identity and manifest binding, rollback, and a failed updater child while
the original process remains alive. Portal tests cover the signed opt-in
command, persistence, authentication, and replay rejection. Release
qualification must additionally exercise the final signed package upgrade
and mining on mainnet before publication.

Opting in removes the routine need to install each release manually while
the app stays open and has internet access. It cannot guarantee recovery
from every Windows, disk, permission, or package-integrity failure. An
unrecoverable failure preserves the installation and requires attention;
the updater never bypasses signature checks to force an installation.
