# Veld Node 3.2.4 candidate

The portal Pool page has separate Start pool mining and Stop pool mining
controls for the selected paired machine. A compatible client advertises this
capability; older clients remain visible but cannot receive unsupported commands.
Veld must be open, online and paired for remote controls to work. These controls
cannot wake a sleeping PC or launch a closed app.

Start uses the endpoint, payout address, certificate choice and worker count
already saved in the client's Pool tab. It never imports a wallet or requests a
passphrase. Configure the pool locally once before remote use. Unsaved local
edits must be resolved on the client. Stop turns off automatic pool resume as
well as requesting the owned worker's clean exit. Starting solo mode while the
pool worker is running is refused without a remote approval dialog.

The command uses the existing device-bound P-256 signature, owner pairing,
expiry and durable replay protection. The portal accepts no pool configuration
or payout changes in this command. Acknowledgement and the later worker report
are separate: accepting Start does not itself prove mining has resumed. The
page waits for a current hashing report; Stop waits for a subsequent stopped
report. No credentials or account viewing tokens are sent to the portal.

Pool controls no longer invalidate the entire native window on every mouse
movement or unchanged timer update. Explorer and portal mobile navigation use
the wallet's document-scroll layout. Wallet history pagination follows the
results and uses charcoal styling in both themes. The obsolete btcVELD launch
paragraph is removed, and the pool landing page repeats less introductory copy.

This candidate does not change hashing, pool accounting, payouts, consensus,
validator requirements or the activation rules already applied at height 9,500.
Production publication and qualification receipts are recorded separately;
this document alone is not evidence that a release has been published.
