# Veld Pool operator panel

The panel manages the pool's recorded payment policy, payout pause/resume,
operator-funded co-mining pause/resume and canonical reconciliation. It shows
service health, miner liabilities and paginated change history. It cannot edit
payout addresses, erase earned balances, release reserved inputs, sign arbitrary
transactions, withdraw stake, execute commands or call arbitrary node RPCs.

This implementation is staged and unpublished. The owner's publication hold
also covers the admin listener, changed coordinator and website. Existing live
miners and their installed client are not migrated by these source changes.

## Access and service separation

There are three distinct service identities:

| Identity | Access |
| --- | --- |
| `veld-pool-core` | Canonical node RPC, restricted signers, economic journals and rollback anchors |
| `veld-pool-gateway` | Public HTTPS and fixed worker/viewer API; no operator socket or keys |
| `veld-pool-admin` | Private HTTPS, panel credential verifier and fixed operator IPC; no wallet/RPC keys or economic files |

The operator HTTPS listener binds `127.0.0.1:24444`, requires TLS 1.3, verifies
Host and Origin, and does not trust forwarded headers. Do not expose it through
the public pool reverse proxy. The private control socket additionally checks
the connecting process UID with Linux SO_PEERCRED. Changing a gateway request
path or using a worker/viewing token cannot grant operator access.

For remote access from Windows, use an authenticated SSH forward after the
deployment is approved (replace `OPERATOR_SSH_HOST` with the approved SSH alias):

```powershell
ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:24444:127.0.0.1:24444 OPERATOR_SSH_HOST
```

Then open `https://127.0.0.1:24444`. Keep the local and remote ports equal: the
strict origin check intentionally rejects a changed port or public hostname.
Trust the independently verified admin certificate in the operator browser.
Never disable certificate validation for an installed panel.

## Offline installation and configuration

Use the existing installer/configuration/provisioning commands from README.md
with **the same additional `--admin-user veld-pool-admin` argument on all three**.
The account must already exist, be non-root, and have a primary group distinct
from both core and gateway. `configure.py` also accepts `--admin-port 24444`.
All existing genesis, private peer, key paths, network profile and service ports
remain explicitly configured by the normal installer. This does not generate
coins, enroll validators, enable a fork or automatically connect a node.

For example, using an already verified package and new version directory:

```sh
python3 /absolute/package/setup/install.py \
  --package /absolute/package --prefix /opt/veld-pool/3.2.1 \
  --config /etc/veld-pool --state /var/lib/veld-pool \
  --core-user veld-pool-core --gateway-user veld-pool-gateway \
  --admin-user veld-pool-admin
```

Render a fresh configuration with `configure.py` and its normal explicit chain
arguments, adding `--admin-user veld-pool-admin --admin-port 24444`. Then:

```sh
sudo python3 /opt/veld-pool/3.2.1/setup/provision.py \
  --config /etc/veld-pool --state /var/lib/veld-pool \
  --core-user veld-pool-core --gateway-user veld-pool-gateway \
  --admin-user veld-pool-admin
```

The renderer produces `admin.json` and the matching coordinator `operator`
section. Provisioning creates the protected `operator-ipc` directory and
`/etc/veld-pool/admin`. The installer includes `veld-pool-admin.service` and all
HTML/CSS/JavaScript modules in the hashed package. No service is enabled or
started by these setup scripts.

Supply a certificate for IP `127.0.0.1` and its key at the generated admin paths.
For an isolated lab, a disposable certificate can be generated as follows:

```sh
sudo -u veld-pool-admin sh -c 'umask 077; openssl req -x509 -newkey rsa:3072 -nodes \
  -days 30 -subj /CN=Veld-Pool-Operator -addext subjectAltName=IP:127.0.0.1 \
  -keyout /etc/veld-pool/admin/private-key.pem \
  -out /etc/veld-pool/admin/certificate.pem'
openssl x509 -in /etc/veld-pool/admin/certificate.pem -noout -fingerprint -sha256
```

For an installed service, use the operator's approved private CA or verify the
local certificate fingerprint over the authenticated administrative connection
before importing it. Do not distribute its private key to miners.

Create a **separate panel-only passphrase** interactively; never use a wallet
seed/passphrase. There is no default password and none is accepted in argv:

```sh
sudo -u veld-pool-admin env PYTHONPATH=/opt/veld-pool/3.2.1/lib \
  python3 /opt/veld-pool/3.2.1/setup/admin_credentials.py \
  --file /etc/veld-pool/admin/access.json
```

The verifier uses a random salt and scrypt. Repeating this command rotates the
panel passphrase and invalidates existing sessions on their next request. A
missing, malformed or incorrectly protected verifier refuses requests; there
is no cached-password fallback. The admin service can restart without changing
pool economics; users sign in again because sessions are memory-only.

After separately approved installation/activation, start backend, coordinator,
then gateway/admin using the staged units. New operator-managed installations
start **with both payout signing and co-mining paused**. Inspect health/funding
and explicitly resume them from the panel. Ordinary mining continues while
these operations are paused. Never point an isolated fixture at a live datadir.

## Policies and changes

Defaults remain 0% fee, 1 VELD minimum per payout address, daily batches and at least 120 canonical
confirmations **plus actual spendability**. The panel permits a minimum of
1–10,000 VELD and whole-hour batch intervals from 1 hour to 7 days. The maturity
floor and native transaction fee cannot be lowered from this panel.

Nonzero service fees are disabled by default. A separately approved ceiling is
provisioned offline with `configure.py --approved-max-fee-ppm N` (1% is 10,000
ppm; maximum supported ceiling 100,000 ppm). This option is not enabled by the
tests or by installation. Changes remain subject to the owner's published fee
terms. A fee change records a policy revision and invalidates only the cached
job authorization: durable nonce leases/high-water marks remain intact.

Each job and receipt freezes its own fee. Mixed-policy PPLNS and co-mining/yield
windows allocate using exact rational work and fees. Old receipts stay on their
old policy even if submitted after a change. Existing earned balances never
change. Existing payment batches retain their original minimum; new batches use
the new policy. Fractional and sub-threshold liabilities remain recorded.

Pausing waits for an in-flight controlled signing operation to finish before
acknowledging. It prevents further signing/broadcast by that engine, preserves
all reservations, and continues observing already-signed payment confirmations.
It cannot revoke signatures or transactions already delivered elsewhere.

Resuming payments checks chain identity, income reconciliation and separate
spendable operator fee funds. The payment engine still rechecks backing, maturity,
funding and destinations at execution. Resuming co-mining checks the configured
restricted signer, immutable operator funding manifest, canonical 1,000 VELD
eligibility requirement and segregated fees. It may resume staking contributed
principal; it cannot spend miner liabilities or withdraw principal. Ordinary
staking yield and actual lottery winnings remain shared with contributors.

## Recovery, audit and shutdown

Each request carries an unpredictable idempotency identity and the settings
revision shown when the form was loaded. A stale form is rejected. A lost
response is retried with the **same request**, and yields the prior recorded
result instead of another mutation. Reasons and before/after settings are
recorded in the authoritative work journal; the paginated audit projection is
rebuildable. Its actor is the panel credential fingerprint, not a miner identity.

Reconcile now queues a durable, read-only-chain recheck. It creates no signature
and does not broadcast. A restart replays pending commands. Failed reconciliation
retains all reservations and displays a failure record; it does not clear a
deficit. An operator-journal write failure stops new payment/signing authority.

Back up the closed authoritative journals and protected configuration with
authenticated encryption. Retain the newest independent anchors separately.
Restoring an older SQLite cache rebuilds projections; restoring an older journal
against a newer anchor is refused. Losing or rewinding both history and anchor
is not claimed safe. Keep signing stopped and reconcile independently.

On upgrade, retain accounts, leases, receipt policies, batches, intents, journals,
anchors and panel configuration. A service which has recorded operator policy
refuses startup if the operator configuration is omitted. Old software which
does not understand operator/fee events must **not** be used for rollback.
Stop admin and gateway first, then coordinator and backend, and wait for a clean
shutdown. Do not copy a live journal or replace signed-payment history.

The panel is part of the operator trust boundary. A compromised host/root or
authorized operator can affect service availability and future fee policy within
the configured ceiling. This does not claim protection against a hostile root
rewriting both the journal and its independently retained anchor.

## Repeatable verification

From the exact source root on disposable Linux:

```sh
python3 -m unittest -v pool.test_operator pool.test_admin pool.test_install
sudo python3 -m unittest -v pool.test_admin_roles
```

For the native Windows browser check, start the disposable fixture in WSL,
passing a **new, absolute** evidence directory on a shared Windows drive:

```sh
python3 tests/pool_admin_browser_fixture.py --output /mnt/c/absolute/admin-evidence
```

In Windows, with Node.js, Playwright and Microsoft Edge installed, run the
matching repository test while the fixture is running:

```powershell
node tests/pool_admin_browser_controls.cjs C:\absolute\admin-evidence
```

Set `NODE_PATH` to the installed Playwright `node_modules` directory if it is
not installed in the repository. The fixture stops after the test signals it
or after five minutes. It writes `ready.json`, `server-result.json`, browser
`result.json`, and desktop/mobile PNGs. It has a disposable test credential
only; never run this fixture against an installed service. Browser certificate
bypass is limited to this ephemeral fixture; HTTPS certificate verification
is separately exercised by `pool.test_admin`.

Tests use actual HTTPS, private Unix IPC, coordinator, payment engine, journal,
configuration and real distinct process UIDs. They use labeled chain/signature
fixtures, not real funds. Native Windows Edge exercises the complete panel/API/
IPC path, lost-response retries, stale-form rejection, mobile layout and logout.
These tests qualify the admin integration, not native mining or mainnet payouts.
Run the complete production artifact/pool gate before any public launch.
