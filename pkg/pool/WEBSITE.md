# Pool website and private dashboard

The gateway serves the website and version-one worker API together. The public
product endpoint is `https://pool.veld.network`. A fresh Windows client suggests
this endpoint and uses system certificate trust; its optional custom CA field
is blank. Starting mining requires the miner's payout address and an explicit
Start action. Existing endpoint, account, certificate and CPU settings take
precedence. Installation must never connect or start mining automatically.

The node, Explorer, portal and website present Veld Pool, without private-test
branding. These source changes are staged locally and publication is on hold.
Public-product wording does not establish completed qualification, activate
payments or co-mining, or authorize deployment. Keep the existing live mining
qualification and its account/nonce/payment records unchanged. Internal test
receipts and incomplete qualification results retain their original meaning.

## Served paths

`/`, `/pool.css`, `/site.css` and `/pool.js` contain setup instructions, service
monitoring, reward rules, private balances and payment history. `/v1/health` is
public. `/v1/account` and `/v1/history` require the account's separate viewing
token. Worker credentials and payout addresses do not authorize private views.
`GET /v1/public` returns a strict projection of anonymous service aggregates for
the Explorer and portal Pool tabs. Only those two exact HTTPS origins receive
CORS permission, without credential support. Private routes have no CORS grant.
The reverse proxy must allow that exact GET path; keep backend RPC and admin
paths closed. Do not replace the existing worker POST allowlist with a wildcard.
The page uses the same HTTPS origin for every request. Do not host the static
page on another origin, add CORS wildcards, or put tokens into query strings.

The native client's **Open dashboard** uses its configured pool origin.
**Copy view access** copies the origin, account ID and view token; the webpage
checks the origin before importing the credentials. Tokens stay in tab memory
and are cleared on reload. The native copy opts out of clipboard history/cloud
sync. Viewing access cannot change payout destinations or sign transactions.

## Complete configuration example

Generate the full backend/coordinator configuration using the existing
`configure.py` and `provision.py` in this directory; see `README.md`. A private
gateway configuration has these exact fields (all file paths are absolute):

```json
{
  "host": "127.0.0.1",
  "port": 24443,
  "certificate": "/etc/veld-pool/tls/pool.crt",
  "private_key": "/etc/veld-pool/tls/pool.key",
  "coordinator_socket": "/var/lib/veld-pool/ipc/coordinator.sock"
}
```

For Veld Pool, the public TLS certificate must cover `pool.veld.network` and
chain to the client's system trust store; miners leave the custom CA blank.
Another pool can use a custom CA with its exact hostname in the certificate
SAN. Never bypass TLS verification or copy a production private key into a
test bundle. The gateway user gets its TLS key and IPC access,
not the backend credentials, signing keys, wallet records or economic journal.

The installed systemd unit starts the gateway with the rendered configuration.
Its initial network policy allows loopback only; adding invited miners requires
an explicitly reviewed private subnet rule and bind address. Public hosting,
port 443 routing and any reverse proxy remain a separate deployment step. Do
not use a proxy's untrusted forwarded headers to bypass connection limits.

## What the displays mean

* Reconciled height is the coordinator's last reconciled chain cursor.
* Active accounts have received work within two minutes; this is not hashrate
  or a count of physical machines. A restart clears this transient metric.
* Verified shares are cumulative accepted accounting work, not payments.
* Pending receipts are immature; available receipts have passed maturity and
  spendability checks. In-payment amounts belong to durable payment intents.
* Paid means canonically confirmed. History is bounded and cursor-paginated.
* Reward categories use actual canonical miner, lottery and staking-yield
  receipts. Orphaned receipts do not contribute. Fractional entitlements remain
  exact in the ledger even when the displayed category is rounded down.

The owner selected shared staking yield for this candidate. Operator stake
principal and fee funds remain separate. Candidate fees are 0%; the payout
threshold is 1 VELD per payout address, batches run daily, and receipts require at least 120
confirmations plus spendability. Co-mining must report disabled when unfunded.

## Operator controls

The public site and the client viewing token grant no administrative authority.
The separate [operator panel](ADMIN.md) applies journaled, versioned policy
changes over a private UID-checked socket. It controls payout scheduling,
pause/resume and reconciliation with funding checks. Its loopback HTTPS listener
is accessible through authenticated operator SSH, never through the public
gateway. Public displays read the current safe policy projection; they do not
receive administrative credentials. Defaults remain 0% fee, 1 VELD minimum per payout address,
daily batches and at least 120 confirmations plus spendability. Nonzero fees
need a separately approved offline ceiling. The implementation remains local
and unpublished under the owner's hold; existing services were not changed.

## Network hashrate

The Explorer candidate sums native canonical block work over a coherent header
snapshot of up to 144 intervals and divides by the observed timestamp range.
It never loads block transaction bodies for this estimate. The legacy public
stats adapter uses a bounded 24-interval history when that native field is absent.
The sample length and elapsed seconds accompany the estimate. Empty or flat-time
samples remain unknown; the 180-second target is not substituted as elapsed time.
This is a statistical estimate of network work, not a measurement of any miner.

## Checks before inviting a tester

The currently installed selected-miner build is independent of these staged
public-product pages. Do not replace it, update the live site/portal/Explorer,
sign a new package or publish a release as part of this copy/default change.
The owner has explicitly held all further publication. At release preparation,
rebuild from an authorized clean source identity and re-run the required gates;
do not relabel existing test binaries as newly qualified public artifacts.

Serve the page from the packaged gateway with a matching certificate. Confirm
unauthenticated monitoring, refused cross-account/cross-pool access, accepted
work, independently reconciled balances and a real confirmed payout. Restart
the client and services without replacing account/journal state. Browser
fixture screenshots alone do not qualify mining, payouts or production builds.
The installation, backup, rollback and incident procedures are in `README.md`.
