# Validator signing safety

The node and standalone validator save endorsement decisions before signing.
They refuse a different block hash for a height already signed, including after
a chain reorganization. An identical claim may be retried. Finality preserves
the signed vote and lock before releasing a vote, and retries its exact bytes.
This is local signing protection: consensus, bond/yield slashing, validator
eligibility, quorum and rewards are unchanged. No fork is required for this fix.

## Identity ownership and storage

Only one signing process may own a validator identity within an OS profile.
The lease is released automatically when that process exits or crashes. A second
process fails closed; it must not erase the journal to obtain the lease.
Different validator identities have independent leases. Mining and validation
of other people's blocks do not require this signing lease.

In addition to the existing datadir `endorsed_heights.dat` or keyfile `.endorsed`
history, signing decisions live outside the chain database:

- Windows: `%LOCALAPPDATA%\.veld-validator-safety\<genesis>\<public-key-hash>\`
- Linux: `$HOME/.veld-validator-safety/<genesis>/<public-key-hash>/`

Each directory contains `endorsed.dat` and, for finality signing, `journal.bin`
and `finality-initialized`. These contain public signing decisions, not private
keys. Treat them as essential safety state. Do not prune, delete, reset or
restore older copies while retaining the validator key. Keep the OS profile
location stable when switching launchers, service accounts or data directories.

Existing endorsement history is imported without discarding conflicting or
malformed rows. The finality daemon imports its legacy
`<keyfile>.finality-state/journal.bin` only when the shared history has never
been initialized. Once initialized, a missing journal stops signing instead of
falling back to an older backup. Existing shared history takes precedence over
a restored chain directory. Journal parsing/read/write failures stop signing;
an uncertain finality write remains stopped until a restart reloads valid state.

## Running and moving a validator

Use one active signer for a key. If a standalone validator is responsible for
an identity, do not also configure node endorsement with that same identity.
A node that cannot obtain the identity lease skips endorsements and logs the
reason; it can continue mining with its other admission requirements satisfied.
To transfer ownership, stop the previous signer before starting the replacement.

For migration to another machine or OS account, stop signing, retain the newest
complete safety directory and legacy histories together with the encrypted key,
and move them as one consistent set. Restore safety state before unlocking the
key on the destination. Do not run the old and new copies concurrently. Do not
roll a validator back to a version that ignores the shared safety store.

This local protection is not distributed coordination: copied keys on separate
machines/accounts, an intentionally changed OS profile path, deletion or rollback
of all safety copies, old software, custom signers or an administrator controlling
the signing process can bypass it. No local file journal can prove that a second
copy of a key has not signed elsewhere. Such deployments require one authoritative
signing service/state owner, not independent active copies of the key.

If history is missing or inconsistent, keep the validator stopped. Preserve the
files and recover the latest complete signing history. A canonical-chain lookup
alone cannot recover signatures released on orphaned blocks. Removing protection
to recover availability can put the bond and yield at risk.

## Verification

Run `tests/run_validator_signing_safety.py` separately on native Windows and
Linux. It builds the production signing implementation and real ML-DSA primitives
with public-profile definitions, but uses disposable keys and synthetic chain
callbacks. It does not start a node or contact mainnet. The fixtures exercise
real endorsement verification, prevotes, five-of-seven quorum verification,
precommits, exact retry, restart, concurrency, reorg decisions, storage failures,
history migration and restored datadir protection. This gate does not establish
funded-mainnet validator readiness or replace production-role build qualification.
