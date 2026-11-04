# Issuer chain binding

The issuer requires explicit `veld_rpc.expected_chain` pins. Both mint and C1
signing, including cached signature replay, check them against the issuer's
authenticated, independently operated node before authorization. Required pins
are the deployment profile, consensus build profile, disposable/external-value
and fixed-difficulty flags, actual genesis block hash and height-one launch hash.
The node's compiled genesis and stored genesis must both match. An unavailable
identity or mismatch stops the request; no previously observed identity is reused.

Obtain pins from the reviewed build/profile and independently verified canonical
history. Do not learn or approve them automatically from the endpoint being
checked, a coordinator request, or a website. The example intentionally contains
unusable placeholders. Test profiles use separate disposable pins and state.

The version-two `signer-authority-state.json` marker binds all three local
authorization journals to those exact pins. Initialization creates a new empty
set only. A version-one marker, changed pins, or existing unbound files require
offline reconciliation; initialization neither adopts nor overwrites them.
One request retains one validated configuration and rechecks the marker while
holding the signer lock.

For an existing installation, keep signing ingress disabled while independent
operators reconcile the full signed-byte caches, staged signatures, prevout
leases, witness reservations, archive records and canonical transaction effects
against the intended chain. Preserve all unresolved authorizations and backups.
Changing a marker, deleting state, or importing only recent transactions cannot
establish that old signatures are retired. Automated legacy migration is not
implemented or qualified. A reviewed migration must preserve the entire
authorization set and validate restart, restore and rollback before activation.

These checks bind a trusted node to reviewed identities; they do not make a
compromised node truthful or independently prove its full history/finality.
Issuer identity and the active-authority marker, independent reservation witness,
exact custody inventory, reserve/liability reconciliation and seven-validator
activation remain separately required. The production rolling-reserve payout
gate remains closed pending native unique intent and safe signature retirement.
No custody membership, threshold, consensus economics or activation is changed.
