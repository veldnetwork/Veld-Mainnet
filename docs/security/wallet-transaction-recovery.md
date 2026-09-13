# Wallet transaction recovery

The browser wallet reserves transaction inputs in a network-bound IndexedDB
journal before producing input signatures. It commits the exact signed bytes
before returning them to any caller or issuing a broadcast. This applies at the
shared signature injector used by Send, stake, validator, governance, redemption,
and liquidity operations. Existing intent, fee, parent, and signer-session checks
still run.

All updated tabs in the same browser profile and origin share an exclusive Web
Lock during signing. The database atomically claims the entire input set. An
exact repeated intent reads its saved bytes; a different transaction cannot
acquire the same input. BroadcastChannel updates displays but does not grant
input ownership. No wallet seed, password, or private key enters the journal.

An unavailable response leaves the signed transaction in In-flight transactions.
Rebroadcast uses those exact bytes after the original wallet is unlocked. It
does not prepare or sign another transaction. An interrupted signing operation
retains its reviewed bytes and metadata. Resume requires user confirmation,
rechecks the original input signatures' messages and authenticated parents,
and preserves the original recipients, amounts, instructions, and fee.

Spendable views use the node's selectable output list and remove journal-guarded
outpoints. Node-pending, immature, and staked outputs are already excluded by the
node. A saved transfer amount is never subtracted again. Confirmation hides a
record from pending activity but does not remove its input guards. If a guarded
output becomes selectable again, the record becomes visible for recovery.

Older pending records migrate only after their exact transaction bytes can be
retrieved and hash-checked. An unavailable older record blocks new signing for
that wallet and remains intact. Migration cannot reconstruct transactions for
which no old record or signed bytes survive.

The implementation requires IndexedDB strict-durability transactions and Web
Locks. Unsupported browsers and unavailable, inconsistent, or full storage stop
signing. The journal allows at most 10,000 records, 100,000 input claims, and
128 MiB of conservatively charged public transaction data and metadata. Browser
quota enforcement is additional. A signed-record write failure releases no
transaction bytes. Records are not silently deleted or aged out to make space.

These are browser-local protections. Other devices, origins, profiles, older
wallet tabs, storage deletion/eviction, restored browser backups, and downgraded
wallet versions do not share a reliable monotonic history. Operators must close
older wallet tabs before using the updated wallet. Clearing browser storage or
downgrading is not a transaction-recovery procedure. This feature does not claim
network-wide input exclusivity or irreversible finality.

The disposable Chromium and WebKit controls exercise persistent process restart,
exact retry, two-tab reuse, independent input reservations, ordinary cancellation,
legacy recovery, and balance/confirmation transitions. Storage failure hooks
check rollback before signing and retention after a signed-record write failure.
A 150-input, 796,844-byte payload checks bounded storage with inert input scripts;
its duration includes the existing per-input UI scheduling and is not a
cryptographic signing benchmark. No real credentials, signatures or transaction
broadcasts are used. Desktop WebKit does not establish installed iOS PWA behavior,
hardware power-loss guarantees, or hosted deployment.
