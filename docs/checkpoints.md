# Checkpoints and chain validation

## Previous client: Veld 3.1.0

Veld 3.1.0 downloads signed fleet checkpoints on clearnet and verifies them
against its compiled ML-DSA-65 public key. These records are advisory. They
do not authorize a reorganization or replace proof-of-work validation.
Tor-only clients do not download the HTTPS feed.

The 3.1.0 client contains no compiled Veld block pins. Qualified validator
finality and locally observed Bitcoin anchor floors are separate mechanisms
with their own activation and verification requirements. A signed snapshot
also remains subject to independent validation from genesis.

## Veld 3.1.1 historical pin

The 3.1.1 public-mainnet build pins the following historical block:

| Height | Hash (`getblockhash` byte order) |
| --- | --- |
| 2,800 | `cca5e8f37cfcf63cd2f9a9393e5bc90dd545ef65394a1d4d1aecceffa25e25fc` |

On 8 September 2026, three fully synchronized 3.1.0 fleet nodes independently
returned this hash while the chain was at height 2,942. The pin was therefore
142 blocks behind the tip, beyond the existing 100-block reorganization bound.
The nodes also agreed on genesis, the launch anchor, activation block 2,880,
and the independently verified snapshot's block at height 2,926.

The existing block-admission and replay checks reject a mismatch at the pin.
The same compiled pin feeds synchronization and reorganization anchoring.
Other build profiles retain their own history without this public-mainnet pin.
This change does not remove proof-of-work, transaction, state, or snapshot
validation. A download server cannot move the compiled pin.

The change is active in the signed 3.1.1 release. It has not been added to
3.1.0 binaries. Windows and Linux qualification, signed package verification,
and independent fleet agreement were checked before publication.

## Signed fleet feed

The public endpoint is `https://veld.network/downloads/checkpoints.json`.
Every entry must verify under the key already compiled into its target clients
and must bind the public-mainnet network, genesis, height, hash, and signing
time. A release or snapshot signature is not a checkpoint signature.

The signing identity should remain in its protected signing environment.
Publish only verified signed records. Keep the previous valid record if a
signing or publication attempt fails, and report the failure separately from
snapshot availability. Never replace a checkpoint at an existing height with
a different hash. Confirm the selected block on independent, fully validated
nodes before signing, and select a block beyond the reorganization horizon.

## Checkpoint authority replacement

The 3.1.1 public-mainnet client uses a replacement ML-DSA-65 checkpoint key.
Its public-key SHA-256 fingerprint is
`240e7e72e393c831dff72f23fa7137a899fe729d83662ca6ffde3b7d35159a32`.
Other network profiles retain their existing checkpoint key.

The previous encrypted key was located in infrastructure backups, but its
unlock credential could not be recovered. The replacement was generated in
the operator's protected local signing environment on 8 September 2026. Its
signatures, encrypted keystore, saved unlock credential, and encrypted recovery
backup were verified before preparing the public key for this release.

Released 3.1.0 clients still trust the previous public key, whose fingerprint
is `10252e6942efdeec7f1f80292cb6b2119a95631ec07fe75b05ebde3262bd1c6e`.
They reject signatures from the replacement key and continue ordinary chain
validation because the downloaded feed is advisory. This source change does
not activate the replacement in those already published binaries.

Publish the replacement feed only with the client release that contains its
public key. Before publication, verify the release identity, independent node
agreement on the selected block, and the signed document with that client's
verifier. Keep the compiled historical pin and signed-feed authority separate;
a signed feed entry cannot move the compiled pin.

The public test fixture contains a signature over block 2,800, independently
rechecked on all three fleet nodes at height 3,110. It tests the replacement
key and field binding. A separately signed public record was published on
8 September 2026 after the 3.1.1 client became available. All three upgraded
fleet nodes accepted that record and matched its block hash.

The compiled pin has no expiry and remains active through restarts. The signed
record also has no age-based expiry in 3.1.1. Clearnet clients refresh the feed
every five minutes; a network failure does not remove the compiled pin. New
enforced heights require a qualified client update. New advisory records
require independent block verification, protected signing, and verified public
readback.

## Automatic advisory publication

The checkpoint publisher runs on n4 under its own service account. It checks
every fifteen minutes and selects the latest 100-block boundary at least 120
blocks behind the agreed tip. The 120-block depth exceeds the 100-block
reorganization limit. A run with no new eligible boundary succeeds without
signing another record.

Before signing and again before publication, n2, n3, and n4 must agree on the
tip, state digest, and candidate block hash. Each must have completed independent
historical validation, have a stable process and synchronized clock, and have
two fresh outbound peers that agree with its tip. A failed check preserves the
previous feed and reports an error.

The checkpoint authority remains separate from Windows release signing. Its
encrypted keystore and unlock credential are stored on n4 as root-owned,
host-bound encrypted systemd credentials. Only the checkpoint service receives
the decrypted credentials during execution. The service has no web listener,
no administrative shell access to the other nodes, no core dumps, restricted
outbound networking, and bounded CPU and memory usage. This is host-bound
software protection, not a hardware security module.

n3 accepts already signed records through a restricted SSH command. It verifies
the compiled checkpoint authority, preserves every previous record, and accepts
only one appended record per transaction. Installation uses an expected prior
hash, an atomic replacement, and a durable rollback journal. The signer verifies
public HTTPS readback through n2 before committing publication. Retries recover
an interrupted transaction and do not sign a conflicting hash at an existing
height.

A separate health timer on n3 checks the feed and the signer's last successful
check-in. It fails if the signer has not checked in for three hours or if an
uncommitted transaction remains. The hourly recovery snapshot job is separate
from checkpoint signing. Neither checkpoint creation nor publication depends
on an operator's PC.

The implementation is in `scripts/checkpoints/` and
`src/veld-checkpoint-tool.cpp`. `scripts/checkpoints/build-tool.sh` builds the
tool from the pinned public-mainnet authority and verifies the signed fixture.
Run `tests/checkpoint_publication_tests.py` and `tests/checkpoint_tool_tests.py`
against the built tool before changing the deployed workflow. Deployment
configuration must pin SSH host keys, restrict the service transport key to the
forced checkpoint gateway, and give that identity no arbitrary command or
forwarding privileges. Preserve the existing encrypted authority recovery
backup when enrolling or recovering a signer.
