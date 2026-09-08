# Checkpoints and chain validation

## Released client

Veld 3.1.0 downloads signed fleet checkpoints on clearnet and verifies them
against its compiled ML-DSA-65 public key. These records are advisory. They
do not authorize a reorganization or replace proof-of-work validation.
Tor-only clients do not download the HTTPS feed.

The released client contains no compiled Veld block pins. Qualified validator
finality and locally observed Bitcoin anchor floors are separate mechanisms
with their own activation and verification requirements. A signed snapshot
also remains subject to independent validation from genesis.

## Prepared for the next client release

The public-mainnet build pins the following historical block:

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

The change takes effect only in a new client built from this source. It has
not been added to the already published 3.1.0 binaries. Before release, verify
the source and binaries, recheck fleet agreement, and announce the update.

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

The next public-mainnet client uses a replacement ML-DSA-65 checkpoint key.
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
rechecked on all three fleet nodes at height 3,110. It verifies the replacement
key and field binding; it is not an activation of the public feed.
