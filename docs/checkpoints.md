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

If the matching private key cannot be recovered, a replacement key requires
an explicit key-rotation plan and a new client release. Generating another key
does not make its signatures valid for existing clients.
