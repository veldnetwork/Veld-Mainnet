# Version-one SHA-384 key destinations

This candidate retains ML-DSA-65 signatures and introduces an opt-in destination
committing to the complete 1,952-byte public key. It does not change VeldHash,
supply, subsidy allocation, staking thresholds, or custody membership.

The public-mainnet candidate height is **9,500**. This source change does not
deploy or activate an upgrade. Operators must coordinate a qualified release
before activation. Unselected development profiles disable the feature; isolated
boundary tests require both explicit test-build and test-hook definitions.
Public controllers refuse those test overrides.

## Encoding and authorization

The SHA-384 preimage is the ASCII domain `VELD:DESTINATION:MLDSA65:KEY:V1`, one NUL,
one network byte (mainnet 0, testnet 1), the compiled internal genesis hash as
64 ASCII characters, the public-key length as uint32 little-endian, and the full
public key. The 48-byte digest is never shortened to HASH160. The compiled hash
rendering is intentional; it must not be replaced with an Explorer's reversed
display or a server-supplied identity.

The script is exactly `c0 01 30` followed by that digest. Base58Check uses version
0x47 for mainnet and 0x70 for testnet, followed by the 48-byte commitment and the
existing four-byte SHA256d checksum. The checksum detects entry errors; the
authorization strength comes from the full commitment and ML-DSA signature.
The existing canonical signature envelope and SIGHASH_ALL binding are retained.

The new opcode authorizes spending only at or after activation. Historical
consensus allowed creating arbitrary output scripts; this proposal does not
retroactively reject such historical outputs. Wallet and pool preparation
additionally refuse early use of new destinations. Cached mempool validation,
mining identity admission and rollback recheck the current inclusion height.

## Wallets and migration

`veld-keygen new --out FILE --sha384-destination` creates an encrypted keyfile
for the new format. `from-seed` accepts the same option. Default generation stays
legacy for compatibility and does not silently move existing funds.

Native encrypted keyfile import and browser import preserve and locally verify
the claimed destination against the full derived public key. Browser sends,
consolidation, recipient/change review, exact-fee authentication and transaction
recovery use the versioned script. Pool account enrollment and payout signing
both check that new destinations are active.

This is a **key destination**, not a complete policy-commitment format. Existing
staking, validator, governance, token, AMM and custody identities retain their
current protocol formats. The browser refuses unsupported protocol operations
from a new-format identity rather than signing a legacy substitute. Existing
funds and positions must continue to use their original identities. The five
system addresses and Bitcoin custody descriptors are not automatically migrated.
Their policy migration and any new protocol identity scheme need separate
compatibility work. Never describe this change as making every existing address
quantum resistant or as clearing the entire custody system.

## Reproducible qualification

Native tests: `tests/sha384_destination_tests.cpp`, `sha384_chain_boundary_tests.cpp`,
`sha384_rpc_tests.cpp`, `sha384_mining_tests.cpp`. Test the actual production height
9,499/9,500/9,501 and the separately labeled accelerated funded fixtures.
Browser codec/key tests: `node tests/sha384_wallet_tests.js`.
Browser/native bridge: compile `tests/sha384_browser_bridge.cpp` with the existing
ML-DSA objects and OpenSSL libraries, run `--prepare unused legacy` and
`--prepare unused wide`, pass each resulting JSON to
`node tests/sha384_browser_bridge.js INPUT.json SIGNED.txt`, then invoke the
native binary with `--verify SIGNED.txt legacy` or `wide` respectively.

The bridge uses real browser WASM signatures, native preparation, parent and fee
authentication, native admission and independent balance checks. Its funding,
activation height and skipped PoW are explicit disposable fixtures; its transport
and journal are focused-test stand-ins. It is not mainnet or storage-recovery
evidence. `tests/wallet_outbox_browser_controls.cjs` separately checks actual
browser storage/restart behavior with inert signature fixtures.

SHA-384 algorithm reference: [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final).
Full release qualification must still rerun the connected pool, services,
co-mining, native Windows lifecycle and production controllers against the exact
final candidate. These component checks do not authorize publication.
