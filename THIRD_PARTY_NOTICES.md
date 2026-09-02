# Third-party notices

Veld-authored source is distributed under
`SPDX-License-Identifier: AGPL-3.0-only`. The license in the root `LICENSE`
file does not replace or alter the licenses of third-party material. The
notices below cover vendored, embedded, or source-derived code shipped in this
source tree; ordinary system libraries and toolchains supplied by an operator
remain governed by their own terms.

## Vendored and embedded components

| Component | Version or source | Veld paths | Applicable terms | Local notice or license |
| --- | --- | --- | --- | --- |
| PQClean ML-DSA-65 | PQClean commit `202a8f96315f9ed219387a50f7e40d04af037ea8`; generated NIST response SHA-256 `7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072` | `vendor/pqc/mldsa65/`, `include/crypto/mldsa65_nist_kat.h` | CC0 / public domain | `vendor/pqc/mldsa65/LICENSE`; source proof in `scripts/generate-mldsa65-nist-kat.py` |
| PQClean ML-KEM-768 | Same pinned PQClean commit | `vendor/pqc/mlkem768/` | CC0 / public domain | `vendor/pqc/mlkem768/LICENSE` |
| PQClean common Keccak/SHAKE code | Same pinned PQClean commit; public-domain Keccak sources credited in the file header | `vendor/pqc/fips202.c`, `vendor/pqc/fips202.h` | Public domain | Source-file notices and the PQClean license files above |
| PQClean `randombytes` | PQClean common code; Daan Sprenkels, 2017 | `vendor/pqc/randombytes.c`, `vendor/pqc/randombytes.h` | MIT | Full notice preserved at the top of `vendor/pqc/randombytes.c` |
| Emscripten-generated ML-DSA WebAssembly loader | Canonical checked-in artifact rebuilt twice with exact Emscripten 4.0.10 Windows x86-64 toolchain `emscripten-releases` revision `8103ffedfb0c42d231c6af6859a5a1a832260b43`; equivalent container manifest also pinned | `vendor/pqc/dilithium_wasm.js`, `include/network/dilithium_wasm_js.h` | Emscripten MIT/NCSA terms plus the PQClean terms above | `third_party_licenses/Emscripten-LICENSE.txt`, `vendor/pqc/provenance/TOOLCHAIN.lock`, and the PQClean notices above |
| jsQR | 1.4.0 | `include/network/jsqr_js.h` | Apache-2.0 | `third_party_licenses/jsQR-1.4.0-Apache-2.0.txt` |
| Terser | 5.37.0, used by jsDelivr to minify the embedded jsQR file | Build provenance for `include/network/jsqr_js.h`; no Terser runtime is included separately | BSD-2-Clause | `third_party_licenses/Terser-5.37.0-BSD-2-Clause.txt` |
| qrcode-generator | Kazuhiko Arase's JavaScript QR encoder | Inline implementation in `include/network/ui_desktop.h` | MIT | `third_party_licenses/qrcode-generator-MIT.txt` |
| Bitcoin Core arithmetic and SHA-256 structure | Bitcoin Core source identified in the affected source comments | `include/core/btc_pow.h`, SHA-256 portions of `include/crypto/vendored.h` | MIT | `third_party_licenses/Bitcoin-Core-MIT.txt` |
| B-Con crypto-algorithms SHA-256 reference | Brad Conte's reference identified in `include/crypto/vendored.h` | SHA-256 portions of `include/crypto/vendored.h` | Public domain | Attribution and public-domain status preserved in `include/crypto/vendored.h` |
| RFC reference cryptography | ChaCha20 from RFC 7539; BLAKE2b from RFC 7693 Appendix A; Poly1305-donna-style code credited to Andrew Moon | Relevant portions of `include/crypto/vendored.h` | Public domain / CC0 as identified in the source comments | Attribution and terms preserved in `include/crypto/vendored.h` |

## Local modifications and provenance

`vendor/pqc/provenance/PQC_PROVENANCE.tsv` is the authoritative raw-byte
inventory. It records the immutable upstream revision and path, upstream and
local SHA-256, compiled/distributed role, and exact patch for every item. The
ML-DSA tree includes a constant-time challenge comparison; `randombytes.c`
adds fail-closed operating-system randomness and browser Web Crypto support;
`mldsa65/veld_seedgen.c` is Veld-authored. The verification tool reconstructs
all three changes against the exact PQClean commit. The remaining PQClean rows
must be byte-identical to their recorded upstream blobs.

The embedded jsQR header records that jsQR 1.4.0 was minified by jsDelivr using
Terser 5.37.0. Terser is therefore listed as build provenance; this inventory
does not claim that a distinct Terser runtime is shipped. The canonical PQC
JavaScript and its embedded header are byte-bound by the verifier. The pinned
WASM rebuild authenticates the full activated raw tool trees before and after
use, runs twice, compares both outputs to that artifact, and performs a runtime
sign/verify/tamper test using Web Crypto. The attestation identifies the exact
toolchain actually executed; the separately pinned container is not
misrepresented as executed evidence. Release outputs carry these notices,
applicable licenses, and the raw provenance record alongside binaries.

Third-party names and marks belong to their respective owners. Inclusion of a
notice does not imply endorsement of Veld, and this file is not a warranty or a
complete statement of an operator's dynamically linked system dependencies.
