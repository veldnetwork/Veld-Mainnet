# PQC raw-byte provenance

`PQC_PROVENANCE.tsv` is the fail-closed inventory for every PQC C/H file,
generated NIST KAT, JavaScript/WASM payload, embedded header, patch, source
list, toolchain identity, license, verifier, regression, and Linux/Windows
release controller distributed by Veld. Hashes are SHA-256 over exact file
bytes; text mode or newline normalization is never applied.

The upstream project is PQClean at immutable commit
`202a8f96315f9ed219387a50f7e40d04af037ea8`. Rows derived from PQClean carry
the exact upstream path and upstream raw hash. The three local changes are
checked in as patches under `vendor-patches/`: constant-time ML-DSA challenge
comparison, fail-closed/Web Crypto randomness, and Veld's deterministic
ML-DSA seed-keygen addition.

Run the offline release-input check:

```text
python3 scripts/verify-pqc-provenance.py
```

For a source-to-upstream proof, check out the exact PQClean commit and run:

```text
python3 scripts/verify-pqc-provenance.py --upstream-dir /path/to/PQClean
```

The JavaScript file is the one canonical generated artifact. The C++ header is
a byte-preserving deterministic wrapper; it must be regenerated only with:

```text
python3 scripts/verify-pqc-provenance.py --write-embedded-header
```

`include/crypto/mldsa65_nist_kat.h` is generated from the exact commit's first
ML-DSA-65 NIST response. Its generator extracts the exact Git object tree,
compiles PQClean's canonical KAT driver, requires response SHA-256
`7cb96242eac9907a55b5c84c202f0ebd552419c50b2e986dc2e28f07ecebf072`,
and retains only the public message, public key, and detached signature:

```text
python3 scripts/generate-mldsa65-nist-kat.py --upstream-dir /path/to/PQClean
```

The pinned WASM rebuild command is `scripts/rebuild-pqc-wasm.py`; the shell
wrapper accepts the exact activated emsdk root in `VELD_EMSDK_ROOT`. Install
and activate emsdk 4.0.10 at revision
`62a853cd3b3134398ce85cde8bb5cbb2ef0194cb`, then run:

```text
python scripts/rebuild-pqc-wasm.py --emsdk-root /path/to/emsdk EMPTY_OUTPUT_DIR
```

The controller verifies the exact `.emscripten` bytes plus raw-tree digests,
file counts, and byte counts for Emscripten, LLVM/Binaryen, Node, and Python
both before and after use. It rebuilds twice, compares both outputs to one
another and the checked-in JavaScript, and runs keygen/sign/verify/tamper and
Web Crypto smoke coverage. The equivalent Linux container manifest is also
pinned, but is not claimed as executed evidence. Desktop and GUI release gates
require `wasm-rebuild-attestation.tsv` to contain a current `PASS` bound to the
full input digest.

Every Linux and Windows release output stages exact PQClean licenses, notices,
the manifest and provenance directory, and the verification/rebuild tools
under `third-party/`. Desktop and GUI outputs additionally stage the
Emscripten license. The second release gate byte-compares that staged tree to
the attested source immediately before package handoff.
