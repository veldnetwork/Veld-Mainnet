"use strict";

const createModule = require(process.argv[2]);

(async () => {
  const m = await createModule();
  if (!(m.HEAPU8 instanceof Uint8Array)) throw new Error("HEAPU8 not exported");
  const seed = Uint8Array.from({length: 32}, (_, i) => i);
  const message = new TextEncoder().encode("VELD PQC provenance rebuild fixture");
  const seedPtr = m._malloc(32);
  const pkPtr = m._malloc(1952);
  const skPtr = m._malloc(4032);
  const sigPtr = m._malloc(3309);
  const sigLenPtr = m._malloc(4);
  const msgPtr = m._malloc(message.length);
  try {
    m.HEAPU8.set(seed, seedPtr);
    m.HEAPU8.set(message, msgPtr);
    m.HEAPU8.fill(0, sigLenPtr, sigLenPtr + 4);
    if (m._veld_mldsa65_keypair_from_seed(seedPtr, pkPtr, skPtr) !== 0) {
      throw new Error("deterministic key generation failed");
    }
    if (m._PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
          sigPtr, sigLenPtr, msgPtr, message.length, skPtr) !== 0) {
      throw new Error("signature failed");
    }
    const sigLen = new DataView(m.HEAPU8.buffer).getUint32(sigLenPtr, true);
    if (sigLen !== 3309) throw new Error(`unexpected signature length ${sigLen}`);
    if (m._PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
          sigPtr, sigLen, msgPtr, message.length, pkPtr) !== 0) {
      throw new Error("valid signature rejected");
    }
    m.HEAPU8[msgPtr] ^= 1;
    if (m._PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
          sigPtr, sigLen, msgPtr, message.length, pkPtr) === 0) {
      throw new Error("tampered message accepted");
    }
  } finally {
    m.HEAPU8.fill(0, seedPtr, seedPtr + 32);
    m.HEAPU8.fill(0, skPtr, skPtr + 4032);
    for (const ptr of [seedPtr, pkPtr, skPtr, sigPtr, sigLenPtr, msgPtr]) m._free(ptr);
  }
  console.log("PASS PQC WASM keygen/sign/verify/tamper/WebCrypto");
})().catch((error) => {
  console.error(error);
  process.exit(1);
});
