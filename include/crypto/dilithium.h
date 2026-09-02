#pragma once

// ─────────────────────────────────────────────
//  VELD post-quantum signatures — ML-DSA-65 (Dilithium-3)
//
//  NIST FIPS 204 ML-DSA at security level 3.
//  Wraps the PQClean reference implementation vendored under
//  vendor/pqc/mldsa65/. Used to replace secp256k1 for all
//  Veld signature operations (coinbase, send, stake, validator
//  registration, pool / endorsement flushes).
//
//  Key sizes (fixed by the algorithm):
//    public key  = 1952 bytes
//    secret key  = 4032 bytes
//    signature   = 3309 bytes (up to PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES)
//
//  Rationale for choosing ML-DSA-65:
//    - NIST-standardised (FIPS 204, 2024)
//    - Integer arithmetic only — easier to ship side-channel
//      resistant code than Falcon (floating-point)
//    - Signature ~4× smaller than SPHINCS+-128s (3.3KB vs 7.8KB)
//    - Fast verify (~100μs) — important for block validation
// ─────────────────────────────────────────────

#include "../compat/platform.h"
#include "../core/hash.h"
#include "../crypto/ripemd160.h"  // Hash160 typedef
#include <array>
#include <vector>
#include <cstdint>
#include <cstring>
#include <stdexcept>

extern "C" {
#include "../../vendor/pqc/mldsa65/api.h"
}

namespace veld {
namespace dilithium {

constexpr size_t PUBKEY_BYTES  = PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES; // 1952
constexpr size_t SECKEY_BYTES  = PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES; // 4032
constexpr size_t SIG_MAX_BYTES = PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES;          // 3309

using PublicKey = std::array<uint8_t, PUBKEY_BYTES>;
using SecretKey = std::array<uint8_t, SECKEY_BYTES>;
using Signature = std::vector<uint8_t>; // actual size ≤ SIG_MAX_BYTES

struct KeyPair {
    PublicKey public_key{};
    SecretKey secret_key{};
};

// Generate a fresh keypair. Secret key is derived from a 32-byte seed produced
// by the platform CSPRNG (veld::compat::SecureRandom inside PQClean's
// randombytes()). Throws on CSPRNG failure.
inline KeyPair Generate() {
    KeyPair kp;
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(
        kp.public_key.data(), kp.secret_key.data());
    if (rc != 0) throw std::runtime_error("ML-DSA-65 keygen failed");
    return kp;
}

// Sign an arbitrary-length message. Returns a detached signature (not the
// "signed message" form that PQClean also offers — we never need to transport
// the message bundled with the signature, since our TXs already carry both).
inline Signature Sign(const SecretKey& sk, const uint8_t* msg, size_t msglen) {
    Signature sig(SIG_MAX_BYTES, 0);
    size_t siglen = 0;
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
        sig.data(), &siglen, msg, msglen, sk.data());
    if (rc != 0) throw std::runtime_error("ML-DSA-65 sign failed");
    sig.resize(siglen);
    return sig;
}

inline Signature Sign(const SecretKey& sk, const std::vector<uint8_t>& msg) {
    return Sign(sk, msg.data(), msg.size());
}

inline Signature Sign(const SecretKey& sk, const Hash256& sighash) {
    return Sign(sk, sighash.data(), sighash.size());
}

// Verify a detached signature. Returns false on any validation failure — never
// throws (makes it safe to call from block-validation hot paths).
inline bool Verify(const PublicKey& pk,
                   const uint8_t* msg, size_t msglen,
                   const uint8_t* sig, size_t siglen) noexcept {
    if (siglen == 0 || siglen > SIG_MAX_BYTES) return false;
    int rc = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
        sig, siglen, msg, msglen, pk.data());
    return rc == 0;
}

inline bool Verify(const PublicKey& pk,
                   const std::vector<uint8_t>& msg,
                   const std::vector<uint8_t>& sig) noexcept {
    return Verify(pk, msg.data(), msg.size(), sig.data(), sig.size());
}

inline bool Verify(const PublicKey& pk,
                   const Hash256& sighash,
                   const std::vector<uint8_t>& sig) noexcept {
    return Verify(pk, sighash.data(), sighash.size(), sig.data(), sig.size());
}

} // namespace dilithium
} // namespace veld
