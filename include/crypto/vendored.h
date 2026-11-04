// include/crypto/vendored.h
//
// Vendored cryptographic primitives for the Veld blockchain.
//
// Purpose: provide byte-identical drop-in replacements for the subset of
// OpenSSL EVP calls used by Veld so that the Windows build can link without
// libcrypto. Static-linking libcrypto.a into veld-node.exe was matching
// Windows Defender coinminer heuristic signatures; by vendoring the
// primitives we avoid pulling in libcrypto entirely.
//
// All outputs MUST be byte-identical to OpenSSL for the same inputs;
// deviations would cause a consensus split (SHA-256 drives block hashes,
// ChaCha20 + BLAKE2b drive the VeldHash PoW, ChaCha20-Poly1305 drives
// wallet vault encryption).
//
// This header is self-contained — only <cstdint>, <cstring>, <cstddef>.
// No allocations, no exceptions, bool returns for failure paths.
//
// Sources & credits (all liberally licensed):
//   * SHA-256 : FIPS 180-4; structure follows Bitcoin Core's
//               src/crypto/sha256.cpp (MIT) and the original public-domain
//               reference by Brad Conte.
//   * ChaCha20: RFC 7539 §2.3 reference implementation (public domain).
//   * BLAKE2b : RFC 7693 Appendix A reference implementation
//               by J-P Aumasson, S. Neves, Z. Wilcox-O'Hearn, C. Winnerlein
//               (CC0 / public domain).
//   * Poly1305: RFC 7539 §2.5 reference; 32-bit "poly1305-donna" style
//               implementation by Andrew Moon (public domain).
//   * AEAD    : RFC 7539 §2.8 construction.
//
// Known-answer test vectors checked in vendored_crypto_selftest():
//   SHA-256("abc")            == ba7816bf8f01cfea414140de5dae2223
//                                b00361a396177a9cb410ff61f20015ad
//   BLAKE2b-512("abc")        == ba80a53f981c4d0d6a2797b69f12f6e9
//                                4c212f14685ac4b74b12bb6fdbffa2d1
//                                7d87c5392aab792dc252d5de4533cc95
//                                18d38aa8dbf1925ab92386edd4009923
//   ChaCha20 keystream        == RFC 7539 §2.3.2 block-1 test vector
//   Poly1305 one-time MAC     == RFC 7539 §2.5.2 test vector
//   ChaCha20-Poly1305 AEAD    == RFC 7539 §2.8.2 test vector
//
// Caveats:
//   * Poly1305 r-clamping follows RFC 7539 §2.5 (clamp r &=
//     0x0ffffffc0ffffffc0ffffffc0fffffff before use).
//   * ChaCha20 keystream is called with a 16-byte IV formatted as
//     counter(4 LE) || nonce(12), matching OpenSSL's EVP_chacha20
//     IV layout (not the RFC 7539 AEAD layout). The AEAD entry points
//     below use the RFC 7539 12-byte nonce directly and manage the
//     counter internally (starts at 1 for message, 0 for Poly1305 key).
//   * Constant-time tag compare in AEAD decrypt uses an or-accumulator.
//   * All integer I/O is explicit little-endian via helper functions,
//     so byte output is identical regardless of host endianness.

#ifndef VELD_CRYPTO_VENDORED_H
#define VELD_CRYPTO_VENDORED_H

// vendored.h relies on out-of-class definitions of
// `static const` data members written as `inline const`. That is a C++17
// inline-variable feature; under C++14 the linker would emit duplicate
// symbols (one per TU including the header). Hard-fail at compile time
// rather than at link time so the cause is obvious.
static_assert(__cplusplus >= 201703L, "vendored.h requires C++17 inline variables");

#include <cstdint>
#include <cstring>
#include <cstddef>
#include <cstdlib>
#include <cstdio>                // fprintf for pin diagnostics
#include "../compat/platform.h"  // veld::compat::SecureZero (guaranteed scrub)
#include "vendored_pin.h"          // generated SHA-256 pin
#include "vendored_pin_expected.h" // committed expected pin
#include "vendored_pin_history.h"  // append-only pin history
#include "mldsa65_nist_kat.h"      // pinned upstream fixed-vector verification KAT
// pull in ML-DSA-65 API for the selftest
// round-trip KAT at the bottom of vendored_crypto_selftest(). The KAT is
// a pure round-trip (keygen-from-seed → sign → verify → tamper-reject)
// that catches any PQClean miscompile before any wallet key material is
// touched.
extern "C" {
#include "../../vendor/pqc/mldsa65/api.h"
int veld_mldsa65_keypair_from_seed(const uint8_t seed[32],
                                    uint8_t* pk, uint8_t* sk);
}

namespace veld {
namespace vendored_crypto {

// ---------------------------------------------------------------------------
// Endianness helpers (portable, branch-free on little-endian, correct on BE)
// ---------------------------------------------------------------------------

static inline uint32_t vc_load32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

static inline uint32_t vc_load32_be(const uint8_t* p) {
    return ((uint32_t)p[0] << 24)
         | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] << 8)
         |  (uint32_t)p[3];
}

static inline uint64_t vc_load64_le(const uint8_t* p) {
    return (uint64_t)p[0]
         | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16)
         | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32)
         | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48)
         | ((uint64_t)p[7] << 56);
}

static inline void vc_store32_le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void vc_store32_be(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static inline void vc_store64_le(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

static inline void vc_store64_be(uint8_t* p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v);
}

static inline uint32_t vc_rotr32(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

static inline uint32_t vc_rotl32(uint32_t x, unsigned n) {
    return (x << n) | (x >> (32 - n));
}

static inline uint64_t vc_rotr64(uint64_t x, unsigned n) {
    return (x >> n) | (x << (64 - n));
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

class Sha256 {
public:
    Sha256() { reset(); }

    void reset() {
        // FIPS 180-4 §5.3.3 initial hash value
        state_[0] = 0x6a09e667u;
        state_[1] = 0xbb67ae85u;
        state_[2] = 0x3c6ef372u;
        state_[3] = 0xa54ff53au;
        state_[4] = 0x510e527fu;
        state_[5] = 0x9b05688cu;
        state_[6] = 0x1f83d9abu;
        state_[7] = 0x5be0cd19u;
        bitlen_   = 0;
        buflen_   = 0;
        // scrub the 64-byte block buffer on
        // reset. SHA-256 over wallet-vault material or seed-derived
        // ML-DSA keys leaves residue here that survives until the
        // next finalize(). reset() is also called from finalize()
        // itself, so this also covers post-hash stack hygiene.
        veld::compat::SecureZero(buf_, sizeof(buf_));
    }

    void update(const uint8_t* data, size_t len) {
        while (len > 0) {
            size_t take = 64 - buflen_;
            if (take > len) take = len;
            std::memcpy(buf_ + buflen_, data, take);
            buflen_ += take;
            data    += take;
            len     -= take;
            if (buflen_ == 64) {
                transform_(buf_);
                bitlen_ += 512;
                buflen_  = 0;
            }
        }
    }

    void finalize(uint8_t out[32]) {
        bitlen_ += (uint64_t)buflen_ * 8;
        buf_[buflen_++] = 0x80;
        if (buflen_ > 56) {
            while (buflen_ < 64) buf_[buflen_++] = 0x00;
            transform_(buf_);
            buflen_ = 0;
        }
        while (buflen_ < 56) buf_[buflen_++] = 0x00;
        vc_store64_be(buf_ + 56, bitlen_);
        transform_(buf_);
        for (int i = 0; i < 8; ++i) {
            vc_store32_be(out + i * 4, state_[i]);
        }
        reset();
    }

private:
    static const uint32_t K_[64];

    uint32_t state_[8];
    uint64_t bitlen_;
    uint8_t  buf_[64];
    size_t   buflen_;

    static inline uint32_t Ch_(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    static inline uint32_t Maj_(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static inline uint32_t BigS0_(uint32_t x) {
        return vc_rotr32(x, 2) ^ vc_rotr32(x, 13) ^ vc_rotr32(x, 22);
    }
    static inline uint32_t BigS1_(uint32_t x) {
        return vc_rotr32(x, 6) ^ vc_rotr32(x, 11) ^ vc_rotr32(x, 25);
    }
    static inline uint32_t SmS0_(uint32_t x) {
        return vc_rotr32(x, 7) ^ vc_rotr32(x, 18) ^ (x >> 3);
    }
    static inline uint32_t SmS1_(uint32_t x) {
        return vc_rotr32(x, 17) ^ vc_rotr32(x, 19) ^ (x >> 10);
    }

    void transform_(const uint8_t block[64]) {
        uint32_t W[64];
        for (int i = 0; i < 16; ++i) {
            W[i] = vc_load32_be(block + i * 4);
        }
        for (int i = 16; i < 64; ++i) {
            W[i] = SmS1_(W[i-2]) + W[i-7] + SmS0_(W[i-15]) + W[i-16];
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t T1 = h + BigS1_(e) + Ch_(e, f, g) + K_[i] + W[i];
            uint32_t T2 = BigS0_(a) + Maj_(a, b, c);
            h = g; g = f; f = e; e = d + T1;
            d = c; c = b; b = a; a = T1 + T2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
};

// SHA-256 round constants (FIPS 180-4 §4.2.2)
inline const uint32_t Sha256::K_[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

inline void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    Sha256 h;
    h.update(data, len);
    h.finalize(out);
}

// ---------------------------------------------------------------------------
// ChaCha20 (RFC 7539 §2.3)
// ---------------------------------------------------------------------------
//
// Generates keystream for a 32-byte key + 16-byte IV where the IV is laid
// out as counter(4 LE) || nonce(12) — this matches OpenSSL's EVP_chacha20
// IV format. The RFC 7539 AEAD entry points below use a 12-byte nonce and
// manage the counter themselves.

static inline void vc_chacha20_block_(
    const uint32_t state_in[16],
    uint8_t out[64])
{
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = state_in[i];

    // 20 rounds = 10 double-rounds of the ChaCha20 quarter round
    for (int i = 0; i < 10; ++i) {
        // column rounds
        x[0]+=x[4]; x[12]=vc_rotl32(x[12]^x[0],16);
        x[8]+=x[12]; x[4]=vc_rotl32(x[4]^x[8],12);
        x[0]+=x[4]; x[12]=vc_rotl32(x[12]^x[0],8);
        x[8]+=x[12]; x[4]=vc_rotl32(x[4]^x[8],7);

        x[1]+=x[5]; x[13]=vc_rotl32(x[13]^x[1],16);
        x[9]+=x[13]; x[5]=vc_rotl32(x[5]^x[9],12);
        x[1]+=x[5]; x[13]=vc_rotl32(x[13]^x[1],8);
        x[9]+=x[13]; x[5]=vc_rotl32(x[5]^x[9],7);

        x[2]+=x[6]; x[14]=vc_rotl32(x[14]^x[2],16);
        x[10]+=x[14]; x[6]=vc_rotl32(x[6]^x[10],12);
        x[2]+=x[6]; x[14]=vc_rotl32(x[14]^x[2],8);
        x[10]+=x[14]; x[6]=vc_rotl32(x[6]^x[10],7);

        x[3]+=x[7]; x[15]=vc_rotl32(x[15]^x[3],16);
        x[11]+=x[15]; x[7]=vc_rotl32(x[7]^x[11],12);
        x[3]+=x[7]; x[15]=vc_rotl32(x[15]^x[3],8);
        x[11]+=x[15]; x[7]=vc_rotl32(x[7]^x[11],7);

        // diagonal rounds
        x[0]+=x[5]; x[15]=vc_rotl32(x[15]^x[0],16);
        x[10]+=x[15]; x[5]=vc_rotl32(x[5]^x[10],12);
        x[0]+=x[5]; x[15]=vc_rotl32(x[15]^x[0],8);
        x[10]+=x[15]; x[5]=vc_rotl32(x[5]^x[10],7);

        x[1]+=x[6]; x[12]=vc_rotl32(x[12]^x[1],16);
        x[11]+=x[12]; x[6]=vc_rotl32(x[6]^x[11],12);
        x[1]+=x[6]; x[12]=vc_rotl32(x[12]^x[1],8);
        x[11]+=x[12]; x[6]=vc_rotl32(x[6]^x[11],7);

        x[2]+=x[7]; x[13]=vc_rotl32(x[13]^x[2],16);
        x[8]+=x[13]; x[7]=vc_rotl32(x[7]^x[8],12);
        x[2]+=x[7]; x[13]=vc_rotl32(x[13]^x[2],8);
        x[8]+=x[13]; x[7]=vc_rotl32(x[7]^x[8],7);

        x[3]+=x[4]; x[14]=vc_rotl32(x[14]^x[3],16);
        x[9]+=x[14]; x[4]=vc_rotl32(x[4]^x[9],12);
        x[3]+=x[4]; x[14]=vc_rotl32(x[14]^x[3],8);
        x[9]+=x[14]; x[4]=vc_rotl32(x[4]^x[9],7);
    }
    for (int i = 0; i < 16; ++i) {
        uint32_t v = x[i] + state_in[i];
        vc_store32_le(out + i * 4, v);
    }
}

// Initialize a ChaCha20 state with a 32-byte key, 32-bit counter, and
// 96-bit nonce (RFC 7539 ordering).
static inline void vc_chacha20_init_state_(
    uint32_t state[16],
    const uint8_t key[32],
    uint32_t counter,
    const uint8_t nonce12[12])
{
    // "expand 32-byte k" constants
    state[0] = 0x61707865u;
    state[1] = 0x3320646eu;
    state[2] = 0x79622d32u;
    state[3] = 0x6b206574u;
    for (int i = 0; i < 8; ++i) state[4 + i] = vc_load32_le(key + i * 4);
    state[12] = counter;
    state[13] = vc_load32_le(nonce12 + 0);
    state[14] = vc_load32_le(nonce12 + 4);
    state[15] = vc_load32_le(nonce12 + 8);
}

// RFC 7539 keystream generator with explicit counter + 12-byte nonce.
static inline void vc_chacha20_keystream_rfc_(
    const uint8_t key[32],
    uint32_t counter,
    const uint8_t nonce12[12],
    uint8_t* out,
    size_t len)
{
    uint32_t state[16];
    vc_chacha20_init_state_(state, key, counter, nonce12);
    uint8_t block[64];
    while (len > 0) {
        vc_chacha20_block_(state, block);
        // RFC 7539 §2.8 mandates abort at 2^32
        // blocks (256 GiB per nonce); this implementation is
        // caller-responsibility — Veld's largest single-shot payload is
        // the wallet vault (~few MB), well below 256 GiB. Add
        // assert(len <= ((uint64_t)((1ULL<<32)-1)) * 64) if extending
        // to multi-GB inputs.
        state[12] += 1;
        size_t take = len < 64 ? len : 64;
        std::memcpy(out, block, take);
        out += take;
        len -= take;
    }
    // scrub the keystream block. For the AEAD
    // path the first 64 bytes of block[] are the Poly1305 one-time key —
    // leaving even one stale block on the stack lets a memory dump pin
    // tag forgery onto the next AEAD call's key/nonce.
    veld::compat::SecureZero(block, sizeof(block));
}

// Public keystream API matching OpenSSL EVP_chacha20 IV layout:
// iv[0..4)  = counter, little-endian
// iv[4..16) = nonce (12 bytes)
inline void chacha20_keystream(
    const uint8_t key[32],
    const uint8_t iv[16],
    uint8_t* out,
    size_t len)
{
    uint32_t counter = vc_load32_le(iv);
    vc_chacha20_keystream_rfc_(key, counter, iv + 4, out, len);
}

// In-place XOR keystream onto a buffer with RFC 7539 counter + nonce.
static inline void vc_chacha20_xor_(
    const uint8_t key[32],
    uint32_t counter,
    const uint8_t nonce12[12],
    const uint8_t* in,
    uint8_t* out,
    size_t len)
{
    uint32_t state[16];
    vc_chacha20_init_state_(state, key, counter, nonce12);
    uint8_t block[64];
    while (len > 0) {
        vc_chacha20_block_(state, block);
        state[12] += 1;
        size_t take = len < 64 ? len : 64;
        for (size_t i = 0; i < take; ++i) out[i] = in[i] ^ block[i];
        in  += take;
        out += take;
        len -= take;
    }
    // scrub the keystream block before stack
    // unwind. Same rationale as vc_chacha20_keystream_rfc_; this is the
    // path used by the AEAD encrypt/decrypt fast-path so a leak here
    // exposes wallet plaintext keystream after vault unlock.
    veld::compat::SecureZero(block, sizeof(block));
}

// ---------------------------------------------------------------------------
// BLAKE2b-512 (RFC 7693)
// ---------------------------------------------------------------------------

class Blake2b {
public:
    Blake2b() { reset(); }

    void reset() {
        // RFC 7693 §3.2 parameter block: digest_length=64, key_length=0,
        // fanout=1, depth=1 => param[0] = 0x01010040 (little-endian in memory)
        static const uint64_t IV[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        for (int i = 0; i < 8; ++i) h_[i] = IV[i];
        // XOR h[0] with parameter block first 64 bits:
        //   digest_length = 64 (0x40)
        //   key_length    = 0
        //   fanout        = 1
        //   depth         = 1
        //   leaf_length   = 0
        //   node_offset   = 0 (high part of state[0])
        // Combined low 64 bits = 0x0000000001010040
        h_[0] ^= 0x0000000001010040ULL;

        t_[0] = 0;
        t_[1] = 0;
        f_[0] = 0;
        f_[1] = 0;
        buflen_ = 0;
        // scrub the 128-byte BLAKE2b block buffer
        // on reset. VeldHash PoW round 1 hashes the candidate header into
        // BLAKE2b; leaving the previous candidate in buf_ is a low-value
        // leak (header data is public) but reset() is also reused as a
        // post-finalize cleanup, where the leak would include any
        // previously-hashed wallet material in the context buffer.
        veld::compat::SecureZero(buf_, sizeof(buf_));
    }

    void update(const uint8_t* data, size_t len) {
        if (len == 0) return;
        // If buffer has leftover, fill it. BLAKE2 only compresses a full
        // block when we know more data follows — never on exact boundary.
        size_t left = buflen_;
        size_t fill = 128 - left;
        if (len > fill) {
            std::memcpy(buf_ + left, data, fill);
            buflen_ = 128;
            data += fill;
            len  -= fill;
            increment_counter_(128);
            compress_(buf_);
            buflen_ = 0;
            while (len > 128) {
                increment_counter_(128);
                compress_(data);
                data += 128;
                len  -= 128;
            }
        }
        std::memcpy(buf_ + buflen_, data, len);
        buflen_ += len;
    }

    void finalize(uint8_t out[64]) {
        // Final compression: pad buffer with zeros, set f[0] = all-ones.
        increment_counter_(buflen_);
        f_[0] = (uint64_t)-1;
        std::memset(buf_ + buflen_, 0, 128 - buflen_);
        compress_(buf_);
        for (int i = 0; i < 8; ++i) {
            vc_store64_le(out + i * 8, h_[i]);
        }
        reset();
    }

private:
    uint64_t h_[8];
    uint64_t t_[2];
    uint64_t f_[2];
    uint8_t  buf_[128];
    size_t   buflen_;

    void increment_counter_(uint64_t inc) {
        t_[0] += inc;
        t_[1] += (t_[0] < inc) ? 1ULL : 0ULL;
    }

    static const uint8_t SIGMA_[12][16];

    void compress_(const uint8_t block[128]) {
        static const uint64_t IV[8] = {
            0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
            0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
            0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
            0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
        };
        uint64_t m[16];
        uint64_t v[16];
        for (int i = 0; i < 16; ++i) m[i] = vc_load64_le(block + i * 8);
        for (int i = 0; i < 8; ++i)  v[i] = h_[i];
        v[8]  = IV[0];
        v[9]  = IV[1];
        v[10] = IV[2];
        v[11] = IV[3];
        v[12] = IV[4] ^ t_[0];
        v[13] = IV[5] ^ t_[1];
        v[14] = IV[6] ^ f_[0];
        v[15] = IV[7] ^ f_[1];

        #define VC_B2B_G(a,b,c,d,x,y) do { \
            v[a] = v[a] + v[b] + x; \
            v[d] = vc_rotr64(v[d] ^ v[a], 32); \
            v[c] = v[c] + v[d]; \
            v[b] = vc_rotr64(v[b] ^ v[c], 24); \
            v[a] = v[a] + v[b] + y; \
            v[d] = vc_rotr64(v[d] ^ v[a], 16); \
            v[c] = v[c] + v[d]; \
            v[b] = vc_rotr64(v[b] ^ v[c], 63); \
        } while (0)

        for (int r = 0; r < 12; ++r) {
            const uint8_t* s = SIGMA_[r];
            VC_B2B_G( 0, 4,  8, 12, m[s[ 0]], m[s[ 1]]);
            VC_B2B_G( 1, 5,  9, 13, m[s[ 2]], m[s[ 3]]);
            VC_B2B_G( 2, 6, 10, 14, m[s[ 4]], m[s[ 5]]);
            VC_B2B_G( 3, 7, 11, 15, m[s[ 6]], m[s[ 7]]);
            VC_B2B_G( 0, 5, 10, 15, m[s[ 8]], m[s[ 9]]);
            VC_B2B_G( 1, 6, 11, 12, m[s[10]], m[s[11]]);
            VC_B2B_G( 2, 7,  8, 13, m[s[12]], m[s[13]]);
            VC_B2B_G( 3, 4,  9, 14, m[s[14]], m[s[15]]);
        }
        #undef VC_B2B_G

        for (int i = 0; i < 8; ++i) h_[i] ^= v[i] ^ v[i + 8];
    }
};

// BLAKE2b message-schedule permutation (RFC 7693 §2.7)
inline const uint8_t Blake2b::SIGMA_[12][16] = {
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
    { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
    {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
    {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
    {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
    { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
    { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
    {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
    { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
    {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
    { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 }
};

inline void blake2b512(const uint8_t* data, size_t len, uint8_t out[64]) {
    Blake2b h;
    h.update(data, len);
    h.finalize(out);
}

// ---------------------------------------------------------------------------
// Poly1305 (RFC 7539 §2.5) — poly1305-donna 32-bit, by Andrew Moon, public domain
// ---------------------------------------------------------------------------

class Poly1305 {
public:
    // key = 32 bytes; r is clamped internally per RFC 7539 §2.5
    void init(const uint8_t key[32]) {
        // r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        uint32_t t0 = vc_load32_le(key +  0);
        uint32_t t1 = vc_load32_le(key +  4);
        uint32_t t2 = vc_load32_le(key +  8);
        uint32_t t3 = vc_load32_le(key + 12);
        r_[0] = (t0                    ) & 0x3ffffffu;
        r_[1] = ((t0 >> 26) | (t1 <<  6)) & 0x3ffff03u;
        r_[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ffu;
        r_[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fffu;
        r_[4] = ((t3 >>  8)             ) & 0x00fffffu;

        s_[0] = vc_load32_le(key + 16);
        s_[1] = vc_load32_le(key + 20);
        s_[2] = vc_load32_le(key + 24);
        s_[3] = vc_load32_le(key + 28);

        for (int i = 0; i < 5; ++i) h_[i] = 0;
        leftover_ = 0;
        // reset final_ between messages — without
        // this, a Poly1305 instance reused after finish() would carry the
        // previous message's high-bit flag and corrupt the next MAC.
        final_    = 0;
    }

    void update(const uint8_t* m, size_t bytes) {
        if (leftover_) {
            size_t want = 16 - leftover_;
            if (want > bytes) want = bytes;
            for (size_t i = 0; i < want; ++i) buf_[leftover_ + i] = m[i];
            bytes     -= want;
            m         += want;
            leftover_ += want;
            if (leftover_ < 16) return;
            blocks_(buf_, 16);
            leftover_ = 0;
        }
        if (bytes >= 16) {
            size_t want = bytes & ~(size_t)15;
            blocks_(m, want);
            m     += want;
            bytes -= want;
        }
        if (bytes) {
            // Keep this as memcpy; an equivalent byte loop can be vectorised
            // into a form that triggers a false-positive overread warning.
            // `bytes` is bounded in (0, 16) by the >=16 fast-path check and the
            // `if (bytes)` guard. Replacing with std::memcpy makes the
            // bounds explicit (bytes < 16, leftover_ < 16, buf_ has 16
            // bytes available) so the optimiser stops emitting the
            // confused warning while producing identical output.
            std::memcpy(buf_ + leftover_, m, bytes);
            leftover_ += bytes;
        }
    }

    void finish(uint8_t mac[16]) {
        // Process any remaining partial block with final flag.
        if (leftover_) {
            buf_[leftover_++] = 1;
            for (; leftover_ < 16; ++leftover_) buf_[leftover_] = 0;
            final_ = 1;
            blocks_(buf_, 16);
        }

        // Fully reduce h modulo p = 2^130 - 5.
        uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];
        uint32_t c;
        c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
        c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
        c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
        c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

        // compute h + -p
        uint32_t g0 = h0 + 5;  c = g0 >> 26; g0 &= 0x3ffffffu;
        uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
        uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
        uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
        uint32_t g4 = h4 + c - (1u << 26);

        // select h if h < p, or h + -p if h >= p
        uint32_t mask = (g4 >> 31) - 1u; // 0xffffffff if h>=p else 0
        g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
        mask = ~mask;
        h0 = (h0 & mask) | g0;
        h1 = (h1 & mask) | g1;
        h2 = (h2 & mask) | g2;
        h3 = (h3 & mask) | g3;
        h4 = (h4 & mask) | g4;

        // h = h % (2^128)
        uint32_t f0 = ((h0      ) | (h1 << 26)) & 0xffffffffu;
        uint32_t f1 = ((h1 >>  6) | (h2 << 20)) & 0xffffffffu;
        uint32_t f2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffffu;
        uint32_t f3 = ((h3 >> 18) | (h4 <<  8)) & 0xffffffffu;

        // mac = (h + s) % (2^128)
        uint64_t acc;
        acc = (uint64_t)f0 + s_[0];            f0 = (uint32_t)acc;
        acc = (uint64_t)f1 + s_[1] + (acc>>32);f1 = (uint32_t)acc;
        acc = (uint64_t)f2 + s_[2] + (acc>>32);f2 = (uint32_t)acc;
        acc = (uint64_t)f3 + s_[3] + (acc>>32);f3 = (uint32_t)acc;

        vc_store32_le(mac +  0, f0);
        vc_store32_le(mac +  4, f1);
        vc_store32_le(mac +  8, f2);
        vc_store32_le(mac + 12, f3);

        // Zeroize sensitive state.
        for (int i = 0; i < 5; ++i) { h_[i] = 0; r_[i] = 0; }
        for (int i = 0; i < 4; ++i) { s_[i] = 0; }
        // scrub the partial-block buffer and
        // leftover counter. The last partial block holds plaintext (or
        // last-block ciphertext + padding); leaving it in stack memory
        // is a key-leak waiting for a coredump or hiberfil capture.
        veld::compat::SecureZero(buf_, sizeof(buf_));
        leftover_ = 0;
    }

private:
    uint32_t r_[5];
    uint32_t h_[5];
    uint32_t s_[4];
    uint8_t  buf_[16];
    size_t   leftover_;
    uint32_t final_;

    void blocks_(const uint8_t* m, size_t bytes) {
        const uint32_t hibit = final_ ? 0u : (1u << 24);
        uint32_t r0 = r_[0], r1 = r_[1], r2 = r_[2], r3 = r_[3], r4 = r_[4];
        uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
        uint32_t h0 = h_[0], h1 = h_[1], h2 = h_[2], h3 = h_[3], h4 = h_[4];

        while (bytes >= 16) {
            // h += m[i]
            uint32_t t0 = vc_load32_le(m +  0);
            uint32_t t1 = vc_load32_le(m +  4);
            uint32_t t2 = vc_load32_le(m +  8);
            uint32_t t3 = vc_load32_le(m + 12);
            h0 += (t0                    ) & 0x3ffffffu;
            h1 += ((t0 >> 26) | (t1 <<  6)) & 0x3ffffffu;
            h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffffu;
            h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffffu;
            h4 += ((t3 >>  8)             ) | hibit;

            // h *= r
            uint64_t d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * s4) + ((uint64_t)h2 * s3) + ((uint64_t)h3 * s2) + ((uint64_t)h4 * s1);
            uint64_t d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * s4) + ((uint64_t)h3 * s3) + ((uint64_t)h4 * s2);
            uint64_t d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * s4) + ((uint64_t)h4 * s3);
            uint64_t d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * s4);
            uint64_t d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);

            // (partial) h %= p
            uint32_t c;
                          c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffffu;
            d1 += c;      c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffffu;
            d2 += c;      c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffffu;
            d3 += c;      c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffffu;
            d4 += c;      c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffffu;
            h0 += c * 5;  c = h0 >> 26;             h0 &= 0x3ffffffu;
            h1 += c;

            m     += 16;
            bytes -= 16;
        }

        h_[0] = h0; h_[1] = h1; h_[2] = h2; h_[3] = h3; h_[4] = h4;
    }
};

// One-shot Poly1305.
static inline void poly1305_mac(
    const uint8_t key[32],
    const uint8_t* msg, size_t len,
    uint8_t tag[16])
{
    Poly1305 p;
    p.init(key);
    p.update(msg, len);
    p.finish(tag);
}

// ---------------------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (RFC 7539 §2.8)
// ---------------------------------------------------------------------------
//
// Encrypt:
//   1. One-time Poly1305 key = ChaCha20(key, counter=0, nonce) first 32 bytes
//   2. Ciphertext = ChaCha20(key, counter=1, nonce) XOR plaintext
//   3. MAC input = aad || pad16 || ciphertext || pad16 || len(aad) || len(ct)
//   4. Tag = Poly1305(poly_key, MAC input)
//
// Decrypt: same MAC input, constant-time compare, then decrypt if valid.

static inline void vc_aead_compute_tag_(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t tag[16])
{
    // Poly1305 one-time key: first 32 bytes of ChaCha20 block (counter=0).
    uint8_t poly_key_block[64];
    vc_chacha20_keystream_rfc_(key, 0u, nonce, poly_key_block, 64);
    uint8_t poly_key[32];
    std::memcpy(poly_key, poly_key_block, 32);

    Poly1305 p;
    p.init(poly_key);

    static const uint8_t zeros[16] = {0};
    p.update(aad, aad_len);
    if (aad_len % 16) p.update(zeros, 16 - (aad_len % 16));

    p.update(ciphertext, ct_len);
    if (ct_len % 16) p.update(zeros, 16 - (ct_len % 16));

    uint8_t lens[16];
    vc_store64_le(lens + 0, (uint64_t)aad_len);
    vc_store64_le(lens + 8, (uint64_t)ct_len);
    p.update(lens, 16);

    p.finish(tag);

    // scrub via SecureZero, not std::memset.
    // The Poly1305 one-time key MUST be wiped between calls — reuse of
    // the same key against two different nonces is instant AEAD forgery.
    // std::memset on a stack buffer whose addr does not escape is exactly
    // the dead-store the optimizer is allowed to elide under /O2, -O3,
    // or -flto. SecureZero maps to SecureZeroMemory (Windows) or
    // explicit_bzero (Linux), both of which the compiler must retain.
    veld::compat::SecureZero(poly_key_block, sizeof(poly_key_block));
    veld::compat::SecureZero(poly_key,       sizeof(poly_key));
}

inline bool chacha20_poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext_out,
    uint8_t tag_out[16])
{
    // null buffers only allowed when corresponding length is zero
    if ((aad_len != 0 && aad == nullptr) ||
        (pt_len != 0 && (plaintext == nullptr || ciphertext_out == nullptr)) ||
        tag_out == nullptr)
    {
        return false;
    }

    // Encrypt with counter starting at 1 (per RFC 7539 §2.8).
    if (pt_len > 0) {
        vc_chacha20_xor_(key, 1u, nonce, plaintext, ciphertext_out, pt_len);
    }
    vc_aead_compute_tag_(key, nonce, aad, aad_len, ciphertext_out, pt_len, tag_out);
    return true;
}

inline bool chacha20_poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t tag[16],
    uint8_t* plaintext_out)
{
    if ((aad_len != 0 && aad == nullptr) ||
        (ct_len != 0 && (ciphertext == nullptr || plaintext_out == nullptr)) ||
        tag == nullptr)
    {
        return false;
    }

    uint8_t expected_tag[16];
    vc_aead_compute_tag_(key, nonce, aad, aad_len, ciphertext, ct_len, expected_tag);

    // Delegate the constant-time tag compare to the canonical helper in
    // compat/platform.h so there is one implementation to review and harden.
    bool tag_ok = veld::compat::ConstantTimeEqual(expected_tag, tag, 16);
    veld::compat::SecureZero(expected_tag, sizeof(expected_tag));
    if (!tag_ok) return false;

    if (ct_len > 0) {
        vc_chacha20_xor_(key, 1u, nonce, ciphertext, plaintext_out, ct_len);
    }
    return true;
}

// ---------------------------------------------------------------------------
// Self-test — runs known-answer vectors and aborts on mismatch
// ---------------------------------------------------------------------------

static inline bool vc_selftest_eq_(const uint8_t* a, const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; ++i) if (a[i] != b[i]) return false;
    return true;
}

// CALLER CONTRACT: must be invoked from each
// binary's main() before any wallet/network init. See
// src/veld-node.cpp main() for the canonical pattern (Windows-gated).
// Called from veld-node, veld-desktop, and veld-keygen.
inline void vendored_crypto_selftest() {
    // ---- SHA-256 ----
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223
    //                 b00361a396177a9cb410ff61f20015ad
    {
        static const uint8_t msg[3] = { 'a', 'b', 'c' };
        static const uint8_t expected[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        uint8_t got[32];
        sha256(msg, 3, got);
        if (!vc_selftest_eq_(got, expected, 32)) std::abort();
    }

    // ---- BLAKE2b-512 ----
    // BLAKE2b-512("abc") = ba80a53f981c4d0d6a2797b69f12f6e9 ...
    {
        static const uint8_t msg[3] = { 'a', 'b', 'c' };
        static const uint8_t expected[64] = {
            0xba,0x80,0xa5,0x3f,0x98,0x1c,0x4d,0x0d,
            0x6a,0x27,0x97,0xb6,0x9f,0x12,0xf6,0xe9,
            0x4c,0x21,0x2f,0x14,0x68,0x5a,0xc4,0xb7,
            0x4b,0x12,0xbb,0x6f,0xdb,0xff,0xa2,0xd1,
            0x7d,0x87,0xc5,0x39,0x2a,0xab,0x79,0x2d,
            0xc2,0x52,0xd5,0xde,0x45,0x33,0xcc,0x95,
            0x18,0xd3,0x8a,0xa8,0xdb,0xf1,0x92,0x5a,
            0xb9,0x23,0x86,0xed,0xd4,0x00,0x99,0x23
        };
        uint8_t got[64];
        blake2b512(msg, 3, got);
        if (!vc_selftest_eq_(got, expected, 64)) std::abort();
    }

    // ---- ChaCha20 keystream (RFC 7539 §2.3.2 test vector) ----
    // key = 00..1f, nonce = 00 00 00 09 00 00 00 4a 00 00 00 00, counter = 1
    // Expected block-1 keystream (first 64 bytes) from RFC 7539 §2.3.2.
    {
        uint8_t key[32];
        for (int i = 0; i < 32; ++i) key[i] = (uint8_t)i;
        static const uint8_t nonce[12] = {
            0x00,0x00,0x00,0x09,0x00,0x00,0x00,0x4a,0x00,0x00,0x00,0x00
        };
        static const uint8_t expected[64] = {
            0x10,0xf1,0xe7,0xe4,0xd1,0x3b,0x59,0x15,
            0x50,0x0f,0xdd,0x1f,0xa3,0x20,0x71,0xc4,
            0xc7,0xd1,0xf4,0xc7,0x33,0xc0,0x68,0x03,
            0x04,0x22,0xaa,0x9a,0xc3,0xd4,0x6c,0x4e,
            0xd2,0x82,0x64,0x46,0x07,0x9f,0xaa,0x09,
            0x14,0xc2,0xd7,0x05,0xd9,0x8b,0x02,0xa2,
            0xb5,0x12,0x9c,0xd1,0xde,0x16,0x4e,0xb9,
            0xcb,0xd0,0x83,0xe8,0xa2,0x50,0x3c,0x4e
        };
        // Via RFC API (counter=1, nonce=12 bytes):
        uint8_t got[64];
        vc_chacha20_keystream_rfc_(key, 1u, nonce, got, 64);
        if (!vc_selftest_eq_(got, expected, 64)) std::abort();

        // Same, via OpenSSL-compatible 16-byte IV: counter(LE) || nonce(12)
        uint8_t iv[16];
        vc_store32_le(iv, 1u);
        std::memcpy(iv + 4, nonce, 12);
        uint8_t got2[64];
        chacha20_keystream(key, iv, got2, 64);
        if (!vc_selftest_eq_(got2, expected, 64)) std::abort();

        // 130-byte partial-block keystream KAT.
        // Exercises the `len % 64 != 0` boundary in the ChaCha20 inner
        // loop; an incorrect copy length would diverge the AEAD keystream
        // for any payload that is not a multiple of 64 bytes (including
        // every wallet-vault encrypt and the entire AEAD test vector
        // below). We assert: (a) first 64 bytes match the RFC vector
        // already verified above, (b) keystream-then-XOR over an
        // all-zero buffer is bytewise equal to vc_chacha20_xor_'s
        // output (any partial-block divergence between the two
        // implementations would fail here), and (c) the 130-byte
        // length specifically forces a counter-3 block where only
        // 2 bytes are taken — the worst-case partial.
        uint8_t ks130[130];
        vc_chacha20_keystream_rfc_(key, 1u, nonce, ks130, 130);
        if (!vc_selftest_eq_(ks130, expected, 64)) std::abort();
        uint8_t zero130[130] = {0};
        uint8_t xor130[130];
        vc_chacha20_xor_(key, 1u, nonce, zero130, xor130, 130);
        if (!vc_selftest_eq_(ks130, xor130, 130)) std::abort();
        // And verify decrypt-after-encrypt round-trip on a 130-byte
        // payload (more than one full block + a partial trailing block).
        uint8_t pt130[130];
        for (int i = 0; i < 130; ++i) pt130[i] = (uint8_t)(i ^ 0xa5);
        uint8_t ct130[130];
        vc_chacha20_xor_(key, 1u, nonce, pt130, ct130, 130);
        uint8_t rt130[130];
        vc_chacha20_xor_(key, 1u, nonce, ct130, rt130, 130);
        if (!vc_selftest_eq_(rt130, pt130, 130)) std::abort();
    }

    // ---- Poly1305 (RFC 7539 §2.5.2) ----
    // key = 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:
    //       01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
    // msg = "Cryptographic Forum Research Group"
    // tag = a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
    {
        static const uint8_t key[32] = {
            0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
            0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
            0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
            0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b
        };
        static const uint8_t msg[] = {
            'C','r','y','p','t','o','g','r','a','p','h','i','c',' ',
            'F','o','r','u','m',' ','R','e','s','e','a','r','c','h',' ',
            'G','r','o','u','p'
        };
        static const uint8_t expected[16] = {
            0xa8,0x06,0x1d,0xc1,0x30,0x51,0x36,0xc6,
            0xc2,0x2b,0x8b,0xaf,0x0c,0x01,0x27,0xa9
        };
        uint8_t got[16];
        poly1305_mac(key, msg, sizeof(msg), got);
        if (!vc_selftest_eq_(got, expected, 16)) std::abort();
    }

    // ---- ChaCha20-Poly1305 AEAD (RFC 7539 §2.8.2) ----
    // plaintext = "Ladies and Gentlemen of the class of '99: ..."
    // key       = 80:81:..:9f
    // nonce     = 07 00 00 00 40 41 42 43 44 45 46 47
    // aad       = 50 51 52 53 c0 c1 c2 c3 c4 c5 c6 c7
    // Expected ciphertext + tag match RFC 7539 §2.8.2.
    {
        static const uint8_t key[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
            0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
            0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
        };
        static const uint8_t nonce[12] = {
            0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
            0x44,0x45,0x46,0x47
        };
        static const uint8_t aad[12] = {
            0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
            0xc4,0xc5,0xc6,0xc7
        };
        static const uint8_t plaintext[] = {
            0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,0x6e,0x64,0x20,0x47,
            0x65,0x6e,0x74,0x6c,0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
            0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,0x73,0x20,0x6f,0x66,
            0x20,0x27,0x39,0x39,0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
            0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,0x65,0x72,0x20,0x79,
            0x6f,0x75,0x20,0x6f,0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
            0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,0x74,0x68,0x65,0x20,
            0x66,0x75,0x74,0x75,0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
            0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,0x75,0x6c,0x64,0x20,
            0x62,0x65,0x20,0x69,0x74,0x2e
        };
        static const uint8_t expected_ct[sizeof(plaintext)] = {
            0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,0x7b,0x86,0xaf,0xbc,
            0x53,0xef,0x7e,0xc2,0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
            0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,0x3d,0xbe,0xa4,0x5e,
            0x8c,0xa9,0x67,0x12,0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
            0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,0x05,0xd6,0xa5,0xb6,
            0x7e,0xcd,0x3b,0x36,0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
            0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,0xfa,0xb3,0x24,0xe4,
            0xfa,0xd6,0x75,0x94,0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
            0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,0xe5,0x76,0xd2,0x65,
            0x86,0xce,0xc6,0x4b,0x61,0x16
        };
        static const uint8_t expected_tag[16] = {
            0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
            0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
        };
        uint8_t ct[sizeof(plaintext)];
        uint8_t tag[16];
        if (!chacha20_poly1305_encrypt(key, nonce,
                                       aad, sizeof(aad),
                                       plaintext, sizeof(plaintext),
                                       ct, tag)) std::abort();
        if (!vc_selftest_eq_(ct,  expected_ct,  sizeof(plaintext))) std::abort();
        if (!vc_selftest_eq_(tag, expected_tag, 16))                std::abort();

        // Round-trip via decrypt.
        uint8_t pt_roundtrip[sizeof(plaintext)];
        if (!chacha20_poly1305_decrypt(key, nonce,
                                       aad, sizeof(aad),
                                       ct, sizeof(plaintext),
                                       tag, pt_roundtrip)) std::abort();
        if (!vc_selftest_eq_(pt_roundtrip, plaintext, sizeof(plaintext))) std::abort();

        // Tampered tag must fail.
        uint8_t bad_tag[16];
        std::memcpy(bad_tag, tag, 16);
        bad_tag[0] ^= 1;
        uint8_t pt_bad[sizeof(plaintext)];
        if (chacha20_poly1305_decrypt(key, nonce,
                                      aad, sizeof(aad),
                                      ct, sizeof(plaintext),
                                      bad_tag, pt_bad)) std::abort();
    }

    // zero-length-AAD AEAD round-trip.
    // The Poly1305 MAC input includes a 16-byte len(aad)||len(ct)
    // trailer; with aad_len=0 the AAD-padding branch must produce
    // zero pad bytes (not 16) for the tag to verify on the peer.
    // This case is critical for wallet-vault decrypt where AAD is
    // empty (we authenticate only the ciphertext + version header).
    {
        static const uint8_t key[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
            0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
            0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
        };
        static const uint8_t nonce[12] = {
            0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
            0x44,0x45,0x46,0x47
        };
        static const uint8_t pt[5] = { 'h','e','l','l','o' };
        uint8_t ct[5];
        uint8_t tag[16];
        if (!chacha20_poly1305_encrypt(key, nonce,
                                       nullptr, 0,   // zero AAD
                                       pt, sizeof(pt),
                                       ct, tag)) std::abort();
        // Round-trip must verify and recover the plaintext.
        uint8_t rt[5];
        if (!chacha20_poly1305_decrypt(key, nonce,
                                       nullptr, 0,
                                       ct, sizeof(ct),
                                       tag, rt)) std::abort();
        if (!vc_selftest_eq_(rt, pt, sizeof(pt))) std::abort();
    }

    // zero-length-CT AEAD round-trip.
    // AEAD reduces to "MAC over AAD only" when ct_len=0 — the
    // ChaCha20 keystream path (counter=1) is bypassed entirely and
    // the tag is computed over aad || pad16 || 0 || pad16 || lens.
    // A copy-len underflow in the AEAD glue would silently
    // succeed-and-forge here.
    {
        static const uint8_t key[32] = {
            0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
            0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
            0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
            0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
        };
        static const uint8_t nonce[12] = {
            0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,
            0x44,0x45,0x46,0x47
        };
        static const uint8_t aad[7] = { 'a','u','t','h','-','o','k' };
        uint8_t tag[16];
        if (!chacha20_poly1305_encrypt(key, nonce,
                                       aad, sizeof(aad),
                                       nullptr, 0,   // zero CT
                                       nullptr, tag)) std::abort();
        if (!chacha20_poly1305_decrypt(key, nonce,
                                       aad, sizeof(aad),
                                       nullptr, 0,
                                       tag, nullptr)) std::abort();
        // Tampered AAD with empty CT must still reject.
        uint8_t bad_aad[7];
        std::memcpy(bad_aad, aad, 7);
        bad_aad[3] ^= 1;
        if (chacha20_poly1305_decrypt(key, nonce,
                                      bad_aad, sizeof(bad_aad),
                                      nullptr, 0,
                                      tag, nullptr)) std::abort();
    }

    // vendored_pin.h tripwire.
    // The exact raw SHA-256 of this file is code-reviewed and committed in
    // vendored_pin.h, vendored_pin_expected.h, and vendored_pin_history.h.
    // scripts/verify-pqc-provenance.py recomputes it before compilation and
    // again before package handoff. Builds never regenerate or approve a pin.
    // This runtime check ensures the three reviewed values embedded in the
    // binary still agree and rejects a placeholder or malformed value.
    //
    // This is a STARTUP check inside vendored_crypto_selftest(), which
    // is called from main() of every veld-* binary; cost is one strlen
    // and one strcmp.
    {
        const char* pin = veld::crypto::VENDORED_SHA256_HEX;
        if (pin == nullptr) std::abort();
        const std::size_t pin_len = std::strlen(pin);
        // A real SHA-256 hex digest is exactly 64 lowercase hex chars.
        // The placeholder shipped before the build-pipeline integration
        // was "<COMPUTE_AT_BUILD_OR_LEAVE_PLACEHOLDER>" (40 chars, with
        // angle brackets). Any non-64 length is automatically rejected.
        if (pin_len != 64) {
            std::fprintf(stderr,
                "[FATAL] include/crypto/vendored_pin.h holds a placeholder "
                "or malformed reviewed pin (%zu chars). Refusing to start.\n",
                pin_len);
            std::abort();
        }
        // Verify every character is a lowercase hex digit. Defends
        // against a 64-char placeholder slipping through.
        for (std::size_t i = 0; i < 64; ++i) {
            const char c = pin[i];
            const bool is_hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
            if (!is_hex) {
                std::fprintf(stderr,
                    "[FATAL] vendored_pin.h pin[%zu]=0x%02x is not lowercase "
                    "hex; pin is malformed.\n", i, (unsigned)(unsigned char)c);
                std::abort();
            }
        }
        // Cross-check the reviewed pin against the committed expected digest.
        // The build gate and this runtime guard both fail closed on mismatch.
        const char* expected = veld::crypto::VENDORED_SHA256_EXPECTED;
        if (expected == nullptr || std::strlen(expected) != 64) {
            std::fprintf(stderr,
                "[FATAL] vendored_pin_expected.h missing or malformed.\n");
            std::abort();
        }
        // Constant-time compare to avoid leaking any signal about *which*
        // byte differs. Defensive — both values are public — but cheap.
        unsigned char diff = 0;
        for (std::size_t i = 0; i < 64; ++i) {
            diff |= (unsigned char)(pin[i] ^ expected[i]);
        }
        if (diff != 0) {
            std::fprintf(stderr,
                "[FATAL] vendored.h reviewed pin mismatch — pin=%s expected=%s.\n"
                "  Committed provenance values disagree. Refusing to start\n"
                "  with potentially-tampered cryptographic primitives.\n",
                pin, expected);
            std::abort();
        }
        // Check the append-only pin history as an independent committed value.
        // The pin and expected value could otherwise change together. The
        // reviewed history tip makes a partial update fail closed.
        const char* history_tip = veld::crypto::VENDORED_PIN_HISTORY_TIP;
        if (history_tip == nullptr || std::strlen(history_tip) != 64) {
            std::fprintf(stderr,
                "[FATAL] vendored_pin_history.h missing or malformed.\n");
            std::abort();
        }
        unsigned char diff_h = 0;
        for (std::size_t i = 0; i < 64; ++i) {
            diff_h |= (unsigned char)(pin[i] ^ history_tip[i]);
        }
        if (diff_h != 0) {
            std::fprintf(stderr,
                "[FATAL] vendored.h pin/history mismatch — pin=%s history_tip=%s.\n"
                "  Pin and expected agree but history disagrees, OR vice versa.\n"
                "  This indicates an unauthorised pin update that touched some\n"
                "  but not all of the three committed sources. Refusing to start.\n",
                pin, history_tip);
            std::abort();
        }
        // Friendly trust banner. Operators running the binary see the pin
        // they're trusting; if they didn't expect it to change, they'll
        // notice. Quiet mode (env VELD_QUIET_SELFTEST=1) suppresses for
        // production-noise reasons.
        if (std::getenv("VELD_QUIET_SELFTEST") == nullptr) {
            std::fprintf(stderr,
                "  [vendored-pin] reviewed vendored.h SHA-256 = %.16s... (expected match, history match)\n",
                pin);
        }
    }

    // ---- ML-DSA-65 (Dilithium-3) sign+verify round-trip ----
    // Exercise ML-DSA-65 at startup so an LTO, AVX, or toolchain miscompile of
    // vendor/pqc/mldsa65/{sign,poly,
    // polyvec,ntt,reduce,rounding,packing,fips202}.c would silently ship
    // and either (a) produce unverifiable sigs → every wallet un-spendable,
    // or (b) verify forged sigs against all pubkeys → network-wide key
    // forgery. This round-trip KAT catches both failure modes. Abort
    // closes the binary loudly rather than accepting miscompiled crypto.
    //
    // We use a deterministic seed for keygen (the test seed itself is in
    // the binary, so this is trivially reproducible and the key is not
    // secret). The seed-based generator `veld_mldsa65_keypair_from_seed`
    // is our wallet's canonical path, so verifying it here also catches
    // divergence between our seed-derived keygen and stock `crypto_sign_keypair`.
    //
    // signature length is exactly CRYPTO_BYTES =
    // 3309 bytes per PQClean ML-DSA-65 (vendor/pqc/mldsa65/api.h). No
    // trailing sighash tag — Veld stores signatures raw on-chain. The
    // earlier "3310?" speculation has been removed.
    // Scope: verifies keygen-from-seed determinism, signature produces
    // correct length (3309 bytes per CRYPTO_BYTES), verify accepts
    // honest sig, verify rejects a 1-bit-flipped sig.
    {
        static const uint8_t seed[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        // Static to keep 4032-byte sk off the thread's stack (Windows
        // default stack is ~1MB — 4k is fine, but keeping the large
        // buffers in .bss avoids any edge-case stack-overflow on
        // recursive init paths).
        static uint8_t pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES]; // 1952
        static uint8_t sk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_SECRETKEYBYTES]; // 4032
        static uint8_t sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];         // 3309
        if (veld_mldsa65_keypair_from_seed(seed, pk, sk) != 0) std::abort();

        static const uint8_t msg[] = "veld-mldsa65-selftest-2026-04-24";
        const size_t msg_len = sizeof(msg) - 1;
        static const uint8_t ctx[] = "VELD_KAT";
        const size_t ctx_len = sizeof(ctx) - 1;
        size_t siglen = 0;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature_ctx(
                sig, &siglen, msg, msg_len, ctx, ctx_len, sk) != 0) std::abort();
        if (siglen == 0 || siglen > PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) std::abort();

        // Honest verify must pass.
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                sig, siglen, msg, msg_len, ctx, ctx_len, pk) != 0) std::abort();

        // Tampered signature must fail.
        sig[0] ^= 1;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                sig, siglen, msg, msg_len, ctx, ctx_len, pk) == 0) std::abort();
        sig[0] ^= 1; // restore

        // Tampered message must fail.
        static uint8_t tampered_msg[sizeof(msg) - 1];
        std::memcpy(tampered_msg, msg, sizeof(tampered_msg));
        tampered_msg[0] ^= 1;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify_ctx(
                sig, siglen, tampered_msg, msg_len, ctx, ctx_len, pk) == 0) std::abort();

        // // Production sign/verify uses crypto_sign_signature / crypto_sign_
        // verify (NO ctx). The above test exercised the _ctx variants only.
        // A future PQClean refresh that miscompiles the no-ctx wrapper would
        // ship unnoticed. Add an explicit no-ctx KAT covering the production
        // path. Re-uses the same key + msg as the ctx path; the SECRETKEY-
        // RANDOMNESS bytes are zero in both keypair_from_seed paths so this
        // produces a fully deterministic signature whose value is identical
        // across rebuild from the same source.
        size_t siglen_noctx = 0;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(
                sig, &siglen_noctx, msg, msg_len, sk) != 0) std::abort();
        if (siglen_noctx == 0 ||
            siglen_noctx > PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES) std::abort();
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                sig, siglen_noctx, msg, msg_len, pk) != 0) std::abort();
        // Tamper detection on the no-ctx path too.
        sig[0] ^= 1;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                sig, siglen_noctx, msg, msg_len, pk) == 0) std::abort();
        sig[0] ^= 1;
        // Tampered message rejection on the no-ctx path.
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                sig, siglen_noctx, tampered_msg, msg_len, pk) == 0) std::abort();

        // Fixed upstream known-answer verification. This is the first
        // NIST-format ML-DSA-65 KAT shipped by the pinned PQClean commit;
        // its complete generator output matches META.yml's
        // nistkat-sha256 value. Unlike the round trip above, these bytes do
        // not originate from the implementation being tested.
        static uint8_t kat_pk[PQCLEAN_MLDSA65_CLEAN_CRYPTO_PUBLICKEYBYTES];
        static uint8_t kat_sig[PQCLEAN_MLDSA65_CLEAN_CRYPTO_BYTES];
        static uint8_t kat_msg[33];
        auto decode_hex = [](const char* hex, size_t hex_len,
                             uint8_t* out, size_t out_len) -> bool {
            if (hex_len != out_len * 2) return false;
            auto nibble = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            for (size_t i = 0; i < out_len; ++i) {
                const int hi = nibble(hex[i * 2]);
                const int lo = nibble(hex[i * 2 + 1]);
                if (hi < 0 || lo < 0) return false;
                out[i] = static_cast<uint8_t>((hi << 4) | lo);
            }
            return true;
        };
        if (!decode_hex(veld::crypto::mldsa65_kat::kPublicKeyHex,
                        sizeof(veld::crypto::mldsa65_kat::kPublicKeyHex) - 1,
                        kat_pk, sizeof(kat_pk)) ||
            !decode_hex(veld::crypto::mldsa65_kat::kSignatureHex,
                        sizeof(veld::crypto::mldsa65_kat::kSignatureHex) - 1,
                        kat_sig, sizeof(kat_sig)) ||
            !decode_hex(veld::crypto::mldsa65_kat::kMessageHex,
                        sizeof(veld::crypto::mldsa65_kat::kMessageHex) - 1,
                        kat_msg, sizeof(kat_msg))) {
            std::abort();
        }
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                kat_sig, sizeof(kat_sig), kat_msg, sizeof(kat_msg), kat_pk) != 0) {
            std::abort();
        }
        kat_sig[0] ^= 1;
        if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(
                kat_sig, sizeof(kat_sig), kat_msg, sizeof(kat_msg), kat_pk) == 0) {
            std::abort();
        }
        kat_sig[0] ^= 1;

        // Wipe sk after the test (hygiene; this is a fixed-seed test key
        // but keeping the wipe routine exercised on every startup protects
        // against regressions in SecureZero compilation).
        veld::compat::SecureZero(sk, sizeof(sk));
    }
}

} // namespace vendored_crypto
} // namespace veld

#endif // VELD_CRYPTO_VENDORED_H
