#pragma once

// ─────────────────────────────────────────────
//  RIPEMD-160
//  Used in Bitcoin-style address derivation:
//    address = Base58Check(RIPEMD160(SHA256(pubkey)))
//
//  This is a complete, correct, standalone
//  implementation requiring no external libraries.
//
//  Production: optionally link OpenSSL and define
//  VELD_USE_OPENSSL to use its RIPEMD160() instead.
// ─────────────────────────────────────────────

#include "../core/hash.h"
#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>

//  VENDORED: the hand-rolled RIPEMD-160 below is now the
// ONLY path (OpenSSL EVP_ripemd160 was removed alongside the rest of
// the libcrypto excision — see include/crypto/vendored.h).

namespace veld {

using Hash160 = std::array<uint8_t, 20>;

// ─────────────────────────────────────────────
//  RIPEMD-160 CONSTANTS
// ─────────────────────────────────────────────
namespace ripemd_detail {

inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// Boolean functions
inline uint32_t f(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ y ^ z;
}
inline uint32_t g(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) | (~x & z);
}
inline uint32_t h(uint32_t x, uint32_t y, uint32_t z) {
    return (x | ~y) ^ z;
}
inline uint32_t ii(uint32_t x, uint32_t y, uint32_t z) {
    return (x & z) | (y & ~z);
}
inline uint32_t j(uint32_t x, uint32_t y, uint32_t z) {
    return x ^ (y | ~z);
}

// Message schedule indices — left and right rounds
static const uint8_t R_L[80] = {0, 1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
                                7, 4,  13, 1,  10, 6,  15, 3,  12, 0, 9,  5,  2,  14, 11, 8,
                                3, 10, 14, 4,  9,  15, 8,  1,  2,  7, 0,  6,  13, 11, 5,  12,
                                1, 9,  11, 10, 0,  8,  12, 4,  13, 3, 7,  15, 14, 5,  6,  2,
                                4, 0,  5,  9,  7,  12, 2,  10, 14, 1, 3,  8,  11, 6,  15, 13};
static const uint8_t R_R[80] = {5,  14, 7,  0, 9, 2,  11, 4,  13, 6,  15, 8,  1,  10, 3,  12,
                                6,  11, 3,  7, 0, 13, 5,  10, 14, 15, 8,  12, 4,  9,  1,  2,
                                15, 5,  1,  3, 7, 14, 6,  9,  11, 8,  12, 2,  10, 0,  4,  13,
                                8,  6,  4,  1, 3, 11, 15, 0,  5,  12, 2,  13, 9,  7,  10, 14,
                                12, 15, 10, 4, 1, 5,  8,  7,  6,  2,  13, 14, 0,  3,  9,  11};

// Shift amounts — left and right rounds
static const uint8_t S_L[80] = {11, 14, 15, 12, 5,  8,  7,  9,  11, 13, 14, 15, 6,  7,  9,  8,
                                7,  6,  8,  13, 11, 9,  7,  15, 7,  12, 15, 9,  11, 7,  13, 12,
                                11, 13, 6,  7,  14, 9,  13, 15, 14, 8,  13, 6,  5,  12, 7,  5,
                                11, 12, 14, 15, 14, 15, 9,  8,  9,  14, 5,  6,  8,  6,  5,  12,
                                9,  15, 5,  11, 6,  8,  13, 12, 5,  12, 13, 14, 11, 8,  5,  6};
static const uint8_t S_R[80] = {8,  9,  9,  11, 13, 15, 15, 5,  7,  7,  8,  11, 14, 14, 12, 6,
                                9,  13, 15, 7,  12, 8,  9,  11, 7,  7,  12, 7,  6,  15, 13, 11,
                                9,  7,  15, 11, 8,  6,  6,  14, 12, 13, 5,  14, 13, 13, 7,  5,
                                15, 5,  8,  11, 14, 14, 6,  14, 6,  9,  12, 9,  12, 5,  15, 8,
                                8,  5,  12, 9,  12, 5,  14, 6,  8,  13, 6,  5,  15, 13, 11, 11};

// Round constants — left
static const uint32_t K_L[5] = {0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E};
// Round constants — right
static const uint32_t K_R[5] = {0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000};

} // namespace ripemd_detail

// ─────────────────────────────────────────────
//  RIPEMD160 CLASS
// ─────────────────────────────────────────────
class RIPEMD160 {
  public:
    RIPEMD160() {
        Reset();
    }

    void Reset() {
        state_[0] = 0x67452301;
        state_[1] = 0xEFCDAB89;
        state_[2] = 0x98BADCFE;
        state_[3] = 0x10325476;
        state_[4] = 0xC3D2E1F0;
        count_ = 0;
        buf_pos_ = 0;
    }

    void Update(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; ++i) {
            buf_[buf_pos_++] = data[i];
            if (buf_pos_ == 64) {
                Transform();
                buf_pos_ = 0;
            }
        }
        count_ += len * 8;
    }

    void Update(const std::vector<uint8_t>& data) {
        Update(data.data(), data.size());
    }

    Hash160 Digest() {
        // Save true bit count before padding calls modify it
        uint64_t true_bit_count = count_;

        // Padding: append 0x80 then zeros then 64-bit length
        uint8_t pad[64] = {0};
        pad[0] = 0x80;
        size_t pad_len = (buf_pos_ < 56) ? (56 - buf_pos_) : (120 - buf_pos_);
        Update(pad, pad_len);

        // Append true message length (little-endian 64-bit)
        uint8_t len_bytes[8];
        for (int i = 0; i < 8; ++i) {
            len_bytes[i] = (uint8_t)(true_bit_count & 0xFF);
            true_bit_count >>= 8;
        }
        Update(len_bytes, 8);

        // Extract digest (little-endian)
        Hash160 result;
        for (int i = 0; i < 5; ++i) {
            result[i * 4 + 0] = (uint8_t)(state_[i]);
            result[i * 4 + 1] = (uint8_t)(state_[i] >> 8);
            result[i * 4 + 2] = (uint8_t)(state_[i] >> 16);
            result[i * 4 + 3] = (uint8_t)(state_[i] >> 24);
        }
        return result;
    }

  private:
    uint32_t state_[5];
    uint64_t count_;
    uint8_t buf_[64];
    size_t buf_pos_;

    void Transform() {
        using namespace ripemd_detail;

        // Load message block (little-endian)
        uint32_t X[16];
        for (int i = 0; i < 16; ++i) {
            X[i] = (uint32_t)buf_[i * 4] | ((uint32_t)buf_[i * 4 + 1] << 8) |
                   ((uint32_t)buf_[i * 4 + 2] << 16) | ((uint32_t)buf_[i * 4 + 3] << 24);
        }

        uint32_t al = state_[0], bl = state_[1], cl = state_[2], dl = state_[3], el = state_[4];
        uint32_t ar = state_[0], br = state_[1], cr = state_[2], dr = state_[3], er = state_[4];

        // 80 rounds — left and right in parallel
        for (int i = 0; i < 80; ++i) {
            int round = i / 16;
            uint32_t fl, fr;

            // Left boolean function
            switch (round) {
            case 0:
                fl = f(bl, cl, dl);
                break;
            case 1:
                fl = g(bl, cl, dl);
                break;
            case 2:
                fl = h(bl, cl, dl);
                break;
            case 3:
                fl = ii(bl, cl, dl);
                break;
            default:
                fl = j(bl, cl, dl);
                break;
            }

            // Right boolean function (rounds go j, ii, h, g, f)
            switch (round) {
            case 0:
                fr = j(br, cr, dr);
                break;
            case 1:
                fr = ii(br, cr, dr);
                break;
            case 2:
                fr = h(br, cr, dr);
                break;
            case 3:
                fr = g(br, cr, dr);
                break;
            default:
                fr = f(br, cr, dr);
                break;
            }

            uint32_t tl = rotl(al + fl + X[R_L[i]] + K_L[round], S_L[i]) + el;
            al = el;
            el = dl;
            dl = rotl(cl, 10);
            cl = bl;
            bl = tl;

            uint32_t tr = rotl(ar + fr + X[R_R[i]] + K_R[round], S_R[i]) + er;
            ar = er;
            er = dr;
            dr = rotl(cr, 10);
            cr = br;
            br = tr;
        }

        // Combine
        uint32_t t = state_[1] + cl + dr;
        state_[1] = state_[2] + dl + er;
        state_[2] = state_[3] + el + ar;
        state_[3] = state_[4] + al + br;
        state_[4] = state_[0] + bl + cr;
        state_[0] = t;
    }
};

// ─────────────────────────────────────────────
//  PUBLIC API: Hash160 = RIPEMD160(SHA256(data))
//
//   VENDORED CRYPTO: both SHA-256 and RIPEMD-160 now route
//  through vendored implementations. The SHA-256 pass uses
//  include/crypto/vendored.h's Sha256 (FIPS 180-4); the RIPEMD-160
//  pass uses the hand-rolled RIPEMD160 class already defined above
//  in this header (the same implementation that was previously the
//  FIPS-only fallback). Dropping OpenSSL here lets the Windows build
//  link without libcrypto.a, which was tripping Windows Defender's
//  coinminer heuristic. Output is byte-identical — both standards are
//  deterministic and the hand-rolled RIPEMD-160 has been regression-
//  tested against the OpenSSL path — so this is a drop-in, no chain
//  fork, same addresses.
// ─────────────────────────────────────────────
#include "vendored.h"

inline Hash160 Hash160Compute(const uint8_t* data, size_t len) {
    uint8_t sha_out[32];
    ::veld::vendored_crypto::sha256(data, len, sha_out);

    RIPEMD160 rmd;
    rmd.Update(sha_out, 32);
    return rmd.Digest();
}

inline Hash160 Hash160Compute(const std::vector<uint8_t>& data) {
    return Hash160Compute(data.data(), data.size());
}

// Convenience: compute Hash160 of a pubkey array
template <size_t N> inline Hash160 Hash160Compute(const std::array<uint8_t, N>& data) {
    return Hash160Compute(data.data(), data.size());
}

} // namespace veld
