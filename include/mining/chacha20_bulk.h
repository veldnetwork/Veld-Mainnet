#pragma once

// Mining-only four-block implementation of the existing RFC 7539 stream.
// Wallet encryption and the vendored reference implementation are untouched.
#include "../crypto/vendored.h"
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__SSE2__) && (defined(__x86_64__) || defined(_M_X64)) && \
    !defined(VELD_MINING_SCALAR_CHACHA)
#include <emmintrin.h>
#define VELD_MINING_CHACHA_SSE2 1
#endif

namespace veld::mining {
namespace chacha_bulk_detail {
#if defined(VELD_MINING_CHACHA_SSE2)
template <int Bits> inline __m128i Rotate(__m128i value) {
    return _mm_or_si128(_mm_slli_epi32(value, Bits), _mm_srli_epi32(value, 32 - Bits));
}
inline void Quarter(__m128i& a, __m128i& b, __m128i& c, __m128i& d) {
    a = _mm_add_epi32(a, b); d = Rotate<16>(_mm_xor_si128(d, a));
    c = _mm_add_epi32(c, d); b = Rotate<12>(_mm_xor_si128(b, c));
    a = _mm_add_epi32(a, b); d = Rotate<8>(_mm_xor_si128(d, a));
    c = _mm_add_epi32(c, d); b = Rotate<7>(_mm_xor_si128(b, c));
}
#endif
}

inline void MiningChaChaKeystream(const uint8_t key[32], const uint8_t iv[16],
                                uint8_t* output, size_t length) {
#if defined(VELD_MINING_CHACHA_SSE2)
    using namespace chacha_bulk_detail;
    using namespace veld::vendored_crypto;
    uint32_t base[16];
    uint32_t counter = vc_load32_le(iv);
    vc_chacha20_init_state_(base, key, counter, iv + 4);
    while (length >= 256) {
        __m128i words[16];
        for (unsigned i = 0; i < 16; ++i)
            words[i] = _mm_set1_epi32(static_cast<int32_t>(base[i]));
        // Each lane is a separate block. Counter wrap is exactly the existing
        // 32-bit RFC stream wrap, with no carry into the 96-bit nonce.
        const __m128i counters = _mm_set_epi32(
            static_cast<int32_t>(counter + 3u), static_cast<int32_t>(counter + 2u),
            static_cast<int32_t>(counter + 1u), static_cast<int32_t>(counter));
        words[12] = counters;
        for (unsigned round = 0; round < 10; ++round) {
            Quarter(words[0], words[4], words[8], words[12]);
            Quarter(words[1], words[5], words[9], words[13]);
            Quarter(words[2], words[6], words[10], words[14]);
            Quarter(words[3], words[7], words[11], words[15]);
            Quarter(words[0], words[5], words[10], words[15]);
            Quarter(words[1], words[6], words[11], words[12]);
            Quarter(words[2], words[7], words[8], words[13]);
            Quarter(words[3], words[4], words[9], words[14]);
        }
        for (unsigned word = 0; word < 16; ++word) {
            const __m128i original = word == 12 ? counters :
                _mm_set1_epi32(static_cast<int32_t>(base[word]));
            words[word] = _mm_add_epi32(words[word], original);
        }
        // Transpose four word vectors into four contiguous block fragments.
        // SSE2 unaligned stores preserve the exact little-endian RFC stream,
        // avoiding 64 scalar word stores and the intermediate lane array.
        for (unsigned word = 0; word < 16; word += 4) {
            const auto lo01 = _mm_unpacklo_epi32(words[word], words[word + 1]);
            const auto hi01 = _mm_unpackhi_epi32(words[word], words[word + 1]);
            const auto lo23 = _mm_unpacklo_epi32(words[word + 2], words[word + 3]);
            const auto hi23 = _mm_unpackhi_epi32(words[word + 2], words[word + 3]);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 4 * word), _mm_unpacklo_epi64(lo01, lo23));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 64 + 4 * word), _mm_unpackhi_epi64(lo01, lo23));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 128 + 4 * word), _mm_unpacklo_epi64(hi01, hi23));
            _mm_storeu_si128(reinterpret_cast<__m128i*>(output + 192 + 4 * word), _mm_unpackhi_epi64(hi01, hi23));
        }
        counter += 4;
        output += 256;
        length -= 256;
    }
    if (length) {
        uint8_t tail_iv[16];
        std::memcpy(tail_iv, iv, sizeof(tail_iv));
        vc_store32_le(tail_iv, counter);
        chacha20_keystream(key, tail_iv, output, length);
    }
#else
    veld::vendored_crypto::chacha20_keystream(key, iv, output, length);
#endif
}
}
