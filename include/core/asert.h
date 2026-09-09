#pragma once

#include "pow_target.h"
#include <array>
#include <cstdint>

namespace veld {

// Integer ASERT polynomial and rounding from the published specification:
// https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/
// This implementation preserves the full product before applying the shift.
inline bool CalculateASERTBits(uint32_t anchor_bits, int64_t time_delta,
                               uint64_t height_delta, uint32_t spacing,
                               uint32_t half_life, uint32_t& out_bits,
                               uint32_t limit_bits = VELD_POW_LIMIT_BITS) {
    CanonicalPowTarget anchor, limit;
    if (spacing == 0 || half_life == 0 ||
        !DecodeCanonicalVeldTarget(anchor_bits, anchor) ||
        !DecodeCanonicalVeldTarget(limit_bits, limit) ||
        anchor.value > limit.value) return false;

    // A 64-bit height times a 32-bit spacing, then 2^16, fits signed 128 bits.
    const __int128 delta = static_cast<__int128>(time_delta) -
        static_cast<__int128>(spacing) *
            (static_cast<__int128>(height_delta) + 1);
    const __int128 exponent = delta * 65536 / half_life; // truncate toward zero
    if (exponent > 512 * 65536) { out_bits = limit_bits; return true; }
    if (exponent < -512 * 65536) { out_bits = 0x01010000; return true; }
    const int64_t e = static_cast<int64_t>(exponent);
    const int64_t shifts = e >= 0 ? e / 65536 : -((-e + 65535) / 65536);
    const uint64_t fraction = static_cast<uint64_t>(e - shifts * 65536);
    const uint64_t factor = 65536 + ((195766423245049ULL * fraction +
        971821376ULL * fraction * fraction +
        5127ULL * fraction * fraction * fraction + (1ULL << 47)) >> 48);

    std::array<uint32_t, 9> product{};
    uint64_t carry = 0;
    for (size_t i = 0; i < 8; ++i) {
        const uint64_t word = uint64_t(anchor.value.w[i]) * factor + carry;
        product[i] = static_cast<uint32_t>(word);
        carry = word >> 32;
    }
    product[8] = static_cast<uint32_t>(carry);
    btcspv::U256 result;
    for (int bit = 0; bit < 288; ++bit) {
        if ((product[bit / 32] & (uint32_t(1) << (bit % 32))) == 0) continue;
        const int64_t destination = bit + shifts - 16;
        if (destination >= 256) { out_bits = limit_bits; return true; }
        if (destination >= 0) result.setbit(static_cast<int>(destination));
    }
    if (result.IsZero()) result = btcspv::U256::FromU64(1);
    if (result > limit.value) result = limit.value;
    out_bits = btcspv::TargetToCompact(result);
    CanonicalPowTarget canonical;
    return DecodeCanonicalVeldTarget(out_bits, canonical);
}

} // namespace veld
