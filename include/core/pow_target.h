#pragma once

#include "btc_pow.h"
#include "hash.h"

#include <cmath>
#include <cstdint>

namespace veld {

inline constexpr uint32_t VELD_POW_LIMIT_BITS = 0x207fffffu;

enum class CompactTargetError : uint8_t {
    None,
    Negative,
    Zero,
    Overflow,
    AboveLimit,
    NonCanonical,
};

struct CanonicalPowTarget {
    uint32_t bits{0};
    btcspv::U256 value{};
    Hash256 bytes{};
};

struct PowDisplayMetrics {
    double expected_hashes_per_block{0.0};
    double difficulty{0.0};
};

inline btcspv::U256 VeldPowLimit() {
    return btcspv::CompactToTarget(VELD_POW_LIMIT_BITS);
}

inline bool DecodeCanonicalVeldTarget(
        uint32_t raw_bits, CanonicalPowTarget& out,
        CompactTargetError* error = nullptr) {
    auto fail = [&](CompactTargetError why) {
        out = CanonicalPowTarget{};
        if (error) *error = why;
        return false;
    };
    bool negative = false, overflow = false;
    const btcspv::U256 target =
        btcspv::CompactToTarget(raw_bits, &negative, &overflow);
    if (negative) return fail(CompactTargetError::Negative);
    if (overflow) return fail(CompactTargetError::Overflow);
    if (target.IsZero()) return fail(CompactTargetError::Zero);
    if (target > VeldPowLimit()) return fail(CompactTargetError::AboveLimit);
    if (btcspv::TargetToCompact(target) != raw_bits)
        return fail(CompactTargetError::NonCanonical);

    CanonicalPowTarget decoded;
    decoded.bits = raw_bits;
    decoded.value = target;
    decoded.bytes.fill(0);
    for (size_t byte = 0; byte < decoded.bytes.size(); ++byte) {
        const size_t word = byte / 4U;
        const size_t shift = (byte % 4U) * 8U;
        decoded.bytes[31U - byte] =
            static_cast<uint8_t>(target.w[word] >> shift);
    }
    out = decoded;
    if (error) *error = CompactTargetError::None;
    return true;
}

inline bool DecodeExpectedVeldTarget(
        uint32_t raw_bits, uint32_t expected_bits,
        CanonicalPowTarget& out,
        CompactTargetError* error = nullptr) {
    if (!DecodeCanonicalVeldTarget(raw_bits, out, error)) return false;
    if (raw_bits != expected_bits) {
        out = CanonicalPowTarget{};
        if (error) *error = CompactTargetError::NonCanonical;
        return false;
    }
    return true;
}

// Derive operator-facing work metrics from the same canonical compact target
// accepted by consensus. Difficulty is relative to Bitcoin's historical
// difficulty-one target; expected_hashes_per_block is the display-precision
// approximation of 2^256 / target used by the RPC and monitoring surfaces.
inline bool CalculatePowDisplayMetrics(uint32_t raw_bits,
                                       PowDisplayMetrics& out) {
    out = PowDisplayMetrics{};
    CanonicalPowTarget decoded;
    if (!DecodeCanonicalVeldTarget(raw_bits, decoded)) return false;

    const uint32_t exponent = raw_bits >> 24;
    const uint32_t mantissa = raw_bits & 0x007fffffu;
    if (exponent == 0 || exponent > 32 || mantissa == 0) return false;

    const double log2_expected =
        256.0 - 8.0 * static_cast<double>(static_cast<int>(exponent) - 3) -
        std::log2(static_cast<double>(mantissa));
    const double expected_hashes = std::exp2(log2_expected);
    const double log2_diff1_expected =
        256.0 - 8.0 * static_cast<double>(0x1d - 3) -
        std::log2(static_cast<double>(0x00ffff));
    const double diff1_expected = std::exp2(log2_diff1_expected);
    if (!std::isfinite(expected_hashes) || expected_hashes <= 0.0 ||
        !std::isfinite(diff1_expected) || diff1_expected <= 0.0) {
        return false;
    }

    out.expected_hashes_per_block = expected_hashes;
    out.difficulty = expected_hashes / diff1_expected;
    return std::isfinite(out.difficulty) && out.difficulty > 0.0;
}

inline const char* CompactTargetErrorName(CompactTargetError error) {
    switch (error) {
        case CompactTargetError::None: return "none";
        case CompactTargetError::Negative: return "negative";
        case CompactTargetError::Zero: return "zero";
        case CompactTargetError::Overflow: return "overflow";
        case CompactTargetError::AboveLimit: return "above_limit";
        case CompactTargetError::NonCanonical: return "noncanonical";
    }
    return "unknown";
}

} // namespace veld
