#pragma once

#include "btc_pow.h"
#include "hash.h"

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

inline btcspv::U256 VeldPowLimit() {
    return btcspv::CompactToTarget(VELD_POW_LIMIT_BITS);
}

inline bool DecodeCanonicalVeldTarget(uint32_t raw_bits, CanonicalPowTarget& out,
                                      CompactTargetError* error = nullptr) {
    auto fail = [&](CompactTargetError why) {
        out = CanonicalPowTarget{};
        if (error)
            *error = why;
        return false;
    };
    bool negative = false, overflow = false;
    const btcspv::U256 target = btcspv::CompactToTarget(raw_bits, &negative, &overflow);
    if (negative)
        return fail(CompactTargetError::Negative);
    if (overflow)
        return fail(CompactTargetError::Overflow);
    if (target.IsZero())
        return fail(CompactTargetError::Zero);
    if (target > VeldPowLimit())
        return fail(CompactTargetError::AboveLimit);
    if (btcspv::TargetToCompact(target) != raw_bits)
        return fail(CompactTargetError::NonCanonical);

    CanonicalPowTarget decoded;
    decoded.bits = raw_bits;
    decoded.value = target;
    decoded.bytes.fill(0);
    for (size_t byte = 0; byte < decoded.bytes.size(); ++byte) {
        const size_t word = byte / 4U;
        const size_t shift = (byte % 4U) * 8U;
        decoded.bytes[31U - byte] = static_cast<uint8_t>(target.w[word] >> shift);
    }
    out = decoded;
    if (error)
        *error = CompactTargetError::None;
    return true;
}

inline bool DecodeExpectedVeldTarget(uint32_t raw_bits, uint32_t expected_bits,
                                     CanonicalPowTarget& out, CompactTargetError* error = nullptr) {
    if (!DecodeCanonicalVeldTarget(raw_bits, out, error))
        return false;
    if (raw_bits != expected_bits) {
        out = CanonicalPowTarget{};
        if (error)
            *error = CompactTargetError::NonCanonical;
        return false;
    }
    return true;
}

inline const char* CompactTargetErrorName(CompactTargetError error) {
    switch (error) {
    case CompactTargetError::None:
        return "none";
    case CompactTargetError::Negative:
        return "negative";
    case CompactTargetError::Zero:
        return "zero";
    case CompactTargetError::Overflow:
        return "overflow";
    case CompactTargetError::AboveLimit:
        return "above_limit";
    case CompactTargetError::NonCanonical:
        return "noncanonical";
    }
    return "unknown";
}

} // namespace veld
