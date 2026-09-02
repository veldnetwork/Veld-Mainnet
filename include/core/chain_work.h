#pragma once

// Native-chain proof-of-work scoring and exact cumulative-work arithmetic.
//
// This deliberately lives outside blockchain.h so every consensus consumer
// uses one compact-target decoder and one work definition. Fork choice keeps
// the full 320-bit value. Callers whose *economic* metric is intentionally
// uint64-bounded must opt in to BlockWorkForTier(), which saturates explicitly
// instead of silently narrowing consensus chainwork.

#include "pow_target.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string>

namespace veld {

// 320-bit cumulative work. A valid block contributes at most 2^255 work
// (minimum positive target = 1 under target+1 semantics), and a uint64-height
// chain contains at most 2^64 blocks. Therefore total chainwork is < 2^319;
// ten 32-bit limbs cover the entire representable chain-height domain exactly.
struct ChainWork {
    std::array<uint32_t, 10> w{};  // little-endian limbs

    ChainWork() = default;
    ChainWork(uint64_t value) {
        w[0] = static_cast<uint32_t>(value);
        w[1] = static_cast<uint32_t>(value >> 32);
    }
    explicit ChainWork(const btcspv::U256& value) {
        for (size_t i = 0; i < 8; ++i) w[i] = value.w[i];
    }

    int Compare(const ChainWork& other) const {
        for (int i = 9; i >= 0; --i) {
            if (w[i] < other.w[i]) return -1;
            if (w[i] > other.w[i]) return 1;
        }
        return 0;
    }
    bool operator==(const ChainWork& other) const { return Compare(other) == 0; }
    bool operator!=(const ChainWork& other) const { return Compare(other) != 0; }
    bool operator< (const ChainWork& other) const { return Compare(other) <  0; }
    bool operator> (const ChainWork& other) const { return Compare(other) >  0; }
    bool operator<=(const ChainWork& other) const { return Compare(other) <= 0; }
    bool operator>=(const ChainWork& other) const { return Compare(other) >= 0; }

    ChainWork MulU32(uint32_t scalar, bool* overflow = nullptr) const {
        ChainWork result;
        uint64_t carry = 0;
        for (size_t i = 0; i < w.size(); ++i) {
            const uint64_t product = static_cast<uint64_t>(w[i]) * scalar + carry;
            result.w[i] = static_cast<uint32_t>(product);
            carry = product >> 32;
        }
        if (overflow) *overflow = carry != 0;
        return result;
    }

    int BitLength() const {
        for (int i = 9; i >= 0; --i) {
            if (w[i] == 0) continue;
            uint32_t value = w[i];
            int bits = 0;
            while (value != 0) { value >>= 1; ++bits; }
            return i * 32 + bits;
        }
        return 0;
    }

    std::string ToHex() const {
        std::ostringstream out;
        out << std::hex << std::setfill('0');
        for (int i = 9; i >= 0; --i) out << std::setw(8) << w[i];
        return out.str();
    }

    uint64_t ToUint64Saturated() const {
        for (size_t i = 2; i < w.size(); ++i) {
            if (w[i] != 0) return std::numeric_limits<uint64_t>::max();
        }
        return static_cast<uint64_t>(w[0]) |
               (static_cast<uint64_t>(w[1]) << 32);
    }
};

// Compact target = mantissa * 2^(8*(exponent-3)). Exact per-block work is
// floor(2^256 / (target+1)), implemented by btcspv::BlockWork as
// (~target / (target+1)) + 1 without requiring a 257-bit numerator.
// Structurally invalid encodings (including the sign-bit alias) score zero.
// Exact expected-bits gates prevent representation aliases on live ingest.
inline ChainWork BlockWork(uint32_t bits) {
    CanonicalPowTarget target;
    if (!DecodeCanonicalVeldTarget(bits, target)) return ChainWork(0);
    return ChainWork(btcspv::BlockWork(target.value));
}

inline ChainWork AddChainWork(const ChainWork& accumulated,
                              const ChainWork& increment) {
    ChainWork result;
    uint64_t carry = 0;
    for (size_t i = 0; i < result.w.size(); ++i) {
        const uint64_t sum = static_cast<uint64_t>(accumulated.w[i]) +
                             increment.w[i] + carry;
        result.w[i] = static_cast<uint32_t>(sum);
        carry = sum >> 32;
    }
    if (carry != 0) {
        throw std::overflow_error(
            "cumulative chainwork exceeded the full uint64-height domain");
    }
    return result;
}

// The btcVELD tier ladder is a separate, deliberately uint64-bounded economic
// metric. Values above that range all exceed every uint64 tier threshold, so
// explicit saturation preserves its ordering without narrowing fork chainwork.
inline uint64_t BlockWorkForTier(uint32_t bits) {
    return BlockWork(bits).ToUint64Saturated();
}

}  // namespace veld
