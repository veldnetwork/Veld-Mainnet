#pragma once

#include "../compat/platform.h"
#include <array>
#include <cstddef>
#include <cstdint>

namespace veld::mining {

// Randomize the search origin to reduce duplicate work between processes
// mining the same header. Worker offsets and strides partition each process's
// search independently of its payout address.
template <typename RandomFill>
inline bool TryCreateMiningNonceBase(uint64_t& out, RandomFill&& fill) {
    std::array<uint8_t, 8> bytes{};
    if (!fill(bytes.data(), bytes.size()))
        return false;
    uint64_t value = 0;
    for (size_t i = 0; i < bytes.size(); ++i)
        value |= static_cast<uint64_t>(bytes[i]) << (8 * i);
    out = value;
    return true;
}

inline bool TryCreateMiningNonceBase(uint64_t& out) {
    return TryCreateMiningNonceBase(
        out, [](uint8_t* bytes, size_t size) { return compat::SecureRandom(bytes, size); });
}

inline constexpr uint64_t MiningWorkerNonceStart(uint64_t base, unsigned worker_id) {
    // Unsigned wraparound preserves distinct offsets near UINT64_MAX.
    return base + static_cast<uint64_t>(worker_id);
}

} // namespace veld::mining
