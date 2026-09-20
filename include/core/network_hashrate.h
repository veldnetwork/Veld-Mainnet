#pragma once

#include "block.h"
#include "chain_work.h"
#include <algorithm>
#include <cmath>
#include <vector>

namespace veld {
// Display-only estimate. Never used for target selection or admission.
struct NetworkHashrateEstimate {
    double hashes_per_second{0};
    uint64_t intervals{0};
    uint64_t seconds{0};
    bool available{false};
};

inline NetworkHashrateEstimate EstimateNetworkHashrate(
        const std::vector<BlockHeader>& headers) {
    NetworkHashrateEstimate result;
    if (headers.size() < 2 || headers.size() > 145) return result;
    ChainWork work;
    uint64_t low = headers.front().timestamp, high = low;
    for (size_t i = 1; i < headers.size(); ++i) {
        if (headers[i].prev_block_hash != headers[i-1].GetHash()) return result;
        const auto increment = BlockWork(headers[i].bits);
        if (increment == ChainWork(0)) return result;
        work = AddChainWork(work, increment);
        low = std::min(low, headers[i].timestamp);
        high = std::max(high, headers[i].timestamp);
    }
    if (high == low) return result;
    long double total = 0;
    for (size_t i = work.w.size(); i-- > 0;)
        total = std::ldexp(total, 32) + work.w[i];
    result.seconds = uint64_t(high) - low;
    result.intervals = headers.size() - 1;
    result.hashes_per_second = static_cast<double>(total / result.seconds);
    result.available = std::isfinite(result.hashes_per_second);
    return result;
}
} // namespace veld
