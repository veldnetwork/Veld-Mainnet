#pragma once

#include "../core/block.h"
#include <atomic>
#include <limits>
#include <mutex>

namespace veld::mining {

// Workers hash a private snapshot. A timestamp refresh never changes a header
// that another worker is hashing or about to report as a near miss.
class MiningWorkHeader {
  public:
    struct Snapshot {
        BlockHeader header;
        uint64_t generation;

        BlockHeader WithNonce(uint64_t nonce) const {
            auto result = header;
            result.nonce = nonce;
            return result;
        }
    };

    explicit MiningWorkHeader(const BlockHeader& header) : header_(header) {}

    Snapshot Read() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {header_, generation_.load(std::memory_order_relaxed)};
    }

    uint64_t Generation() const {
        return generation_.load(std::memory_order_acquire);
    }

    bool RefreshTimestamp(uint64_t expected_generation, uint64_t now) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (generation_.load(std::memory_order_relaxed) != expected_generation ||
            header_.timestamp == std::numeric_limits<uint64_t>::max() ||
            expected_generation == std::numeric_limits<uint64_t>::max())
            return false;
        header_.timestamp = now > header_.timestamp ? now : header_.timestamp + 1;
        generation_.store(expected_generation + 1, std::memory_order_release);
        return true;
    }

  private:
    mutable std::mutex mutex_;
    BlockHeader header_;
    std::atomic<uint64_t> generation_{0};
};

} // namespace veld::mining
