#pragma once

#include <cstdint>
#include <mutex>
#include <optional>

#include "hash.h"

namespace veld::btcveld {

// Blockchain reorg callbacks arrive one block at a time after the in-memory
// chain already names the final candidate tip. Publishing an intermediate
// callback would pair its derived supply with that final tip. Keep the previous
// coherent tuple until the final callback, while ordinary linear connects
// publish immediately.
constexpr bool ShouldPublishSupplySnapshot(bool from_reorg, uint64_t callback_height,
                                           uint64_t canonical_tip_height) {
    return !from_reorg || callback_height == canonical_tip_height;
}

// RPC-facing btcVELD supply must be tied to one exact canonical block. The
// block-connect path publishes this tuple only after module apply and durable
// canonical commit. Readers take one mutex-protected copy, so they can observe a
// safely lagging ancestor but never old supply paired with a new tip/hash.
struct SupplySnapshot {
    int64_t supply_sats{0};
    uint64_t tip{0};
    Hash256 tip_hash{};
};

class SupplySnapshotPublisher {
  public:
    void Publish(int64_t supply_sats, uint64_t tip, const Hash256& tip_hash) {
        std::lock_guard<std::mutex> lock(mutex_);
        snapshot_ = SupplySnapshot{supply_sats, tip, tip_hash};
    }

    std::optional<SupplySnapshot> Read() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return snapshot_;
    }

  private:
    mutable std::mutex mutex_;
    std::optional<SupplySnapshot> snapshot_;
};

} // namespace veld::btcveld
