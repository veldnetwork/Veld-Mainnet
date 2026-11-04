#pragma once

#include "../consensus/nms.h"
#include <mutex>
#include <optional>

namespace veld::mining {

// One public proof, never a key or a funding reservation. A new parent or
// payout identity replaces the old candidate; callers recheck canonical state.
class NmsProofMailbox {
    mutable std::mutex mutex_;
    std::vector<uint8_t> script_;
    std::optional<NmsRecord> proof_;

  public:
    void Offer(const std::vector<uint8_t>& script, const BlockHeader& header) {
        const auto payload = EncodeNmsPayload(header);
        if (script.size() != 25 || payload.size() != NMS_PAYLOAD_LEN)
            return;
        std::lock_guard<std::mutex> lock(mutex_);
        if (proof_ && script_ == script && proof_->header.prev_block_hash == header.prev_block_hash)
            return;
        script_ = script;
        proof_ = NmsRecord{header, payload};
    }

    std::optional<NmsRecord> Read(const std::vector<uint8_t>& script, const Hash256& parent) const {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!proof_ || script_ != script || proof_->header.prev_block_hash != parent)
            return std::nullopt;
        return proof_;
    }
};

} // namespace veld::mining
