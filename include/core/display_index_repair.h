#pragma once
#include "address_history.h"
#include "miner_archive.h"
#include <array>

namespace veld::display_index {

// Caller owns the canonical transition sequencer and keeps display reads closed
// until the complete operation succeeds. These are derived indexes only.
struct ReorgResult {
    bool miner = false;
    bool history = false;
};
using OldBlockAt = std::function<Block(uint64_t, const Hash256&)>;
using BlockAt = std::function<Block(uint64_t)>;

inline ReorgResult RepairReorg(db::KVStore& store, uint64_t ancestor_height,
                               const Hash256& ancestor_hash, uint64_t old_height,
                               const Hash256& old_hash, uint64_t new_height,
                               const Hash256& new_hash, ReorgResult ready, const OldBlockAt& old_at,
                               const BlockAt& canonical_at) {
    if (old_height <= ancestor_height || new_height <= ancestor_height ||
        old_height - ancestor_height > MAX_REORG_DEPTH ||
        new_height - ancestor_height > MAX_REORG_DEPTH)
        return {};
    ready.miner = ready.miner && miner_archive::MarkersMatch(store, old_height, old_hash);
    ready.history = ready.history && address_history::MarkersMatch(store, old_height, old_hash);
    Hash256 expected = old_hash;
    for (uint64_t height = old_height; height > ancestor_height; --height) {
        if (!ready.miner && !ready.history)
            return {};
        const Block block = old_at(height, expected);
        if (block.height != height || block.GetHash() != expected)
            return {};
        if (ready.miner)
            ready.miner = miner_archive::Rollback(store, block);
        if (ready.history)
            ready.history = address_history::Rollback(store, block);
        expected = block.header.prev_block_hash;
    }
    if (expected != ancestor_hash)
        return {};
    for (uint64_t height = ancestor_height + 1; height <= new_height; ++height) {
        if (!ready.miner && !ready.history)
            return {};
        const Block block = canonical_at(height);
        if (block.height != height || block.header.prev_block_hash != expected)
            return {};
        expected = block.GetHash();
        if (ready.miner)
            ready.miner = miner_archive::Advance(store, block) == miner_archive::AdvanceResult::Ok;
        if (ready.history)
            ready.history = address_history::Advance(store, block);
        if (height == new_height)
            break;
    }
    if (expected != new_hash)
        return {};
    ready.miner = ready.miner && miner_archive::MarkersMatch(store, new_height, new_hash);
    ready.history = ready.history && address_history::MarkersMatch(store, new_height, new_hash);
    return ready;
}

enum class Kind { Miner, History };
enum class StepResult { Pending, Complete, Failed };

// A failed derived index recovers in bounded steps. Each call removes at most
// 256 keys or advances exactly one canonical block, then releases the caller's
// transition guard. Linear commits leave a recovering index closed; a reorg
// behind this cursor restarts cleanup before any page can be published.
class RebuildCursor {
    bool active_ = false;
    size_t prefix_ = 0;
    uint64_t next_height_ = 0;
    Hash256 previous_{};

  public:
    void Reset() {
        active_ = false;
        prefix_ = 0;
        next_height_ = 0;
        previous_ = {};
    }
    StepResult Step(db::KVStore& store, Kind kind, uint64_t tip_height, const Hash256& tip_hash,
                    const BlockAt& canonical_at) {
        const bool miner = kind == Kind::Miner;
        if (!active_) {
            db::WriteBatch invalidate;
            invalidate.Delete(miner ? miner_archive::HEIGHT_KEY : address_history::TIP_HEIGHT_KEY);
            invalidate.Delete(miner ? miner_archive::HASH_KEY : address_history::TIP_HASH_KEY);
            if (!store.Write(invalidate))
                return StepResult::Failed;
            active_ = true;
        }
        const std::array<std::string, 4> prefixes =
            miner ? std::array<std::string, 4>{miner_archive::COUNT_PREFIX,
                                               miner_archive::LAST_PREFIX,
                                               miner_archive::UNDO_PREFIX, ""}
                  : std::array<std::string, 4>{address_history::ROW_PREFIX,
                                               address_history::OUTPOINT_PREFIX,
                                               address_history::BLOCK_PREFIX, "ah1:"};
        const size_t count = miner ? 3 : 4;
        if (prefix_ < count) {
            db::WriteBatch erase;
            store.Iterate(prefixes[prefix_], [&](const std::string& key, const std::string&) {
                erase.Delete(key);
                return erase.ops.size() < 256;
            });
            if (!erase.ops.empty() && !store.Write(erase))
                return StepResult::Failed;
            if (erase.ops.size() < 256)
                ++prefix_;
            return StepResult::Pending;
        }
        if (next_height_ > 0 && (next_height_ - 1 > tip_height ||
                                 canonical_at(next_height_ - 1).GetHash() != previous_)) {
            Reset();
            return StepResult::Pending;
        }
        const Block block = canonical_at(next_height_);
        if (block.height != next_height_ ||
            (next_height_ > 0 && block.header.prev_block_hash != previous_))
            return StepResult::Failed;
        const bool ok =
            miner ? miner_archive::Advance(store, block) == miner_archive::AdvanceResult::Ok
                  : address_history::Advance(store, block);
        if (!ok)
            return StepResult::Failed;
        previous_ = block.GetHash();
        if (next_height_ == tip_height) {
            if (previous_ != tip_hash)
                return StepResult::Failed;
            Reset();
            return StepResult::Complete;
        }
        if (next_height_ == UINT64_MAX)
            return StepResult::Failed;
        ++next_height_;
        return StepResult::Pending;
    }
};
} // namespace veld::display_index
