#pragma once
#include "../core/constants.h"
#include "recent_lookup_progress.h"
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace veld::explorer {
// One budget belongs to the complete request, including nested prevout lookups.
// Charge a worst-case cold read before loading; errors consume their allowance.
struct ExplorerHistoryBudget {
    static constexpr size_t MAX_READS = 8;
    static constexpr size_t BODY_LIMIT = 1024U * 1024U;
    size_t reads = 0;
    size_t remaining_load_bytes = MAX_READS * MAX_BLOCK_SIZE;

    template<typename Chain>
    auto Read(Chain& chain, uint64_t height) -> decltype(chain.GetBlock(height, BODY_LIMIT)) {
        if (reads >= MAX_READS || remaining_load_bytes < MAX_BLOCK_SIZE)
            throw std::runtime_error("Explorer historical lookup incomplete: work budget reached");
        ++reads;
        remaining_load_bytes -= MAX_BLOCK_SIZE;
        return chain.GetBlock(height, BODY_LIMIT);
    }
};

// Unavailable history is tracked separately from examined history. Skip holes
// within a pass so one missing body cannot hide readable older transactions;
// only a fully examined range can support a not-found response.
struct ExplorerLookupProgress : rpc_detail::RecentLookupProgress {
    std::bitset<WINDOW> unavailable;

    void ObserveTip(uint64_t height, const std::string& hash, bool anchor_canonical) {
        if (tip_hash.empty() || !anchor_canonical || height < tip_height) {
            unavailable.reset();
        } else if (height > tip_height) {
            const auto delta = height - tip_height;
            if (delta >= WINDOW) unavailable.reset();
            else unavailable <<= static_cast<size_t>(delta);
        }
        rpc_detail::RecentLookupProgress::ObserveTip(height, hash, anchor_canonical);
        // This renderer searches the inclusive recent 501-block range.
        for (size_t i = 501; i < WINDOW; ++i) unavailable.reset(i);
    }
    void MarkUnavailable(uint64_t height) {
        if (height <= tip_height && tip_height - height < 501) {
            unavailable.set(static_cast<size_t>(tip_height - height));
            MarkExamined(height); // visited this pass, but not evidence of absence
        }
    }
    void MarkAvailable(uint64_t height) {
        MarkExamined(height);
        if (height <= tip_height && tip_height - height < WINDOW)
            unavailable.reset(static_cast<size_t>(tip_height - height));
    }
    bool Complete() const {
        const auto next = Next();
        return (!next || tip_height - *next > 500) && unavailable.none();
    }
    void RetryUnavailable() { examined &= ~unavailable; }
};
}
