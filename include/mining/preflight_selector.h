#pragma once

#include "../core/block.h"
#include "../core/marker_composition.h"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace veld {
namespace mining {

// This intentionally recognizes a stateful family by its canonical marker
// prefix, even when the rest of the payload is malformed.  The selector is a
// fail-closed construction aid, not a protocol parser; malformed stateful
// requests must remain removable from an otherwise valid template.
inline bool MiningTxTouchesStatefulProtocol(const Transaction& tx) {
    for (const auto& out : tx.outputs) {
        const std::string payload = MarkerOpReturnPayload(out.script_pubkey);
        if (payload.empty())
            continue;
        for (int family = 0; family < kNumStatefulMarkerFamilies; ++family) {
            if (payload.rfind(kStatefulMarkerFamilies[family], 0) == 0)
                return true;
        }
    }
    return false;
}

struct ConstructivePreflightSelection {
    bool success{false};
    bool used_fallback{false};
    size_t preflight_calls{0};
    uint64_t retained_fees{0};
    Block candidate;
    std::vector<bool> retained_mempool;
    std::string error;
};

// Build and preflight one deterministic mining candidate.  The ordered
// mempool vector has already received AMM policy priority and Bitcoin-header
// dependency ordering; this routine never changes that relative order.
// Mandatory protocol transactions always remain the fixed suffix.
//
// Fast path: the complete candidate is tested exactly once and returned
// unchanged when valid.
//
// Fallback: first prove a coinbase + non-stateful + mandatory baseline, then
// greedily add stateful requests in their existing order.  A rejected trial
// mutates only local copies.  The bound is exactly 2 + the number of stateful
// candidates (one complete trial, one baseline trial, then one per request).
template <typename BuildCoinbase, typename Preflight>
ConstructivePreflightSelection SelectConstructivePreflightCandidate(
    const Block& candidate_skeleton,
    const std::vector<std::pair<Transaction, uint64_t>>& ordered_mempool,
    const std::vector<Transaction>& mandatory_txs, BuildCoinbase&& build_coinbase,
    Preflight&& preflight) {
    ConstructivePreflightSelection result;
    result.retained_mempool.assign(ordered_mempool.size(), true);

    auto rebuild = [&](const std::vector<bool>& retained, Block* out,
                       uint64_t* retained_fees) -> bool {
        if (!out || !retained_fees || retained.size() != ordered_mempool.size())
            return false;

        uint64_t fees = 0;
        size_t retained_count = 0;
        for (size_t i = 0; i < ordered_mempool.size(); ++i) {
            if (!retained[i])
                continue;
            const uint64_t fee = ordered_mempool[i].second;
            if (fee > std::numeric_limits<uint64_t>::max() - fees)
                return false;
            fees += fee;
            ++retained_count;
        }

        Block rebuilt = candidate_skeleton;
        rebuilt.transactions.clear();
        rebuilt.transactions.reserve(1 + retained_count + mandatory_txs.size());
        rebuilt.transactions.push_back(build_coinbase(fees));
        for (size_t i = 0; i < ordered_mempool.size(); ++i) {
            if (retained[i])
                rebuilt.transactions.push_back(ordered_mempool[i].first);
        }
        for (const auto& mandatory : mandatory_txs)
            rebuilt.transactions.push_back(mandatory);
        rebuilt.UpdateMerkleRoot();

        *retained_fees = fees;
        *out = std::move(rebuilt);
        return true;
    };

    if (!rebuild(result.retained_mempool, &result.candidate, &result.retained_fees)) {
        result.error = "mempool fee accounting overflow";
        return result;
    }

    ++result.preflight_calls;
    if (preflight(result.candidate)) {
        result.success = true;
        return result;
    }

    result.used_fallback = true;
    std::vector<size_t> stateful_indices;
    std::vector<bool> retained(ordered_mempool.size(), true);
    for (size_t i = 0; i < ordered_mempool.size(); ++i) {
        if (!MiningTxTouchesStatefulProtocol(ordered_mempool[i].first))
            continue;
        retained[i] = false;
        stateful_indices.push_back(i);
    }

    Block passing_candidate;
    uint64_t passing_fees = 0;
    if (!rebuild(retained, &passing_candidate, &passing_fees)) {
        result.error = "mempool fee accounting overflow";
        return result;
    }

    ++result.preflight_calls;
    if (!preflight(passing_candidate)) {
        result.candidate = std::move(passing_candidate);
        result.retained_fees = passing_fees;
        result.retained_mempool = std::move(retained);
        result.error = "non-stateful/mandatory baseline failed module preflight";
        return result;
    }

    for (const size_t index : stateful_indices) {
        std::vector<bool> trial_retained = retained;
        trial_retained[index] = true;
        Block trial_candidate;
        uint64_t trial_fees = 0;
        if (!rebuild(trial_retained, &trial_candidate, &trial_fees)) {
            result.error = "mempool fee accounting overflow";
            return result;
        }

        ++result.preflight_calls;
        if (!preflight(trial_candidate))
            continue;

        retained = std::move(trial_retained);
        passing_candidate = std::move(trial_candidate);
        passing_fees = trial_fees;
    }

    result.success = true;
    result.candidate = std::move(passing_candidate);
    result.retained_fees = passing_fees;
    result.retained_mempool = std::move(retained);
    return result;
}

} // namespace mining
} // namespace veld
