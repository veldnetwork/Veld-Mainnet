#pragma once

#include <cstdint>
#include <cstddef>
#include <mutex>

namespace veld::mining {

// Serialize the check-and-submit operation. Eligibility comes from canonical
// credits and the current mempool, so it survives restarts and follows reorgs.
class NmsSubmissionGate {
    std::mutex mutex_;
  public:
    std::unique_lock<std::mutex> TryBegin() {
        return std::unique_lock<std::mutex>(mutex_, std::try_to_lock);
    }
};

template<typename Chain, typename Pool, typename Script, typename Hash>
bool NeedsNmsSubmission(const Chain& chain, const Pool& pool,
                        const Script& script, const Hash& parent) {
    return chain.NmsNeedsSubmission(script, parent) &&
           !pool.HasNmsSubmission(script, parent);
}

inline bool NmsTemplateRefreshNeeded(uint64_t selected_revision,
                                     uint64_t current_revision,
                                     uint64_t elapsed_ms,
                                     size_t selected_claims,
                                     size_t claim_limit) {
    // Rebuild at most once per five seconds, and only when a new claim could
    // fit. The proof search will reuse the dataset for the unchanged parent.
    return selected_revision != current_revision && elapsed_ms >= 5000 &&
           selected_claims < claim_limit;
}

} // namespace veld::mining
