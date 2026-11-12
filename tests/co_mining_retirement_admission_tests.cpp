#include "consensus/nms.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
struct Context {
    uint64_t parent = 700799;
    mutable unsigned reads = 0;
    std::optional<uint64_t> GetHeightByHashLocked(const Hash256&) const {
        ++reads;
        return parent;
    }
    uint32_t ComputeNextBitsAtLocked(uint64_t) const {
        ++reads;
        return VELD_POW_LIMIT_BITS;
    }
};
int main() {
    try {
        static_assert(SUBSIDY_ACTIVATION_HEIGHT == 4000 && FIRST_HALVING_HEIGHT == 700801);
        Context context;
        BlockHeader header;
        header.bits = VELD_POW_LIMIT_BITS;
        auto rec = ParseNmsPayload(EncodeNmsPayload(header));
        if (!rec)
            throw std::runtime_error("fixture payload");
        // A positive cached hash proof models previously verified work; retirement
        // must still reject it before ancestry/cache lookups and local PoW budgets.
        g_nms_verify_cache.Insert(HashToHex(Hash256d(rec->raw)), true);
        if (ValidateNmsWithDisposition(*rec, context, 700800) != NmsValidationDisposition::Valid ||
            context.reads != 2)
            throw std::runtime_error("historical qualifying proof no longer accepted");
        context.parent = 700800;
        context.reads = 0;
        if (ValidateNmsWithDisposition(*rec, context, 700801) !=
                NmsValidationDisposition::ConsensusInvalid ||
            context.reads != 0)
            throw std::runtime_error("retirement bypassed by cached qualifying proof");
        context.parent = 700799;
        if (ValidateNmsWithDisposition(*rec, context, 700800) != NmsValidationDisposition::Valid)
            throw std::runtime_error("historical replay depends on later retirement state");
        std::cout
            << "PASS_RETIREMENT_ADMISSION cached_positive_refused historical_replay_preserved\n";
    } catch (const std::exception& e) {
        std::cerr << "FAIL " << e.what() << '\n';
        return 1;
    }
}
