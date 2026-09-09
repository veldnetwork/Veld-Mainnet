#pragma once
#include "constants.h"
#include <algorithm>
#include <optional>

namespace veld {

struct CoinbaseAllocation {
    uint64_t subsidy{0};
    uint64_t miner{0};
    uint64_t pool{0};
    uint64_t vault{0};
    uint64_t endorsement{0};
};

// Fees recycle existing units. Only the effective subsidy consumes supply
// headroom. Fee-only routing takes precedence over the periodic subsidy rule.
inline std::optional<CoinbaseAllocation> ComputeCoinbaseAllocation(
        uint64_t height, uint64_t base_subsidy,
        uint64_t parent_supply, uint64_t authenticated_fees) noexcept {
    if (parent_supply > MAX_SUPPLY_UNITS) return std::nullopt;
    CoinbaseAllocation out;
    out.subsidy = std::min(base_subsidy, MAX_SUPPLY_UNITS - parent_supply);
    if (authenticated_fees > MAX_SUPPLY_UNITS - out.subsidy)
        return std::nullopt;
    if (out.subsidy == 0) {
        out.vault = (authenticated_fees * 40) / 100;
        out.endorsement = (authenticated_fees * 10) / 100;
        out.miner = authenticated_fees - out.vault - out.endorsement;
    } else if (height > 0 && height % VAULT_BLOCK_INTERVAL == 0) {
        out.vault = out.subsidy + authenticated_fees;
    } else if (parent_supply < STAKING_UNLOCK_SUPPLY) {
        out.miner = (out.subsidy * 50) / 100;
        out.vault = out.subsidy - out.miner + authenticated_fees;
    } else {
        out.pool = (out.subsidy * 20) / 100;
        out.vault = (out.subsidy * 20) / 100;
        out.endorsement = (out.subsidy * 10) / 100;
        out.miner = out.subsidy - out.pool - out.vault - out.endorsement;
        out.vault += authenticated_fees;
    }
    return out;
}

} // namespace veld
