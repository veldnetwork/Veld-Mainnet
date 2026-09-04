#pragma once

#include "canonical_numeric.h"

#include <cstdint>
#include <string>
#include <string_view>

namespace veld {

struct CanonicalStakeOp {
    enum class Action : uint8_t { LOCK, UNLOCK };

    Action action{Action::LOCK};
    std::string address;
    uint64_t amount_units{0};
    uint8_t lockup_tier{0}; // LOCK: 1..4; UNLOCK: 0
};

// Single arithmetic rule shared by consensus application and mempool policy.
// `mature_units` is the amount actually eligible to leave at the candidate
// height; an oversized request cannot consume immature stake.  A transition is
// valid only when it fully exits or retains the already-configured minimum.
inline bool StakeUnlockPreservesMinimum(uint64_t current_units, uint64_t mature_units,
                                        uint64_t requested_units,
                                        uint64_t effective_min_units) noexcept {
    if (mature_units > current_units)
        return false;
    const uint64_t applied = requested_units < mature_units ? requested_units : mature_units;
    const uint64_t projected = current_units - applied;
    return projected == 0 || projected >= effective_min_units;
}

// Parse the exact on-chain staking grammar.  In particular, this rejects the
// prefix-accepted forms produced by stoull/stoi ("100x", "+100", " 100",
// "0100", "T1x", ...), as well as missing/trailing fields.
inline bool ParseCanonicalStakeOp(std::string_view payload, CanonicalStakeOp& out) noexcept {
    constexpr std::string_view lock_prefix = "VELD_STAKE|LOCK|";
    constexpr std::string_view unlock_prefix = "VELD_STAKE|UNLOCK|";

    CanonicalStakeOp parsed;
    bool is_lock = false;
    if (payload.substr(0, lock_prefix.size()) == lock_prefix) {
        payload.remove_prefix(lock_prefix.size());
        parsed.action = CanonicalStakeOp::Action::LOCK;
        is_lock = true;
    } else if (payload.substr(0, unlock_prefix.size()) == unlock_prefix) {
        payload.remove_prefix(unlock_prefix.size());
        parsed.action = CanonicalStakeOp::Action::UNLOCK;
    } else {
        return false;
    }

    const size_t address_end = payload.find('|');
    if (address_end == std::string_view::npos || address_end == 0)
        return false;
    parsed.address.assign(payload.substr(0, address_end));
    payload.remove_prefix(address_end + 1);

    const size_t amount_end = payload.find('|');
    const std::string_view amount_text =
        amount_end == std::string_view::npos ? payload : payload.substr(0, amount_end);
    if (!ParseCanonicalUint64Text(amount_text, parsed.amount_units))
        return false;

    if (!is_lock) {
        if (amount_end != std::string_view::npos)
            return false;
        out = std::move(parsed);
        return true;
    }

    if (amount_end == std::string_view::npos)
        return false;
    payload.remove_prefix(amount_end + 1);
    if (payload.size() != 2 || payload[0] != 'T' || payload[1] < '1' || payload[1] > '4') {
        return false;
    }
    parsed.lockup_tier = static_cast<uint8_t>(payload[1] - '0');
    out = std::move(parsed);
    return true;
}

} // namespace veld
