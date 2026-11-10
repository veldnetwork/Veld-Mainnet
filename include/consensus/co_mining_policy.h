#pragma once
#include "subsidy_schedule.h"

namespace veld {
// Retirement shares the reviewed subsidy activation. Public activation zero
// preserves all historical rules. The final normal draw precedes retirement.
static_assert(FIRST_HALVING_HEIGHT % COMINE_WINDOW_BLOCKS == 1,
              "Co-mining retirement must follow a complete lottery window");
inline constexpr bool CoMiningRetired(uint64_t height) noexcept {
    return SubsidyScheduleActive(height) && height >= FIRST_HALVING_HEIGHT;
}
inline constexpr uint64_t CoMiningRetirementHeight() noexcept {
    return SUBSIDY_ACTIVATION_HEIGHT == 0 ? 0 : FIRST_HALVING_HEIGHT;
}
inline constexpr bool CoMiningPayoutDue(uint64_t height) noexcept {
    return height > 0 && height % COMINE_WINDOW_BLOCKS == 0 && !CoMiningRetired(height);
}
} // namespace veld
