#pragma once

#include "core/constants.h"
#include <cstdint>

namespace veld {

// Coordinated consensus security upgrade at block 2880.
// Any binary built from this candidate activates at that height automatically.
// Release requires an authenticated pre-upgrade checkpoint, complete replay and
// restart qualification, and a coordinated compatible rollout. No runtime or
// per-node override exists. Zero remains the unscheduled/disabled sentinel.
#if defined(VELD_CONSENSUS_SECURITY_TEST_HEIGHT)
#if !defined(VELD_TEST_HOOKS) || defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "Consensus security test height is restricted to isolated test builds"
#endif
constexpr uint64_t CONSENSUS_SECURITY_UPGRADE_HEIGHT = VELD_CONSENSUS_SECURITY_TEST_HEIGHT;
#else
constexpr uint64_t CONSENSUS_SECURITY_UPGRADE_HEIGHT = 2880;
#endif
static_assert(CONSENSUS_SECURITY_UPGRADE_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "Consensus security upgrade must use a settlement boundary");

inline constexpr bool ConsensusSecurityUpgradeActive(uint64_t height) {
    return CONSENSUS_SECURITY_UPGRADE_HEIGHT != 0 &&
           height >= CONSENSUS_SECURITY_UPGRADE_HEIGHT;
}

} // namespace veld
