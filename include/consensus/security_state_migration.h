#pragma once
#include "security_upgrade.h"

namespace veld {

// The public-mainnet transition shares the block-3840 protocol schedule.
// Historical activation constants, including 2880, remain intact.
#if defined(VELD_SECURITY_STATE_MIGRATION_TEST_HEIGHT) && defined(VELD_PROTOCOL_UPGRADE_TEST_HEIGHT)
#error "select one isolated migration schedule"
#endif
#if defined(VELD_SECURITY_STATE_MIGRATION_TEST_HEIGHT)
#if !defined(VELD_TEST_HOOKS) || !defined(VELD_TEST_CHAIN_BUILD) || defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET)
#error "state migration test height requires an isolated non-public test build"
#endif
inline constexpr uint64_t SECURITY_STATE_MIGRATION_HEIGHT =
    VELD_SECURITY_STATE_MIGRATION_TEST_HEIGHT;
#else
inline constexpr uint64_t SECURITY_STATE_MIGRATION_HEIGHT = PROTOCOL_UPGRADE_HEIGHT;
#endif
static_assert(SECURITY_STATE_MIGRATION_HEIGHT % BOND_SETTLEMENT_INTERVAL == 0,
              "state migration requires an epoch/settlement boundary");

inline constexpr bool SecurityStateMigrationActive(uint64_t inclusion_height) {
    return SECURITY_STATE_MIGRATION_HEIGHT != 0 &&
           inclusion_height >= SECURITY_STATE_MIGRATION_HEIGHT;
}
inline constexpr uint64_t NextInclusionHeight(uint64_t tip) {
    return tip == UINT64_MAX ? UINT64_MAX : tip + 1;
}

} // namespace veld
