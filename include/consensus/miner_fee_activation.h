#pragma once
#include "../core/constants.h"

// Public activation belongs to the coordinated creator-token / merged-mining
// release. Zero keeps the candidate inactive until that source-pinned schedule
// has passed shipping qualification. Compiler flags cannot activate public fees.
#if defined(VELD_MINER_FEE_ACTIVATION_HEIGHT)
#error "Miner fee activation must be pinned in reviewed source"
#endif
#if defined(VELD_MINER_FEE_TEST_HEIGHT)
#if !defined(VELD_MAINNET_POW) || !defined(VELD_TEST_CHAIN_BUILD) || \
    !defined(VELD_TEST_HOOKS) || !defined(VELD_PROTOCOL_UPGRADE_TEST_HEIGHT) || \
    defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET) || defined(VELD_PUBLIC_TESTNET)
#error "Miner fee test height requires an isolated non-public qualification build"
#endif
#endif

namespace veld {
#if defined(VELD_MINER_FEE_TEST_HEIGHT)
inline constexpr uint64_t MINER_FEE_ACTIVATION_HEIGHT = VELD_MINER_FEE_TEST_HEIGHT;
static_assert(MINER_FEE_ACTIVATION_HEIGHT > PROTOCOL_UPGRADE_HEIGHT);
#else
inline constexpr uint64_t MINER_FEE_ACTIVATION_HEIGHT = 0;
#endif
inline constexpr bool MinerFeesActive(uint64_t height) noexcept {
    return MINER_FEE_ACTIVATION_HEIGHT != 0 &&
           height >= MINER_FEE_ACTIVATION_HEIGHT && ProtocolUpgradeActive(height);
}
} // namespace veld
