#pragma once
#include "../core/constants.h"

// Two reductions after four and eight complete protocol years. Height zero
// keeps its historical genesis subsidy. No balances or allocation shares change.
// A reviewed future activation must precede the first reduction; zero keeps
// public builds on the existing schedule while this candidate is qualified.
#if defined(VELD_SUBSIDY_ACTIVATION_HEIGHT)
#error "Subsidy activation must be pinned in reviewed source"
#endif
#if defined(VELD_SUBSIDY_TEST_HEIGHT)
#if !defined(VELD_MAINNET_POW) || !defined(VELD_TEST_CHAIN_BUILD) || \
    !defined(VELD_TEST_HOOKS) || !defined(VELD_PROTOCOL_UPGRADE_TEST_HEIGHT) || \
    defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET) || defined(VELD_PUBLIC_TESTNET)
#error "Subsidy test height requires an isolated non-public qualification build"
#endif
#endif

// Shortened boundaries exercise the full durable node through both reductions
// without constructing 1.4 million fixture blocks. Public builds cannot use
// either override; production heights below remain source-pinned.
#if defined(VELD_SUBSIDY_TEST_FIRST_HALVING) || defined(VELD_SUBSIDY_TEST_SECOND_HALVING)
#if !defined(VELD_SUBSIDY_TEST_HEIGHT) || !defined(VELD_SUBSIDY_TEST_FIRST_HALVING) || \
    !defined(VELD_SUBSIDY_TEST_SECOND_HALVING)
#error "Both isolated subsidy boundaries and the guarded test activation are required"
#endif
#endif

namespace veld {
#if defined(VELD_SUBSIDY_TEST_FIRST_HALVING)
inline constexpr uint64_t FIRST_HALVING_HEIGHT = VELD_SUBSIDY_TEST_FIRST_HALVING;
inline constexpr uint64_t SECOND_HALVING_HEIGHT = VELD_SUBSIDY_TEST_SECOND_HALVING;
static_assert(FIRST_HALVING_HEIGHT > 0 && SECOND_HALVING_HEIGHT > FIRST_HALVING_HEIGHT);
#else
inline constexpr uint64_t FIRST_HALVING_HEIGHT = 4ULL * BLOCKS_PER_YEAR + 1;
inline constexpr uint64_t SECOND_HALVING_HEIGHT = 8ULL * BLOCKS_PER_YEAR + 1;
#endif
#if defined(VELD_SUBSIDY_TEST_HEIGHT)
inline constexpr uint64_t SUBSIDY_ACTIVATION_HEIGHT = VELD_SUBSIDY_TEST_HEIGHT;
#else
inline constexpr uint64_t SUBSIDY_ACTIVATION_HEIGHT = 0;
#endif
static_assert(SUBSIDY_ACTIVATION_HEIGHT == 0 ||
                  (PROTOCOL_UPGRADE_HEIGHT != 0 &&
                   SUBSIDY_ACTIVATION_HEIGHT >= PROTOCOL_UPGRADE_HEIGHT &&
                   SUBSIDY_ACTIVATION_HEIGHT < FIRST_HALVING_HEIGHT),
              "The subsidy schedule must be activated before the first halving");
static_assert(ANNUAL_EMISSION_UNITS % 4 == 0);

inline constexpr bool SubsidyScheduleActive(uint64_t height) noexcept {
    return SUBSIDY_ACTIVATION_HEIGHT != 0 && height >= SUBSIDY_ACTIVATION_HEIGHT &&
           ProtocolUpgradeActive(height);
}

inline constexpr unsigned SubsidyHalvings(uint64_t height) noexcept {
    if (!SubsidyScheduleActive(height)) return 0;
    return height >= SECOND_HALVING_HEIGHT ? 2 : height >= FIRST_HALVING_HEIGHT ? 1 : 0;
}

// Each complete protocol year has an exact integer emission budget. Its final
// block receives the division remainder. There is no third halving. The existing
// canonical allocation/supply transition still limits the last reward to 21M.
inline constexpr uint64_t ScheduledBlockSubsidy(uint64_t height) noexcept {
    const uint64_t annual = ANNUAL_EMISSION_UNITS >> SubsidyHalvings(height);
    const uint64_t base = annual / BLOCKS_PER_YEAR;
    return base + (height > 0 && height % BLOCKS_PER_YEAR == 0
                       ? annual % BLOCKS_PER_YEAR : 0);
}
} // namespace veld
