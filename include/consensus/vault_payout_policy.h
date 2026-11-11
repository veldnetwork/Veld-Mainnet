#pragma once
#include "native_334_activation.h"

// Public activation is pinned in reviewed source, never an operator option.
#if defined(VELD_VAULT_RESERVE_ACTIVATION_HEIGHT)
#error "Vault reserve activation must be pinned in reviewed source"
#endif
#if defined(VELD_VAULT_RESERVE_TEST_HEIGHT)
#if !defined(VELD_MAINNET_POW) || !defined(VELD_TEST_CHAIN_BUILD) || !defined(VELD_TEST_HOOKS) ||  \
    !defined(VELD_PROTOCOL_UPGRADE_TEST_HEIGHT) || defined(VELD_PUBLIC_RELEASE) ||                 \
    defined(VELD_PUBLIC_MAINNET) || defined(VELD_PUBLIC_TESTNET)
#error "Vault reserve test height requires isolated non-public qualification"
#endif
#endif

namespace veld {
#if defined(VELD_VAULT_RESERVE_TEST_HEIGHT)
inline constexpr uint64_t VAULT_RESERVE_ACTIVATION_HEIGHT = VELD_VAULT_RESERVE_TEST_HEIGHT;
#else
inline constexpr uint64_t VAULT_RESERVE_ACTIVATION_HEIGHT = NATIVE_334_ACTIVATION_HEIGHT;
#endif
inline constexpr uint64_t VAULT_RESERVE_TARGET_UNITS = 20'000ULL * VELD_UNITS;
static_assert(VAULT_RESERVE_ACTIVATION_HEIGHT == 0 ||
              (PROTOCOL_UPGRADE_HEIGHT != 0 &&
               VAULT_RESERVE_ACTIVATION_HEIGHT >= PROTOCOL_UPGRADE_HEIGHT));

inline constexpr bool VaultReservePolicyActive(uint64_t height) noexcept {
    return VAULT_RESERVE_ACTIVATION_HEIGHT != 0 && height >= VAULT_RESERVE_ACTIVATION_HEIGHT &&
           ProtocolUpgradeActive(height);
}

// Available rewards-vault funds only: exclude fee reserve and all separately
// custodied staking principal. Preserve the historical budget below the target.
// After activation, allow additional surplus, still under the 8% backstop.
// The target is not a new lock: legacy payouts can cross it. Concentration caps,
// dust and absent recipients can leave more than the target in the vault.
inline constexpr uint64_t VaultDistributionBudget(uint64_t height, uint64_t available,
                                                  uint64_t cycle_coinbase_inflow) noexcept {
    const uint64_t backstop = static_cast<uint64_t>(static_cast<__uint128_t>(available) *
                                                    VAULT_DISTRIBUTION_PPM / 1'000'000ULL);
    uint64_t budget = backstop;
    if (height >= VAULT_INFLOW_CAP_ACTIVATION_HEIGHT) {
        const uint64_t inflow_cap =
            static_cast<uint64_t>(static_cast<__uint128_t>(cycle_coinbase_inflow) *
                                  VAULT_INFLOW_PAYOUT_PPM / 1'000'000ULL);
        if (budget > inflow_cap)
            budget = inflow_cap;
    }
    if (VaultReservePolicyActive(height) && available > VAULT_RESERVE_TARGET_UNITS) {
        uint64_t surplus = available - VAULT_RESERVE_TARGET_UNITS;
        if (surplus > backstop)
            surplus = backstop;
        if (budget < surplus)
            budget = surplus;
    }
    return budget;
}
} // namespace veld
