#pragma once
#include "../core/constants.h"

// Inclusion height governs registration and reward accounting. Finality uses
// the immutable epoch snapshot height, so old certificates keep their meaning.
// Public activation remains disabled until a coordinated release is qualified.
#if defined(VELD_VALIDATOR_POLICY_ACTIVATION_HEIGHT)
#error "Validator policy activation must be pinned in reviewed source"
#endif
#if defined(VELD_VALIDATOR_POLICY_TEST_HEIGHT)
#if !defined(VELD_MAINNET_POW) || !defined(VELD_TEST_CHAIN_BUILD) || \
    !defined(VELD_TEST_HOOKS) || !defined(VELD_PROTOCOL_UPGRADE_TEST_HEIGHT) || \
    defined(VELD_PUBLIC_RELEASE) || defined(VELD_PUBLIC_MAINNET) || defined(VELD_PUBLIC_TESTNET)
#error "Validator policy test height requires isolated non-public qualification"
#endif
#endif
namespace veld {
#if defined(VELD_VALIDATOR_POLICY_TEST_HEIGHT)
inline constexpr uint64_t VALIDATOR_POLICY_ACTIVATION_HEIGHT = VELD_VALIDATOR_POLICY_TEST_HEIGHT;
#else
inline constexpr uint64_t VALIDATOR_POLICY_ACTIVATION_HEIGHT = 0;
#endif
static_assert(VALIDATOR_POLICY_ACTIVATION_HEIGHT == 0 ||
              (PROTOCOL_UPGRADE_HEIGHT != 0 && VALIDATOR_POLICY_ACTIVATION_HEIGHT >= PROTOCOL_UPGRADE_HEIGHT));
inline constexpr bool ValidatorBondPolicyActive(uint64_t height) noexcept {
    return VALIDATOR_POLICY_ACTIVATION_HEIGHT != 0 && height >= VALIDATOR_POLICY_ACTIVATION_HEIGHT &&
           ProtocolUpgradeActive(height);
}
inline constexpr uint64_t MinimumValidatorBond(uint64_t height) noexcept {
    return ValidatorBondPolicyActive(height) ? 5000ULL * VELD_UNITS : MIN_VALIDATOR_STAKE;
}
inline constexpr uint64_t ValidatorGovernanceBondFloor(uint64_t height) noexcept {
    return ValidatorBondPolicyActive(height) ? 25000ULL * VELD_UNITS : GOVERNANCE_ACTIVATION_BONDED_UNITS;
}
} // namespace veld
