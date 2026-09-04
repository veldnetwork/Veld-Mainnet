#include "consensus/staking.h"

#include <cstdint>
#include <iostream>

using namespace veld;

namespace {

size_t checks = 0;

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        ++checks;                                                                                  \
        if (!(expr)) {                                                                             \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__ << " " #expr "\n";                 \
            return 1;                                                                              \
        }                                                                                          \
    } while (false)

} // namespace

int main() {
#if !defined(VELD_MAINNET_POW) || !defined(VELD_PUBLIC_RELEASE) || !defined(VELD_PUBLIC_MAINNET)
#error "staking_activation_tests requires the public-mainnet profile"
#endif

    static_assert(STAKING_UNLOCK_SUPPLY == 10'000ULL * VELD_UNITS,
                  "public-mainnet staking activation changed");
    static_assert(MIN_STAKE_UNITS == 1'000ULL * VELD_UNITS, "public-mainnet minimum stake changed");
    static_assert(MAX_STAKE_UNITS == 10'000ULL * VELD_UNITS,
                  "public-mainnet maximum stake changed");
    static_assert(MIN_VALIDATOR_STAKE == 10'000ULL * VELD_UNITS,
                  "public-mainnet validator bond changed");

    StakingLedger ledger;
    CHECK(!ledger.IsStakingActive(STAKING_UNLOCK_SUPPLY - 1));
    CHECK(ledger.IsStakingActive(STAKING_UNLOCK_SUPPLY));
    CHECK(ledger.IsStakingActive(STAKING_UNLOCK_SUPPLY + 1));

    std::cout << "PASS staking_activation_tests checks=" << checks
              << " activation_veld=" << (STAKING_UNLOCK_SUPPLY / VELD_UNITS)
              << " validator_bond_veld=" << (MIN_VALIDATOR_STAKE / VELD_UNITS) << "\n";
    return 0;
}
