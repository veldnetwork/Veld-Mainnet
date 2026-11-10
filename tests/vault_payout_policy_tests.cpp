#include "consensus/vault_payout_policy.h"
#include <array>
#include <iostream>
#include <stdexcept>
using namespace veld;
namespace {
size_t checks = 0;
void Check(bool ok) {
    ++checks;
    if (!ok)
        throw std::runtime_error("vault policy case " + std::to_string(checks));
}
// Division first plus a remainder term is independent of the implementation's
// wide multiply, and avoids overflowing even at UINT64_MAX.
uint64_t Fraction(uint64_t value, uint64_t ppm) {
    return value / 1'000'000 * ppm + value % 1'000'000 * ppm / 1'000'000;
}
uint64_t Oracle(uint64_t height, uint64_t balance, uint64_t inflow) {
    const auto limit = Fraction(balance, 80'000);
    auto payout = std::min(limit, Fraction(inflow, 900'000));
    if (VAULT_RESERVE_ACTIVATION_HEIGHT != 0 && height >= VAULT_RESERVE_ACTIVATION_HEIGHT) {
        const uint64_t surplus =
            balance > 2'000'000'000'000ULL ? balance - 2'000'000'000'000ULL : 0;
        payout = std::max(payout, std::min(limit, surplus));
    }
    return payout;
}
}
int main() {
    try {
        static_assert(VELD_UNITS == 100'000'000 &&
                      VAULT_RESERVE_TARGET_UNITS == 2'000'000'000'000ULL);
        const uint64_t active = VAULT_RESERVE_ACTIVATION_HEIGHT;
        const std::array<uint64_t, 13> balances{0,
                                                1,
                                                12,
                                                13,
                                                999,
                                                12'500,
                                                19'999 * VELD_UNITS,
                                                VAULT_RESERVE_TARGET_UNITS - 1,
                                                VAULT_RESERVE_TARGET_UNITS,
                                                VAULT_RESERVE_TARGET_UNITS + 1,
                                                21'000 * VELD_UNITS,
                                                22'000 * VELD_UNITS,
                                                UINT64_MAX};
        for (const auto h : {uint64_t(0), active ? active - 1 : 0, active, active + 1, UINT64_MAX})
            for (const auto balance : balances)
                for (const auto inflow : balances) {
                    auto actual = VaultDistributionBudget(h, balance, inflow);
                    Check(actual == Oracle(h, balance, inflow));
                    Check(actual <= Fraction(balance, 80'000));
                    Check(actual >= std::min(Fraction(balance, 80'000), Fraction(inflow, 900'000)));
                }
        Check(VaultDistributionBudget(0, 21'000 * VELD_UNITS, 300 * VELD_UNITS) ==
              270 * VELD_UNITS);
        if (active) {
            Check(VaultDistributionBudget(active, 21'000 * VELD_UNITS, 300 * VELD_UNITS) ==
                  1000 * VELD_UNITS);
            Check(VaultDistributionBudget(active, 22'000 * VELD_UNITS, 300 * VELD_UNITS) ==
                  1760 * VELD_UNITS);
            Check(VaultDistributionBudget(active, 19'000 * VELD_UNITS, 300 * VELD_UNITS) ==
                  270 * VELD_UNITS);
            // The target does not freeze the pre-existing payout at/near it.
            Check(VaultDistributionBudget(active, VAULT_RESERVE_TARGET_UNITS + 1,
                                          300 * VELD_UNITS) == 270 * VELD_UNITS);
            Check(VaultDistributionBudget(active, 21'000 * VELD_UNITS, 0) == 1000 * VELD_UNITS);
        } else {
            Check(!VaultReservePolicyActive(UINT64_MAX));
            Check(VaultDistributionBudget(UINT64_MAX, 21'000 * VELD_UNITS, 0) == 0);
        }
        uint64_t seed = 777;
        for (unsigned i = 0; i < 100'000; ++i) {
            seed = seed * 6364136223846793005ULL + 1;
            const auto balance = seed;
            seed = seed * 6364136223846793005ULL + 1;
            Check(VaultDistributionBudget(UINT64_MAX, balance, seed) ==
                  Oracle(UINT64_MAX, balance, seed));
        }
        std::cout << "PASS vault integer policy checks=" << checks << " activation=" << active
                  << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
