#include "consensus/subsidy_schedule.h"
#include "core/coinbase_allocation.h"
#include <iostream>
#include <limits>
#include <stdexcept>

using namespace veld;
static size_t checks = 0;
void Check(bool value, const char* message) {
    ++checks;
    if (!value)
        throw std::runtime_error(message);
}
uint64_t Oracle(uint64_t h) {
    // Independent fixed monetary specification, not the implementation constants.
    const uint64_t annual =
#ifdef VELD_SUBSIDY_TEST_HEIGHT
        h <= 700800    ? 55000000000000ULL
        : h <= 1401600 ? 27500000000000ULL
                       : 13750000000000ULL;
#else
        55000000000000ULL;
#endif
    return annual / 175200 + (h != 0 && h % 175200 == 0 ? annual % 175200 : 0);
}
int main() {
    try {
        static_assert(BLOCKS_PER_YEAR == 175200 && MAX_SUPPLY_UNITS == 2100000000000000ULL);
        static_assert(FIRST_HALVING_HEIGHT == 700801 && SECOND_HALVING_HEIGHT == 1401601);
        static_assert(NMS_MIN_BOND_UNITS == 1000 * VELD_UNITS);
        Check(ScheduledBlockSubsidy(0) == 313926940, "genesis changed");
        uint64_t total = ScheduledBlockSubsidy(0);
        for (uint64_t year = 0; year < 140; ++year) {
            uint64_t annual = 0;
            for (uint64_t n = 1; n <= 175200; ++n) {
                const uint64_t h = year * 175200 + n;
                const auto reward = ScheduledBlockSubsidy(h);
                Check(reward == Oracle(h), "subsidy oracle mismatch");
                annual += reward;
                const uint64_t headroom = MAX_SUPPLY_UNITS - total;
                const auto out = ComputeCoinbaseAllocation(h, reward, total, 0);
                Check(out && out->subsidy == std::min(reward, headroom), "supply cap mismatch");
                Check(out->miner + out->pool + out->vault + out->endorsement == out->subsidy,
                      "allocation fails conservation");
                total += out->subsidy;
            }
            Check(annual == Oracle(year * 175200 + 1) * 175200 + Oracle((year + 1) * 175200) -
                                Oracle(year * 175200 + 1),
                  "annual rounding mismatch");
        }
        Check(total == MAX_SUPPLY_UNITS, "tail does not reach supply cap");
        for (uint64_t h :
             {700799ULL, 700800ULL, 700801ULL, 700900ULL, 1401599ULL, 1401600ULL, 1401601ULL,
              1401700ULL, 2102401ULL, std::numeric_limits<unsigned long long>::max()}) {
            const auto reward = ScheduledBlockSubsidy(h);
            Check(reward == Oracle(h), "boundary subsidy mismatch");
            for (uint64_t supply : {STAKING_UNLOCK_SUPPLY - 1, STAKING_UNLOCK_SUPPLY,
                                    MAX_SUPPLY_UNITS - 17, MAX_SUPPLY_UNITS}) {
                for (uint64_t fee : {0ULL, 1ULL, 10001ULL, 100000000ULL}) {
                    const auto out = ComputeCoinbaseAllocation(h, reward, supply, fee);
                    const auto issuance = ComputeCoinbaseAllocation(h, reward, supply, 0);
                    Check(out && issuance, "allocation rejected");
                    Check(out->miner + out->pool + out->vault + out->endorsement ==
                              out->subsidy + fee,
                          "fees inflate or destroy supply");
                    if (MinerFeesActive(h)) {
                        Check(out->miner == issuance->miner + fee && out->pool == issuance->pool &&
                                  out->vault == issuance->vault &&
                                  out->endorsement == issuance->endorsement,
                              "miner fee routing changed issuance shares");
                    }
                    if (out->subsidy && h % 100 == 0)
                        Check(issuance->vault == out->subsidy && !issuance->miner &&
                                  !issuance->pool && !issuance->endorsement,
                              "100th block allocation changed");
                    else if (out->subsidy) {
                        // Independent retirement boundary from the agreed monetary specification.
                        // Retirement pays validators regardless of the former supply unlock gate.
#ifdef VELD_SUBSIDY_TEST_HEIGHT
                        const bool retired = h >= 700801;
#else
                        const bool retired = false;
#endif
                        if (retired)
                            Check(issuance->pool == 0 && issuance->vault == out->subsidy / 5 &&
                                      issuance->endorsement == out->subsidy / 5 &&
                                      issuance->miner == out->subsidy - 2 * (out->subsidy / 5),
                                  "retired ordinary 60/0/20/20 split changed");
                        else if (supply >= STAKING_UNLOCK_SUPPLY)
                            Check(issuance->pool == out->subsidy / 5 &&
                                      issuance->vault == out->subsidy / 5 &&
                                      issuance->endorsement == out->subsidy / 10,
                                  "historical ordinary 50/20/20/10 split changed");
                    }
                }
            }
        }
        std::cout << "PASS_SUBSIDY_SCHEDULE checks=" << checks
                  << " active=" << (SUBSIDY_ACTIVATION_HEIGHT != 0) << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
