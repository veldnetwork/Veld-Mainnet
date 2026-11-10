#include "network/subsidy_view.h"
#include <iostream>
#include <stdexcept>
using namespace veld;
void check(bool ok) {
    if (!ok)
        throw std::runtime_error("subsidy presentation mismatch");
}
int main() {
    const auto ordinary = SubsidyView::Next(700800, STAKING_UNLOCK_SUPPLY);
    check(ordinary.height == 700801);
#ifdef VELD_SUBSIDY_TEST_HEIGHT
    check(ordinary.allocation.subsidy == 156963470);
    check(ordinary.Fields().find("\"subsidy_halvings\":1") != std::string::npos);
    check(SubsidyRulesHtml(4000).find("schedule is active") != std::string::npos);
    check(SubsidyRulesHtml(3999).find("activates at block 4000") != std::string::npos);
    check(FeeRulesHtml(4000).find("go to the block winner") != std::string::npos);
    check(SubsidyView::Next(1401600, STAKING_UNLOCK_SUPPLY).allocation.subsidy == 78481735);
#else
    check(ordinary.allocation.subsidy == 313926940);
    check(ordinary.Fields().find("\"subsidy_schedule_active\":false") != std::string::npos);
    check(SubsidyRulesHtml(1401601).find("No halving schedule is currently activated") !=
          std::string::npos);
    check(FeeRulesHtml(1401601).find("flow to the vault") != std::string::npos);
#endif
    const auto special = SubsidyView::Next(700899, STAKING_UNLOCK_SUPPLY);
    check(special.allocation.miner == 0 && special.allocation.vault == special.allocation.subsidy);
    const auto last = SubsidyView::Next(1401600, MAX_SUPPLY_UNITS - 17);
    check(last.allocation.subsidy == 17);
    check(SubsidyView::Next(1401600, MAX_SUPPLY_UNITS).allocation.subsidy == 0);
    const auto bootstrap = SubsidyView::Next(1, 0);
    check(bootstrap.allocation.pool == 0 && bootstrap.allocation.endorsement == 0);
    bool rejected = false;
    try {
        SubsidyView::Next(0, MAX_SUPPLY_UNITS + 1);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    check(rejected);
    rejected = false;
    try {
        SubsidyView::Next(UINT64_MAX, 0);
    } catch (const std::overflow_error&) {
        rejected = true;
    }
    check(rejected);
    const auto near_cap = SubsidyProjection::Next480(1401600, MAX_SUPPLY_UNITS - 17);
#ifdef VELD_SUBSIDY_TEST_HEIGHT
    check(near_cap.miner == 11 && near_cap.vault == 3);
#else
    check(near_cap.miner == 10 && near_cap.vault == 3);
#endif
    const auto at_cap = SubsidyProjection::Next480(1401600, MAX_SUPPLY_UNITS);
    check(at_cap.miner == 0 && at_cap.vault == 0);
    const auto regular = SubsidyProjection::Next480(700800, STAKING_UNLOCK_SUPPLY);
    // 480 successive heights contain four vault-only blocks here. Literal
    // values independently cover the different subsidy-era rounding.
#ifdef VELD_SUBSIDY_TEST_HEIGHT
    check(regular.miner == 476ULL * 94178082 &&
          regular.vault == 476ULL * 31392694 + 4ULL * 156963470);
#else
    check(regular.miner == 476ULL * 156963470 &&
          regular.vault == 476ULL * 62785388 + 4ULL * 313926940);
#endif
    std::cout << "PASS_SUBSIDY_VIEW " << ordinary.Fields() << '\n';
}
