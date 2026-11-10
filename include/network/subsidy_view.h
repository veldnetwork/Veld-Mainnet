#pragma once
#include "../consensus/subsidy_schedule.h"
#include "../core/coinbase_allocation.h"
#include <limits>
#include <stdexcept>
#include <string>

namespace veld {
// Read-only presentation of the next block. Reuse the canonical allocation so
// the supply cap, bootstrap phase and every-100th-block rule remain visible.
struct SubsidyView {
    uint64_t height;
    CoinbaseAllocation allocation;
    static SubsidyView Next(uint64_t tip, uint64_t supply) {
        if (tip == std::numeric_limits<uint64_t>::max())
            throw std::overflow_error("No next subsidy height");
        const auto h = tip + 1;
        const auto value = ComputeCoinbaseAllocation(h, ScheduledBlockSubsidy(h), supply, 0);
        if (!value)
            throw std::invalid_argument("Invalid subsidy supply");
        return {h, *value};
    }
    std::string Fields() const {
        return "\"reward_height\":" + std::to_string(height) +
               ",\"block_subsidy_units\":" + std::to_string(allocation.subsidy) +
               ",\"miner_subsidy_units\":" + std::to_string(allocation.miner) +
               ",\"subsidy_activation_height\":" + std::to_string(SUBSIDY_ACTIVATION_HEIGHT) +
               ",\"subsidy_schedule_active\":" +
               (SubsidyScheduleActive(height) ? "true" : "false") +
               ",\"subsidy_halvings\":" + std::to_string(SubsidyHalvings(height)) +
               ",\"first_halving_height\":" + std::to_string(FIRST_HALVING_HEIGHT) +
               ",\"second_halving_height\":" + std::to_string(SECOND_HALVING_HEIGHT) +
               ",\"co_mining_retired\":" + (CoMiningRetired(height) ? "true" : "false") +
               ",\"co_mining_retirement_height\":" + std::to_string(CoMiningRetirementHeight()) +
               ",\"co_mining_subsidy_units\":" + std::to_string(allocation.pool) +
               ",\"validator_subsidy_units\":" + std::to_string(allocation.endorsement) +
               ",\"miner_fees_active\":" + (MinerFeesActive(height) ? "true" : "false");
    }
};

struct SubsidyProjection {
    uint64_t miner = 0, vault = 0;
    static SubsidyProjection Next480(uint64_t tip, uint64_t supply) {
        if (tip > std::numeric_limits<uint64_t>::max() - BLOCKS_PER_DAY)
            throw std::overflow_error("No complete subsidy projection window");
        SubsidyProjection result;
        for (uint64_t step = 0; step < BLOCKS_PER_DAY; ++step) {
            const auto next = SubsidyView::Next(tip + step, supply);
            result.miner += next.allocation.miner;
            result.vault += next.allocation.vault;
            supply += next.allocation.subsidy;
        }
        return result;
    }
    std::string Fields() const {
        return "\"miner_subsidy_next_480_units\":" + std::to_string(miner) +
               ",\"vault_subsidy_next_480_units\":" + std::to_string(vault);
    }
};

inline std::string SubsidyRulesHtml(uint64_t height) {
    std::string text = "<p>Veld targets a block every <strong>180 seconds</strong>. ";
    if (SUBSIDY_ACTIVATION_HEIGHT == 0) {
        text += "The current base subsidy is <strong>3.13926940 VELD</strong>. "
                "No halving schedule is currently activated on this network. "
                "A rounding adjustment every 175,200 blocks gives 550,000 VELD per protocol year.";
    } else {
        text += SubsidyScheduleActive(height)
                    ? "The two-halving schedule is active. "
                    : "The two-halving schedule activates at block " +
                          std::to_string(SUBSIDY_ACTIVATION_HEIGHT) + ". ";
        text += "Annual issuance is 550,000 VELD for the first four protocol years, "
                "275,000 VELD for the next four, then 137,500 VELD. "
                "Reduced subsidies begin at blocks " +
                std::to_string(FIRST_HALVING_HEIGHT) + " and " +
                std::to_string(SECOND_HALVING_HEIGHT) +
                ". There is no third halving. Each protocol year contains 175,200 blocks; "
                "its final block includes the integer rounding remainder.";
    }
    if (SUBSIDY_ACTIVATION_HEIGHT != 0)
        text +=
            " Co-mining retires at the first halving. From that block, ordinary subsidies "
            "are 60% miner, 20% vault and 20% validator pool. Every 100th block still "
            "sends its entire subsidy to the vault. Previous payouts and stake principal remain intact.";
    return text +
           "</p><p>The <strong>21,000,000 VELD hard cap</strong> remains. "
           "The last subsidy is limited to remaining issuance. Block heights determine the schedule; "
           "calendar dates depend on mining. There is no premine.</p>";
}

inline std::string FeeRulesHtml(uint64_t height) {
    if (MinerFeesActive(height))
        return "Transaction fees go to the block winner, including every 100th block and after the supply cap. "
               "Fees recycle existing VELD and do not change the subsidy allocation.";
    return "During the subsidy era, transaction fees flow to the vault on top of its block share. "
           "When effective subsidy is zero, fee routing is 50% miner, 40% vault, and 10% validator pool, "
           "subject to integer rounding. The fee-only allocation applies at every height, including "
           "every 100th block. Exact permitted subsidy plus authenticated fees remain mandatory.";
}
} // namespace veld
