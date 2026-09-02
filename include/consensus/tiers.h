#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  VELD TIER SYSTEM
//
//  Tiers apply a multiplier to a miner's vault distribution share.
//  The multiplier does NOT affect per-block coinbase — it only weights
//  the mining address when the vault distributes to stakers.
//  Named tiers shown everywhere user-facing — no "Tier 3", just "Gold".
//
//  All five activity tiers use rolling windows
//  (at least 1 block per BLOCKS_PER_DAY window = 1 "active" day). No cumulative
//  lifetime milestones: stop mining for long enough and the tier drops.
//
//    Bronze:   7 of last 14 days active     → 1.10×   (low-bar onboarding)
//    Silver:   25 of last 30 days active    → 1.25×
//    Gold:     165 of last 180 days active  → 1.50×
//    Platinum: 335 of last 365 days active  → 1.80×
//    Diamond:  1000 of last 1,095 days active → 3.00× (elite cap)
//
//  Combined-multiplier hard cap: mining_tier × lockup_tier capped at
//  LOCKUP_MAX_MULTIPLIER = 3.00 in rpc.h:2477 and veld-distribute.cpp.
//  "Active" = mined at least 1 block in that wall-clock-day window (480
//  blocks at the 180-second launch cadence).
// ─────────────────────────────────────────────────────────────────────────────

#include "../core/constants.h"
#include "../core/blockchain.h"
#include "../consensus/staking.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>

namespace veld {

static constexpr uint64_t WINDOW_BLOCKS = BLOCKS_PER_DAY;   // 1 "active" day per window
static_assert(TARGET_BLOCK_TIME != 60 || WINDOW_BLOCKS == 1'440,
              "wall-clock re-expression must preserve the legacy 60s profile");

static constexpr uint64_t BRONZE_ACTIVE   = 7;    static constexpr uint64_t BRONZE_WINDOWS   = 14;
static constexpr uint64_t SILVER_ACTIVE   = 25;   static constexpr uint64_t SILVER_WINDOWS   = 30;
static constexpr uint64_t GOLD_ACTIVE     = 165;  static constexpr uint64_t GOLD_WINDOWS     = 180;
static constexpr uint64_t PLATINUM_ACTIVE = 335;  static constexpr uint64_t PLATINUM_WINDOWS = 365;
static constexpr uint64_t DIAMOND_ACTIVE  = 1000; static constexpr uint64_t DIAMOND_WINDOWS  = 1'095;

static constexpr double BASE_MULT     = 1.00;
static constexpr double BRONZE_MULT   = 1.10;
static constexpr double SILVER_MULT   = 1.25;
static constexpr double GOLD_MULT     = 1.50;
static constexpr double PLATINUM_MULT = 1.80;
static constexpr double DIAMOND_MULT  = 3.00;

struct TierInfo {
    int         level{0};
    double      multiplier{1.0};
    std::string name;
    std::string description;
    bool        is_window_tier{false};
    uint64_t    blocks_required{0};
    uint64_t    blocks_mined{0};
    uint64_t    blocks_to_next{0};
    uint64_t    windows_active{0};
    uint64_t    windows_total{0};
    uint64_t    windows_required{0};
};

class TierEngine {
public:
    TierEngine(const Blockchain& chain, const StakingLedger& staking)
        : chain_(chain), staking_(staking) {}

    TierInfo GetTier(const std::string& script_hex) const {
        uint64_t height = chain_.Height();
        uint64_t mined  = chain_.GetBlocksMined(script_hex);

        {
            uint64_t active = chain_.GetActiveWindowCount(script_hex, DIAMOND_WINDOWS, height);
            if (active >= DIAMOND_ACTIVE)
                return window_tier(5, DIAMOND_MULT, "Diamond",
                    "1000 of last 1,095 days active", active, DIAMOND_WINDOWS, DIAMOND_ACTIVE, mined);
        }
        {
            uint64_t active = chain_.GetActiveWindowCount(script_hex, PLATINUM_WINDOWS, height);
            if (active >= PLATINUM_ACTIVE)
                return window_tier(4, PLATINUM_MULT, "Platinum",
                    "335 of last 365 days active", active, PLATINUM_WINDOWS, PLATINUM_ACTIVE, mined);
        }
        {
            uint64_t active = chain_.GetActiveWindowCount(script_hex, GOLD_WINDOWS, height);
            if (active >= GOLD_ACTIVE)
                return window_tier(3, GOLD_MULT, "Gold",
                    "165 of last 180 days active", active, GOLD_WINDOWS, GOLD_ACTIVE, mined);
        }
        {
            uint64_t active = chain_.GetActiveWindowCount(script_hex, SILVER_WINDOWS, height);
            if (active >= SILVER_ACTIVE)
                return window_tier(2, SILVER_MULT, "Silver",
                    "25 of last 30 days active", active, SILVER_WINDOWS, SILVER_ACTIVE, mined);
        }
        {
            uint64_t active = chain_.GetActiveWindowCount(script_hex, BRONZE_WINDOWS, height);
            if (active >= BRONZE_ACTIVE)
                return window_tier(1, BRONZE_MULT, "Bronze",
                    "7 of last 14 days active", active, BRONZE_WINDOWS, BRONZE_ACTIVE, mined);
        }
        TierInfo t; t.level=0; t.multiplier=BASE_MULT; t.name="";
        t.description="Mine at least 7 of the last 14 days to reach Bronze";
        t.blocks_mined=mined;
        return t;
    }

    double GetMultiplier(const std::string& script_hex) const {
        return GetTier(script_hex).multiplier;
    }

    uint64_t ApplyMultiplier(uint64_t base_units, const std::string& script_hex) const {
        return (uint64_t)((double)base_units * GetMultiplier(script_hex));
    }

    std::string GetTierJSON(const std::string& script_hex, const std::string& address = "") const {
        auto t = GetTier(script_hex);
        uint64_t staked = staking_.GetStake(address);
        std::ostringstream j;
        j << std::fixed << std::setprecision(8);
        j << "{";
        j << "\"tier\":"          << t.level                                       << ",";
        j << "\"name\":\""        << t.name                                        << "\",";
        j << "\"multiplier\":"    << std::setprecision(2) << t.multiplier          << ",";
        j << "\"description\":\"" << t.description                                 << "\",";
        j << "\"blocks_mined\":"  << chain_.GetBlocksMined(script_hex)             << ",";
        j << "\"staked_veld\":"   << std::setprecision(8) << (double)staked/VELD_UNITS << ",";
        j << "\"next_tier\":\""   << next_name(t.level)                            << "\",";
        if (!t.is_window_tier) {
            j << "\"type\":\"block_count\","
              << "\"blocks_required\":" << t.blocks_required << ","
              << "\"blocks_to_next\":"  << t.blocks_to_next;
        } else {
            j << "\"type\":\"rolling_window\","
              << "\"windows_active\":"   << t.windows_active   << ","
              << "\"windows_total\":"    << t.windows_total     << ","
              << "\"windows_required\":" << t.windows_required;
        }
        j << "}";
        return j.str();
    }

    std::string GetTierInfoJSON(const std::string& address, const std::string& script_hex) const {
        return GetTierJSON(script_hex, address);
    }

    std::string GetAllTiersJSON() const {
        std::ostringstream j;
        j << std::fixed << std::setprecision(2);
        j << "[";
        struct D { int l; double m; const char* n; const char* t; const char* r; };
        D d[] = {
            {0,BASE_MULT,     "",        "rolling_window", "Just mine"},
            {1,BRONZE_MULT,   "Bronze",  "rolling_window", "7 of last 14 days active"},
            {2,SILVER_MULT,   "Silver",  "rolling_window", "25 of last 30 days active"},
            {3,GOLD_MULT,     "Gold",    "rolling_window", "165 of last 180 days active"},
            {4,PLATINUM_MULT, "Platinum","rolling_window", "335 of last 365 days active"},
            {5,DIAMOND_MULT,  "Diamond", "rolling_window", "1000 of last 1,095 days active"},
        };
        for (int i=0;i<6;++i) {
            if (i) j << ",";
            j << "{\"level\":"      << d[i].l << ","
              << "\"name\":\""      << d[i].n << "\","
              << "\"multiplier\":"  << d[i].m << ","
              << "\"type\":\""      << d[i].t << "\","
              << "\"requirement\":\"" << d[i].r << "\"}";
        }
        j << "]";
        return j.str();
    }

private:
    const Blockchain&    chain_;
    const StakingLedger& staking_;

    static std::string next_name(int lvl) {
        switch(lvl) {
            case 0: return "Bronze";
            case 1: return "Silver";
            case 2: return "Gold";
            case 3: return "Platinum";
            case 4: return "Diamond";
            default: return "";
        }
    }

    static TierInfo window_tier(int lvl, double mult, const char* name, const char* desc,
                                 uint64_t active, uint64_t total, uint64_t required,
                                 uint64_t mined) {
        TierInfo t;
        t.level=lvl; t.multiplier=mult; t.name=name; t.description=desc;
        t.is_window_tier=true;
        t.windows_active=active; t.windows_total=total; t.windows_required=required;
        t.blocks_mined=mined;
        return t;
    }
};

}
