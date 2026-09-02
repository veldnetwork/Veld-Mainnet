#include "core/blockchain.h"
#include "core/amm_pool.h"
#include "network/ui_desktop.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

using namespace veld;

namespace {

size_t checks = 0;

#define CHECK(expr)                                                          \
    do {                                                                     \
        ++checks;                                                            \
        if (!(expr)) {                                                       \
            std::cerr << "FAIL " << __FILE__ << ':' << __LINE__             \
                      << " " #expr "\n";                                    \
            return 1;                                                        \
        }                                                                    \
    } while (false)

std::string ReadSource(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

} // namespace

int main() {
    constexpr int64_t btcveld_sats = 50'000;
    constexpr int64_t fixed_veld_units =
        btcveld_sats * BTCVELD_AMM_OPENING_VELD_UNITS_PER_BTCVELD_SAT;
    constexpr int64_t market_veld_units = fixed_veld_units + VELD_UNITS;

    CHECK(AmmLedger::IsCanonicalOpeningSeedRatio(
        fixed_veld_units, btcveld_sats));
    CHECK(!AmmLedger::IsCanonicalOpeningSeedRatio(
        market_veld_units, btcveld_sats));

#if defined(VELD_MAINNET_POW) && defined(VELD_PUBLIC_RELEASE) && \
    defined(VELD_PUBLIC_MAINNET)
    static_assert(BTCVELD_AMM_MARKET_SEED_ACTIVATION_HEIGHT == 1,
                  "desktop policy injection assumes public activation at h=1");
#endif
    const bool market_anchor_active =
        AmmLedger::MarketSeedAnchorActive(1);
    const char* expected_profile = market_anchor_active
        ? "market-anchor" : "legacy-fixed-ratio";
    if (market_anchor_active) {
        const auto quote = AmmLedger::QuoteInitialSeedAtHeight(
            market_veld_units, btcveld_sats, 1);
        CHECK(quote.valid);
        CHECK(quote.gross_lp > 0);
    } else {
        CHECK(!AmmLedger::QuoteInitialSeedAtHeight(
            market_veld_units, btcveld_sats, 1).valid);
        CHECK(AmmLedger::QuoteInitialSeedAtHeight(
            fixed_veld_units, btcveld_sats, 1).valid);
    }

    const std::string html(DESKTOP_HTML);
    CHECK(html.find(
        "var BV_MARKET_SEED_ANCHOR_ACTIVE="
        "__VELD_AMM_MARKET_SEED_ANCHOR_ACTIVE__;") != std::string::npos);
    CHECK(html.find(
        "(!BV_MARKET_SEED_ANCHOR_ACTIVE&&") != std::string::npos);
    CHECK(html.find(
        "else if(!BV_MARKET_SEED_ANCHOR_ACTIVE&&BigInt(vSats)!==") !=
        std::string::npos);
    CHECK(html.find("prep.market_seed_anchor_active") != std::string::npos);
    CHECK(html.find(
        "typeof prep.market_seed_anchor_active!=='boolean'") !=
        std::string::npos);
    CHECK(html.find("prep.seed_anchor_policy") != std::string::npos);
    CHECK(html.find("the fixed launch price of 100,000") ==
          std::string::npos);
    CHECK(html.find(
        "The fixed launch ratio becomes the permanent four-band fee anchor") ==
        std::string::npos);
    std::string rendered = html;
    const std::string marker = "__VELD_AMM_MARKET_SEED_ANCHOR_ACTIVE__";
    const size_t marker_pos = rendered.find(marker);
    CHECK(marker_pos != std::string::npos);
    rendered.replace(marker_pos, marker.size(),
                     market_anchor_active ? "true" : "false");
    CHECK(rendered.find(marker) == std::string::npos);
    CHECK(rendered.find(std::string("var BV_MARKET_SEED_ANCHOR_ACTIVE=") +
                        (market_anchor_active ? "true;" : "false;")) !=
          std::string::npos);
    const size_t prepare_call = html.find(
        "return rpc('prepareammseed',[currentAddr, String(vSats), String(bSats)])");
    const size_t exact_legs = html.find("prep.d_veld_sats", prepare_call);
    const size_t policy_check = html.find(
        "prep.market_seed_anchor_active", prepare_call);
    const size_t exact_anchor = html.find("prep.anchor_veld", prepare_call);
    const size_t liveness_check = html.find(
        "prep.seed_liveness_policy", prepare_call);
    const size_t lp_check = html.find("prep.lp_supply", prepare_call);
    const size_t unsigned_check = html.find(
        "_bvVerifyAmmPrepared(prep", prepare_call);
    const size_t signing = html.find(
        "veldCrypto.injectSignatures", prepare_call);
    CHECK(prepare_call != std::string::npos);
    CHECK(exact_legs < policy_check);
    CHECK(policy_check < exact_anchor);
    CHECK(exact_anchor < liveness_check);
    CHECK(liveness_check < lp_check);
    CHECK(lp_check < unsigned_check);
    CHECK(unsigned_check < signing);

    const std::filesystem::path root =
        std::filesystem::path(__FILE__).parent_path().parent_path();
    const std::string desktop = ReadSource(root / "src" / "veld-desktop.cpp");
    const std::string rpc = ReadSource(root / "include" / "network" / "rpc.h");
    CHECK(!desktop.empty());
    CHECK(desktop.find(
        "subst_all(\"__VELD_AMM_MARKET_SEED_ANCHOR_ACTIVE__\"") !=
        std::string::npos);
    CHECK(desktop.find("AmmLedger::MarketSeedAnchorActive(1)") !=
          std::string::npos);
    CHECK(!rpc.empty());
    CHECK(rpc.find("{\"market_seed_anchor_active\", JB::Bool(") !=
          std::string::npos);
    CHECK(rpc.find("first-valid-seed-anchor-v1") != std::string::npos);
    CHECK(rpc.find("legacy_fixed_veld_units_per_btcveld_sat") !=
          std::string::npos);
    CHECK(rpc.find("{\"opening_veld_units_per_btcveld_sat\", JB::Number(") !=
          std::string::npos);

    std::cout << "PASS daybreak_amm_market_seed_tests checks=" << checks
              << " profile=" << expected_profile
              << " nonfixed_ratio=" << market_veld_units << ':'
              << btcveld_sats << "\n";
    return 0;
}
