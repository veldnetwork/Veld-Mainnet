// Exercise the shipping profile's real source-pinned boundary without a node.
#include "consensus/finality_qc.h"
#include "consensus/miner_fee_activation.h"
#include "consensus/security_state_migration.h"
#include "consensus/subsidy_schedule.h"
#include "consensus/vault_payout_policy.h"
#include "core/coinbase_allocation.h"
#include "network/subsidy_view.h"
#include <array>
#include <iostream>
#include <stdexcept>

using namespace veld;
namespace fq = veld::finality::qc;
namespace {
unsigned checks = 0;
void Check(bool okay, const char* reason) {
    ++checks;
    if (!okay)
        throw std::runtime_error(reason);
}
#ifdef VELD_PUBLIC_MAINNET
constexpr uint64_t expected_activation = 34750;
static_assert(PROTOCOL_UPGRADE_HEIGHT == 3840);
static_assert(SECURITY_STATE_MIGRATION_HEIGHT == 3840);
static_assert(CONSENSUS_SECURITY_UPGRADE_HEIGHT == 2880);
static_assert(VALIDATOR_REGISTRATION_FORK_HEIGHT == 9500);
#else
constexpr uint64_t expected_activation = 0;
static_assert(PROTOCOL_UPGRADE_HEIGHT == 0);
#endif
static_assert(NATIVE_334_ACTIVATION_HEIGHT == expected_activation);
static_assert(MINER_FEE_ACTIVATION_HEIGHT == expected_activation);
static_assert(VALIDATOR_POLICY_ACTIVATION_HEIGHT == expected_activation);
static_assert(SUBSIDY_ACTIVATION_HEIGHT == expected_activation);
static_assert(VAULT_RESERVE_ACTIVATION_HEIGHT == expected_activation);
static_assert(FIRST_HALVING_HEIGHT == 700801 && SECOND_HALVING_HEIGHT == 1401601);
static_assert(NMS_MIN_BOND_UNITS == 1000ULL * VELD_UNITS);
static_assert(fq::REGISTRATION_MATURITY == 480 && fq::EPOCH_BLOCKS == 480);
static_assert(fq::FINALITY_EQUIV_EVIDENCE_WINDOW == 43200);
static_assert(VAULT_DISTRIBUTION_INTERVAL == 480);
#ifdef VELD_DEVELOPER_TESTNET
static_assert(APPCHAIN_BRIDGE_ENABLED && APPCHAIN_BRIDGE_ACTIVATION_HEIGHT == 3);
#else
static_assert(!APPCHAIN_BRIDGE_ENABLED);
#endif
} // namespace

int main() {
    try {
        for (uint64_t h : std::array<uint64_t, 17>{0, 2879, 2880, 3839, 3840, 9499, 9500,
                                                  34749, 34750, 34751, 34800, 700800, 700801,
                                                  1401600, 1401601, 2102401, UINT64_MAX}) {
            const bool active = expected_activation != 0 && h >= 34750;
            Check(MinerFeesActive(h) == active, "miner fee boundary");
            Check(ValidatorBondPolicyActive(h) == active, "validator policy boundary");
            Check(SubsidyScheduleActive(h) == active, "subsidy schedule boundary");
            Check(VaultReservePolicyActive(h) == active, "vault reserve boundary");
            Check(MinimumValidatorBond(h) == (active ? 5000ULL : 10000ULL) * VELD_UNITS,
                  "validator minimum");
            Check(fq::MinimumValidatorCountAt(h) == (active ? 5 : 7), "finality membership");
            Check(fq::BondPerKeyAt(h) == (active ? 5000ULL : 10000ULL) * VELD_UNITS,
                  "finality equal weight");
            Check(ValidatorGovernanceBondFloor(h) == (active ? 25000ULL : 50000ULL) * VELD_UNITS,
                  "governance bond floor");
            Check(SubsidyHalvings(h) == (active ? (h >= 1401601 ? 2 : h >= 700801 ? 1 : 0) : 0),
                  "halving boundary");
            Check(CoMiningRetired(h) == (active && h >= 700801), "retirement boundary");
            for (uint64_t supply : std::array<uint64_t, 4>{0, STAKING_UNLOCK_SUPPLY,
                                                          MAX_SUPPLY_UNITS - 17, MAX_SUPPLY_UNITS}) {
                const auto reward = ScheduledBlockSubsidy(h);
                const auto issuance = ComputeCoinbaseAllocation(h, reward, supply, 0);
                const auto paid = ComputeCoinbaseAllocation(h, reward, supply, 10001);
                Check(issuance && paid, "allocation admitted");
                Check(paid->subsidy == issuance->subsidy, "fees cannot mint supply");
                Check(paid->miner + paid->pool + paid->vault + paid->endorsement ==
                          paid->subsidy + 10001,
                      "conservation");
                if (active) {
                    Check(paid->miner == issuance->miner + 10001 &&
                              paid->vault == issuance->vault && paid->pool == issuance->pool &&
                              paid->endorsement == issuance->endorsement,
                          "all fees to miner");
                } else if (issuance->subsidy) {
                    Check(paid->vault == issuance->vault + 10001 &&
                              paid->miner == issuance->miner && paid->pool == issuance->pool &&
                              paid->endorsement == issuance->endorsement,
                          "historical fees to vault");
                } else {
                    Check(paid->miner == 5001 && paid->vault == 4000 &&
                              paid->endorsement == 1000 && paid->pool == 0,
                          "historical post-cap allocation");
                }
            }
        }
        Check(ScheduledBlockSubsidy(34749) == 313926940 &&
                  ScheduledBlockSubsidy(34750) == 313926940,
              "activation cannot halve current subsidy");
        Check(!fq::IsSupermajority(15000, 25000) && fq::IsSupermajority(20000, 25000),
              "strict four of five quorum");
        // Block 34,750 lies inside epoch 72. Its frozen snapshot remains historical.
        Check(fq::SnapshotHeightFor(72) == 34559 && fq::SnapshotHeightFor(73) == 35039,
              "snapshot cadence changed");
        Check(fq::MinimumValidatorCountAt(fq::SnapshotHeightFor(72)) == 7 &&
                  fq::MinimumValidatorCountAt(fq::SnapshotHeightFor(73)) ==
                      (expected_activation ? 5 : 7),
              "policy must use snapshot height");
        Check(VaultDistributionBudget(34749, 21000ULL * VELD_UNITS, 300ULL * VELD_UNITS) ==
                  270ULL * VELD_UNITS,
              "historical vault budget");
        Check(VaultDistributionBudget(34750, 21000ULL * VELD_UNITS, 300ULL * VELD_UNITS) ==
                  (expected_activation ? 1000ULL : 270ULL) * VELD_UNITS,
              "activated vault budget");
        if (expected_activation) {
            Check(SubsidyRulesHtml(34749).find("activates at block 34750") != std::string::npos,
                  "upcoming activation presentation");
            Check(SubsidyView::Next(34749, 0).Fields().find("\"miner_fees_active\":true") !=
                      std::string::npos,
                  "next inclusion presentation");
        }
        std::cout << "PASS_NATIVE_334_ACTIVATION height=" << expected_activation
                  << " checks=" << checks << '\n';
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
