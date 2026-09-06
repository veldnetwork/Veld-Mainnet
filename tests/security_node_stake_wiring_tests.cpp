#include "node/node.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace veld;

namespace {
size_t checks = 0;
void Check(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}

// Ordinary ledger snapshots isolate callback selection from chain construction.
// The populated-node qualification separately earns and spends real test coins.
void SetOrdinaryStake(StakingLedger& ledger, const std::string& address,
                      uint64_t amount) {
    StakingLedger::StateSnapshot state;
    StakeRecord record{};
    record.address = address;
    record.amount_units = amount;
    record.locked_at_height = 1;
    record.unlock_height = 20;
    record.backing_vout = 0;
    record.backing_txid[0] = 1;
    state.stakes[address].push_back(record);
    state.total_stake = amount;
    state.total_supply_units = STAKING_UNLOCK_SUPPLY;
    ledger.RestoreState(state);
}

void CheckConfiguration(const NetworkConfig& config,
                        const std::filesystem::path& root) {
    VeldNode node(config, root.string());
    node.SetQuietBoot(true);
    const std::string owner = "ordinary-stake-query-owner";
    constexpr uint64_t main_amount = 1'000ULL * VELD_UNITS;
    constexpr uint64_t alternate_amount = 2'000ULL * VELD_UNITS;
    auto& chain = node.GetChain();
    Check(chain.GetStakedForAddr(owner) == 0, "empty ledger query");
    SetOrdinaryStake(node.GetStaking(), owner, main_amount);
    const auto digest = node.GetStaking().StakingDigest();
    Check(chain.GetStakedForAddr(owner) == main_amount,
          "node total-stake query must match its ledger");
    Check(chain.GetMatureStakeForAddr(owner, 19) == 0,
          "wiring must preserve maturity");
    Check(chain.GetMatureStakeForAddr(owner, 20) == main_amount,
          "mature-stake query must agree with total stake");
    Check(chain.GetStakedForAddr("absent-owner") == 0,
          "absent owner must remain zero");

    StakingLedger alternate;
    SetOrdinaryStake(alternate, owner, alternate_amount);
    Blockchain::AltEngineOverlay overlay;
    overlay.staking = &alternate;
    {
        Blockchain::AltEngineOverlayGuard guard(&overlay);
        Check(chain.GetStakedForAddr(owner) == alternate_amount,
              "alternate transition must query its own ledger");
        Check(chain.GetMatureStakeForAddr(owner, 20) == alternate_amount,
              "alternate total and maturity queries must agree");
    }
    Check(chain.GetStakedForAddr(owner) == main_amount,
          "canonical query must resume after alternate guard");
    Check(node.GetStaking().StakingDigest() == digest,
          "callback reads must not mutate consensus state");
    std::cout << "PASS STAKE_QUERY_CONFIGURATION name=" << config.name
              << " validator_override=" << config.validator_system_always_active
              << '\n';
}
} // namespace

int main(int argc, char** argv) {
    try {
        Check(argc == 2, "fresh scratch directory required");
        const auto root = std::filesystem::absolute(argv[1]).lexically_normal();
        Check(root.filename().string().rfind("stake-wiring-scratch-", 0) == 0,
              "qualification scratch scope required");
        Check(!std::filesystem::exists(root), "fresh scratch required");
        const auto mainnet = MainnetConfig();
        Check(!mainnet.validator_system_always_active,
              "default network must exercise the normal activation policy");
        CheckConfiguration(mainnet, root / "mainnet");
        CheckConfiguration(TestnetConfig(), root / "testnet");
        CheckConfiguration(RegtestConfig(), root / "regtest");
        Blockchain standalone;
        Check(standalone.GetStakedForAddr("absent-owner") == 0,
              "standalone fallback must remain unchanged");
        std::cout << "PASS security_node_stake_wiring_tests checks=" << checks
                  << " backing_height=" << STAKE_OUTPOINT_BACKING_ACTIVATION_HEIGHT
                  << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
