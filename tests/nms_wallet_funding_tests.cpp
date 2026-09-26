#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#include "network/rpc.h"
#include "mining/nms_submission.h"
#include <filesystem>
#include <iostream>
#include <stdexcept>

using namespace veld;

int main(int argc, char** argv) {
    unsigned checks = 0;
    const auto check = [&](bool value, const char* message) {
        ++checks;
        if (!value)
            throw std::runtime_error(message);
    };
    try {
        check(argc == 2 && !std::filesystem::exists(argv[1]), "fresh fixture path required");
        Blockchain chain;
        check(chain
                  .AddBlockDirect(CreateGenesisBlock(), true, true, false,
                                  mining::PowAdmissionContext::Internal())
                  .IsAccepted(),
              "fixture genesis");
        std::vector<uint8_t> script{0x76, 0xa9, 0x14};
        script.insert(script.end(), 20, 0x31);
        script.insert(script.end(), {0x88, 0xac});
        const std::string address = ScriptToAddress(script);
        Block block;
        block.height = 1;
        block.header.version = PROTOCOL_VERSION;
        block.header.prev_block_hash = chain.TipCopy().GetHash();
        block.header.timestamp = chain.TipCopy().header.timestamp + TARGET_BLOCK_TIME;
        block.header.bits = chain.ComputeNextBits();
        block.transactions.push_back(
            Blockchain::BuildCanonicalCoinbase(block.height, chain.TotalSupplyUnits(), 0, script));
        block.UpdateMerkleRoot();
        check(
            chain.AddBlockDirect(block, true, true, false, mining::PowAdmissionContext::Internal())
                .IsAccepted(),
            "fixture first block");
        Mempool pool;
        StorageEngine storage(argv[1], MAINNET_MAGIC);
        RpcServer rpc(chain, pool, storage);
        StakingLedger staking;
        rpc.SetStaking(&staking);
        constexpr uint64_t required = 2 * MIN_TX_FEE;
        auto coin = [&](uint8_t id, uint64_t amount) {
            UTXO output;
            output.tx_hash.fill(id);
            output.output_index = 0;
            output.value = amount;
            output.script_pubkey = script;
            output.block_height = 0;
            output.is_coinbase = false;
            chain.TestInjectUTXO(output);
            return output;
        };
        const auto backing = coin(1, 1000 * VELD_UNITS);
        coin(2, required + 1);
        const auto usable = coin(3, required + DUST_THRESHOLD_UNITS);
        coin(4, 2000 * VELD_UNITS);
        StakingLedger::StateSnapshot snapshot;
        snapshot.stakes[address].push_back(
            StakeRecord{address, backing.value, 1, 10000, true, 1, backing.tx_hash, 0});
        snapshot.total_stake = backing.value;
        staking.RestoreState(snapshot);
        auto transition = chain.AcquireConsensusTransitionGuard();
        const auto state = rpc.ComputeWalletState(address);
        check(state.stake_backing_consistent, "normal stake backing is inconsistent");
        check(state.staked_units == backing.value, "stake balance changed");
        check(state.immature_coinbase_units > 0, "immature reward fixture missing");
        check(state.selectable.size() == 3, "backed or immature output entered selectable set");
        const auto* selected =
            mining::SelectNmsFundingOutput(state.selectable, chain.Height(), state.spendable_units,
                                           MIN_TX_FEE, MIN_TX_FEE, DUST_THRESHOLD_UNITS);
        check(selected && selected->tx_hash == usable.tx_hash, "usable funding was not selected");
        check(chain.GetUTXO(backing.tx_hash, 0).has_value() &&
                  staking.GetStake(address) == backing.value,
              "selection changed staked principal");
        std::cout << "PASS nms_wallet_funding_tests checks=" << checks
                  << " read_only_fixture_state=true keys=0 signatures=0 submissions=0 network=0\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
