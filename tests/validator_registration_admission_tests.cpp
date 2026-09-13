#define VELD_MAINNET_POW 1
#define VELD_TEST_CHAIN_BUILD 1
#define VELD_TEST_HOOKS 1
#define VELD_DSTATE_QUALIFICATION 1
#define VELD_ASERT_TESTCHAIN 1
#define VELD_TEST_BRANCH_CONTEXT 1
#define VELD_TEST_STAKE_OUTPOINT_BACKING 1
#define VELD_PROTOCOL_UPGRADE_TEST_HEIGHT 3840
#ifndef VELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT
#define VELD_VALIDATOR_REGISTRATION_FORK_TEST_HEIGHT 6200
#endif

#include "coinbase_admission_test_support.h"

namespace {
using namespace coinbase_test;
constexpr uint64_t activation = VALIDATOR_REGISTRATION_FORK_HEIGHT;
constexpr uint64_t parent_height = activation > 6600 ? activation - 1 : 6600;
static_assert(MIN_VALIDATOR_STAKE == 10000ULL * VELD_UNITS);

Node Reopen(const fs::path& path, uint64_t height) {
    auto config = RegtestConfig();
    config.port = 31359;
    auto node = std::make_unique<VeldNode>(config, path.string());
    node->SetQuietBoot(true);
    node->TestReplayDStateQualificationCorpus(height);
    Check(node->GetTCPServer() == nullptr, "restart opened a listener");
    return node;
}

std::string KeyHex(const RealKeyPair& key) {
    return BytesToHex(std::vector<uint8_t>(key.public_key.begin(), key.public_key.end()));
}

uint64_t Balance(VeldNode& node, const RealKeyPair& key) {
    uint64_t sum = 0;
    for (const auto& coin : node.GetChain().GetUTXOsForScript(key.GetP2PKHScript()))
        sum += coin.value;
    return sum;
}

std::vector<UTXO> Mature(VeldNode& node, const RealKeyPair& key) {
    auto coins = node.GetChain().GetUTXOsForScript(key.GetP2PKHScript());
    std::erase_if(coins, [&](const auto& coin) {
        return coin.is_coinbase && node.GetChain().Height() < coin.block_height + COINBASE_MATURITY;
    });
    return coins;
}

void SignAndQueue(VeldNode& node, Transaction& tx, const RealKeyPair& key) {
    for (size_t i = 0; i < tx.inputs.size(); ++i)
        tx.inputs[i].script_sig = key.SignInput(tx, static_cast<uint32_t>(i), key.GetP2PKHScript()).script_sig;
    Check(tx.Serialize().size() < 1024 * 1024, "fixture transaction exceeds mempool envelope");
    const auto result = node.GetMempoolMut().Add(tx, MIN_TX_FEE,
        static_cast<uint32_t>(node.GetChain().Height()), node.GetChain());
    Check(result == Mempool::AddResult::ACCEPTED,
        std::string("legitimate funded transaction refused: ") + Mempool::ResultToString(result));
}

void Consolidate(VeldNode& node, const RealKeyPair& key) {
    auto coins = Mature(node, key);
    std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) {
        return a.value > b.value || (a.value == b.value &&
            UTXOKey(a.tx_hash, a.output_index) < UTXOKey(b.tx_hash, b.output_index));
    });
    if (coins.size() < 128) return;
    Transaction tx;
    uint64_t sum = 0;
    for (size_t i = 0; i < 128; ++i) {
        TxInput input;
        input.prev_tx_hash = coins[i].tx_hash;
        input.prev_out_index = coins[i].output_index;
        tx.inputs.push_back(input);
        sum += coins[i].value;
    }
    tx.outputs.emplace_back(sum - MIN_TX_FEE, key.GetP2PKHScript());
    SignAndQueue(node, tx, key);
}

Transaction Register(VeldNode& node, const RealKeyPair& key) {
    auto coins = Mature(node, key);
    std::sort(coins.begin(), coins.end(), [](const auto& a, const auto& b) {
        return a.value > b.value || (a.value == b.value &&
            UTXOKey(a.tx_hash, a.output_index) < UTXOKey(b.tx_hash, b.output_index));
    });
    Transaction tx;
    uint64_t sum = 0;
    for (const auto& coin : coins) {
        TxInput input;
        input.prev_tx_hash = coin.tx_hash;
        input.prev_out_index = coin.output_index;
        tx.inputs.push_back(input);
        sum += coin.value;
        if (sum >= MIN_VALIDATOR_STAKE + MIN_TX_FEE) break;
    }
    Check(sum >= MIN_VALIDATOR_STAKE + MIN_TX_FEE, "naturally earned bond funding insufficient");
    Check(tx.inputs.size() <= 128, "bond funding was not consolidated");
    tx.outputs.emplace_back(0, BuildOpReturnScript(
        std::string(ValidatorRegistry::VAL_PREFIX) + "REGISTER|" + KeyHex(key)));
    tx.outputs.emplace_back(MIN_VALIDATOR_STAKE, AddressToScript(STAKE_VAULT_ADDRESS));
    if (sum > MIN_VALIDATOR_STAKE + MIN_TX_FEE)
        tx.outputs.emplace_back(sum - MIN_VALIDATOR_STAKE - MIN_TX_FEE, key.GetP2PKHScript());
    SignAndQueue(node, tx, key);
    return tx;
}

void BondAccounting(VeldNode& node, const RealKeyPair& key, const Transaction& tx,
                    uint64_t owner_before, uint64_t inclusion, uint64_t supply_before) {
    const auto snapshot = node.GetValidators().SnapshotState();
    const auto it = snapshot.validators.find(KeyHex(key));
    Check(it != snapshot.validators.end(), "accepted deposit has no attributable validator record");
    const auto& record = it->second;
    Check(record.active && record.bond_custodial && record.address == key.address &&
        record.registered_height == inclusion && record.bond_units == MIN_VALIDATOR_STAKE,
        "validator identity, height or principal differs from funded deposit");
    Check(snapshot.total_staked_units == 0, "validator bond changed ordinary staking");
    Check(Balance(node, key) == owner_before - MIN_VALIDATOR_STAKE - MIN_TX_FEE,
        "owner balance does not account for bond and fee");
    const auto output = node.GetChain().GetUTXO(tx.GetTxID(), 1);
    Check(output && output->value == record.bond_units &&
        output->script_pubkey == AddressToScript(STAKE_VAULT_ADDRESS), "vault output and bond principal differ");
    Check(node.TestReadDurableUTXO(tx.GetTxID(), 1).has_value(), "bond output was not durable");
    for (const auto& input : tx.inputs) {
        Check(!node.GetChain().GetUTXO(input.prev_tx_hash, input.prev_out_index), "spent bond input remains live");
        Check(!node.TestReadDurableUTXO(input.prev_tx_hash, input.prev_out_index), "spent bond input remains durable");
    }
    Coherent(node, supply_before + BLOCK_REWARD_UNITS);
}
}

int main(int argc, char** argv) {
    try {
        using namespace coinbase_test;
        Check(argc == 2, "supply one absent disposable fixture directory");
        const auto root = fs::absolute(argv[1]).lexically_normal();
        Check(!fs::exists(root), "existing fixture must be preserved");
        fs::create_directories(root);
        const auto owner = GenerateKeyPair(false);
        const auto other_miner = GenerateKeyPair(false);
        auto accepted = Fresh(root / "accepted");
        std::vector<Block> history;
        for (uint64_t h = 1; h <= parent_height; ++h) {
            if (h % 128 == 0) Consolidate(*accepted, owner);
            auto block = Build(*accepted, owner, h);
            Admit(*accepted, block);
            history.push_back(block);
            if (h % 480 == 0) std::cout << "PROGRESS naturally funded durable height=" << h << std::endl;
        }
        Check(accepted->GetValidators().SnapshotState().validators.empty(), "fixture unexpectedly registered a validator");
        auto branch = Fresh(root / "branch");
        for (const auto& block : history) Admit(*branch, block);
        Equal(*accepted, *branch);
        const auto owner_before = Balance(*accepted, owner);
        const auto supply_before = accepted->GetChain().TotalSupplyUnits();
        const auto tx = Register(*accepted, owner);
        const auto candidate = Build(*accepted, other_miner, 100000 + parent_height);
        Check(std::any_of(candidate.transactions.begin(), candidate.transactions.end(), [&](const auto& included) {
            return included.GetTxID() == tx.GetTxID();
        }), "builder omitted funded registration");

        size_t writes = 0;
        const auto before_failure = branch->TestObserveDStateQualificationState();
        branch->GetChainMut().SetDurableBlockBodyWriter([&](const Hash256&, const std::vector<uint8_t>&) {
            ++writes;
            return false;
        });
        Check(!branch->TestIngestDStateQualificationFrame(candidate.Serialize(), candidate.height),
            "candidate accepted despite body persistence failure");
        Check(writes > 0, "persistence failure control did not reach body writer");
        const auto after_failure = branch->TestObserveDStateQualificationState();
        Check(before_failure.utxo_digest == after_failure.utxo_digest &&
            before_failure.consensus_state_digest == after_failure.consensus_state_digest &&
            before_failure.supply_digest == after_failure.supply_digest &&
            before_failure.durable_tip_hash == after_failure.durable_tip_hash,
            "refused candidate partially changed accounting or durable tip");
        for (const auto& input : tx.inputs) {
            Check(branch->GetChain().GetUTXO(input.prev_tx_hash, input.prev_out_index).has_value(), "refusal consumed funding input");
            Check(branch->TestReadDurableUTXO(input.prev_tx_hash, input.prev_out_index).has_value(), "refusal consumed durable input");
        }
        branch.reset();
        branch = Reopen(root / "branch", parent_height);
        Equal(*accepted, *branch);
        std::cout << "PASS failed persistence leaves attributable funds and state unchanged after restart" << std::endl;

        Admit(*accepted, candidate);
        BondAccounting(*accepted, owner, tx, owner_before, candidate.height, supply_before);
        auto independent = Fresh(root / "independent");
        for (const auto& block : history) Admit(*independent, block);
        Admit(*independent, candidate);
        accepted.reset();
        accepted = Reopen(root / "accepted", candidate.height);
        Equal(*accepted, *independent);
        BondAccounting(*accepted, owner, tx, owner_before, candidate.height, supply_before);
        std::cout << "PASS accepted bond accounting, independent admission and durable restart" << std::endl;

        uint64_t disconnected = 0, applied = 0;
        for (uint64_t h = parent_height + 1; h <= parent_height + 3; ++h) {
            const auto block = Build(*branch, other_miner, 200000 + h);
            Admit(*branch, block);
            Admit(*accepted, block);
            disconnected += accepted->GetChain().LastReorgDisconnectCount();
            applied += accepted->GetChain().LastReorgApplyCount();
        }
        Check(disconnected > 0 && applied > 0, "longer branch did not exercise actual disconnect/apply");
        Equal(*accepted, *branch);
        Check(!accepted->GetValidators().SnapshotState().validators.contains(KeyHex(owner)), "orphaned bond record survived reorganization");
        Check(!accepted->GetChain().GetUTXO(tx.GetTxID(), 1), "orphaned vault output survived reorganization");
        Check(Balance(*accepted, owner) == owner_before, "reorganization did not restore owner funds");
        for (const auto& input : tx.inputs)
            Check(accepted->TestReadDurableUTXO(input.prev_tx_hash, input.prev_out_index).has_value(), "reorganization did not restore durable funding input");

        const auto retry_supply = branch->GetChain().TotalSupplyUnits();
        const auto retry = Register(*branch, owner);
        const auto retry_block = Build(*branch, other_miner, 300000 + parent_height);
        Admit(*branch, retry_block);
        Admit(*accepted, retry_block);
        BondAccounting(*accepted, owner, retry, owner_before, retry_block.height, retry_supply);
        Equal(*accepted, *branch);
        accepted.reset();
        accepted = Reopen(root / "accepted", retry_block.height);
        Equal(*accepted, *branch);
        BondAccounting(*accepted, owner, retry, owner_before, retry_block.height, retry_supply);
        std::ofstream receipt(root / "result.json");
        receipt << "{\"status\":\"passed\",\"activation\":" << activation
            << ",\"funded_parent\":" << parent_height << ",\"checks\":" << checks
            << ",\"network_started\":false,\"hash_work_bypassed\":true,\"injected_funds\":false}\n";
        std::cout << "PASS validator bond full accounting checks=" << checks << " activation=" << activation << std::endl;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << std::endl;
        return 1;
    }
}
